# ##originally named gatt_core.py, renamed since this contains the core of our stack.
import sys
import errno
import select as native_select
import functools
import threading
import gevent
from gevent.select import select
# this is hack because the above does not work
from gevent import monkey
monkey.patch_select()
from gevent.lock import BoundedSemaphore
import logging
import time
from blesuite.pybt.gap import GAP
from blesuite.pybt.stack import BTEvent
import blesuite.pybt.att as att


log = logging.getLogger(__name__)

MAX_PACKET_LIFE = 15  # seconds (arbitrary number)

mutex = BoundedSemaphore(1)


PUBLIC_DEVICE_ADDRESS = 0x00
RANDOM_DEVICE_ADDRESS = 0x01

ROLE_TYPE_CENTRAL = 0x00
ROLE_TYPE_PERIPHERAL = 0x01


class ConnectionError(Exception):
    pass


class GATTError(object):
    def __init__(self, request, handle, ecode, pkt, conn_handle, opcode=-1):
        self.request = request
        self.handle = handle
        self.ecode = ecode
        self.pkt = pkt
        self.conn_handle = conn_handle
        # opcode is used by requests looking for errors
        # related to malformed packet responses
        self.opcode = opcode


class GATTResponse(object):
    def __init__(self, opcode, data, pkt, conn_handle, handle=None):
        self.opcode = opcode
        self.data = data # LIST
        self.handle = handle
        self.pkt = pkt
        self.conn_handle = conn_handle


class GATTRequest(object):

    def __init__(self, opcode, expected_response_opcode, conn_handle, handle=None,
                 uuid=None, value= None, start=None, end=None, dest_addr=None, timeout=15 * 1000):
        self.opcode = opcode
        self.conn_handle = conn_handle
        self.handle = handle
        self.start = start
        self.end = end
        self.uuid = uuid
        self.expected_response_opcode = expected_response_opcode
        self.value = value
        self.dest_addr = dest_addr
        self.timeout = timeout  # in ms
        self.creation_time = time.time() * 1000  # time in ms
        self.response = None
        self.error = False
        # self.errorMessage = None
        self.error_object = None

    def has_response(self):
        if self.response is None:
            return False
        return True

    def has_error(self):
        return self.error

    def get_error_message(self):
        code = self.error_object.ecode
        if isinstance(code, list):
            code = code[0]
        if code in att.ATT_ERROR_CODE_NAME.keys():
            return ["Error: %s" % att.ATT_ERROR_CODE_NAME[code]]
        else:
            return ["Unknown Error: %s" % code]


class SocketHandler(object):
    def __init__(self, conn):
        self.conn = conn
        self.event_handler = conn.event_handler

    def dump_gap(self, data):
        if len(data) > 0:
            try:
                gap = GAP()
                gap.decode(data)
                print ("GAP: %s" % gap)
            except Exception as e:
                print (e)
                pass

    def generate_response(self, data):
        # we manually have to create response object because the packet
        # structures received vary
        pkt = data[1]
        conn_handle = data[0]
        if att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["read"][1] == pkt.opcode:
            log.debug("FOUND READ RESPONSE: %s" % (pkt))
            try:
                self.conn.responses.append(GATTResponse(pkt.opcode, [pkt.value], pkt, conn_handle))
            except AttributeError as e:
                log.debug("Potentially received malformed packet. AttributeError raised: %s" % (e))
                self.conn.responses.append(GATTError(e, -1, -1, pkt, conn_handle))
        elif att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["write"][1] == pkt.opcode:
            log.debug("FOUND WRITE RESPONSE: %s" % (pkt))
            self.conn.responses.append(GATTResponse(pkt.opcode, [""], pkt, conn_handle))
        elif att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["prepare_write"][1] == pkt.opcode:
            log.debug("FOUND PREPARE WRITE RESPONSE: %s" % (pkt))
            self.conn.responses.append(GATTResponse(pkt.opcode, [pkt.gatt_handle, pkt.offset, pkt.data],
                                                    pkt, conn_handle))
        elif att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["execute_write"][1] == pkt.opcode:
            log.debug("FOUND EXECUTE WRITE RESPONSE: %s" % (pkt))
            self.conn.responses.append(GATTResponse(pkt.opcode, [""], pkt, conn_handle))
        elif att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["read_by_type"][1] == pkt.opcode:
            log.debug("FOUND READ_BY_TYPE RESPONSE: %s" % (pkt))
            data = pkt.data
            group_lens = int(data[0].encode('hex'), 16)
            list_data = []
            for i in range(0, len(data[2:]), group_lens):
                list_data.append(data[2:][i:i + group_lens])
            self.conn.responses.append(GATTResponse(pkt.opcode, list_data, pkt, conn_handle))
        elif att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["read_by_group_type"][1] == pkt.opcode:
            log.debug("FOUND READ_BY_GROUP_TYPE RESPONSE")
            self.conn.responses.append(GATTResponse(pkt.opcode, [pkt.data], pkt, conn_handle))
        elif att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["find_information"][1] == pkt.opcode:
            log.debug("FOUND FIND_INFORMATION RESPONSE")
            self.conn.responses.append(GATTResponse(pkt.opcode, [pkt.data], pkt, conn_handle))
        elif att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["exchange_MTU"][1] == pkt.opcode:
            log.debug("FOUND EXCHANGE MTU RESPONSE: %s" % (pkt))
            self.conn.responses.append(GATTResponse(pkt.opcode, [pkt.mtu], pkt, conn_handle))
            self.conn.connection_mtus[conn_handle] = pkt.mtu
        elif att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["error_response"][1] == pkt.opcode:
            log.debug("FOUND ERROR_RESPONSE RESPONSE handle: %s ecode: %s conn_handle: %s packetRqst: %s" % (pkt.handle, pkt.ecode, conn_handle, pkt.request))
            self.conn.errors.append(GATTError(pkt.request, pkt.handle, [pkt.ecode], pkt, conn_handle))

    def process_responses(self):
        # check for valid responses
        for response in self.conn.responses:
            for request in self.conn.requests:
                self.conn.mutex.acquire()
                try:
                    if (response.opcode == request.expected_response_opcode and
                       response.conn_handle == request.conn_handle):
                        log.debug("Matched response to request!")
                        request.response = response
                        log.debug("Matched response: %s" % response)
                        log.debug("Current response list: %s" % self.conn.responses)
                        self.conn.responses.remove(response)
                        self.conn.requests.remove(request)
                        break
                    else:
                        if ((time.time()*1000)-request.creation_time) >= request.timeout:
                            log.debug("Request timed out")
                            request.error = True
                            error = GATTError(request, None,
                                              "Request timed out. Expected response not received",
                                              None, request.conn_handle)
                            request.error_object = error
                            # self.conn.responses.remove(response)
                            self.conn.requests.remove(request)
                            break
                finally:
                    self.conn.mutex.release()
        # check for errors
        for error in self.conn.errors:
            for request in self.conn.requests:
                self.conn.mutex.acquire()
                try:
                    if ((request.handle == error.handle or request.start == error.handle or
                         request.opcode == error.request) and
                       request.conn_handle == error.conn_handle):
                        log.debug("Matched error to request!")
                        log.debug("Matched error: %s" % error.ecode)
                        log.debug("Current error list: %s" % self.conn.errors)
                        request.error = True
                        request.error_object = error
                        self.conn.requests.remove(request)
                        self.conn.errors.remove(error)
                        break
                    elif (error.handle == -1 and error.opcode != -1 and
                          (error.conn_handle == request.conn_handle)):
                        for key in att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS:
                            if len(att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS) != 2:
                                # we can only pair malformed responses of action types
                                # that have a cooresponding response opcode
                                continue
                            if (att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS[key][0] == request.opcode and
                                    att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS[key][1] == error.opcode):
                                log.debug("Potentially matched malformed packet error to request!")
                                log.debug("Matched error: %s" % error.ecode)
                                log.debug("Current error list: %s" % self.conn.errors)
                                request.error = True
                                request.error_object = error
                                self.conn.requests.remove(request)
                                self.conn.errors.remove(error)
                                break
                finally:
                    self.conn.mutex.release()
        # check for timeouts
        for request in self.conn.requests:
            self.conn.mutex.acquire()
            try:
                if ((time.time()*1000)-request.creation_time) >= request.timeout:
                    log.debug("Request timed out")
                    request.error = True
                    error = GATTError(request, None,
                                      "Request timed out. Expected response not received",
                                      None, request.conn_handle)
                    request.error_object = error
                    # request.errorMessage = ("Request timed out. Expected response not received "
                    #                        "on handle %s" % request.handle)
                    # self.conn.responses.remove(response)
                    self.conn.requests.remove(request)
            finally:
                self.conn.mutex.release()

    def process_l2cap(self, data):
        from scapy.layers.bluetooth import L2CAP_Hdr, L2CAP_CmdHdr, L2CAP_Connection_Parameter_Update_Response

        conn_handle = data[0]
        pkt = data[1]
        if pkt.cid == 0x05 and pkt.code == 0x12:  # L2CAP LE Connection Parameter Update Request
            # ensure no packets can be sent by application while we process this
            self.conn.block = True
            min_interval = pkt.min_interval
            max_interval = pkt.max_interval
            latency = pkt.slave_latency
            timeout = pkt.timeout_mult
            log.debug("Got L2CAP LE Connection Parameter Update Request")
            log.debug("Sending connection parameter response")
            # send L2CAP response, then send HCI command
            self.conn.role.stack.raw_l2cap(L2CAP_Hdr(len=6, cid=5)/L2CAP_CmdHdr(code=19, id=pkt.id, len=2) /
                                           L2CAP_Connection_Parameter_Update_Response(move_result=0),
                                           conn_handle)
            log.debug("Sending HCI update connection params")
            # min and max CE seem to not be defined? spec says they are implementation specific?
            self.conn.role.stack.update_connection_params(conn_handle, min_interval, max_interval,
                                                          latency, timeout, 0, 0)
            # update PyBT params
            self.conn.role.stack.interval_min = min_interval
            self.conn.role.stack.interval_max = max_interval
            # resume
            self.conn.block = False

    # Make this look a bit like a thread.
    

class Connection(object):
    def __init__(self, role, role_type, event_handler=None):
        self.connected = False
        # role is role object, role is the int identifier
        self.role = role
        self.role_type = role_type
        self.seen = {}
        self.onconnect = []
        self.event_handler = event_handler
        self.socket_handler = None
        self.socket_handler_thread = None
        self.responses = []
        self.requests = []
        self.connect_requests = []
        self.errors = []
        self.connected_addr = None
        self.connected_addr_type = None
        self.connection_statuses = {}
        self.peer_addresses_by_connection_handle = {}
        self.connected_addr_type_by_connection_handle = {}
        self.connection_mtus = {}
        self.advertising = False
        self.block = False
        self.mutex = mutex
        self.sec = None





    def connect(self, conn_handle, addr, kind=None):
        log.debug("Connecting...")
        # just to make sure comparisons are done with uppercase
        addr = addr.upper()
        if kind is None:
            # We may have inferred it's kind from seeing it advertising
            kind = self.seen.get(addr, (None,))[0]

        if kind is None:
            print ("Error: please give address type")
        else:
            print ("Connecting..")

            if conn_handle in self.connection_statuses.keys() and self.connection_statuses[conn_handle] is True:
                log.debug("Connection already established")
                return
            request = GATTRequest(None, None, None, dest_addr=addr)
            self.connect_requests.append(request)
            self.role.stack.connect(addr, kind)
            return request



    def set_event_handler(self, event_handler):
        self.event_handler = event_handler
        self.socket_handler.event_handler = event_handler
        return


    def read_remote_used_features(self, conn_handle):
        log.debug("Read remote used feature for connection handle: %s" % conn_handle)
        # TODO Verify that we don't need to track the LE Meta packet that results from this
        self.read_remote_used_features_req(conn_handle)
        return



    def exchange_mtu_async(self, mtu, conn_handle, timeout=15 * 1000):
        request = GATTRequest(att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["exchange_MTU"][0],
                              att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["exchange_MTU"][1],
                              conn_handle,
                              handle=None,
                              timeout=timeout)
        self.requests.append(request)
        self.exchange_mtu_req(mtu, conn_handle)
        return request



    def read_async(self, handle, conn_handle, timeout=15 * 1000):
        request = GATTRequest(att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["read"][0],
                              att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["read"][1],
                              conn_handle,
                              handle=handle, timeout=timeout)
        self.requests.append(request)
        self.read(handle, conn_handle)
        return request



    def read_blob_async(self, handle, offset, conn_handle, timeout=15 * 1000):
        request = GATTRequest(att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["read_blob"][0],
                              att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["read_blob"][1],
                              conn_handle,
                              handle=handle, timeout=timeout)
        self.requests.append(request)
        self.read_blob(handle, offset, conn_handle)
        return request



    def read_multiple_async(self, handles, conn_handle, timeout=15 * 1000):
        request = GATTRequest(att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["read_multiple"][0],
                              att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["read_multiple"][1],
                              conn_handle, timeout=timeout)
        self.requests.append(request)
        self.read_multiple(handles, conn_handle)
        return request


    def read_by_type_async_128bit(self, uuid, conn_handle, start=0x0001, end=0xffff, timeout=15 * 1000):
        request = GATTRequest(att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["read_by_type"][0],
                              att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["read_by_type"][1],
                              conn_handle,
                              uuid=uuid, start=start, end=end, timeout=timeout)
        uuid1 = uuid.uuid.replace('-', '')[16:]
        uuid2 = uuid.uuid.replace('-', '')[:16]
        self.requests.append(request)
        self.read_by_type_128bit(start, end, int(uuid1, 16), int(uuid2, 16), conn_handle)
        return request

    def read_by_type_async(self, uuid, conn_handle, start=0x0001, end=0xffff, timeout=15 * 1000):
        request = GATTRequest(att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["read_by_type"][0],
                              att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["read_by_type"][1],
                              conn_handle,
                              uuid=uuid, start=start, end=end, timeout=timeout)
        self.requests.append(request)
        self.read_by_type(start, end, int(uuid.uuid, 16), conn_handle)
        return request




    def write_req_async(self, handle, value, conn_handle, timeout=15 * 1000):
        request = GATTRequest(att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["write"][0],
                              att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["write"][1],
                              conn_handle,
                              handle=handle, value=value, timeout=timeout)
        self.requests.append(request)
        self.write_req(handle, value, conn_handle)
        return request

    # Note: We do not create sync or async function for the write_cmd function
    # Write command doesn't return us errors or responses, we blindy send and if there's
    # an error, it is ignored. We don't need to track the request.
    def write_command(self, handle, value, conn_handle, timeout=15 * 1000):
        request = GATTRequest(att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["write_command"][0],
                              att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["write_command"][1],
                              conn_handle,
                              handle=handle, value=value, timeout=timeout)
        self.write_cmd(handle, value, conn_handle)
        return request



    def prepare_write_req_async(self, handle, value, offset, conn_handle, timeout=15 * 1000):
        request = GATTRequest(att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["prepare_write"][0],
                              att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["prepare_write"][1],
                              conn_handle,
                              handle=handle, value=value, timeout=timeout)
        self.requests.append(request)
        self.prepare_write_req(handle, value, offset, conn_handle)
        return request


    def execute_write_req_async(self, flags, conn_handle, timeout=15 * 1000):
        request = GATTRequest(att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["execute_write"][0],
                              att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["execute_write"][1],
                              conn_handle,
                              handle=None, value=None, timeout=timeout)
        self.requests.append(request)
        self.execute_write_req(flags, conn_handle)
        return request

    def find_information_sync(self, start, end, conn_handle, timeout=15 * 1000):
        request = GATTRequest(att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["find_information"][0],
                              att.ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS["find_information"][1],
                              conn_handle,
                              start=start, end=end, timeout=timeout)
        self.requests.append(request)
        self.find_information(conn_handle, start, end)
        while not request.has_response() and not request.has_error():
            log.debug("Waiting...hasResponse:%s hasError:%s" % (request.has_response(), request.has_error()))
            gevent.sleep(1)
            self._check_timeout_and_errors()
        return request



    def send_raw_att(self, body, conn_handle, timeout=15 * 1000):
        #request = GATTRequest(None,
        #                      None,
        #                      conn_handle,
        #                      handle=None,
        #                      value=body, timeout=timeout)
        self.raw_att(body, conn_handle)
        return None

    def send_raw_l2cap(self, body, conn_handle):
        self.raw_l2cap(body, conn_handle)
        return None

    def read_remote_used_features_req(self, conn_handle):
        if self.block:
            while True:
                time.sleep(1)
        self.role.stack.read_remote_used_features(conn_handle)

    def exchange_mtu_req(self, mtu, conn_handle):
        if self.block:
            while True:
                time.sleep(1)
        self.role.att.exchange_mtu(mtu, conn_handle)

    def write_req(self, handle, value, conn_handle):
        if self.block:
            while True:
                time.sleep(1)
        self.role.att.write_req(handle, value, conn_handle)

    def write_cmd(self, handle, value, conn_handle):
        if self.block:
            while True:
                time.sleep(1)
        self.role.att.write_cmd(handle, value, conn_handle)

    def prepare_write_req(self, handle, value, offset, conn_handle):
        if self.block:
            while True:
                time.sleep(1)
        self.role.att.prepare_write_req(handle, value, offset, conn_handle)

    def execute_write_req(self, flags, conn_handle):
        if self.block:
            while True:
                time.sleep(1)
        self.role.att.execute_write_req(flags, conn_handle)

    def read(self, handle, conn_handle):
        if self.block:
            while True:
                time.sleep(1)
        self.role.att.read(handle, conn_handle)

    def read_blob(self, handle, offset, conn_handle):
        if self.block:
            while True:
                time.sleep(1)
        self.role.att.read_blob(handle, offset, conn_handle)

    def read_multiple(self, handles, conn_handle):
        if self.block:
            while True:
                time.sleep(1)
        self.role.att.read_multiple(handles, conn_handle)

    def read_by_type(self, start, end, uuid, conn_handle):
        if self.block:
            while True:
                time.sleep(1)
        self.role.att.read_by_type(start, end, uuid, conn_handle)

    def read_by_type_128bit(self, start, end, uuid, uuid2, conn_handle):
        if self.block:
            while True:
                time.sleep(1)
        self.role.att.read_by_type_128bit(start, end, uuid, uuid2, conn_handle)

    def read_by_group_type(self, start, end, uuid, conn_handle):
        if self.block:
            while True:
                time.sleep(1)
        self.role.att.read_by_group_type(start, end, uuid, conn_handle)

    def find_information(self, conn_handle, start, end):
        if self.block:
            while True:
                time.sleep(1)
        self.role.att.find_information(conn_handle, start, end)

    def raw_att(self, body, conn_handle):
        if self.block:
            while True:
                time.sleep(1)
        self.role.stack.raw_att(body, conn_handle)

    def raw_l2cap(self, body, conn_handle):
        if self.block:
            while True:
                time.sleep(1)
        self.role.stack.raw_l2cap(body, conn_handle)

    def set_interval(self, int_min, int_max):
        self.role.stack.interval_min = int_min
        self.role.stack.interval_max = int_max

    def on_connect(self, thunk):
        self.onconnect.append(thunk)
    
    def raw(self, cmd):
        if self.block:
            while True:
                time.sleep(1)
        self.role.stack.raw_att(cmd)
