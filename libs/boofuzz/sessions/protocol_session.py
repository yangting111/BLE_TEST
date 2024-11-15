import datetime
import errno
import os
import socket
import threading
import time
from builtins import input
from io import open

from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.wsgi import WSGIContainer

from boofuzz import (
    blocks,
    constants,
    event_hook,
    exception,
    fuzz_logger,
    fuzz_logger_curses,
    fuzz_logger_db,
    fuzz_logger_text,
    helpers,
    pgraph,
    primitives,
)
from boofuzz.exception import BoofuzzFailure
from boofuzz.monitors.BLE_TargetMonitor import BLE_TargetMonitor

from boofuzz.web.app import app
from Ble_Test.packet.sul_interface_normal import *
from scapy.packet import *
from Ble_Test.libs.scapy.compat import raw 
from .connection import Connection
from .session_info import SessionInfo
from .web_app import WebApp

def open_test_run(db_filename, port=constants.DEFAULT_WEB_UI_PORT, address=constants.DEFAULT_WEB_UI_ADDRESS):
    s = SessionInfo(db_filename=db_filename)
    w = WebApp(session_info=s, web_port=port, web_address=address)
    w.server_init()

class ProtocolSession(pgraph.Graph):

    # initialize the session
    def __init__(self,target=None, 
                 monitor=None,
                 console_gui=False, 
                 single_num_mutations=0,
                 fuzz_db_keep_only_n_pass_cases=0,
                 restart_sleep_time=3,
                 web_port=constants.DEFAULT_WEB_UI_PORT,
                 receive_data_after_fuzz=True,
                 web_address=constants.DEFAULT_WEB_UI_ADDRESS,
                 fuzz_loggers=None,
                 crash_threshold_element=5,
                 db_filename=None,
                 ):
        super().__init__()

        self.target = target
        self.sulinterface = self.target._connection
        self._crash_threshold_element = crash_threshold_element
        self.root = pgraph.Node()
        self.root.label = "__ROOT_NODE__"
        self.last_recv = None
        self.last_send = []
        self.single_num_mutations = single_num_mutations
        self.total_num_mutations = 0
        self.total_mutant_index = 0
        self.console_gui = console_gui
        self.fuzz_node = None
        self.fuzz_by_field_name = False
        self.fuzz_by_layer = True
        self.web_address = web_address
        self.web_port = web_port
        self._keep_web_open = False
        self.monitor = monitor
        self.restart_sleep_time = restart_sleep_time
        self.cur_path = None
        self.cur_name = None
        self.check_failures = False
        self._run_id = datetime.datetime.utcnow().replace(microsecond=0).isoformat().replace(":", "-")
        if db_filename is not None:
            helpers.mkdir_safe(db_filename, file_included=True)
            self._db_filename = db_filename
        else:
            helpers.mkdir_safe(os.path.join(constants.RESULTS_DIR))
            self._db_filename = os.path.join(constants.RESULTS_DIR, "run-{0}.db".format(self._run_id))        

        self._db_logger = fuzz_logger_db.FuzzLoggerDb(
            db_filename=self._db_filename, num_log_cases=fuzz_db_keep_only_n_pass_cases
        )

        if fuzz_loggers is None:
            fuzz_loggers = []
            # if self.console_gui and os.name != "nt":
            #     fuzz_loggers.append(
            #         fuzz_logger_curses.FuzzLoggerCurses(web_port=self.web_port, web_address=self.web_address)
            #     )
            #     self._keep_web_open = False
            # else:
            fuzz_loggers = [fuzz_logger_text.FuzzLoggerText()]
        self._db_logger = fuzz_logger_db.FuzzLoggerDb(
            db_filename=self._db_filename, num_log_cases=fuzz_db_keep_only_n_pass_cases
        )
        self._fuzz_data_logger = fuzz_logger.FuzzLogger(fuzz_loggers=[self._db_logger] + fuzz_loggers)
        if self.web_port is not None:
            self.web_interface_thread = self.build_webapp_thread(port=self.web_port, address=self.web_address)


      
        self.on_failure = event_hook.EventHook()
        self._receive_data_after_fuzz = receive_data_after_fuzz

         
        if self.monitor is None: 
            if self.target and self.sulinterface is not None:
                self.monitor = BLE_TargetMonitor(target=self.target, fuzz_data_logger=self._fuzz_data_logger)
            else:
                self.monitor = None


    # def import_file(self):
    #     """
    #     Load various object values from disk.

    #     :see: export_file()
    #     """
    #     if self.session_filename is None:
    #         return

    #     try:
    #         with open(self.session_filename, "rb") as f:
    #             data = pickle.loads(zlib.decompress(f.read()))
    #     except (IOError, zlib.error, pickle.UnpicklingError):
    #         return

    #     # update the skip variable to pick up fuzzing from last test case.
    #     # self._index_start = data["total_mutant_index"]
    #     # self.session_filename = data["session_filename"]
    #     # self.sleep_time = data["sleep_time"]
    #     # self.restart_sleep_time = data["restart_sleep_time"]
    #     # self.restart_interval = data["restart_interval"]
    #     # self.web_port = data["web_port"]
    #     # self.web_address = data["web_address"]
    #     # self._crash_threshold_node = data["crash_threshold"]
    #     # self.total_num_mutations = data["total_num_mutations"]
    #     # self.total_mutant_index = data["total_mutant_index"]
    #     # self.monitor_results = data["monitor_results"]
    #     # self.is_paused = data["is_paused"]

    
    # def export_file(self):
    #     """
    #     Dump various object values to disk.

    #     :see: import_file()
    #     """

    #     if not self.session_filename:
    #         return

    #     data = {
    #         # "session_filename": self.session_filename,
    #         # "index_start": self.total_mutant_index,
    #         # "sleep_time": self.sleep_time,
    #         # "restart_sleep_time": self.restart_sleep_time,
    #         # "restart_interval": self.restart_interval,
    #         # "web_port": self.web_port,
    #         # "web_address": self.web_address,
    #         # "crash_threshold": self._crash_threshold_node,
    #         # "total_num_mutations": self.total_num_mutations,
    #         # "total_mutant_index": self.total_mutant_index,
    #         # "monitor_results": self.monitor_results,
    #         # "is_paused": self.is_paused,
    #     }

    #     fh = open(self.session_filename, "wb+")
    #     fh.write(zlib.compress(pickle.dumps(data, protocol=2)))
    #     fh.close()


    def connect(self, src, dst=None, callback=None):

        if isinstance(src, str):
            if dst is None:
                dst = src
                src_node = self.root
            else:
                src_node = self.find_node("label", src)
                if src_node is None:
                    src_node = pgraph.Node()
                    src_node.label = src

        if isinstance(dst, str):
            dst_node = self.find_node("label", dst)
            if dst_node is None:
                dst_node = pgraph.Node()
                dst_node.label = dst

        # if source or destination is not in the graph, add it.
        if self.find_node("label", src_node.label) is None:
            self.add_node(src_node)

        if self.find_node("label", dst_node.label) is None:
            self.add_node(dst_node)

        # create an edge between the two nodes and add it to the graph.
        edge = Connection(src_node, dst_node, callback=callback)
        self.add_edge(edge)

        return edge


    def server_init(self):
        """Called by fuzz() to initialize variables, web interface, etc."""
        if self.web_port is not None:
            if not self.web_interface_thread.is_alive():
                # spawn the web interface.
                self.web_interface_thread.start()
    

    def _callback_current_node(self, node, edge, test_case_context):
        """Execute callback preceding current node.
        Args:
            test_case_context (ProtocolSession): Context for test case-scoped data.
            node (pgraph.node.node (Node), optional): Current Request/Node
            edge (pgraph.edge.edge (pgraph.edge), optional): Edge along the current fuzz path from "node" to next node.
        Returns:
            bytes: Data rendered by current node if any; otherwise None.
        """
        data = None

        # if the edge has a callback, process it. the callback has the option to render the node, modify it and return.
        if edge.callback:
            self._fuzz_data_logger.open_test_step("Callback function '{0}'".format(edge.callback.__name__))
            data = edge.callback(
                self.target,
                self._fuzz_data_logger,
                session=self,
                node=node,
                edge=edge,
                test_case_context=test_case_context,
            )

        return data

    # fuzz the session
    def fuzz_graph(self,name=None,layer=None):
        # name: fuzz one packet
        # layer: fuzz by layer packet class

        fuzz_node = []
        fuzz_layer = []


        if name is not None and all(i in self.nodes for i in name):
            fuzz_node = name
        elif name is None:
            pass
        else:
            self._fuzz_data_logger.log_info("Node name not found: {}".format(name))
            return
        
        if layer is not None and isinstance(layer, list):
            fuzz_layer = layer
        elif layer is None:
            pass     
        else:
            self._fuzz_data_logger.log_info("Please specify a layer name")
            return
        
        if len(fuzz_node) == 0 and len(fuzz_layer) == 0:
            self._fuzz_data_logger.log_info("Normal packet is transmitted")
        
        self.server_init()

        pathlist = self.graph_path(self.root)

        if self.monitor.start_target() is True:
            self._fuzz_data_logger.log_info("Target is alive")
        else:
            self._fuzz_data_logger.log_info("Target is dead")
            return
        
        print(pathlist)

        try:
            self.num_cases_actually_fuzzed = 0
            self.start_time = time.time()
            for path in pathlist:
                self.cur_path = path
                for pkt_name in path[1:]:
                    if pkt_name == path[-1]:
                        print(Fore.LIGHTCYAN_EX + "Fuzzing packet by name: {}".format(pkt_name))
                        self.cur_name = pkt_name
                        self.check_failures = True
                        self._fuzz_data_logger.open_test_case(pkt_name, path)

                        if pkt_name in fuzz_node and len(fuzz_layer) == 0:

                            self._fuzz_data_logger.log_info("Fuzzing packet by name: {}, Fuzzing layer should not be None".format(pkt_name),)

                        elif pkt_name in fuzz_node and len(fuzz_layer) != 0:

                            self._fuzz_data_logger.log_info("Fuzzing packet : {0}, Layer : {1}".format(pkt_name, fuzz_layer))
                            
                            for i in range(self.single_num_mutations):

                                fuzz_pkt = self.fuzz_packet(self.sulinterface.get_packet(pkt_name), fuzz_layer)

                                self.transmit(fuzz_pkt)

                                self.num_cases_actually_fuzzed += 1
                        elif pkt_name not in fuzz_node and len(fuzz_layer) == 0:

                            fuzz_pkt = self.sulinterface.get_packet(pkt_name)

                            self.transmit(fuzz_pkt)
                        else:
                            self._fuzz_data_logger.log_info("Fuzzing Layer : {0}".format(fuzz_layer))

                            for i in range(self.single_num_mutations):

                                fuzz_pkt = self.fuzz_packet(self.nodes[pkt_name], fuzz_layer)

                                self.transmit(fuzz_pkt)

                                self.num_cases_actually_fuzzed += 1
                    else:
                        self.check_failures = False
                        fuzz_pkt = self.sulinterface.get_packet(pkt_name)
                        self.transmit(fuzz_pkt)

                # SUL restart
                if self.monitor is not None:
                    self.monitor.restart_target()
                
            if self._keep_web_open and self.web_port is not None:
                self.end_time = time.time()
                print(
                    "\nFuzzing session completed. Keeping webinterface up on {}:{}".format(
                        self.web_address, self.web_port
                    ),
                    "\nPress ENTER to close webinterface",
                )
                input()            

        except KeyboardInterrupt:

            self._fuzz_data_logger.log_fail("SIGINT received ... exiting")
            raise
            
        return
    def fuzz_packet(self, pkt, fuzz_layer = None):

        if isinstance(pkt, list):
            return self.fuzz_packetlist(pkt, fuzz_layer)
        elif isinstance(pkt, Packet):
            return self.fuzz_one_packet(pkt, fuzz_layer)
        else:
            raise BoofuzzFailure("Invalid packet type for fuzz: {0}".format(type(pkt)))

    def fuzz_packetlist(self, pktlist, fuzz_layer = None):

        new_pktlist = []
        for pkt in pktlist:
            new_pktlist.append(self.fuzz_one_packet(pkt, fuzz_layer))
        return new_pktlist

    def fuzz_one_packet(self, p, fuzz_layer = None):

        p = p.copy()
        q = p    
        new_default_fields = {}
        multiple_type_fields = []  # type: List[str]
        if fuzz_layer is None:
            self._fuzz_data_logger.log_info("fuzz_layer should not None")
            return
        while not isinstance(q, NoPayload):
            if isinstance(q, tuple(fuzz_layer)):    
                for f in q.fields_desc:
                    if isinstance(f, PacketListField):
                        for r in getattr(q, f.name):
                            fuzz(r, _inplace=1)
                    elif isinstance(f, MultipleTypeField):
                        # the type of the field will depend on others
                        multiple_type_fields.append(f.name)
                    elif f.default is not None:
                        if not isinstance(f, ConditionalField) or f._evalcond(q):
                            rnd = f.randval()
                            if rnd is not None:
                                new_default_fields[f.name] = rnd
                # Process packets with MultipleTypeFields
                if multiple_type_fields:
                    # freeze the other random values
                    new_default_fields = {
                        key: (val._fix() if isinstance(val, VolatileValue) else val)
                        for key, val in six.iteritems(new_default_fields)
                    }
                    q.default_fields.update(new_default_fields)
                    # add the random values of the MultipleTypeFields
                    for name in multiple_type_fields:
                        fld = cast(MultipleTypeField, q.get_field(name))
                        rnd = fld._find_fld_pkt(q).randval()
                        if rnd is not None:
                            new_default_fields[name] = rnd
                q.default_fields.update(new_default_fields)
            else:
                pass
            q = q.payload
        return p


    def build_webapp_thread(self, port=constants.DEFAULT_WEB_UI_PORT, address=constants.DEFAULT_WEB_UI_ADDRESS):
        app.session = self
        http_server = HTTPServer(WSGIContainer(app))
        while True:
            try:
                http_server.listen(port, address=address)
            except socket.error as exc:
                # Only handle "Address already in use"
                if exc.errno != errno.EADDRINUSE:
                    raise
                port += 1
            else:
                self._fuzz_data_logger.log_info("Web interface can be found at http://%s:%d" % (address, port))
                break
        flask_thread = threading.Thread(target=IOLoop.instance().start)
        flask_thread.daemon = True
        return flask_thread
    

    def normal_send(self, path):

        self.check_failures = False
        for pkt_name in path[1:-1]:
            pkt = self.sulinterface.get_packet(pkt_name)
            self.transmit(pkt)

    def transmit(self, packet):
        if isinstance(packet, list):
            self.transmit_list(packet)
        elif isinstance(packet, Packet):
            self.transmit_one(packet)
        else:
            raise BoofuzzFailure("Invalid packet type for transmit: {0}".format(type(packet)))

    def transmit_list(self, packet_list):
            
            for pkt in packet_list:
                self.transmit_one(pkt)

    def transmit_one(self, packet):

        rawpkt = raw(packet)
        try:  # send

            self.target.send(rawpkt)
            print(Fore.CYAN + "TX ---> " + packet.summary()[7:])
        except exception.BLESerialTargetReset as e:
            self._fuzz_data_logger.log_fail()
   
        received = b""
        try:  # recv
            if self._receive_data_after_fuzz:
                received = self.target.recv()
        except exception.BoofuzzTargetConnectionFailedError as e:
                self._fuzz_data_logger.log_error(rawpkt)
                self.monitor.restart_target()
                self.normal_send(self.cur_path)

        self.last_recv = received

        if self.check_failures is True:
            self._fuzz_data_logger.log_info("Checking for failures")
            if self.monitor.alive() is True:
                pass
            else:
                self._fuzz_data_logger.log_error(rawpkt)
                self.monitor.restart_target()
                self.normal_send(self.cur_path)

            

