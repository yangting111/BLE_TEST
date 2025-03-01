import re
# 按行读取.txt文件


def read_file_by_line(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    return lines

# 有包含raw
def match_raw(file_path):
    lines = read_file_by_line(file_path)
    pattern = r'\|raw'
    for line in lines:
        match = re.search(pattern, line)
        if bool(match):
            print(line)

# 有两个pairing_request_pkt|pairing_response_pkt
def two_pairing_request_pkt_pairing_response_pkt(file_path):
    lines = read_file_by_line(file_path)
    pattern = r'(pairing_request_pkt\|pairing_response_pkt).*(pairing_request_pkt\|pairing_response_pkt)'
    for line in lines:
        match = re.search(pattern, line)
        if bool(match):
            print(line)


# 匹配 (ll_enc_req_pkt|ll_enc_rsp_pkt,ll_start_enc_req_pkt) 但是 (ll_enc_req_pkt|ll_enc_rsp_pkt,ll_start_enc_req_pkt) 之前没有 (pairing_random_pkt|pairing_random_pkt) 的正则表达式
def match_not_after_pairing_random(file_path):
    lines = read_file_by_line(file_path)
    pattern = r'^(?!.*pairing_random_pkt\|pairing_random_pkt.*)(.*(ll_enc_req_pkt\|ll_enc_rsp_pkt,ll_start_enc_req_pkt))'
    for line in lines:
        match = re.search(pattern, line)
        if bool(match):
            print(line)
# 匹配 ll_pause_enc_req_pkt|ll_pause_enc_rsp_pkt 但是 ll_pause_enc_req_pkt|ll_pause_enc_rsp_pkt 之前没有 ll_start_enc_rsp_pkt|ll_start_enc_rsp_pkt 的正则表达式
def match_not_after_start_enc_rsp(file_path):
    lines = read_file_by_line(file_path)
    pattern = r'^(?!.*ll_start_enc_rsp_pkt\|ll_start_enc_rsp_pkt.*)(.*ll_pause_enc_req_pkt\|ll_pause_enc_rsp_pkt)'
    for line in lines:
        match = re.search(pattern, line)
        if bool(match):
            print(line)

# 匹配 connect_req 之后有 ll_enc_req_pkt|ll_enc_rsp_pkt 的正则表达式
def match_connect_req_followed_by_enc_req(file_path):
    lines = read_file_by_line(file_path)
    pattern = r'connect_req.*(ll_start_enc_rsp_pkt\|ll_start_enc_rsp_pkt)'
    for line in lines:
        match = re.search(pattern, line)
        if bool(match):
            print(line)



# 有两个
if __name__ == '__main__':
    file_path = '/home/yangting/Documents/Ble_state_check/result/log_file/Esp32/output.txt'
    # match_raw(file_path)
    # print('--------------------------------match_raw--------------------------------')
    # match_raw(file_path)
    # print('--------------------------------two_pairing_request_pkt_pairing_response_pkt--------------------------------')
    # two_pairing_request_pkt_pairing_response_pkt(file_path)
    # print('--------------------------------two_pairing_request_pkt_pairing_response_pkt--------------------------------')
    # match_not_after_pairing_random(file_path)
    # print('--------------------------------match_not_after_start_enc_rsp--------------------------------')
    # match_not_after_start_enc_rsp(file_path)
    print('--------------------------------match_connect_req_followed_by_enc_req--------------------------------')
    match_connect_req_followed_by_enc_req(file_path)


        
