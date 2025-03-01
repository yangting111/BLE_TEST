map = {
       'Raw':'raw_pkt',
       "BTLE_ADV_IND":'adv_ind_pkt',
       'BTLE_ADV_DIRECT_IND':'adv_direct_ind_pkt',
       'BTLE_ADV_NONCONN_IND':'adv_nonconn_ind',
       'BTLE_SCAN_REQ':'scan_req',
       'BTLE_SCAN_RSP':'scan_rsp',
       'BTLE_CONNECT_REQ':'connect_req',
       'BTLE_ADV_SCAN_IND':'adv_scan_ind',
       'LL_CONNECTION_UPDATE_IND':'ll_connection_update_ind_pkt',
       'LL_CHANNEL_MAP_IND':'ll_channel_map_req_pkt', 
       'LL_TERMINATE_IND':'ll_terminate_ind_pkt', 
       'LL_ENC_REQ':'ll_enc_req_pkt',
       'LL_ENC_RSP':'ll_enc_rsp_pkt',
       'LL_START_ENC_REQ':'ll_start_enc_req_pkt', 
       'LL_START_ENC_RSP':'ll_start_enc_rsp_pkt', 
       'LL_UNKNOWN_RSP':'ll_unknown_rsp_pkt', 
       'LL_FEATURE_REQ':'ll_feature_req_pkt', 
       'LL_FEATURE_RSP':'ll_feature_rsp_pkt', 
       'LL_PAUSE_ENC_REQ':'ll_pause_enc_req_pkt', 
       'LL_PAUSE_ENC_RSP':'ll_pause_enc_rsp_pkt', 
       'LL_VERSION_IND':'ll_version_ind_pkt', 
       'LL_REJECT_IND':'ll_reject_ind_pkt', 
       'LL_SLAVE_FEATURE_REQ':'ll_slave_feature_req_pkt', 
       'LL_CONNECTION_PARAM_REQ':'ll_connection_param_req_pkt', 
       'LL_CONNECTION_PARAM_RSP':'ll_connection_param_rsp_pkt', 
       'LL_REJECT_EXT_IND':'ll_reject_ind_ext_pkt', 
       'LL_PING_REQ':'ll_ping_req_pkt', 
       'LL_PING_RSP':'ll_ping_rsp_pkt', 
       'LL_LENGTH_REQ':'ll_length_req_pkt', 
       'LL_LENGTH_RSP':'ll_length_rsp_pkt',
       'LL_PHY_REQ':'ll_phy_req_pkt',
       'LL_PHY_RSP':'ll_phy_rsp_pkt',
       'LL_PHY_UPDATE_IND':'ll_phy_update_ind_pkt',
       'LL_MIN_USED_CHANNELS_IND':'ll_min_used_channels_ind_pkt',
       'L2CAP_CmdRej':'l2cap_command_reject_rsp_pkt',
       'L2CAP_DisconnReq':'l2cap_disconnection_req_pkt',
       'L2CAP_DisconnResp':'l2cap_disconnection_rsp_pkt',
       'L2CAP_Connection_Parameter_Update_Request':'l2cap_connection_parameter_update_req_pkt',
       'L2CAP_Connection_Parameter_Update_Response':'l2cap_connection_parameter_update_rsp_pkt',
       'L2CAP_LE_Credit_Based_Connection_Request':'l2cap_le_credit_based_connection_req_pkt',
       'L2CAP_LE_Credit_Based_Connection_Response':'l2cap_le_credit_based_connection_rsp_pkt',
       'L2CAP_LE_Flow_Control_Credit_IND':'l2cap_le_flow_control_credit_ind_pkt',
       'L2CAP_Credit_Based_Connection_Request':'l2cap_credit_based_connection_req_pkt',
       'L2CAP_Credit_Based_Connection_Response':'l2cap_credit_based_connection_rsp_pkt',
       'L2CAP_Credit_Based_Reconfigure_Request':'l2cap_credit_based_reconfigure_req_pkt',
       'L2CAP_Credit_Based_Reconfigure_Response':'l2cap_credit_based_reconfigure_rsp_pkt',
       'SM_Pairing_Request':'pairing_request_pkt', 
       'SM_Pairing_Response': 'pairing_response_pkt', 
       'SM_Confirm': 'pairing_confirm_pkt', 
       'SM_Random':'pairing_random_pkt', 
       'SM_Failed':'pairing_failed_pkt', 
       'SM_Encryption_Information':'encryption_information_pkt', 
       'SM_Master_Identification':'master_identification_pkt', 
       'SM_Identity_Information':'identity_information_pkt', 
       'SM_Identity_Address_Information':'identity_address_information_pkt', 
       'SM_Signing_Information': 'signing_information_pkt', 
       'SM_Security_Request':'security_request_pkt', 
       'SM_Public_Key': 'pairing_public_key_pkt', 
       'SM_DHKey_Check':'pairing_dhkey_check_pkt', 
       'SM_Keypress_Notification':'pairing_keypress_notification_pkt',
       'ATT_Error_Response': "att_error_rsp_pkt",
       'ATT_Exchange_MTU_Request': "att_exchange_mtu_req_pkt",
       'ATT_Exchange_MTU_Response': "att_exchange_mtu_rsp_pkt",
       'ATT_Find_Information_Request': "att_find_information_req_pkt",
       'ATT_Find_Information_Response': "att_find_information_rsp_pkt",
       'ATT_Find_By_Type_Value_Request': "att_find_by_type_value_req_pkt",
       'ATT_Find_By_Type_Value_Response': "att_find_by_type_value_rsp_pkt",
       'ATT_Read_By_Type_Request':"att_read_by_type_req_pkt",
       'ATT_Read_By_Type_Response':"att_read_by_type_rsp_pkt",
       'ATT_Read_Request':"att_read_req_pkt",
       'ATT_Read_Response':"att_read_rsp_pkt",
       'ATT_Read_Blob_Request':"att_read_blob_req_pkt",
       'ATT_Read_Blob_Response': "att_read_blob_rsp_pkt",
       'ATT_Read_Multiple_Request': "att_read_multiple_req_pkt",
       'ATT_Read_Multiple_Response': "att_read_multiple_rsp_pkt",
       'ATT_Read_By_Group_Type_Request':  "att_read_by_group_type_req_pkt",
       'ATT_Read_By_Group_Type_Response': "att_read_by_group_type_rsp_pkt",
       'ATT_Read_Multiple_Variable_Request':  "att_read_multiple_variable_req_pkt",
       'ATT_Read_Multiple_Variable_Response':  "att_read_multiple_variable_rsp_pkt",
       'ATT_Write_Request': "att_write_req_pkt",
       'ATT_Write_Response': "att_write_rsp_pkt",
       'ATT_Write_Command':  "att_write_cmd_pkt",
       'ATT_Signed_Write_Command': "att_signed_write_pkt",
       'ATT_Prepare_Write_Request': "att_prepare_write_req_pkt",
       'ATT_Prepare_Write_Response':  "att_prepare_write_rsp_pkt",
       'ATT_Execute_Write_Request':  "att_execute_write_req_pkt",
       'ATT_Execute_Write_Response': "att_execute_write_rsp_pkt",
       'ATT_Handle_Value_Notification':  "att_handle_value_notification_pkt",
       'ATT_Handle_Value_Indication': "att_handle_value_indication_pkt",
       'ATT_Handle_Value_Confirmation':  "att_handle_value_confirmation_pkt",
       'ATT_Multiple_Handle_Value_Notification':  "att_multiple_handle_value_notification_pkt"}

def get_map(out:str):
    # out = "BTLE|BTLE_CTRL|BTLE_DATA|LL_START_ENC_RSP"

    out = out.split("|")
    map_out = []
    for i in out:
        if i in map:
            map_out.append(map[i])

    result = ",".join(map_out)
    return result


# if __name__ == "__main__":
#     out = 'BTLE|BTLE_CTRL|BTLE_DATA|L2CAP_Hdr|LL_START_ENC_RSP|SM_Encryption_Information|SM_Hdr|SM_Identity_Address_Information|SM_Identity_Information|SM_Master_Identification|SM_Signing_Information'
#     print(type(get_map(out)) )
