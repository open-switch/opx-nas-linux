/*
 * Copyright (c) 2019 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */

/*!
 * \file   os_interface_stg.cpp
 */

#include "private/nas_os_if_priv.h"
#include "dell-base-stg.h"
#include "nas_nlmsg.h"
#include "event_log.h"
#include "net_publish.h"
#include "ds_api_linux_interface.h"
#include "nas_os_vlan_utils.h"
#include "nas_linux_l2.h"

#include <linux/if_link.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

static const size_t os_stp_state_frwd = 3;
bool os_bridge_stp_enabled (if_details *details)
{
    const std::string SYSFS_CLASS_NET = "/sys/class/net/";
    std::stringstream str_stream;
    int master;
    if(details->_attrs[IFLA_MASTER]){
        master = *(int *) nla_data(details->_attrs[IFLA_MASTER]);
    }else{
        return false;
    }
    char intf_name[HAL_IF_NAME_SZ+1];
    if(cps_api_interface_if_index_to_name(master,intf_name,sizeof(intf_name))==NULL){
        EV_LOGGING(NAS_OS,DEBUG,"NAS-LINUX-INTERFACE","Invalid Interface Index %d ",master);
        return false;
    }
    str_stream << SYSFS_CLASS_NET << intf_name << "/bridge/stp_state";

    std::string path = str_stream.str();

    std::ifstream in(path);
    if(!in.good()) {
        return false;
    }

    std::string s;

    int stp_state = 0;
    if(getline(in, s)) {
        stp_state = stoi(s);
    }

    EV_LOGGING(NAS_OS, INFO, "NAS-OS", "STP %s, path %s state %d",
            details->if_name.c_str(), path.c_str(), stp_state);

    return ((stp_state)? true:false);
}

bool INTERFACE::os_interface_stg_attrs_handler(if_details *details, cps_api_object_t obj)
{
    if (details->_attrs[IFLA_PROTINFO]) {
        struct nlattr *brinfo[IFLA_BRPORT_MAX];
        memset(brinfo,0,sizeof(brinfo));
        nla_parse_nested(brinfo,IFLA_BRPORT_MAX,details->_attrs[IFLA_PROTINFO]);
        if (brinfo[IFLA_BRPORT_STATE]) {
            int stp_state = *(int *)nla_data(brinfo[IFLA_BRPORT_STATE]);
            uint8_t cur_stp_state;
            /*
             * Check if cached stp state is there, then revert the state back in kernel if cached state
             * is not matching with the current state in the kernel.
             */
            if(get_if_stp_state(details->_ifindex,&cur_stp_state) == STD_ERR_OK){
                if( stp_state != cur_stp_state){
                    cps_api_object_t stg_obj = cps_api_object_create();
                    if(stg_obj == nullptr){
                        return false;
                    }
                    EV_LOGGING(NAS_OS,INFO,"NAS-OS-STG","Reverting the STP state to %d for interface index %d",
                                                cur_stp_state, details->_ifindex);
                    cps_api_object_attr_add_u32(stg_obj, BASE_STG_ENTRY_INTF_IF_INDEX_IFINDEX, details->_ifindex);
                    cps_api_object_attr_add_u32(stg_obj, BASE_STG_ENTRY_INTF_STATE, cur_stp_state);
                    /*
                     * Below attr is added to distinguish the path to program kernel state from netlink
                     * path to the nas-l2 path
                     */

                    cps_api_object_attr_add_u32(stg_obj, BASE_STG_ENTRY_INTF_IF, cur_stp_state);


                    if (nl_int_update_stp_state(stg_obj) != STD_ERR_OK) {
                        EV_LOGGING(NAS_OS,INFO,"NAS-OS-STG","Failed to updated kernel STP state to %d for interface index %d",
                            cur_stp_state, details->_ifindex);
                    }
                    cps_api_object_delete(stg_obj);

                }

            }

            if(stp_state == os_stp_state_frwd){
                /*
                 * When stp state of interface becomes forwarding, check if there were
                 * any pending failed dynamic macs on this interface and try to re-program
                 * them.
                 */
                nas_os_mac_add_pending_mac_if_event(details->_ifindex);
            }

            if(os_bridge_stp_enabled(details)){

                cps_api_object_t cln_obj = cps_api_object_create();

                cps_api_object_clone(cln_obj,obj);

                cps_api_key_init(cps_api_object_key(cln_obj),cps_api_qualifier_TARGET,
                        (cps_api_object_category_types_t) cps_api_obj_CAT_BASE_STG,BASE_STG_ENTRY_OBJ,0);


                cps_api_attr_id_t ids[2] = {BASE_STG_ENTRY_INTF, BASE_STG_ENTRY_INTF_STATE };
                const int ids_len = sizeof(ids)/sizeof(ids[0]);

                cps_api_object_e_add(cln_obj,ids,ids_len,cps_api_object_ATTR_T_U32,&stp_state,sizeof(stp_state));

                ids[1]= BASE_STG_ENTRY_INTF_IF_INDEX_IFINDEX;

                hal_ifindex_t ifindex;
                if(!nas_os_physical_to_vlan_ifindex(details->_ifindex,0,false,&ifindex)){
                    cps_api_object_delete(cln_obj);
                    return false;
                }

                cps_api_object_e_add(cln_obj,ids,ids_len,cps_api_object_ATTR_T_U32,&ifindex,
                                    sizeof(ifindex));

                net_publish_event(cln_obj);
            }

        }
    }

    return true;
}
