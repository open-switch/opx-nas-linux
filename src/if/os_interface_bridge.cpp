/*
 * Copyright (c) 2016 Dell Inc.
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
 * \file   os_interface_bridge.cpp
 */

#include "private/nas_os_if_priv.h"
#include "private/nas_nlmsg_object_utils.h"
#include "private/os_if_utils.h"
#include "nas_os_if_conversion_utils.h"
#include "dell-base-if.h"
#include "dell-base-if-vlan.h"

#include "dell-interface.h"
#include "nas_nlmsg.h"

#include "nas_os_vlan_utils.h"

#include "event_log.h"
#include "ds_api_linux_interface.h"
#include "std_utils.h"

#include <linux/if_link.h>
#include <linux/if.h>
#include <string>
#include <mutex>
#include <unordered_map>

/* A container to store the tagged/untagged member ports with VLANs mapping */
static auto mbr_intf_to_vlan_map = new std::unordered_map<hal_ifindex_t,std::unordered_set<hal_ifindex_t>>;
static std::mutex _mtx;

bool nas_os_is_port_part_of_vlan(hal_ifindex_t vlan_ifindex, hal_ifindex_t port_ifindex){
    std::lock_guard<std::mutex> _lg(_mtx);
    auto it = mbr_intf_to_vlan_map->find(port_ifindex);
    if(it == mbr_intf_to_vlan_map->end()){
        return false;
    }

    return it->second.find(vlan_ifindex) != it ->second.end();
}
static bool os_interface_update_vlan_info(hal_ifindex_t mem_idx, hal_ifindex_t vlan_if_index,
        std::string sub_mbr_name, bool is_tag, bool add) {

    int mbr_ifindex = 0; /* VLAN member port */
    if (is_tag) {
        char mbr_name[HAL_IF_NAME_SZ+1];
        safestrncpy(mbr_name, sub_mbr_name.c_str(), sizeof(mbr_name));
        /* Convert vlan enslave port (tagged VLAN interface) to member port
         * if-index (i.e e101-001-0.200 to if-index of e101-001-0 */
        if (!nas_os_sub_intf_name_to_intf_ifindex(mbr_name, &mbr_ifindex)) {
            EV_LOGGING(NAS_OS,ERR,"NAS-UPD-VLAN", "Add %s vlan-index:%d sub-mbr name:%s to "
                       "mbr-index %d mapping does not exist!", ((is_tag) ? "tag" : "untag"),
                       vlan_if_index, sub_mbr_name.c_str(), mem_idx);
            return false;
        }
    } else {
        mbr_ifindex = mem_idx;
    }
    EV_LOGGING(NAS_OS,INFO,"NAS-UPD-VLAN", "%s %s mbr-index:%d vlan-index:%d sub-mbr name:%s(%d)",
            (add ? "Add" : "Del"), ((is_tag) ? "tag" : "untag"), mbr_ifindex,
            vlan_if_index, sub_mbr_name.c_str(), mem_idx);
    /* Enable the IPv6 on Physical/LAG when it's not part of any VLAN, otherwise disable it */
    /* Tagged/Untagged member interface with VLANs handling */
    std::lock_guard<std::mutex> _lg(_mtx);
    if(add){
        auto intf_it = mbr_intf_to_vlan_map->find(mbr_ifindex);
        if(intf_it == mbr_intf_to_vlan_map->end()) {
            /* Tagged/Untagged member if index with VLAN association not present, create one */
            std::unordered_set<hal_ifindex_t> tagged_intf_list;
            tagged_intf_list.insert(vlan_if_index);
            mbr_intf_to_vlan_map->insert({mbr_ifindex,std::move(tagged_intf_list)});
        }else{
            /* Update the VLAN if_index for the existing member if index*/
            intf_it->second.insert(vlan_if_index);
        }
    } else {
        auto intf_it = mbr_intf_to_vlan_map->find(mbr_ifindex);
        if(intf_it != mbr_intf_to_vlan_map->end()){
            intf_it->second.erase(vlan_if_index);
            if(intf_it->second.size()==0){
                mbr_intf_to_vlan_map->erase(mbr_ifindex);
                EV_LOGGING(NAS_OS,INFO,"NAS-UPD-VLAN", "Enable IPv6 on mbr-index:%d vlan-index:%d sub-mbr-index:%d",
                        mbr_ifindex, vlan_if_index, mem_idx);
            }
        }
    }
    return true;
}

bool static os_interface_vlan_bridge_handler(hal_ifindex_t mas_idx, hal_ifindex_t mem_idx,
        std::string mem_name, bool tag)
{
    if_bridge *br_hdlr = os_get_bridge_db_hdlr();

    if(br_hdlr == nullptr) return true;

    if(br_hdlr->bridge_mbr_present(mas_idx, mem_idx)) {
        EV_LOG(INFO, NAS_OS,3, "NET-MAIN", "Duplicate netlink add master %d ifx %d",
                mas_idx, mem_idx);
        return false;
    }
    // TODO this checks is added here due to the behavior in Stretch release.
    // Here during a member deletion from bridge, an add event comes after member delete event.
    // So the work around is to check in the kernel is member is actually part of the bridge.
    // We can remove the workaround once it is fixed in the kernel in the subsequent release.
    if (!check_bridge_membership_in_os(mas_idx, mem_idx)) {
        EV_LOGGING(NAS_OS,ERR,"NET-MAIN"," False member addition MSG ifidx %d, Master %d ", mem_idx, mas_idx);
        return false;
    }

    if(!tag) {
        os_interface_update_vlan_info(mem_idx, mas_idx, mem_name, false, true);
        br_hdlr->bridge_untag_mbr_add(mas_idx, mem_idx);
        // If tagged member list is empty, defer the publishing of untagged ports
    } else {
        os_interface_update_vlan_info(mem_idx, mas_idx, mem_name, true, true);
        br_hdlr->bridge_tag_mbr_add(mas_idx, mem_idx);
    }

    return true;
}

bool INTERFACE::os_interface_bridge_attrs_handler(if_details *details, cps_api_object_t obj)
{
    if_bridge *br_hdlr = os_get_bridge_db_hdlr();
    hal_ifindex_t master_idx = (details->_attrs[IFLA_MASTER]!=NULL)?
        *(int *)nla_data(details->_attrs[IFLA_MASTER]):0;

    if (details->_type == BASE_CMN_INTERFACE_TYPE_BRIDGE) {
        return true;
    }

    if (details->_attrs[IFLA_MASTER]==NULL) {
        // if master is null then return
        return true;
    }
    // Now check if netlink event is for this interface (bond/tun/vlan_subintf/vxlan)
    // addition/deletion to a bridge
    if(details->_op == cps_api_oper_DELETE) {
        if((details->_type == BASE_CMN_INTERFACE_TYPE_VLAN_SUBINTF) ||
           (details->_type == BASE_CMN_INTERFACE_TYPE_VXLAN)) {
             EV_LOGGING(NAS_OS,INFO,"NAS-UPD-VLAN", "Delete tagged member %s from bridge %d", details->if_name.c_str(), master_idx);
            /*  Vlan Interface Deletion from  a bridge */
            cps_api_object_attr_add(obj,DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS, details->if_name.c_str(), strlen(details->if_name.c_str())+1);
            if(br_hdlr) br_hdlr->bridge_tag_mbr_del(master_idx, details->_ifindex);
            os_interface_update_vlan_info(details->_ifindex, master_idx, details->if_name, true, false);
            EV_LOGGING(NAS_OS,INFO, "NET-MAIN", " Delete mem  %d intf name %s", details->_ifindex, details->if_name.c_str());
        } else {
            /*  PHY Interface Deletion from  a bridge */
             EV_LOGGING(NAS_OS,INFO,"NAS-UPD-VLAN", "Delete untagged member %s from bridge %d", details->if_name.c_str(), master_idx);
            cps_api_object_attr_add(obj,DELL_IF_IF_INTERFACES_INTERFACE_UNTAGGED_PORTS, details->if_name.c_str(), strlen(details->if_name.c_str())+1);
            if(br_hdlr) br_hdlr->bridge_untag_mbr_del(master_idx, details->_ifindex);
            os_interface_update_vlan_info(details->_ifindex, master_idx, details->if_name, false, false);
            EV_LOGGING(NAS_OS, INFO, "NET-MAIN", " Delete mem  tun %d intf name %s", details->_ifindex, details->if_name.c_str());
        }

        details->_type = BASE_CMN_INTERFACE_TYPE_L2_PORT;
        return true;
    }

    // check if slave is present in the event then return since this is lag membership case
    if ((details->_info_kind == nullptr) || ((details->_flags & IFF_SLAVE)!=0)) return true;


    //if ((!strncmp(details->_info_kind, "tun", 3) && ((details->_flags & IFF_SLAVE)==0)) ||
    if ((!strncmp(details->_info_kind, "tun", 3) ) ||
           (details->_type == BASE_CMN_INTERFACE_TYPE_LAG)) {
        // IF interface is bond or tun type then consider it untagged member addition to the bridge
            EV_LOG(INFO, NAS_OS,3, "NET-MAIN", "Add untagged Member  %d intf name %s", details->_ifindex, details->if_name.c_str());
            if(!os_interface_vlan_bridge_handler(master_idx, details->_ifindex, details->if_name, false))
                return true;

            details->_type = BASE_CMN_INTERFACE_TYPE_L2_PORT;
            details->_op = cps_api_oper_CREATE;
            cps_api_object_attr_add(obj, DELL_IF_IF_INTERFACES_INTERFACE_UNTAGGED_PORTS,
                    details->if_name.c_str(), strlen(details->if_name.c_str())+1);
    }

    if(((details->_type == BASE_CMN_INTERFACE_TYPE_VXLAN) || (details->_type == BASE_CMN_INTERFACE_TYPE_VLAN_SUBINTF)) &&
                                                             (details->_attrs[IFLA_MASTER]!=nullptr)) {
        EV_LOGGING(NAS_OS, INFO, "NET-MAIN", "Received interface %s with master set %d",
                details->if_name.c_str(), *(int *)nla_data(details->_attrs[IFLA_MASTER]));

        if ((details->_type == BASE_CMN_INTERFACE_TYPE_VLAN_SUBINTF) && (details->_linkinfo[IFLA_INFO_DATA])) {
            /* Add VLAN ID if present   */
            struct nlattr *vlan[IFLA_VLAN_MAX];
            memset(vlan,0,sizeof(vlan));

            nla_parse_nested(vlan,IFLA_VLAN_MAX,details->_linkinfo[IFLA_INFO_DATA]);
            if (vlan[IFLA_VLAN_ID]) {
                cps_api_object_attr_add_u32(obj,BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID,
                                        *(uint16_t*)nla_data(vlan[IFLA_VLAN_ID]));
            }
        }
        details->_type = BASE_CMN_INTERFACE_TYPE_L2_PORT;
        details->_op = cps_api_oper_CREATE;

        /* Treat vxlan interface as tagged member and
         * Check if this is the first tagged port add, if so append
         * the previously added untagged ports if any
         */

        if(!os_interface_vlan_bridge_handler(master_idx, details->_ifindex, details->if_name, true)) {
            return false;
        }
        cps_api_object_attr_add(obj, DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS,
                details->if_name.c_str(),strlen(details->if_name.c_str())+1);
    } // vxlan interface add/delete to bridge
    EV_LOG(INFO, NAS_OS, 3, "NET-MAIN", "In IFLA_INFO_KIND for %s index %d name:%s",
            details->_info_kind, details->_ifindex, details->if_name.c_str());
    return true;
}
