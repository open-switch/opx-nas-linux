/*
 * Copyright (c) 2017 Dell Inc.
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

/*
 * nas_os_mcast_snoop.c
 */

#include "cps_class_map.h"
#include "ds_api_linux_interface.h"
#include "event_log.h"
#include "nas_nlmsg.h"
#include "hal_if_mapping.h"
#include "nas_os_mcast_snoop.h"
#include "std_utils.h"
#include "ietf-igmp-mld-snooping.h"
#include "netlink_stats.h"
#include "net_publish.h"

#include <unordered_map>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <linux/if_bridge.h>
#include <sys/socket.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

static const int MAX_NETLINK_BUF = 10000;

static const auto _ipv4_cps_keymap = new std::unordered_map<std::string, cps_api_attr_id_t> {
        {"vlan", IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN},
        {"vlan_id", IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_VLAN_ID},
        {"grp_list", IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP},
        {"interface", IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_INTERFACE},
        {"grp_addr", IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_ADDRESS}
    };

static const auto _ipv6_cps_keymap = new std::unordered_map<std::string, cps_api_attr_id_t> {
        {"vlan", IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN},
        {"vlan_id", IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_VLAN_ID},
        {"grp_list", IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP},
        {"interface", IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_INTERFACE},
        {"grp_addr", IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_ADDRESS}
    };

static const auto _cps_keymap = new std::unordered_map<std::string, std::unordered_map<std::string, cps_api_attr_id_t>> {
         {"ipv4", *_ipv4_cps_keymap},
         {"ipv6", *_ipv6_cps_keymap}
    };


static bool _populate_mdb_entry_object(struct br_mdb_entry *br_entry, int msg_type, hal_vlan_id_t vlan_id, char *if_name, cps_api_object_t obj) {

    std::string _addr_proto;
    char *grp_addr = nullptr;
    size_t grp_addr_len = 0;
    if (ntohs(br_entry->addr.proto) == ETH_P_IP) {
        struct in_addr ip_addr;
        ip_addr.s_addr = br_entry->addr.u.ip4;

        grp_addr = inet_ntoa(ip_addr);
        grp_addr_len = strlen(grp_addr);
        _addr_proto = "ipv4";
    }
    else if (ntohs(br_entry->addr.proto) == ETH_P_IPV6) {
        char ip6_grp_addr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(br_entry->addr.u.ip6), ip6_grp_addr, INET6_ADDRSTRLEN);

        grp_addr = ip6_grp_addr;
        grp_addr_len = INET6_ADDRSTRLEN;
        _addr_proto = "ipv6";

    }
    else return false;

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj), (*_cps_keymap)[_addr_proto]["vlan"], cps_api_qualifier_OBSERVED);

    cps_api_operation_types_t op;
    std::string msg = "mdb";
    if (msg_type == RTM_NEWMDB ) { op = cps_api_oper_CREATE; msg = "new_mdb"; }
    else if  (msg_type == RTM_DELMDB ) { op = cps_api_oper_DELETE; msg = "del_mdb"; }
    else return false;

    cps_api_object_set_type_operation(cps_api_object_key(obj), op);

    cps_api_object_attr_add_u16(obj, (*_cps_keymap)[_addr_proto]["vlan_id"], vlan_id);

    cps_api_attr_id_t ids[3] = {(*_cps_keymap)[_addr_proto]["grp_list"], 0, (*_cps_keymap)[_addr_proto]["interface"]};
    const int ids_len = sizeof(ids)/sizeof(ids[0]);

    cps_api_object_e_add(obj, ids,ids_len, cps_api_object_ATTR_T_BIN, if_name,HAL_IF_NAME_SZ);


    ids[2] = (*_cps_keymap)[_addr_proto]["grp_addr"];

    cps_api_object_e_add(obj, ids, ids_len, cps_api_object_ATTR_T_BIN, grp_addr, grp_addr_len+1);
    EV_LOGGING(NETLINK_MCAST_SNOOP,DEBUG,"NAS-LINUX-MCAST-SNOOP", "Group address %s ", grp_addr);

    // INFO log with all information
    EV_LOGGING(NETLINK_MCAST_SNOOP,INFO,"NAS-LINUX-MCAST-SNOOP", "Message Type %s Protocol %s Vlan ID %d Member port %s Group address %s", msg.c_str(), _addr_proto.c_str(), vlan_id, if_name, grp_addr);

    return true;
}

static bool _populate_mdb_router_object(int msg_type, hal_vlan_id_t vlan_id, char *if_name, cps_api_object_t obj,
                                        bool is_mld) {

    cps_api_operation_types_t op;
    std::string msg = "mdb";
    std::string type_str = "IGMP";

    if (msg_type == RTM_NEWMDB ) { op = cps_api_oper_CREATE; msg = "new_mdb"; }
    else if  (msg_type == RTM_DELMDB ) { op = cps_api_oper_DELETE; msg = "del_mdb"; }
    else return false;

    if (is_mld) {
        type_str = "MLD";
        cps_api_key_from_attr_with_qual(cps_api_object_key(obj), IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN, cps_api_qualifier_OBSERVED);

        cps_api_object_attr_add_u16(obj, IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_VLAN_ID, vlan_id);

        cps_api_object_attr_add(obj, IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_MROUTER_INTERFACE, if_name,HAL_IF_NAME_SZ);
    }
    else {
        cps_api_key_from_attr_with_qual(cps_api_object_key(obj), IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN, cps_api_qualifier_OBSERVED);

        cps_api_object_attr_add_u16(obj, IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_VLAN_ID, vlan_id);

        cps_api_object_attr_add(obj, IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_MROUTER_INTERFACE, if_name,HAL_IF_NAME_SZ);
    }

    cps_api_object_set_type_operation(cps_api_object_key(obj), op);

    EV_LOGGING(NETLINK_MCAST_SNOOP,DEBUG,"NAS-LINUX-MCAST-SNOOP", "%s Mrouter port Name %s", type_str.c_str(), if_name);

    // Info log with all information
    EV_LOGGING(NETLINK_MCAST_SNOOP,DEBUG,"NAS-LINUX-MCAST-SNOOP", "Message type %s Vlan ID %d Mrouter port %s", msg.c_str(), vlan_id, if_name);
    return true;
}

static bool _get_ifname(uint32_t ifindex, char *if_name, unsigned int len) {
    char *saveptr;
    char name[HAL_IF_NAME_SZ];

    if(cps_api_interface_if_index_to_name( ifindex,name, HAL_IF_NAME_SZ)==NULL){
        EV_LOGGING(NETLINK_MCAST_SNOOP,ERR,"NAS-LINUX-MCAST-SNOOP", "Member port Interface not found");
        return false;
    }
    char *converted_intf_name = strtok_r(name,".",&saveptr);
    safestrncpy(if_name, converted_intf_name, HAL_IF_NAME_SZ);
    EV_LOGGING(NETLINK_MCAST_SNOOP,DEBUG,"NAS-LINUX-MCAST-SNOOP", "Member port Interface (%s)", if_name);
    return true;
}

bool nl_to_mcast_snoop_info(int sock, int msg_type, struct nlmsghdr *hdr, void *context) {
    struct nlattr *nest_attr;
    struct nlattr *info_attr;
    struct br_mdb_entry *br_entry;
    struct br_port_msg *brp_msg = (struct br_port_msg *)NLMSG_DATA(hdr);
    static char netlink_buf[MAX_NETLINK_BUF];

    EV_LOGGING(NETLINK_MCAST_SNOOP,DEBUG,"NAS-LINUX-MCAST-SNOOP", "message type %d Family %d VLAN ifindex %d ", msg_type, brp_msg->family, brp_msg->ifindex);

    if (! (msg_type == RTM_NEWMDB || msg_type == RTM_DELMDB))
    {
        EV_LOGGING(NETLINK_MCAST_SNOOP,ERR,"NAS-LINUX-MCAST-SNOOP", "Unsupported msg type ");
        return false;
    }


    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(intf_ctrl));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.if_index = brp_msg->ifindex;
    if (dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
        EV_LOGGING(NETLINK_MCAST_SNOOP,ERR,"NAS-LINUX-MCAST-SNOOP", "VLAN (%d) not found",  brp_msg->ifindex);
        return false;
    }
    EV_LOGGING(NETLINK_MCAST_SNOOP,DEBUG,"NAS-LINUX-MCAST-SNOOP", "VLAN name (%s) ID (%d)",  intf_ctrl.if_name, intf_ctrl.vlan_id);

    int attrlen = nlmsg_attrlen(hdr,sizeof(struct br_port_msg));
    struct nlattr *attr = nlmsg_attrdata(hdr, sizeof(struct br_port_msg));

    while (nla_ok(attr, attrlen)) {
        int attr_type = nla_type(attr);
        if (attr_type == MDBA_MDB) {
            nla_for_each_nested(nest_attr, attr, attrlen) {
                if (nla_type(nest_attr) == MDBA_MDB_ENTRY) {
                    info_attr = (nlattr*)nla_data(nest_attr);
                    if (nla_type(info_attr) == MDBA_MDB_ENTRY_INFO) {
                        br_entry = (struct br_mdb_entry *)nla_data(info_attr);
                        EV_LOGGING(NETLINK_MCAST_SNOOP,DEBUG,"NAS-LINUX-MCAST-SNOOP", "Member port ifindex %d Protocol %s ", br_entry->ifindex, (ntohs(br_entry->addr.proto) == ETH_P_IP) ? "ipv4": "ipv6");

                       // Get member port interface name from ifindex
                       char if_name[HAL_IF_NAME_SZ] = {0};
                       if (! _get_ifname(br_entry->ifindex, if_name, HAL_IF_NAME_SZ)) {
                           EV_LOGGING(NETLINK_MCAST_SNOOP,ERR,"NAS-LINUX-MCAST-SNOOP", "Failure in getting member port interface name for ifindex %d ", br_entry->ifindex);
                           return false;
                       }

                       // Populate CPS Object
                       cps_api_object_t obj = cps_api_object_init(netlink_buf,sizeof(netlink_buf));

                       if( !_populate_mdb_entry_object(br_entry, msg_type, intf_ctrl.vlan_id, if_name, obj) ) {
                           EV_LOGGING(NETLINK_MCAST_SNOOP,ERR,"NAS-LINUX-MCAST-SNOOP", "Invalid protocol ");
                       }
                       else {
                           nas_nl_stats_update_pub_msg (sock, msg_type);
                           if (net_publish_event(obj) != cps_api_ret_code_OK) {
                               EV_LOGGING(NETLINK_MCAST_SNOOP,ERR,"NAS-LINUX-MCAST-SNOOP", "Failure to publish route update");
                               nas_nl_stats_update_pub_msg_failed (sock, msg_type);
                           }
                       }

                    }
                }
            }
        }
        else if (attr_type == MDBA_ROUTER) {
            nla_for_each_nested(nest_attr, attr, attrlen) {
                if (nla_type(nest_attr) == MDBA_ROUTER_PORT) {
                     uint32_t ifindex = *((uint32_t *)(nla_data(nest_attr)));

                     // Get Mrouter port interface name from ifindex
                       char if_name[HAL_IF_NAME_SZ] = {0};
                       if(! _get_ifname(ifindex, if_name, HAL_IF_NAME_SZ)) {
                           EV_LOGGING(NETLINK_MCAST_SNOOP,ERR,"NAS-LINUX-MCAST-SNOOP", "Failure in getting Mrouter port interface name for ifindex %d ", ifindex);
                           return false;
                       }

                     /* Kernel does not indicates or has facility to indicate it IGMP or MLD mrouter port.
                        So just publishing it as IGMP alone is not sufficient and the mrouter port will
                        not added to MLD routes. So here both IGMP and MLD object needs to be published
                        separately.
                     */

                     cps_api_object_t igmp_obj = cps_api_object_init(netlink_buf, sizeof(netlink_buf));

                     _populate_mdb_router_object(msg_type, intf_ctrl.vlan_id, if_name, igmp_obj, 1);
                     nas_nl_stats_update_pub_msg (sock, msg_type);

                     if (net_publish_event(igmp_obj) != cps_api_ret_code_OK) {
                         EV_LOGGING(NETLINK_MCAST_SNOOP,ERR,"NAS-LINUX-MCAST-SNOOP", "Failure to publish MLD Mrouter port %s ", if_name);
                         nas_nl_stats_update_pub_msg_failed (sock, msg_type);
                     }

                     cps_api_object_t mld_obj = cps_api_object_init(netlink_buf,sizeof(netlink_buf));

                     _populate_mdb_router_object(msg_type, intf_ctrl.vlan_id, if_name, mld_obj, 0);

                     nas_nl_stats_update_pub_msg (sock, msg_type);
                     if (net_publish_event(igmp_obj) != cps_api_ret_code_OK) {
                         EV_LOGGING(NETLINK_MCAST_SNOOP,ERR,"NAS-LINUX-MCAST-SNOOP", "Failure to publish IGMP Mrouter port %s ", if_name);
                         nas_nl_stats_update_pub_msg_failed (sock, msg_type);
                     }
                 }
             }
        }

        attr = nla_next(attr, &attrlen);
    }

    return true;
}


static bool nas_os_get_mcast_querier_status(const char * vlan_name){
    std::stringstream str_stream;
    str_stream << "/sys/devices/virtual/net/" << vlan_name << "/bridge/multicast_querier";
    std::string path = str_stream.str();

    std::ifstream in(path);
    if(!in.good()) {
        return false;
    }

    std::string s;
    int querier_status = 0;

    if(getline(in, s)) {
        querier_status = stoi(s);
    }

    EV_LOGGING(NAS_OS, DEBUG, "NAS-OS", "Bridge %s Querier state %d",
                vlan_name,querier_status);

    return ((querier_status)? true:false);
}


static bool nas_os_set_macst_querier_status(const char * vlan_name, bool enable){
    std::stringstream str_stream;
    str_stream << "/sys/devices/virtual/net/" << vlan_name << "/bridge/multicast_querier";

    std::string path = str_stream.str();

    std::ofstream out(path);
    if(!out.good()) {
        return false;
    }

    const char * querier_status = enable ? "1" : "0";

    try{
        out.write(querier_status,1);
    }catch(...){
        EV_LOGGING(NAS_OS,ERR,"NAS-OS","Failed to update the querier status to %d for %s",enable,vlan_name);
        return false;
    }

    EV_LOGGING(NAS_OS, DEBUG, "NAS-OS", "Updated Bridge %s Querier state %d",
                vlan_name,enable);

    return true;

}


bool nas_os_refresh_mcast_querier_status(hal_vlan_id_t vlan_id){
    EV_LOGGING(NAS_OS,DEBUG,"MACST","Refreshing MCAST querier status");
    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl,0,sizeof(interface_ctrl_t));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_VLAN;
    intf_ctrl.vlan_id = vlan_id;
    intf_ctrl.int_type = nas_int_type_VLAN;

    if(dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK){
        return false;
    }

    if(nas_os_get_mcast_querier_status(intf_ctrl.if_name)){
        return nas_os_set_macst_querier_status(intf_ctrl.if_name,false) &&
                nas_os_set_macst_querier_status(intf_ctrl.if_name,true);
    }

    return false;

}
