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

/*
 * filename: nas_os_vlan.c
 */

#include "event_log.h"
#include "nas_os_vlan.h"
#include "nas_os_vlan_utils.h"
#include "nas_os_interface.h"
#include "cps_api_object_key.h"
#include "cps_api_object_attr.h"
#include "std_mac_utils.h"
#include "dell-base-if-vlan.h"
#include "dell-base-if.h"
#include "dell-interface.h"
#include "netlink_tools.h"
#include "nas_nlmsg.h"
#include "ds_api_linux_interface.h"
#include "nas_os_int_utils.h"
#include "nas_os_if_priv.h"
#include "nas_os_lag.h"
#include "os_if_utils.h"
#include "std_utils.h"
#include "nas_os_if_conversion_utils.h"
#include "nas_os_l3_utils.h"

#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <map>


static std::mutex _intf_mutex;
static auto & _intf_to_tagged_intf_map = *(new std::unordered_map<hal_ifindex_t,std::unordered_set<hal_ifindex_t>>);
static auto & _intf_str_to_tagged_ifindex_map = *(new std::map<std::string,hal_ifindex_t>);
const static int MAX_CPS_MSG_BUFF=4096;

/*
 * Default mac aging time 30 minutes in jiffy
 */
static const unsigned long default_bridge_mac_ageing = 180000;

extern "C"{

bool nas_os_set_bridge_default_mac_ageing(hal_ifindex_t br_index)
{
    const std::string SYSFS_CLASS_NET = "/sys/class/net/";

    char intf_name[HAL_IF_NAME_SZ+1];
    if(cps_api_interface_if_index_to_name(br_index,intf_name,sizeof(intf_name))==NULL){
        EV_LOGGING(NAS_OS,ERR,"NAS-LINUX-INTERFACE","Invalid Interface Index %d ",br_index);
        return false;
    }
    std::string age_str =  SYSFS_CLASS_NET + std::string(intf_name) + "/bridge/ageing_time";
    FILE *f = fopen(age_str.c_str(),"w");
    if(f){
       if(fprintf(f,"%ld\n",default_bridge_mac_ageing)< 0){
           EV_LOGGING(NAS_OS,ERR,"NAS-OS","Failed to set mac ageing for bridge index %d",br_index);
           fclose(f);
           return false;
       }
       fclose(f);
    }else{
        EV_LOGGING(NAS_OS,ERR,"NAS-OS","Path %s does not exist",age_str.c_str());
        return false;
    }

    EV_LOGGING(NAS_OS,INFO,"NAS-OS","Setted mac ageing for bridge index %d",br_index);

    return true;
}

}

void _update_intf_to_tagged_intf_map(hal_ifindex_t ifname, hal_ifindex_t vlan_index, bool add){
    std::lock_guard<std::mutex> lock(_intf_mutex);
    char if_name[HAL_IF_NAME_SZ+1];
    memset(if_name,0,sizeof(if_name));

    if(cps_api_interface_if_index_to_name(vlan_index, if_name, sizeof(if_name)) == NULL){
        return;
    }

    if(add){
        auto intf_it = _intf_to_tagged_intf_map.find(ifname);
        if(intf_it == _intf_to_tagged_intf_map.end()){
            std::unordered_set<hal_ifindex_t> tagged_intf_list;
            tagged_intf_list.insert(vlan_index);
            _intf_to_tagged_intf_map[ifname] = std::move(tagged_intf_list);
        }else{
            intf_it->second.insert(vlan_index);
        }
        _intf_str_to_tagged_ifindex_map[if_name]=vlan_index;

    }else{
        auto intf_it = _intf_to_tagged_intf_map.find(ifname);
        if(intf_it != _intf_to_tagged_intf_map.end()){
            intf_it->second.erase(vlan_index);
            if(intf_it->second.size()==0){
                _intf_to_tagged_intf_map.erase(ifname);
            }
        }
        _intf_str_to_tagged_ifindex_map.erase(if_name);
    }
    return;
}


bool get_tagged_intf_list(hal_ifindex_t intf_name,std::unordered_set<hal_ifindex_t> & intf_list){
    std::lock_guard<std::mutex> lock(_intf_mutex);
    auto it = _intf_to_tagged_intf_map.find(intf_name);
    if(it != _intf_to_tagged_intf_map.end()){
        intf_list = it->second;
        return true;
    }
    return false;
}


bool get_tagged_intf_index_from_name(const char * intf_name,hal_ifindex_t & intf_index){
    std::lock_guard<std::mutex> lock(_intf_mutex);
    auto it = _intf_str_to_tagged_ifindex_map.find(intf_name);
    if(it != _intf_str_to_tagged_ifindex_map.end()){
        intf_index = it->second;
        return true;
    }
    return false;
}

/* Used to delete an bridge like br3 */

t_std_error nas_os_delete_bridge (cps_api_object_t obj) {

    hal_ifindex_t phy_index;

    cps_api_object_attr_t _name = cps_api_object_attr_get(obj,IF_INTERFACES_INTERFACE_NAME);
    if (_name == NULL) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS", "Missing bridge name to be deleted ");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    std::string if_name((const char *)cps_api_object_attr_data_bin(_name));
    if (!(nas_os_if_index_get(if_name, phy_index))) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS", "Delete bridge :Failed to find ifindex for %s", if_name.c_str());
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    EV_LOGGING(NAS_OS, INFO, "NAS-OS", "Delete bridge name %s, idx %d", if_name.c_str(), phy_index);
    return nas_os_del_interface(phy_index);

}

/* Used to delete sunintf like e101-001-0.100 */

t_std_error nas_os_delete_subinterface (cps_api_object_t obj) {

    hal_ifindex_t phy_index, vlan_index;
    vlan_index = 0;
    cps_api_object_attr_t if_name_attr = cps_api_get_key_data(obj, IF_INTERFACES_INTERFACE_NAME);
    cps_api_object_attr_t vlan_id_attr = cps_api_object_attr_get(obj, BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID);
    cps_api_object_attr_t parent = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_PARENT_INTERFACE);

    if (if_name_attr == NULL || vlan_id_attr == NULL || parent == NULL) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS", " NAS OS del sub_int: Missing bridge name or vlan id or parent \n");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    int vlan_id = (int)cps_api_object_attr_data_u32(vlan_id_attr);
    std::string parent_name((char *)cps_api_object_attr_data_bin(parent));
    std::string sub_if((char *)cps_api_object_attr_data_bin(if_name_attr));

    EV_LOGGING(NAS_OS, INFO, "NAS-OS", "del subintf %s with vlan id %d", sub_if.c_str(), vlan_id);

    if (!(nas_os_if_index_get(parent_name, phy_index)) || !(nas_os_if_index_get(sub_if, vlan_index))) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS", "Del  sub_intf :Failed ifindex for parent %s, sub_intf %s ",
                    parent_name.c_str(), sub_if.c_str());
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    if (nas_os_del_interface(vlan_index) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS", "Failed: Failed to del subintf  %s", sub_if.c_str());
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    _update_intf_to_tagged_intf_map(phy_index, vlan_index, false);

    return STD_ERR_OK;
}

#define NL_MSG_BUFFER_LEN 4096

t_std_error nas_os_add_vlan(cps_api_object_t obj, hal_ifindex_t *br_index)
{
    char buff[NL_MSG_BUFFER_LEN];
    hal_ifindex_t if_index = 0;
    const char *info_kind = "bridge";

    memset(buff,0,NL_MSG_BUFFER_LEN);

    struct nlmsghdr *nlh = (struct nlmsghdr *) nlmsg_reserve((struct nlmsghdr *)buff,sizeof(buff),sizeof(struct nlmsghdr));
    struct ifinfomsg *ifmsg = (struct ifinfomsg *) nlmsg_reserve(nlh,sizeof(buff),sizeof(struct ifinfomsg));

    cps_api_object_attr_t vlan_name_attr = cps_api_get_key_data(obj, IF_INTERFACES_INTERFACE_NAME);
    if(vlan_name_attr == CPS_API_ATTR_NULL) {
        EV_LOG(ERR, NAS_OS, ev_log_s_CRITICAL, "NAS-OS", "Missing Vlan name for adding to kernel");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    const char *br_name = (const char *) cps_api_object_attr_data_bin(vlan_name_attr);

    /*
     * If Bridge already exist in the kernel then do not create one,
     * get the ifindex from kernel and return it
     */
    if((if_index = cps_api_interface_name_to_if_index(br_name)) != 0){
        *br_index = if_index;
        return STD_ERR_OK;
    }

    EV_LOG(INFO, NAS_OS, ev_log_s_MINOR, "NAS-OS", "ADD Bridge name %s ",
           br_name);
    nas_os_pack_nl_hdr(nlh, RTM_NEWLINK, (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL));

    /* @TODO : Setting promisc mode to lift IP packets for now.
     *         Revisit when we get more details..
     */
    nas_os_pack_if_hdr(ifmsg, AF_BRIDGE, (IFF_BROADCAST | IFF_PROMISC | IFF_MULTICAST), if_index);

    //Add the interface name
    nlmsg_add_attr(nlh,sizeof(buff),IFLA_IFNAME, br_name, (strlen(br_name)+1));

    //Add MAC if already sent
    cps_api_object_attr_t mac_attr = cps_api_object_attr_get(obj,DELL_IF_IF_INTERFACES_INTERFACE_PHYS_ADDRESS);

    if(mac_attr !=NULL) {
        hal_mac_addr_t mac_addr;
        void *addr = cps_api_object_attr_data_bin(mac_attr);
        if (std_string_to_mac(&mac_addr, (const char *)addr, sizeof(mac_addr))) {
            nlmsg_add_attr(nlh, sizeof(buff), IFLA_ADDRESS, &mac_addr , sizeof(hal_mac_addr_t));
            EV_LOG(INFO, NAS_OS, ev_log_s_MAJOR, "NAS-OS", "Setting mac address %s in vlan interface %s ",
                    (const char *)addr, br_name);
        }
    }

    //Add the info_kind to indicate bridge
    struct nlattr *attr_nh = nlmsg_nested_start(nlh, sizeof(buff));
    attr_nh->nla_len = 0;
    attr_nh->nla_type = IFLA_LINKINFO;
    nlmsg_add_attr(nlh,sizeof(buff),IFLA_INFO_KIND, info_kind, (strlen(info_kind)+1));
    nlmsg_nested_end(nlh,attr_nh);

    if(nl_do_set_request(NL_DEFAULT_VRF_NAME, nas_nl_sock_T_INT,nlh,buff,sizeof(buff)) != STD_ERR_OK) {
        EV_LOG(ERR, NAS_OS, ev_log_s_CRITICAL, "NAS-OS", "Failure adding Vlan %s to kernel",
               br_name);
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    //return the kernel index to caller, used by caller in case of ADD VLAN
    if((*br_index = cps_api_interface_name_to_if_index(br_name)) == 0) {
        EV_LOG(ERR, NAS_OS, ev_log_s_CRITICAL, "NAS-OS", "Error finding the ifindex of bridge");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    return STD_ERR_OK;
}

t_std_error nas_os_del_vlan(cps_api_object_t obj)
{
    hal_ifindex_t if_index;
    const char *br_name = NULL;
    EV_LOG(INFO, NAS_OS, ev_log_s_MINOR, "NAS-OS", "DEL Vlan");

    cps_api_object_attr_t vlan_name = cps_api_get_key_data(obj, IF_INTERFACES_INTERFACE_NAME);
    cps_api_object_attr_t vlan_if = cps_api_object_attr_get(obj, DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);

    if((vlan_if == NULL) && (vlan_name == NULL)) {
        EV_LOG(ERR, NAS_OS, ev_log_s_CRITICAL, "NAS-OS", "Key parameters missing for vlan deletion in kernel");
                return (STD_ERR(NAS_OS,FAIL, 0));
    }

    if (vlan_if != NULL)  {
        if_index = (hal_ifindex_t)cps_api_object_attr_data_u32(vlan_if);
    } else {
        br_name = (const char *) cps_api_object_attr_data_bin(vlan_name);
        if((if_index = cps_api_interface_name_to_if_index(br_name)) == 0) {
            EV_LOG(ERR, NAS_OS, ev_log_s_CRITICAL, "NAS-OS", "Error finding the ifindex of vlan interface");
            return (STD_ERR(NAS_OS,FAIL, 0));
        }
    }
    EV_LOG(INFO, NAS_OS, ev_log_s_MINOR, "NAS-OS", "DEL Bridge name %s index %d", br_name, if_index);
    /* Remove the VRF association if exists before deleting the VLAN interface */
    if (nas_remove_intf_to_vrf_binding(if_index) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-LAG", "Error deleting VRF association from VLAN if-index:%d",
                   if_index);
    }

    return nas_os_del_interface(if_index);
}

static t_std_error nas_os_add_vlan_in_br(int vlan_index, int if_index, int br_index)
{
    char buff[NL_MSG_BUFFER_LEN];
    memset(buff,0,sizeof(buff));

    struct nlmsghdr *nlh = (struct nlmsghdr *) nlmsg_reserve((struct nlmsghdr *)buff,sizeof(buff),sizeof(struct nlmsghdr));
    struct ifinfomsg *ifmsg = (struct ifinfomsg *) nlmsg_reserve(nlh,sizeof(buff),sizeof(struct ifinfomsg));

    //nlmsg_len is updated in reserve api's above ..
    nas_os_pack_nl_hdr(nlh, RTM_SETLINK, (NLM_F_REQUEST | NLM_F_ACK));

    nas_os_pack_if_hdr(ifmsg, AF_UNSPEC, 0, vlan_index);

    EV_LOG(INFO, NAS_OS, ev_log_s_MINOR, "NAS-OS", "Vlan I/F index %d Bridge %d port %d ",
           ifmsg->ifi_index, br_index, if_index);

    nlmsg_add_attr(nlh,sizeof(buff),IFLA_MASTER, &br_index, sizeof(int));
    // TODO check if if_index needs to be sent for adding member
    // This may not be even applicable for vxlan type of interface
    nlmsg_add_attr(nlh,sizeof(buff),IFLA_LINK, &if_index, sizeof(int));

    if(nl_do_set_request(NL_DEFAULT_VRF_NAME, nas_nl_sock_T_INT,nlh,buff,sizeof(buff)) != STD_ERR_OK) {
        EV_LOG(ERR, NAS_OS, ev_log_s_CRITICAL, "NAS-OS", "Failure adding port to bridge in kernel");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    nas_os_update_tagged_intf_mac_learning(if_index,vlan_index);

    return STD_ERR_OK;
}


t_std_error nas_os_add_intf_to_bridge(cps_api_object_t obj)
{
    hal_ifindex_t idx, br_index, parent_idx;

    cps_api_object_attr_t if_name_attr = cps_api_get_key_data(obj, IF_INTERFACES_INTERFACE_NAME);
    cps_api_object_attr_t tagged_attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS);
    cps_api_object_attr_t untagged_attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_UNTAGGED_PORTS);
    cps_api_object_attr_t vlan_id_attr = cps_api_object_attr_get(obj, BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID);
    cps_api_object_attr_t parent = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_PARENT_INTERFACE);
    cps_api_object_attr_t ifindex_attr = cps_api_object_attr_get(obj,DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);

    if (if_name_attr == NULL || vlan_id_attr == NULL) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS", " NAS OS add port to bridge: Missing bridge name or vlan id /n");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    std::string bridge_name((char *)cps_api_object_attr_data_bin(if_name_attr));

    int vlan_id = (int)cps_api_object_attr_data_u32(vlan_id_attr);

    char mem_name[HAL_IF_NAME_SZ];
    if (tagged_attr != NULL) {
        if (parent == NULL) {
            EV_LOGGING(NAS_OS, ERR, "NAS-OS", " NAS OS add port to bridge: Missing parent for tagged interface for bridge %s",
                                       bridge_name.c_str());
            return (STD_ERR(NAS_OS,FAIL, 0));
        }
        safestrncpy(mem_name ,(char*)cps_api_object_attr_data_bin(tagged_attr), HAL_IF_NAME_SZ); /* mem_name is  e101-001-1.100 */
    } else if (untagged_attr != NULL) {
        safestrncpy(mem_name ,(char*)cps_api_object_attr_data_bin(untagged_attr), HAL_IF_NAME_SZ);
    } else {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS", " NAS OS add port to bridge: Missing member information for %s ", bridge_name.c_str());
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    std::string interface_name(mem_name);
    do {
        if (!(nas_os_if_index_get(bridge_name, br_index))) {
           EV_LOGGING(NAS_OS, ERR, "NAS-OS", " NAS OS add port to bridge: get br index failed %s", bridge_name.c_str());
           break;
        }

        if (!(nas_os_if_index_get(interface_name, idx))) {
            EV_LOGGING(NAS_OS, INFO, "NAS-OS", " NAS OS add port to bridge: get intf index failed %s", interface_name.c_str());
        }

        if (tagged_attr != NULL) {
            if(ifindex_attr){
                idx = cps_api_object_attr_data_uint(ifindex_attr);
            }else{
                EV_LOGGING(NAS_OS,ERR,"NAS-OS","No interface index passed to add vlan sub intf to bridge");
                break;
            }
            std::string parent_name((char *)cps_api_object_attr_data_bin(parent));
            if (!(nas_os_if_index_get(parent_name, parent_idx)))  {
                EV_LOGGING(NAS_OS, ERR, "NAS-OS", " NAS OS add port to bridge: get parent index failed %s", parent_name.c_str());
                break;
            }
        } else {
            parent_idx = idx;
        }
        EV_LOGGING(NAS_OS, INFO, "NAS-OS", "NAS OS add port to bridge : vlanid %d ,idx %d, parent_idx %d, br_idx %d",
                       vlan_id, idx,parent_idx, br_index);

        return nas_os_add_vlan_in_br(idx,parent_idx, br_index);
    } while (0);
    return (STD_ERR(NAS_OS,FAIL, 0));
}

static t_std_error nas_os_add_tag_port_to_os(int vlan_id, const char *vlan_name, int port_index, const char * phy_if_name, int *vlan_index)
{
    char buff[NL_MSG_BUFFER_LEN];

    memset(buff,0,sizeof(buff));

    struct nlmsghdr *nlh = (struct nlmsghdr *) nlmsg_reserve((struct nlmsghdr *)buff,sizeof(buff),sizeof(struct nlmsghdr));
    struct ifinfomsg *ifmsg = (struct ifinfomsg *) nlmsg_reserve(nlh,sizeof(buff),sizeof(struct ifinfomsg));

    nas_os_pack_nl_hdr(nlh, RTM_NEWLINK, (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL));

    db_interface_state_t astate;
    db_interface_operational_state_t ostate;

    unsigned int flags = (IFF_BROADCAST | IFF_MULTICAST) ;


    if (nas_os_util_int_admin_state_get(phy_if_name,&astate,&ostate)!=STD_ERR_OK)
        return (STD_ERR(NAS_OS,FAIL, 0));;

    /* For tagged interface, kernel does not inherit the port's admin status
     * during creation. But any update that happens on the port later
     * is inherited. Update the tagged interface admin to port's admin status */
    if(astate == DB_ADMIN_STATE_UP) {
        flags |= IFF_UP;
    }

    nas_os_pack_if_hdr(ifmsg, AF_UNSPEC, flags, 0);

    EV_LOGGING(NAS_OS, INFO, "NAS-OS", "Add tagged Vlan Name %s Vlan Id %d for port %d",
           vlan_name, vlan_id, port_index);

    nlmsg_add_attr(nlh,sizeof(buff), IFLA_IFNAME, vlan_name, (strlen(vlan_name)+1));
    nlmsg_add_attr(nlh,sizeof(buff),IFLA_LINK, &port_index, sizeof(int));

    /* VLAN info is set of nested attributes
     * IFLA_LINK_INFO(IFLA_INFO_KIND, IFLA_INFO_DATA(IFLA_VLAN_ID))*/
    struct nlattr *attr_nh = nlmsg_nested_start(nlh, sizeof(buff));
    attr_nh->nla_len = 0;
    attr_nh->nla_type = IFLA_LINKINFO;

    const char *info_kind = "vlan";
    nlmsg_add_attr(nlh,sizeof(buff),IFLA_INFO_KIND, info_kind, (strlen(info_kind)+1));

    if(vlan_id != 0) {
        struct nlattr *attr_nh_data = nlmsg_nested_start(nlh, sizeof(buff));
        attr_nh_data->nla_len = 0;
        attr_nh_data->nla_type = IFLA_INFO_DATA;

        nlmsg_add_attr(nlh,sizeof(buff),IFLA_VLAN_ID, &vlan_id, sizeof(int));

        nlmsg_nested_end(nlh,attr_nh_data);
    }
    //End of IFLA_LINK_INFO
    nlmsg_nested_end(nlh,attr_nh);

    if(nl_do_set_request(NL_DEFAULT_VRF_NAME, nas_nl_sock_T_INT,nlh,buff,sizeof(buff)) != STD_ERR_OK ||
        (*vlan_index = cps_api_interface_name_to_if_index(vlan_name)) == 0) {
        EV_LOGGING(NAS_OS, DEBUG, "NAS-OS", "Failed to add tagged intf %d in kernel", vlan_name);
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    return STD_ERR_OK;
}


/* Needs sub_interface name like e101-001-0.100 in IF_INTERFACES_INTERFACE_NAME
 * vlan_id in BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID
 * returns wely created sub-interfcae index in DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX
 */

t_std_error nas_os_create_subinterface(cps_api_object_t obj) {

    char sub_intf[HAL_IF_NAME_SZ];
    char phy_if_name[HAL_IF_NAME_SZ];
    int vlan_index;
    hal_ifindex_t  phy_index;

    cps_api_object_attr_t if_name_attr = cps_api_object_attr_get(obj, IF_INTERFACES_INTERFACE_NAME);
    cps_api_object_attr_t vlan_id_attr = cps_api_object_attr_get(obj, BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID);
    cps_api_object_attr_t parent = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_PARENT_INTERFACE);


    if (if_name_attr == NULL || vlan_id_attr == NULL || parent == NULL ) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS", " NAS OS create subintf: Missing intf name or vlan id  or parent \n");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    safestrncpy(sub_intf, (const char*)cps_api_object_attr_data_bin(if_name_attr), HAL_IF_NAME_SZ);
    safestrncpy(phy_if_name, (const char*)cps_api_object_attr_data_bin(parent), HAL_IF_NAME_SZ);
    int vlan_id = (int)cps_api_object_attr_data_u32(vlan_id_attr);
    std::string parent_name(phy_if_name);

    if (!(nas_os_if_index_get(parent_name, phy_index))) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS", "Create sub_intf :Failed ifindex for %s", parent_name.c_str());
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    if (nas_os_add_tag_port_to_os(vlan_id, sub_intf, phy_index, phy_if_name, &vlan_index) !=
         STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS", "Failed: Failed to create subintf  %s", sub_intf);
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    _update_intf_to_tagged_intf_map(phy_index, vlan_index,true);

    cps_api_object_attr_delete(obj,DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);
    cps_api_object_attr_add_u32(obj, DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX,vlan_index);
    return STD_ERR_OK;
    //Add the interface to bridge comes separately
}

/* @TODO: To be deprecated */

static t_std_error nas_os_add_t_port_to_os(int vlan_id, const char *vlan_name, int port_index, int *vlan_index)

{
    char buff[NL_MSG_BUFFER_LEN];

    memset(buff,0,sizeof(buff));

    struct nlmsghdr *nlh = (struct nlmsghdr *) nlmsg_reserve((struct nlmsghdr *)buff,sizeof(buff),sizeof(struct nlmsghdr));
    struct ifinfomsg *ifmsg = (struct ifinfomsg *) nlmsg_reserve(nlh,sizeof(buff),sizeof(struct ifinfomsg));

    nas_os_pack_nl_hdr(nlh, RTM_NEWLINK, (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL));

    db_interface_state_t astate;
    db_interface_operational_state_t ostate;

    unsigned int flags = (IFF_BROADCAST | IFF_MULTICAST) ;

    char if_name[HAL_IF_NAME_SZ+1];

    cps_api_interface_if_index_to_name(port_index, if_name, sizeof(if_name));

    if (nas_os_util_int_admin_state_get(if_name,&astate,&ostate)!=STD_ERR_OK)
        return (STD_ERR(NAS_OS,FAIL, 0));;

    /* For tagged interface, kernel does not inherit the port's admin status
     * during creation. But any update that happens on the port later
     * is inherited. Update the tagged interface admin to port's admin status */
    if(astate == DB_ADMIN_STATE_UP) {
        flags |= IFF_UP;
    }

    nas_os_pack_if_hdr(ifmsg, AF_UNSPEC, flags, 0);

    EV_LOG(INFO, NAS_OS, ev_log_s_MINOR, "NAS-OS", "Add tagged Vlan Name %s Vlan Id %d for port %d",
           vlan_name, vlan_id, port_index);

    nlmsg_add_attr(nlh,sizeof(buff), IFLA_IFNAME, vlan_name, (strlen(vlan_name)+1));
    nlmsg_add_attr(nlh,sizeof(buff),IFLA_LINK, &port_index, sizeof(int));

    /* VLAN info is set of nested attributes
     * IFLA_LINK_INFO(IFLA_INFO_KIND, IFLA_INFO_DATA(IFLA_VLAN_ID))*/
    struct nlattr *attr_nh = nlmsg_nested_start(nlh, sizeof(buff));
    attr_nh->nla_len = 0;
    attr_nh->nla_type = IFLA_LINKINFO;

    const char *info_kind = "vlan";
    nlmsg_add_attr(nlh,sizeof(buff),IFLA_INFO_KIND, info_kind, (strlen(info_kind)+1));

    if(vlan_id != 0) {
        struct nlattr *attr_nh_data = nlmsg_nested_start(nlh, sizeof(buff));
        attr_nh_data->nla_len = 0;
        attr_nh_data->nla_type = IFLA_INFO_DATA;

        nlmsg_add_attr(nlh,sizeof(buff),IFLA_VLAN_ID, &vlan_id, sizeof(int));

        nlmsg_nested_end(nlh,attr_nh_data);
    }
    //End of IFLA_LINK_INFO
    nlmsg_nested_end(nlh,attr_nh);

    if(nl_do_set_request(NL_DEFAULT_VRF_NAME, nas_nl_sock_T_INT,nlh,buff,sizeof(buff)) != STD_ERR_OK ||
        (*vlan_index = cps_api_interface_name_to_if_index(vlan_name)) == 0) {
        EV_LOGGING(NAS_OS, DEBUG, "NAS-OS", "Failed to add tagged intf %s in kernel", vlan_name);
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    return STD_ERR_OK;
}

t_std_error nas_os_t_port_to_vlan(int vlan_id, const char *vlan_name, int port_index, int br_index, int *vlan_index) {

    if (nas_os_add_t_port_to_os(vlan_id, vlan_name, port_index, vlan_index) !=
         STD_ERR_OK) {
        /* Adding tagged bond interface with no member fails in kernel.
         * Handle such case.
         */
        if (nas_handle_no_mem_tagged_bond(vlan_id, vlan_name, port_index,
                                             vlan_index) != STD_ERR_OK) {
            return (STD_ERR(NAS_OS,FAIL, 0));

        }
    }

    _update_intf_to_tagged_intf_map(port_index,*vlan_index,true);

    //Add the interface in the bridge now
    t_std_error ret = nas_os_add_vlan_in_br(*vlan_index, port_index, br_index);
    if (ret != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS", "Failed to add port with index  %d to %s in kernel",
                                port_index,vlan_name);
        return ret;
    }
    return ret;

}

t_std_error nas_os_ut_port_to_vlan(hal_ifindex_t port_index, hal_ifindex_t br_index)
{
    return (nas_os_add_vlan_in_br(port_index, port_index, br_index));
}

t_std_error nas_os_add_port_to_vlan(cps_api_object_t obj, hal_ifindex_t *vlan_index)
{
    char buff[NL_MSG_BUFFER_LEN];
    memset(buff,0,sizeof(buff));

    EV_LOG(INFO, NAS_OS, ev_log_s_MINOR, "NAS-OS", "ADD Port to Vlan");

    cps_api_object_attr_t vlan_index_attr = cps_api_object_attr_get(obj, DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);
    cps_api_object_attr_t vlan_id_attr = cps_api_object_attr_get(obj, BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID);
    cps_api_object_attr_t vlan_t_port_attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS);
    cps_api_object_attr_t vlan_ut_port_attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_UNTAGGED_PORTS);
    cps_api_object_attr_t mtu_attr = cps_api_object_attr_get(obj,DELL_IF_IF_INTERFACES_INTERFACE_MTU);
    if((vlan_index_attr == NULL) ||
       (vlan_id_attr == NULL) ||
       ((vlan_t_port_attr == NULL) &&
       (vlan_ut_port_attr == NULL))) {
        EV_LOG(ERR, NAS_OS, ev_log_s_CRITICAL, "NAS-OS", "Key parameters missing for vlan addition in kernel");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    uint32_t mtu = 0;
    if(mtu_attr != nullptr){
        mtu = cps_api_object_attr_data_u32(mtu_attr);
    }
    int vlan_id = (int)cps_api_object_attr_data_u32(vlan_id_attr);
    hal_ifindex_t br_index = (int)cps_api_object_attr_data_u32(vlan_index_attr);
    hal_ifindex_t if_index = 0;
    // for now adding only one port at a time
    if (vlan_t_port_attr != NULL) {
        if_index = (hal_ifindex_t)cps_api_object_attr_data_u32(vlan_t_port_attr);
    }
    else {
        if_index = (hal_ifindex_t)cps_api_object_attr_data_u32(vlan_ut_port_attr);
        //set the vlan id to 0 for untagged port as kernel does not use it.
        vlan_id = 0;
    }

    /* construct the vlan interface name, if port is e00-1 and vlan_id is 100
     * then interface is e00-1.100 */

    //get port name first
    char if_name[HAL_IF_NAME_SZ+1], vlan_name[HAL_IF_NAME_SZ+1];
    if(cps_api_interface_if_index_to_name(if_index, if_name, sizeof(if_name)) == NULL) {
        EV_LOG(ERR, NAS_OS, ev_log_s_CRITICAL, "NAS-OS", "Failure getting interface name for %d", if_index);
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    nas_os_get_vlan_if_name(if_name, sizeof(if_name), vlan_id, vlan_name);

    // @TODO check for admin status and bring it up after adding port to vlan.

    if(vlan_t_port_attr) {
        t_std_error rc;
        rc = nas_os_t_port_to_vlan(vlan_id, vlan_name, if_index, br_index, vlan_index);
        /*
         * When adding a tagged member port to a bridge need to set its mtu to be the same
         * as bridge mtu otherwise kernel will reset the bridge mtu to be lowest of all
         * member ports
         */
        if(mtu && (rc == STD_ERR_OK) ){

            /*
             * Use the same object, delete the physical port ifindex and add the
             * tagged member port ifindex to object
             */
            cps_api_object_attr_delete(obj,DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);
            cps_api_object_attr_add_u32(obj, DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX,*vlan_index);

            return nas_os_interface_set_attribute(obj,DELL_IF_IF_INTERFACES_INTERFACE_MTU);
        }
        return rc;
    }

    //if not tagged then add untagged port
    return nas_os_ut_port_to_vlan(if_index, br_index);
}


t_std_error nas_os_change_master(hal_ifindex_t port_index, hal_vlan_id_t vlan_id, hal_ifindex_t m_index)
{
    char buff[NL_MSG_BUFFER_LEN];
    memset(buff,0,sizeof(buff));

    struct nlmsghdr *nlh = (struct nlmsghdr *) nlmsg_reserve((struct nlmsghdr *)buff,sizeof(buff),sizeof(struct nlmsghdr));
    struct ifinfomsg *ifmsg = (struct ifinfomsg *) nlmsg_reserve(nlh,sizeof(buff),sizeof(struct ifinfomsg));

    if(port_index == 0) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS", "Invalid vlan interface index for deletion");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    hal_ifindex_t vlan_ifindex= 0;

    if(vlan_id){
        if(nas_os_physical_to_vlan_ifindex(port_index,vlan_id,true, &vlan_ifindex)){
            port_index = vlan_ifindex;
        }
    }

    nas_os_pack_nl_hdr(nlh, RTM_SETLINK, (NLM_F_REQUEST | NLM_F_ACK));
    nas_os_pack_if_hdr(ifmsg, AF_UNSPEC, 0, port_index);

    EV_LOGGING(NAS_OS, INFO, "NAS-OS", "Del i/f %d from bridge", port_index);

    /*
     * when deleting from bridge set the master index to zero otherwise
     * update it to new master
     */

    nlmsg_add_attr(nlh, sizeof(buff),IFLA_MASTER, &m_index, sizeof(int));

    if(nl_do_set_request(NL_DEFAULT_VRF_NAME, nas_nl_sock_T_INT,nlh,buff,sizeof(buff)) != STD_ERR_OK) {
        EV_LOG(ERR, NAS_OS, ev_log_s_CRITICAL, "NAS-OS", "Failure deleting port from bridge in kernel");
           return (STD_ERR(NAS_OS,FAIL, 0));
    }

    return STD_ERR_OK;
}

/* This will set master for an interface. when deleting from bridge set the master index to zero */

static t_std_error nas_os_set_master(hal_ifindex_t if_index, hal_vlan_id_t vlan_id)
{
    char buff[NL_MSG_BUFFER_LEN];
    memset(buff,0,sizeof(buff));

    struct nlmsghdr *nlh = (struct nlmsghdr *) nlmsg_reserve((struct nlmsghdr *)buff,sizeof(buff),sizeof(struct nlmsghdr));
    struct ifinfomsg *ifmsg = (struct ifinfomsg *) nlmsg_reserve(nlh,sizeof(buff),sizeof(struct ifinfomsg));

    if(if_index == 0) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS", "Invalid vlan interface index for deletion");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    nas_os_pack_nl_hdr(nlh, RTM_SETLINK, (NLM_F_REQUEST | NLM_F_ACK));

    nas_os_pack_if_hdr(ifmsg, AF_UNSPEC, 0, if_index);

    EV_LOGGING(NAS_OS, INFO , "NAS-OS", "Del i/f %d from bridge",
            if_index);
    int master_index = vlan_id;

    nlmsg_add_attr(nlh, sizeof(buff),IFLA_MASTER, &master_index, sizeof(int));

    if(nl_do_set_request(NL_DEFAULT_VRF_NAME, nas_nl_sock_T_INT,nlh,buff,sizeof(buff)) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS", "Failure setting master %d for  port %d  in kernel",
           master_index, if_index);
           return (STD_ERR(NAS_OS,FAIL, 0));
    }

    return STD_ERR_OK;
}

t_std_error nas_os_del_intf_from_bridge(cps_api_object_t obj) {

    hal_ifindex_t idx, parent_idx;

    cps_api_object_attr_t vlan_id_attr = cps_api_object_attr_get(obj, BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID);
    cps_api_object_attr_t tagged_attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS);
    cps_api_object_attr_t untagged_attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_UNTAGGED_PORTS);
    cps_api_object_attr_t parent = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_PARENT_INTERFACE);


    if((vlan_id_attr == NULL) ||
      ((tagged_attr == NULL) &&
      (untagged_attr == NULL))) {
        EV_LOGGING(NAS_OS,ERR, "NAS-OS", "Parameters missing for deletion of member from bridge");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    int vlan_id = (int)cps_api_object_attr_data_u32(vlan_id_attr);
    char mem_name[HAL_IF_NAME_SZ];

    if (tagged_attr != NULL) {
        if (parent == NULL) {
             EV_LOGGING(NAS_OS, ERR, "NAS-OS", " NAS OS del intf from bridge: missing parent intf for vlan_id %d",
                       vlan_id);
             return (STD_ERR(NAS_OS,FAIL, 0));
        }
        safestrncpy(mem_name, (char*)cps_api_object_attr_data_bin(tagged_attr), HAL_IF_NAME_SZ); /* mem_name is  e101-001-1.100 */

    } else if (untagged_attr != NULL) {
        safestrncpy(mem_name, (char*)cps_api_object_attr_data_bin(untagged_attr), HAL_IF_NAME_SZ);
    } else {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS", " NAS OS del port from bridge: Missing member information for vlan id ", vlan_id);
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    std::string interface_name(mem_name);
    if (!(nas_os_if_index_get(interface_name, idx))) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS", " NAS OS del port from bridge: failed to find ifindex for %s", mem_name);
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    if (tagged_attr != NULL) {
        std::string parent_name((char *)cps_api_object_attr_data_bin(parent));
        if (!(nas_os_if_index_get(parent_name, parent_idx))) {
           EV_LOGGING(NAS_OS, ERR, "NAS-OS", " NAS OS del port from bridge: failed to find ifindex for parent %s",
                                     parent_name.c_str());
           return (STD_ERR(NAS_OS,FAIL, 0));
        }
        EV_LOGGING(NAS_OS, INFO, "NAS-OS", " NAS OS del tag port from bridge: parent_name %s, index %d",
                                                          parent_name.c_str(), parent_idx);
        _update_intf_to_tagged_intf_map(parent_idx, idx, false);
    }
    EV_LOGGING(NAS_OS, INFO, "NAS-OS", " NAS OS del port from bridge name %s index %d", mem_name,idx);
    return nas_os_set_master(idx, 0);
}


/* @TODO:  Will be deprecated */

t_std_error nas_os_del_port_from_vlan(cps_api_object_t obj)
{
    char if_name[HAL_IF_NAME_SZ+1] = "", vlan_name[HAL_IF_NAME_SZ+1];

    cps_api_object_attr_t vlan_id_attr = cps_api_object_attr_get(obj, BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID);
    cps_api_object_attr_t vlan_t_port_attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS);
    cps_api_object_attr_t vlan_ut_port_attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_UNTAGGED_PORTS);

    EV_LOG(INFO, NAS_OS, ev_log_s_MINOR, "NAS-OS", "Del port from Vlan");

    if((vlan_id_attr == NULL) ||
      ((vlan_t_port_attr == NULL) &&
      (vlan_ut_port_attr == NULL))) {
        EV_LOG(ERR, NAS_OS, ev_log_s_CRITICAL, "NAS-OS", "Parameters missing for deletion of vlan");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    int vlan_id = (int)cps_api_object_attr_data_u32(vlan_id_attr);
    hal_ifindex_t port_index = 0;
    // for now deleting only one port at a time
    if(vlan_t_port_attr != NULL) {
        port_index = (int)cps_api_object_attr_data_u32(vlan_t_port_attr);

        if(cps_api_interface_if_index_to_name(port_index, if_name, sizeof(if_name)) == NULL) {
            EV_LOG(ERR, NAS_OS, ev_log_s_CRITICAL, "NAS-OS", "Failure getting interface name for %d", port_index);
            return (STD_ERR(NAS_OS,FAIL, 0));
        }

        nas_os_get_vlan_if_name(if_name, sizeof(if_name), vlan_id, vlan_name);


        int vlan_if_index = cps_api_interface_name_to_if_index(vlan_name);
        if (vlan_if_index == 0) {
            EV_LOG(ERR, NAS_OS, ev_log_s_CRITICAL, "NAS-OS", "No interface exist for %s \n", vlan_name);
            return (STD_ERR(NAS_OS,FAIL, 0));
        }

        _update_intf_to_tagged_intf_map(port_index,vlan_if_index,false);
        if(nas_os_change_master(vlan_if_index,0,0) != STD_ERR_OK)
            return (STD_ERR(NAS_OS,FAIL, 0));
                //Call the interface delete
        return nas_os_del_interface(vlan_if_index);
    }
    else {
        port_index = (int)cps_api_object_attr_data_u32(vlan_ut_port_attr);
        return nas_os_change_master(port_index,0,0);
    }

}


t_std_error nas_os_del_vlan_interface(cps_api_object_t obj)
{
    char if_name[HAL_IF_NAME_SZ+1] = "", vlan_name[HAL_IF_NAME_SZ+1] = "";

    EV_LOG(INFO, NAS_OS, ev_log_s_MINOR, "NAS-OS", "Del Vlan Interface ");

    cps_api_object_attr_t port_attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS);
    cps_api_object_attr_t vlan_id_attr = cps_api_object_attr_get(obj, BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID);

    if((port_attr == NULL) ||
       (vlan_id_attr == NULL)){
        EV_LOG(ERR, NAS_OS, ev_log_s_CRITICAL, "NAS-OS", "Missing Vlan interface parameters for deletion");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    hal_ifindex_t port_index = (int)cps_api_object_attr_data_u32(port_attr);
    hal_vlan_id_t vlan_id = (hal_vlan_id_t)cps_api_object_attr_data_u32(vlan_id_attr);

    EV_LOG(INFO, NAS_OS, ev_log_s_MINOR, "NAS-OS", "Vlan i/f %d, ID %d for deletion", port_index, vlan_id);

    if(cps_api_interface_if_index_to_name(port_index, if_name, sizeof(if_name)) == NULL) {
        EV_LOG(ERR, NAS_OS, ev_log_s_CRITICAL, "NAS-OS", "Failure getting interface name for %d", port_index);
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    nas_os_get_vlan_if_name(if_name, sizeof(if_name), vlan_id, vlan_name);

    int vlan_if_index = cps_api_interface_name_to_if_index(vlan_name);

    //Call the interface delete
    return nas_os_del_interface(vlan_if_index);
}

bool nas_os_tag_port_exist(cps_api_object_t obj){

    char if_name[HAL_IF_NAME_SZ+1];
    char vlan_name[HAL_IF_NAME_SZ+1];

    cps_api_object_attr_t vlan_id_attr = cps_api_object_attr_get(obj, BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID);
    cps_api_object_attr_t vlan_t_port_attr = cps_api_object_attr_get(obj,
                            DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS);

    if((vlan_id_attr == NULL) ||
      (vlan_t_port_attr == NULL)) {
        EV_LOGGING(NAS_OS,ERR,"NAS-LINUX-INTERFACE","Parameter missing for port exist ");
        return false;
    }

    int vlan_id = (int)cps_api_object_attr_data_u32(vlan_id_attr);
    hal_ifindex_t port_index = 0;

    port_index = (int)cps_api_object_attr_data_u32(vlan_t_port_attr);

    if(cps_api_interface_if_index_to_name(port_index,if_name,sizeof(if_name))==NULL){
        EV_LOG(ERR,NAS_OS,0,"NAS-LINUX-INTERFACE","Invalid Interface Index %d ",port_index);
        return false;
    }
    nas_os_get_vlan_if_name(if_name, sizeof(if_name), vlan_id, vlan_name);

    if(cps_api_interface_name_to_if_index(vlan_name) == 0){
        EV_LOG(ERR,NAS_OS,0,"NAS-LINUX-INTERFACE","Invalid Interface name %s ",vlan_name);
        return false;
    }
    return true;
}


t_std_error nas_os_vlan_set_member_port_mtu(cps_api_object_t obj){

    cps_api_object_attr_t ifindex_attr = cps_api_object_attr_get(obj,DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);
    cps_api_object_attr_t vlan_id_attr = cps_api_object_attr_get(obj,BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID);

    if(ifindex_attr == nullptr || vlan_id_attr == nullptr){
        EV_LOGGING(NAS_OS,DEBUG,"NAS-LINUX-INTERFACE","Missing neccessary params for updating member port mtu");
        return STD_ERR(NAS_OS,PARAM,0);
    }
    hal_ifindex_t ifindex = cps_api_object_attr_data_u32(ifindex_attr);
    hal_vlan_id_t vlan_id = cps_api_object_attr_data_u16(vlan_id_attr);
    hal_ifindex_t vlan_ifindex = 0;
    /*
     * Object would contain physical port index and vlan id. It needs to be converted
     * into tagged member port ifindex
     */
    if(nas_os_physical_to_vlan_ifindex(ifindex,vlan_id,true,&vlan_ifindex)){

        /*
         * Use the same object, delete the physical port ifindex and add the
         * tagged member port ifindex to object
         */
        cps_api_object_attr_delete(obj,DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);
        cps_api_object_attr_add_u32(obj, DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX,vlan_ifindex);
        return nas_os_interface_set_attribute(obj,DELL_IF_IF_INTERFACES_INTERFACE_MTU);
    }

    return STD_ERR(NAS_OS,PARAM,0);
}
