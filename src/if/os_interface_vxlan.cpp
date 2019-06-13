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

/*
 * filename: os_interface_vxlan.cpp
 */

#include "event_log.h"
#include "cps_api_object_key.h"
#include "cps_api_object_attr.h"
#include "nas_os_int_utils.h"
#include "nas_os_if_priv.h"
#include "dell-base-interface-common.h"
#include "dell-interface.h"
#include "dell-base-if.h"
#include "ds_api_linux_interface.h"
#include "nas_nlmsg.h"
#include "netlink_tools.h"
#include "nas_os_vxlan.h"
#include <net/if.h>
#define NL_MSG_BUFFER_LEN 4096

bool INTERFACE::os_interface_vxlan_attrs_handler(if_details *details, cps_api_object_t obj)
{
    uint32_t vxlan_id = 0;
    uint32_t src_ip = 0;
    uint8_t *src_ipv6;

    BASE_CMN_AF_TYPE_t af_type = BASE_CMN_AF_TYPE_INET;

    if ((details->_info_kind == nullptr) ||  (details->_attrs[IFLA_MASTER]!=NULL)) {
        return true;
    }

    EV_LOGGING(NAS_OS, INFO, "NET-MAIN", "In IFLA_INFO_KIND for %s index %d",
            details->_info_kind, details->_ifindex);

    struct nlattr *vxlan[IFLA_VXLAN_MAX];

    if(!strncmp(details->_info_kind, "vxlan", 5)) {
        if ((details->_attrs[IFLA_LINKINFO] != nullptr) &&
            (details->_linkinfo[IFLA_INFO_KIND]!=nullptr)) {

                    memset(vxlan,0,sizeof(vxlan));

                    nla_parse_nested(vxlan,IFLA_VXLAN_MAX, details->_linkinfo[IFLA_INFO_DATA]);
                    if (vxlan[IFLA_VXLAN_ID]) {
                        EV_LOGGING(NAS_OS, INFO, "NET-MAIN", "***Received*** VXLAN ID %d for index %d",
                                *(uint32_t*)nla_data(vxlan[IFLA_VXLAN_ID]), details->_ifindex);
                        vxlan_id = *(uint32_t*)nla_data(vxlan[IFLA_VXLAN_ID]);
                        cps_api_object_attr_add_u32(obj, DELL_IF_IF_INTERFACES_INTERFACE_VNI, vxlan_id);

                    }
                    if(vxlan[IFLA_VXLAN_LOCAL]) {
                        src_ip = (*(uint32_t*)(nla_data(vxlan[IFLA_VXLAN_LOCAL])));
                        EV_LOGGING(NAS_OS, INFO, "NET-MAIN", "Received VXLAN local address 0x%x for index %d",
                                src_ip, details->_ifindex);
                        af_type = BASE_CMN_AF_TYPE_INET;
                        cps_api_object_attr_add(obj, DELL_IF_IF_INTERFACES_INTERFACE_SOURCE_IP_ADDR,
                                                    (void *)&src_ip, sizeof(src_ip));
                        cps_api_object_attr_add_u32(obj,DELL_IF_IF_INTERFACES_INTERFACE_SOURCE_IP_ADDR_FAMILY,  af_type);

                    } else if (vxlan[IFLA_VXLAN_LOCAL6]) {
                        src_ipv6 = (uint8_t*)(nla_data(vxlan[IFLA_VXLAN_LOCAL6]));
                        af_type = BASE_CMN_AF_TYPE_INET6;
                        cps_api_object_attr_add(obj, DELL_IF_IF_INTERFACES_INTERFACE_SOURCE_IP_ADDR,
                                                    (void *)src_ipv6, HAL_INET6_LEN);
                        cps_api_object_attr_add_u32(obj,DELL_IF_IF_INTERFACES_INTERFACE_SOURCE_IP_ADDR_FAMILY,  af_type);
                    }

                    if(vxlan[IFLA_VXLAN_GROUP]) {
                        EV_LOGGING(NAS_OS, INFO, "NET-MAIN", "Received VXLAN group address 0x%x for index %d",
                               ntohl(*(uint32_t*)(nla_data(vxlan[IFLA_VXLAN_GROUP]))),
                               details->_ifindex);
                    }
                    //the device
                    if(vxlan[IFLA_VXLAN_LINK]) {
                        EV_LOGGING(NAS_OS, INFO, "NET-MAIN", "Received VXLAN link %d for index %d",
                               *(uint32_t*)nla_data(vxlan[IFLA_VXLAN_LINK]),
                               details->_ifindex);
                    }
                    if(vxlan[IFLA_VXLAN_PORT]) {
                        EV_LOGGING(NAS_OS, INFO, "NET-MAIN", "Received VXLAN port %d for index %d",
                               htons(*(uint16_t*)(nla_data(vxlan[IFLA_VXLAN_PORT]))),
                               details->_ifindex);
                    }
                    if(vxlan[IFLA_VXLAN_LEARNING]) {
                        EV_LOGGING(NAS_OS, INFO, "NET-MAIN", "Received VXLAN learning %d for index %d",
                               *(uint16_t*)nla_data(vxlan[IFLA_VXLAN_LEARNING]),
                               details->_ifindex);
                    }
                    if(vxlan[IFLA_VXLAN_AGEING]) {
                        EV_LOGGING(NAS_OS, INFO, "NET-MAIN", "Received VXLAN ageing %d for index %d",
                               *(uint32_t*)nla_data(vxlan[IFLA_VXLAN_AGEING]),
                               details->_ifindex);
                    }
                    if(vxlan[IFLA_VXLAN_TTL]) {
                        EV_LOGGING(NAS_OS, INFO, "NET-MAIN", "Received VXLAN ttl %d for index %d",
                               *(uint8_t*)nla_data(vxlan[IFLA_VXLAN_TTL]), details->_ifindex);
                    }
                    if(vxlan[IFLA_VXLAN_TOS]) {
                        EV_LOGGING(NAS_OS, INFO, "NET-MAIN", "Received VXLAN tos %d for index %d",
                               *(uint8_t*)nla_data(vxlan[IFLA_VXLAN_TOS]), details->_ifindex);
                    }
                    if(vxlan[IFLA_VXLAN_L2MISS]) {
                        EV_LOGGING(NAS_OS, INFO, "NET-MAIN", "Received VXLAN L2 miss %d for index %d",
                               *(uint8_t*)nla_data(vxlan[IFLA_VXLAN_L2MISS]), details->_ifindex);
                    }

                    if(vxlan[IFLA_VXLAN_L3MISS]) {
                        EV_LOGGING(NAS_OS, INFO, "NET-MAIN", "Received VXLAN l3 miss %d for index %d",
                               *(uint8_t*)nla_data(vxlan[IFLA_VXLAN_L3MISS]), details->_ifindex);
                    }
                    details->_type = BASE_CMN_INTERFACE_TYPE_VXLAN;
            } else {
                return false;
            }
        }
    return true;
}

#define NL_MSG_BUFF 4096

static const uint32_t default_vxlan_mac_ageing = 5400;

t_std_error nas_os_create_vxlan_interface(cps_api_object_t obj){
    char buff[NL_MSG_BUFF];
    memset(buff,0,sizeof(nlmsghdr)+sizeof(ifinfomsg));

    struct nlmsghdr *nlh = (struct nlmsghdr *) nlmsg_reserve((struct nlmsghdr *)buff,sizeof(buff),
            sizeof(struct nlmsghdr));
    struct ifinfomsg *ifmsg = (struct ifinfomsg *) nlmsg_reserve(nlh,sizeof(buff),
            sizeof(struct ifinfomsg));

    cps_api_object_attr_t name_attr = cps_api_get_key_data(obj, IF_INTERFACES_INTERFACE_NAME);
    cps_api_object_attr_t vni_attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_VNI);
    cps_api_object_attr_t ip_attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_SOURCE_IP_ADDR);
    cps_api_object_attr_t ip_family_attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_SOURCE_IP_ADDR_FAMILY);
    cps_api_object_attr_t admin_attr = cps_api_object_attr_get(obj,IF_INTERFACES_INTERFACE_ENABLED);

    if(!name_attr || !vni_attr || !ip_attr || !ip_family_attr) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VXLAN","Missing VXLAN interface name/vni/ip for creating vxlan");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    const char *vxlan_name = (const char *)cps_api_object_attr_data_bin(name_attr);
    uint32_t vxlan_id = cps_api_object_attr_data_uint(vni_attr);
    hal_ip_addr_t ip;
    ip.af_index = cps_api_object_attr_data_uint(ip_family_attr);
    hal_ifindex_t if_index = 0;
    const char *info_kind = "vxlan";

    EV_LOGGING(NAS_OS, INFO, "NAS-OS-VXLAN","Create VxLAN interface %s in OS",vxlan_name);

    unsigned int flags = IFF_BROADCAST | IFF_MULTICAST;
    if (admin_attr != nullptr && (bool)cps_api_object_attr_data_uint(admin_attr)) {
        flags |= IFF_UP;
    }

    nas_os_pack_nl_hdr(nlh, RTM_NEWLINK, (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL));
    nas_os_pack_if_hdr(ifmsg, AF_PACKET, flags , if_index);

    nlmsg_add_attr(nlh,sizeof(buff),IFLA_IFNAME, vxlan_name, (strlen(vxlan_name)+1));
    struct nlattr *attr_nh = nlmsg_nested_start(nlh, sizeof(buff));
    attr_nh->nla_len = 0;
    attr_nh->nla_type = IFLA_LINKINFO;
    nlmsg_add_attr(nlh,sizeof(buff),IFLA_INFO_KIND, info_kind, (strlen(info_kind)+1));


    struct nlattr *attr_nh_data = nlmsg_nested_start(nlh, sizeof(buff));
    attr_nh_data->nla_len = 0;
    attr_nh_data->nla_type = IFLA_INFO_DATA;

    nlmsg_add_attr(nlh,sizeof(buff),IFLA_VXLAN_ID,&vxlan_id, sizeof(vxlan_id));
    if(ip.af_index == AF_INET){
        memcpy(&ip.u.ipv4,cps_api_object_attr_data_bin(ip_attr),sizeof(ip.u.ipv4));
        nlmsg_add_attr(nlh,sizeof(buff),IFLA_VXLAN_LOCAL,&ip.u.ipv4, sizeof(ip.u.ipv4));
    }else{
        memcpy(&ip.u.ipv6,cps_api_object_attr_data_bin(ip_attr),sizeof(ip.u.ipv6));
        nlmsg_add_attr(nlh,sizeof(buff),IFLA_VXLAN_LOCAL6,&ip.u.ipv6, sizeof(ip.u.ipv6));
    }
    nlmsg_add_attr(nlh,sizeof(buff),IFLA_VXLAN_AGEING, &default_vxlan_mac_ageing, sizeof(uint32_t));
    static const uint16_t dst_port = ntohs(4789);
    nlmsg_add_attr(nlh,sizeof(buff),IFLA_VXLAN_PORT,&dst_port, sizeof(dst_port));
    nlmsg_nested_end(nlh,attr_nh_data);
    nlmsg_nested_end(nlh,attr_nh);

    if(nl_do_set_request(NL_DEFAULT_VRF_NAME, nas_nl_sock_T_INT,nlh,buff,sizeof(buff)) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VXLAN", "Vxlan interface creation failed in kernel");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    /*
     * Disable ipv6 on VXLAN interface.
     */
    if (nas_os_interface_ipv6_config_handle(vxlan_name, false) == false) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VXLAN", "Failed: To disable ipv6 on sub interface (%s)", vxlan_name);
    }
    hal_ifindex_t vxlan_index=0;

    if((vxlan_index = cps_api_interface_name_to_if_index(vxlan_name)) == 0) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VXLAN", "Error finding the ifindex of vxlan");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    cps_api_object_attr_add_u32(obj,DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX,vxlan_index);

    return STD_ERR_OK;

}

