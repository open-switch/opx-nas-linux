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
 * nas_os_lpbk.c
 *
 *  Created on: January 16, 2019
 */
#include "dell-base-if.h"
#include "ds_api_linux_interface.h"
#include "ds_common_types.h"
#include "event_log.h"
#include "nas_nlmsg.h"
#include "nas_os_interface.h"
#include "nas_os_lpbk.h"
#include <net/if.h>
#include "netlink_tools.h"
#include "std_mac_utils.h"
#include <string.h>

#define NL_MSG_BUFF 4096
#define NULL_BYTE   1


t_std_error nas_os_lpbk_create(cps_api_object_t obj)
{
    char *lpbk_name = NULL;
    cps_api_object_attr_t attr;

    char buff[NL_MSG_BUFF];
    hal_ifindex_t if_index = 0;
    const char *info_kind = "dummy";
    unsigned int flags = (IFF_BROADCAST | IFF_NOARP);

    memset(buff, 0, NL_MSG_BUFF);

    struct nlmsghdr *nlh = (struct nlmsghdr *) nlmsg_reserve((struct nlmsghdr *)buff, sizeof(buff), sizeof(struct nlmsghdr));
    struct ifinfomsg *ifmsg = (struct ifinfomsg *) nlmsg_reserve(nlh, sizeof(buff), sizeof(struct ifinfomsg));

    flags &= ~IFF_UP;

    nas_os_pack_nl_hdr(nlh, RTM_NEWLINK, (NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL));
    nas_os_pack_if_hdr(ifmsg, AF_PACKET, flags, if_index);

    attr = cps_api_object_attr_get(obj, IF_INTERFACES_INTERFACE_NAME);
    if (attr == CPS_API_ATTR_NULL) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-LPBK", "Missing loopback name for adding to kernel");
        return (STD_ERR(NAS_OS, FAIL, 0));
    } else {
        lpbk_name = (char*)cps_api_object_attr_data_bin(attr);
        nlmsg_add_attr(nlh,sizeof(buff),IFLA_IFNAME, lpbk_name , strlen(lpbk_name)+1);
        EV_LOGGING(NAS_OS, DEBUG, "NAS-OS-LPBK", "loopback name is %s", lpbk_name);
    }

    attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_MTU);
    if (attr != CPS_API_ATTR_NULL) {
        unsigned int mtu = 0;
        mtu = cps_api_object_attr_data_u32(attr);
        nlmsg_add_attr(nlh, sizeof(buff), IFLA_MTU, &mtu , sizeof(mtu));
        EV_LOGGING(NAS_OS, DEBUG, "NAS-OS-LPBK", "setting MTU (%d) in kernel", mtu);
    }

    attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_PHYS_ADDRESS);
    if (attr != CPS_API_ATTR_NULL) {
        char *addr = NULL;
        hal_mac_addr_t mac_addr;
        addr = (char*)cps_api_object_attr_data_bin(attr);
        if (std_string_to_mac(&mac_addr, (const char *)addr, sizeof(mac_addr))) {
            nlmsg_add_attr(nlh, sizeof(buff), IFLA_ADDRESS, &mac_addr , sizeof(hal_mac_addr_t));
            EV_LOGGING(NAS_OS, DEBUG, "NAS-OS-LPBK", "setting MAC address (%s) in kernel", (const char *)mac_addr);
        }
    }

    nlmsg_add_attr(nlh, sizeof(buff), IFLA_IFNAME, lpbk_name, (strlen(lpbk_name) + NULL_BYTE));

    struct nlattr *attr_nh = nlmsg_nested_start(nlh, sizeof(buff));
    attr_nh->nla_len = 0;
    attr_nh->nla_type = IFLA_LINKINFO;
    nlmsg_add_attr(nlh, sizeof(buff), IFLA_INFO_KIND, info_kind, (strlen(info_kind) + NULL_BYTE));
    nlmsg_nested_end(nlh, attr_nh);

    if(nl_do_set_request(NL_DEFAULT_VRF_NAME, nas_nl_sock_T_INT, nlh, buff, sizeof(buff)) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-LPBK", "Failure creating loopback (%s) in kernel", lpbk_name);
        return (STD_ERR(NAS_OS, FAIL, 0));
    } else {
        /* add interface index */
        hal_ifindex_t ifix = cps_api_interface_name_to_if_index(lpbk_name);
        cps_api_object_attr_add_u32(obj, DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX, ifix);
    }

    return STD_ERR_OK;
}

t_std_error nas_os_lpbk_delete(cps_api_object_t obj)
{
    cps_api_object_attr_t attr;
    hal_ifindex_t         if_index = 0;
    char                 *lpbk_name = NULL;

    attr = cps_api_object_attr_get(obj, IF_INTERFACES_INTERFACE_NAME);
    if (attr == CPS_API_ATTR_NULL) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-LPBK", "Missing loopback name for delete  request");
        return cps_api_ret_code_ERR;
    } else {
        lpbk_name = (char*)cps_api_object_attr_data_bin(attr);
    }

    if_index = cps_api_interface_name_to_if_index(lpbk_name);
    if (nas_os_del_interface(if_index) != STD_ERR_OK){
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-LPBK", "Failure deleting loopback (%s) from kernel", lpbk_name);
        return cps_api_ret_code_ERR;
    }

    cps_api_object_attr_add_u32(obj, DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX, if_index);
    return cps_api_ret_code_OK;
}

