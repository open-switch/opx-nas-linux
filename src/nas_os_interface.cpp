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
 * filename: nas_os_interface.c
 */


#include "event_log.h"
#include "netlink_tools.h"
#include "nas_nlmsg.h"

#include "cps_api_operation.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"
#include "std_assert.h"
#include "dell-interface.h"
#include "dell-base-if.h"
#include "dell-base-if-linux.h"
#include "nas_os_interface.h"
#include "nas_os_if_priv.h"
#include "nas_os_int_utils.h"
#include "hal_if_mapping.h"

#include "nas_nlmsg_object_utils.h"
#include "ds_api_linux_interface.h"
#include "std_mac_utils.h"

#include <sys/socket.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>


#include <pthread.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <map>


#define NL_MSG_INTF_BUFF_LEN 2048

extern "C" t_std_error nas_os_del_interface(hal_ifindex_t if_index)
{
    char buff[NL_MSG_INTF_BUFF_LEN];

    memset(buff,0,sizeof(buff));

    EV_LOG(INFO, NAS_OS, ev_log_s_MINOR, "NAS-OS", "Del Interface %d", if_index);

    struct nlmsghdr *nlh = (struct nlmsghdr *) nlmsg_reserve((struct nlmsghdr *)buff,sizeof(buff),sizeof(struct nlmsghdr));
    struct ifinfomsg *ifmsg = (struct ifinfomsg *) nlmsg_reserve(nlh,sizeof(buff),sizeof(struct ifinfomsg));

    nas_os_pack_nl_hdr(nlh, RTM_DELLINK,NLM_F_REQUEST);

    nas_os_pack_if_hdr(ifmsg, AF_UNSPEC, 0, if_index);

    if(nl_do_set_request(NL_DEFAULT_VRF_NAME, nas_nl_sock_T_INT, nlh, buff,sizeof(buff)) != STD_ERR_OK) {
        EV_LOG(ERR, NAS_OS, ev_log_s_CRITICAL, "NAS-OS", "Failure deleting interface in kernel");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    return STD_ERR_OK;
}

extern "C" t_std_error nas_os_get_interface_obj_by_name(const char *ifname, cps_api_object_t obj) {
    hal_ifindex_t ifix = cps_api_interface_name_to_if_index(ifname);
    if (ifix==0) return STD_ERR(NAS_OS,PARAM,0);
    return nas_os_get_interface_obj(ifix,obj);
}

extern "C" t_std_error nas_os_get_interface_mtu(const char *ifname, cps_api_object_t obj) {

     unsigned int mtu;
         t_std_error ret;

         ret = nas_os_util_int_mtu_get(ifname, &mtu);
         cps_api_object_attr_add_u32(obj, DELL_IF_IF_INTERFACES_INTERFACE_MTU,
                                                (mtu  + NAS_LINK_MTU_HDR_SIZE));
         return (ret);
 }

extern "C" t_std_error nas_os_get_interface_obj(hal_ifindex_t ifix,cps_api_object_t obj) {
    cps_api_object_list_guard lg(cps_api_object_list_create());
    if (lg.get()==NULL) return STD_ERR(NAS_OS,FAIL,0);

    if (_get_interfaces(lg.get(),ifix,false,0)
            != cps_api_ret_code_OK) {
        return STD_ERR(NAS_OS,FAIL,0);
    }

    cps_api_object_t ret = cps_api_object_list_get(lg.get(),0);
    if (ret==nullptr) {
        return STD_ERR(NAS_OS,FAIL,0);
    }
    cps_api_object_clone(obj,ret);
    return STD_ERR_OK;
}

extern "C" t_std_error nas_os_get_interface(cps_api_object_t filter,cps_api_object_list_t result) {
    cps_api_object_attr_t ifix =
                cps_api_object_attr_get(filter, DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);
    hal_ifindex_t ifindex = 0;
    cps_api_object_attr_t type_attr =
                cps_api_object_attr_get(filter, BASE_IF_LINUX_IF_INTERFACES_INTERFACE_DELL_TYPE);
    uint_t if_type = 0;
    if (ifix != nullptr) {
        ifindex = cps_api_object_attr_data_u32(ifix);
        type_attr = nullptr; // Won't consider if_type if ifindex is specified
    } else if (type_attr != nullptr) {
        if_type = cps_api_object_attr_data_u32(type_attr);
    }
    _get_interfaces(result,ifindex, ifix==nullptr, if_type);
    return STD_ERR_OK;
}

static void _set_mac(cps_api_object_t obj, struct nlmsghdr *nlh, struct ifinfomsg * inf,size_t len) {
    cps_api_object_attr_t attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_PHYS_ADDRESS);
    if (attr==NULL) return;
    void *addr = cps_api_object_attr_data_bin(attr);
    hal_mac_addr_t mac_addr;

    int addr_len = strlen(static_cast<char *>(addr));
    if (std_string_to_mac(&mac_addr, static_cast<const char *>(addr), addr_len)) {
        char mac_str[40] = {0};
        EV_LOGGING(NAS_OS, NOTICE, "NAS-OS", "Setting mac address %s, actual string %s, len %d",
                std_mac_to_string(&mac_addr,mac_str,sizeof(mac_str)), static_cast<char *>(addr), addr_len);
        nlmsg_add_attr(nlh,len,IFLA_ADDRESS, mac_addr , cps_api_object_attr_len(attr));
    }
}

static void _set_mtu(cps_api_object_t obj, struct nlmsghdr *nlh, struct ifinfomsg * inf,size_t len) {
    cps_api_object_attr_t attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_MTU);
    if (attr==NULL) return;
    int mtu = (int)cps_api_object_attr_data_uint(attr) - NAS_LINK_MTU_HDR_SIZE;
    EV_LOGGING(NAS_OS, NOTICE, "NAS-OS", "set mtu to %d ", mtu);
    nlmsg_add_attr(nlh,len,IFLA_MTU, &mtu , sizeof(mtu));
}

static void _set_name(cps_api_object_t obj, struct nlmsghdr *nlh, struct ifinfomsg * inf,size_t len) {
    cps_api_object_attr_t attr = cps_api_object_attr_get(obj, IF_INTERFACES_INTERFACE_NAME);
    if (attr==NULL) return;
    const char *name = (const char*)cps_api_object_attr_data_bin(attr);
    nlmsg_add_attr(nlh,len,IFLA_IFNAME, name , strlen(name)+1);
}

static void _set_ifalias(cps_api_object_t obj, struct nlmsghdr *nlh, struct ifinfomsg * inf,size_t len) {
    cps_api_object_attr_t attr = cps_api_object_attr_get(obj,NAS_OS_IF_ALIAS);
    if (attr==NULL) return;
    const char *name = (const char*)cps_api_object_attr_data_bin(attr);
    nlmsg_add_attr(nlh,len,IFLA_IFALIAS, name , strlen(name)+1);
}

static void _set_admin(cps_api_object_t obj, struct nlmsghdr *nlh, struct ifinfomsg * inf,size_t len) {
    cps_api_object_attr_t attr = cps_api_object_attr_get(obj,IF_INTERFACES_INTERFACE_ENABLED);
    if (attr==NULL) return;
    bool admin_enabled = (bool) cps_api_object_attr_data_uint(attr);

    if (admin_enabled) {
        inf->ifi_flags |= IFF_UP;
    } else  {
        inf->ifi_flags &= ~IFF_UP;
    }
    EV_LOGGING(NAS_OS, NOTICE, "NAS-OS", "set admin state to %s ", ((admin_enabled) ? "true" : "false"));
}

static t_std_error _set_intf_attribute (const char *vrf_name, hal_ifindex_t if_index,
                                        cps_api_object_t obj,cps_api_attr_id_t id) {
    char buff[NL_MSG_INTF_BUFF_LEN];
    memset(buff,0,sizeof(buff));

    struct nlmsghdr *nlh = (struct nlmsghdr *) nlmsg_reserve((struct nlmsghdr *)buff,sizeof(buff),sizeof(struct nlmsghdr));
    struct ifinfomsg *ifmsg = (struct ifinfomsg *) nlmsg_reserve(nlh,sizeof(buff),sizeof(struct ifinfomsg));

    nas_os_pack_nl_hdr(nlh, RTM_SETLINK, NLM_F_REQUEST);
    nas_os_pack_if_hdr(ifmsg, AF_UNSPEC, 0, if_index);

    char if_name[HAL_IF_NAME_SZ+1];
    memset(if_name, 0, sizeof(if_name));
    if (nas_os_util_int_if_name_get(vrf_name, if_index, if_name) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS", "Failure getting interface for VRF:%s %d",
                   vrf_name, if_index);
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    unsigned flags = 0;
    if(nas_os_util_int_flags_get(vrf_name, if_name, &flags) == STD_ERR_OK) {
        ifmsg->ifi_flags = flags;
    }

    EV_LOGGING(NAS_OS, NOTICE, "NAS-OS", "set attribute for  %s ", if_name);
    static const std::map<cps_api_attr_id_t,void (*)( cps_api_object_t ,struct nlmsghdr *,
            struct ifinfomsg *,size_t)> _funcs = {
            {DELL_IF_IF_INTERFACES_INTERFACE_MTU, _set_mtu},
            {IF_INTERFACES_INTERFACE_NAME, _set_name},
            {IF_INTERFACES_INTERFACE_ENABLED, _set_admin},
            {NAS_OS_IF_ALIAS, _set_ifalias },
            {DELL_IF_IF_INTERFACES_INTERFACE_PHYS_ADDRESS, _set_mac},
    };

    auto it =_funcs.find(id);
    if (it==_funcs.end()) return STD_ERR_OK;
    it->second(obj,nlh,ifmsg,sizeof(buff));

    if(nl_do_set_request(vrf_name, nas_nl_sock_T_INT, nlh, buff,sizeof(buff)) != STD_ERR_OK) {
        EV_LOG(ERR, NAS_OS, ev_log_s_CRITICAL, "NAS-OS", "Failure updating interface in kernel");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    return STD_ERR_OK;
}

static t_std_error _set_router_intf_attribute (hal_ifindex_t if_index,
                                               cps_api_object_t obj,cps_api_attr_id_t id) {
    t_std_error rc = STD_ERR_OK;
    interface_ctrl_t intf_ctrl;

    if ((id != DELL_IF_IF_INTERFACES_INTERFACE_MTU) && (id != IF_INTERFACES_INTERFACE_ENABLED)) {
        return STD_ERR_OK;
    }
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.vrf_id = NAS_DEFAULT_VRF_ID;
    intf_ctrl.if_index = if_index;

    if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, INFO, "NAS-OS", "Failure getting interface for VRF:%u %d",
                   intf_ctrl.vrf_id, intf_ctrl.if_index);
        return STD_ERR_OK;
    }
    EV_LOGGING(NAS_OS, INFO, "NAS-OS", "Intf attribute id:%lu success for VRF:%u intf:%d",
               id, intf_ctrl.l3_intf_info.vrf_id, intf_ctrl.l3_intf_info.if_index);
    if (intf_ctrl.l3_intf_info.if_index) {
        /* Update the MTU and admin status on router interface as well when there is
         * an update on the lower layer interface */
        interface_ctrl_t router_intf_ctrl;
        memset(&router_intf_ctrl, 0, sizeof(router_intf_ctrl));
        router_intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
        router_intf_ctrl.vrf_id = intf_ctrl.l3_intf_info.vrf_id;
        router_intf_ctrl.if_index = intf_ctrl.l3_intf_info.if_index;

        if ((dn_hal_get_interface_info(&router_intf_ctrl)) != STD_ERR_OK) {
            EV_LOGGING(NAS_OS, ERR, "NAS-OS", "Failure getting interface for VRF:%u %d",
                       router_intf_ctrl.vrf_id, router_intf_ctrl.if_index);
            return (STD_ERR(NAS_OS,FAIL, 0));
        }

        rc = _set_intf_attribute(router_intf_ctrl.vrf_name, router_intf_ctrl.if_index, obj, id);
        if (rc != STD_ERR_OK) {
            EV_LOGGING(NAS_OS, ERR, "NAS-OS", "Failure updating interface:%d id:%lu in kernel",
                       router_intf_ctrl.if_index, id);
            return (STD_ERR(NAS_OS,FAIL, 0));
        }
        EV_LOGGING(NAS_OS, INFO, "NAS-OS", "Intf attribute id:%lu success for VRF:%s intf:%d(%s)",
                   id, router_intf_ctrl.vrf_name, router_intf_ctrl.if_index, router_intf_ctrl.if_name);
    }
    return STD_ERR_OK;
}

extern "C" t_std_error nas_os_interface_set_attribute(cps_api_object_t obj,cps_api_attr_id_t id) {
    t_std_error rc = STD_ERR_OK;

    cps_api_object_attr_t _ifix = cps_api_object_attr_get(obj, DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);
    if (_ifix==NULL) return (STD_ERR(NAS_OS,FAIL, 0));

    hal_ifindex_t if_index = cps_api_object_attr_data_uint(_ifix);
    if (if_index==0) return STD_ERR(NAS_OS,FAIL, 0);

    rc = _set_intf_attribute(NL_DEFAULT_VRF_NAME, if_index, obj, id);
    if (rc != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS", "Failure updating interface:%d id:%lu in kernel", if_index, id);
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    rc = _set_router_intf_attribute(if_index, obj, id);
    if (rc != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS", "Failure updating router interface:%d id:%lu in kernel",
                   if_index, id);
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    return STD_ERR_OK;
}

