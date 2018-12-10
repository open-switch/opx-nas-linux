/*
 * Copyright (c) 2018 Dell Inc.
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
 * nas_os_ip.cpp
 *
 */

#include "dell-base-ip.h"
#include "event_log.h"

#include "cps_api_operation.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"
#include "ds_api_linux_interface.h"
#include "ds_api_linux_route.h"
#include "nas_os_int_utils.h"
#include "private/nas_os_if_priv.h"
#include "nas_nlmsg_object_utils.h"
#include "standard_netlink_requests.h"
#include "nas_os_l3_utils.h"
#include "std_ip_utils.h"
#include "nas_vrf_utils.h"
#include "std_system.h"
#include "hal_if_mapping.h"

#include <map>
#include <sstream>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <linux/netconf.h>

/* This provides the global IP forwarding status */
static bool is_global_ipv4_fwd_enable = true;
static bool is_global_ipv6_fwd_enable = true;

bool nas_os_is_reserved_ipv4(hal_ip_addr_t *p_ip_addr)
{
    /* 127.x.x.x - reserved address range */
    if ((p_ip_addr->af_index == HAL_INET4_FAMILY) &&
        ((p_ip_addr->u.v4_addr & 0xff) == 0x7f))
        return true;

    return false;
}

bool nas_os_is_reserved_ipv6(hal_ip_addr_t *p_ip_addr)
{
    if ((p_ip_addr->af_index == HAL_INET6_FAMILY) &&
        (((((p_ip_addr->u.v6_addr[0]) & (0xff)) == (0xff)) &&
          (((p_ip_addr->u.v6_addr[1]) & (0xf0)) == (0x00))) ||
         (STD_IP_IS_V6_ADDR_LOOP_BACK(p_ip_addr)))) {
        return true;
    }
    return false;
}

extern "C" t_std_error nas_os_read_ipv6_status(const char *vrf_name, char *name, int *ipv6_status) {
    const std::string NETCONF_IPV6_CONF = "/proc/sys/net/ipv6/conf/";
    int                 netns_handle = 0;
    t_std_error rc = (STD_ERR(NAS_OS,FAIL, 0));

    if ((strncmp(vrf_name, NAS_DEFAULT_VRF_NAME, NAS_VRF_NAME_SZ) != 0) &&
        (std_sys_set_netns(vrf_name, &netns_handle) != STD_ERR_OK)) {
        return rc;
    }
    std::string disabled_ipv6 = NETCONF_IPV6_CONF + std::string(name) + "/disable_ipv6";
    FILE *fp = fopen(disabled_ipv6.c_str(),"r");
    do {
        if (fp == NULL) {
            break;
        }
        int ret = fscanf(fp, "%d",ipv6_status);
        /*If data read from file returned not 1 (the no. of argument read), return failure */
        if (ret != 1) {
            fclose(fp);
            break;
        }

        /* ipv6_status now reflects the disable_ipv6 status,
         * so, to get the IPv6 enabled do the following. */
        if (*ipv6_status)
            *ipv6_status = false;
        else
            *ipv6_status = true;
        fclose(fp);
        rc = STD_ERR_OK;
    } while(0);
    if (netns_handle)
        std_sys_reset_netns (&netns_handle);
    return rc;
}

extern "C" bool nl_get_ip_info (int rt_msg_type, struct nlmsghdr *hdr, cps_api_object_t obj,
                                void *context, uint32_t vrf_id) {

    struct ifaddrmsg *ifmsg = (struct ifaddrmsg *)NLMSG_DATA(hdr);

    if(hdr->nlmsg_len < NLMSG_LENGTH(sizeof(*ifmsg)))
        return false;

    typedef enum { IP_KEY, IFINDEX, PREFIX, ADDRESS, IFNAME, VRFNAME, DAD_FAILED, ENABLED, AUTOCONF_ADDR} attr_t ;
    static const std::map<uint32_t, std::map<int,cps_api_attr_id_t>> _ipmap = {
      {AF_INET,
      {
        {IP_KEY,  BASE_IP_IPV4_OBJ},
        {IFINDEX, BASE_IP_IPV4_IFINDEX},
        {PREFIX,  BASE_IP_IPV4_ADDRESS_PREFIX_LENGTH},
        {ADDRESS, BASE_IP_IPV4_ADDRESS_IP},
        {IFNAME,  BASE_IP_IPV4_NAME},
        {VRFNAME, BASE_IP_IPV4_VRF_NAME}
      }},

      {AF_INET6,
      {
        {IP_KEY,  BASE_IP_IPV6_OBJ},
        {IFINDEX, BASE_IP_IPV6_IFINDEX},
        {PREFIX,  BASE_IP_IPV6_ADDRESS_PREFIX_LENGTH},
        {ADDRESS, BASE_IP_IPV6_ADDRESS_IP},
        {IFNAME,  BASE_IP_IPV6_NAME},
        {VRFNAME, BASE_IP_IPV6_VRF_NAME},
        {DAD_FAILED, BASE_IP_IPV6_DAD_FAILED},
        {ENABLED, BASE_IP_IPV6_ENABLED},
        {AUTOCONF_ADDR, BASE_IP_IPV6_ADDRESS_AUTOCONF_ADDR},
      }}
    };

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),_ipmap.at(ifmsg->ifa_family).at(IP_KEY),
                                    cps_api_qualifier_OBSERVED);

    cps_api_set_key_data(obj,_ipmap.at(ifmsg->ifa_family).at(IFINDEX), cps_api_object_ATTR_T_U32,
                         &ifmsg->ifa_index,sizeof(ifmsg->ifa_index));
    /* Get the VRF name from vrf-id */
    const char *vrf_name = nas_os_get_vrf_name(vrf_id);
    if (vrf_name == NULL) {
        return false;
    }
    /* Ignore the IP address event notification for sub-interaces. */
    if (vrf_id == NAS_DEFAULT_VRF_ID) {
        interface_ctrl_t intf_ctrl;
        memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
        intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
        intf_ctrl.vrf_id = vrf_id;
        intf_ctrl.if_index = ifmsg->ifa_index;
        bool is_intf_chk_req = true;
        if (((dn_hal_get_interface_info(&intf_ctrl)) == STD_ERR_OK) &&
            (intf_ctrl.int_type == nas_int_type_MACVLAN)) {
            /* Dont ignore the address update on MAC-VLAN sub-interface,
             * since this is required for VRRPv3 functionality to work */
            is_intf_chk_req = false;
        }
        if (is_intf_chk_req && (nas_rt_is_reserved_intf_idx(ifmsg->ifa_index,
                                                            true))) {
            return false;
        }
    }
    cps_api_object_attr_add(obj, _ipmap.at(ifmsg->ifa_family).at(VRFNAME), vrf_name,
                            strlen(vrf_name)+1);
    cps_api_object_attr_add_u32(obj, _ipmap.at(ifmsg->ifa_family).at(IFINDEX), ifmsg->ifa_index);
    cps_api_object_attr_add_u32(obj, _ipmap.at(ifmsg->ifa_family).at(PREFIX), ifmsg->ifa_prefixlen);

    int nla_len = nlmsg_attrlen(hdr,sizeof(*ifmsg));
    struct nlattr *head = nlmsg_attrdata(hdr, sizeof(struct ifaddrmsg));

    struct nlattr *attrs[__IFLA_MAX];
    memset(attrs,0,sizeof(attrs));

    if (nla_parse(attrs,__IFLA_MAX,head,nla_len)!=0) {
        EV_LOG_TRACE(ev_log_t_NAS_OS,ev_log_s_WARNING,"IP-NL-PARSE","Failed to parse attributes");
        return false;
    }
    char            addr_str[INET6_ADDRSTRLEN];
    char            local_addr_str[INET6_ADDRSTRLEN];
    EV_LOGGING(NAS_OS,INFO,"NAS-OS-IP", "Operation:%s(%d) VRF:%s(%d) flags:0x%x if-index:%s(%d) IP:%s/%d if-flags:0x%x scope:%d local:%s",
               ((rt_msg_type == RTM_NEWADDR) ? "Add" : ((rt_msg_type == RTM_DELADDR) ? "Del" : "Set")),
               rt_msg_type, vrf_name, vrf_id,
               (attrs[IFA_FLAGS] ? *(int *)nla_data((struct nlattr*)attrs[IFA_FLAGS]) :0),
               (attrs[IFA_LABEL] ? (char*)nla_data((struct nlattr*)attrs[IFA_LABEL]) :""),
               ifmsg->ifa_index,
               ((attrs[IFA_ADDRESS] != NULL) ?
                ((ifmsg->ifa_family == AF_INET) ?
                 (inet_ntop(ifmsg->ifa_family,
                            ((struct in_addr *) nla_data((struct nlattr*)attrs[IFA_ADDRESS])),
                            addr_str, INET_ADDRSTRLEN)) :
                 (inet_ntop(ifmsg->ifa_family,
                            ((struct in6_addr *) nla_data((struct nlattr*)attrs[IFA_ADDRESS])),
                            addr_str, INET6_ADDRSTRLEN))) : "NA"), ifmsg->ifa_prefixlen, ifmsg->ifa_flags, ifmsg->ifa_scope,
               ((attrs[IFA_LOCAL] != NULL) ?
                ((ifmsg->ifa_family == AF_INET) ?
                 (inet_ntop(ifmsg->ifa_family,
                            ((struct in_addr *) nla_data((struct nlattr*)attrs[IFA_LOCAL])),
                            local_addr_str, INET_ADDRSTRLEN)) :
                 (inet_ntop(ifmsg->ifa_family,
                            ((struct in6_addr *) nla_data((struct nlattr*)attrs[IFA_LOCAL])),
                            local_addr_str, INET6_ADDRSTRLEN))) : "NA"));

    if (attrs[IFA_ADDRESS]!=NULL) {
        size_t addr_len = (ifmsg->ifa_family == AF_INET)?HAL_INET4_LEN:HAL_INET6_LEN;
        hal_ip_addr_t ip;
        memset(&ip, 0, sizeof(ip));
        ip.af_index = ifmsg->ifa_family;
        if (ifmsg->ifa_family == AF_INET) {
            struct in_addr *inp = (struct in_addr *) nla_data((struct nlattr*)attrs[IFA_ADDRESS]);
            std_ip_from_inet(&ip,inp);
            if (nas_os_is_reserved_ipv4(&ip)) {
                EV_LOGGING(NETLINK,ERR,"ROUTE-EVT","IPv4 address ignored - if-index:%d", ifmsg->ifa_index);
                return false;
            }
        } else if (ifmsg->ifa_family == AF_INET6) {
            struct in6_addr *inp6 = (struct in6_addr *) nla_data((struct nlattr*)attrs[IFA_ADDRESS]);
            std_ip_from_inet6(&ip,inp6);
            if (nas_os_is_reserved_ipv6(&ip)) {
                EV_LOGGING(NETLINK,ERR,"ROUTE-EVT","IPv6 address ignored - if-index:%d", ifmsg->ifa_index);
                return false;
            }
        }
        cps_api_attr_id_t ids[1] = {_ipmap.at(ifmsg->ifa_family).at(ADDRESS)};
        cps_api_object_e_add(obj, ids, 1, cps_api_object_ATTR_T_BIN,
                             (const void *)(nla_data(attrs[IFA_ADDRESS])),addr_len);
    }

    if(attrs[IFA_LABEL]!=NULL) {
      rta_add_name(attrs[IFA_LABEL], obj, _ipmap.at(ifmsg->ifa_family).at(IFNAME));
    }

    int ifa_flags = 0;
    if ((attrs[IFA_FLAGS]) && (ifmsg->ifa_family == AF_INET6)) {
        ifa_flags = *(int *)nla_data((struct nlattr*)attrs[IFA_FLAGS]);
        if (ifa_flags & IFA_F_DADFAILED) {
            cps_api_object_attr_add_u32(obj, _ipmap.at(ifmsg->ifa_family).at(DAD_FAILED),
                                        true);
        }
        /* Set the flag if the IPv6 address is created dynamically. */
        if (ifa_flags & IFA_F_MANAGETEMPADDR) {
            cps_api_object_attr_add_u32(obj, _ipmap.at(ifmsg->ifa_family).at(AUTOCONF_ADDR),
                                        true);
        }
    }
    if (rt_msg_type == RTM_NEWADDR)  {
        cps_api_object_set_type_operation(cps_api_object_key(obj),cps_api_oper_CREATE);
    } else if (rt_msg_type == RTM_DELADDR)  {
        cps_api_object_set_type_operation(cps_api_object_key(obj),cps_api_oper_DELETE);
    } else {
        cps_api_object_set_type_operation(cps_api_object_key(obj),cps_api_oper_SET);
    }

    if (ifmsg->ifa_family == AF_INET6) {
        char intf_name[HAL_IF_NAME_SZ+1];
        if (nas_os_util_int_if_name_get(vrf_name, ifmsg->ifa_index, intf_name) != STD_ERR_OK) {
            EV_LOGGING(NAS_OS, ERR, "IP-PUB",
                       "Interface %d to if_name from OS returned error",
                       ifmsg->ifa_index);
            if (rt_msg_type == RTM_DELADDR)  {
                /* @@TODO Once the local intf cache supports intf-index to intf-name get, fill the below attributes,
                 * in case of intf. del, this util which gets the intf-name from kernel fails,
                 * and the IP addr del pub is ignored here, for now, allow it. */
                return true;
            }
            return false;
        }

        if(attrs[IFA_LABEL] == NULL) {
            /* If interface name is not present in the netlink data,
             * fetch the interface name from internal DB and fill it in the CPS object.*/
            cps_api_object_attr_add(obj, _ipmap.at(ifmsg->ifa_family).at(IFNAME),
                                    (const void *)intf_name, strlen(intf_name)+1);
        }
        if (ifa_flags & IFA_F_DADFAILED) {
            int ipv6_enabled = 0;
            /* If DAD failed, get the IPv6 status from kernel and update it in the CPS object.
             * if accept-dad= enable-dad-disable-ipv6-oper and MAC based duplicate LLA is found,
             * kernel changes the IPv6 status to disabled automatically, this should be notified
             * to the App to take appropriate action */
            if (nas_os_read_ipv6_status(vrf_name, intf_name, &ipv6_enabled) == STD_ERR_OK) {
                cps_api_object_attr_add_u32(obj, _ipmap.at(ifmsg->ifa_family).at(ENABLED),
                                            ipv6_enabled);
            } else {
                EV_LOGGING(NAS_OS,ERR,"NAS-IP","IPv6 status read for the vrf-name:%s intf:%s failed!",
                           vrf_name, intf_name);
            }
        }
    }
    return true;
}

/* This function handles the netconf netlink messages from the kernel and constructs
 * the CPS object with the if-index and fwd attributes */
extern "C" bool nl_get_ip_netconf_info (int rt_msg_type, struct nlmsghdr *hdr, cps_api_object_t obj, void *context,
                                        uint32_t vrf_id) {
    struct rtattr   *rtatp = NULL;
    struct netconfmsg *ncmsg = (struct netconfmsg*)NLMSG_DATA(hdr);
    typedef enum { IP_KEY, IFINDEX, FWD, VRFNAME } attr_t ;
    static const std::map<uint32_t, std::map<int,cps_api_attr_id_t>> _ipmap = {
        {AF_INET,
            {
                {IP_KEY,  BASE_IP_IPV4_OBJ},
                {IFINDEX, BASE_IP_IPV4_IFINDEX},
                {FWD,     BASE_IP_IPV4_FORWARDING},
                {VRFNAME, BASE_IP_IPV4_VRF_NAME}
            }},

        {AF_INET6,
            {
                {IP_KEY,  BASE_IP_IPV6_OBJ},
                {IFINDEX, BASE_IP_IPV6_IFINDEX},
                {FWD,     BASE_IP_IPV6_FORWARDING},
                {VRFNAME, BASE_IP_IPV6_VRF_NAME}
            }}
    };
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),_ipmap.at(ncmsg->ncm_family).at(IP_KEY),
                                    cps_api_qualifier_TARGET);
    /* Get the VRF name from vrf-id */
    const char *vrf_name = nas_os_get_vrf_name(vrf_id);
    if (vrf_name == NULL) {
        return false;
    }

    cps_api_object_attr_add(obj, _ipmap.at(ncmsg->ncm_family).at(VRFNAME), (char*)vrf_name,
                            strlen((char*)vrf_name)+1);

    unsigned int attrlen = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*ncmsg));

    rtatp = ((struct rtattr*)(((char*)(ncmsg)) + NLMSG_ALIGN(sizeof(struct netconfmsg))));
    int if_index = 0;
    int forward = 0;
    bool is_if_index_set = false, is_fwd_set = false;
    for (; RTA_OK(rtatp, attrlen); rtatp = RTA_NEXT (rtatp, attrlen)) {
        if(rtatp->rta_type == NETCONFA_IFINDEX) {
            if_index = *(int *)nla_data((struct nlattr*)rtatp);
            if ((if_index == NETCONFA_IFINDEX_ALL) ||
                (if_index == NETCONFA_IFINDEX_DEFAULT)) {
                /* If the forwarding mode setting to be applied on default/all interfaces,
                 * set the if-index to 0*/
                if_index = 0;
            }
            is_if_index_set = true;
        }
        else if(rtatp->rta_type == NETCONFA_FORWARDING) {
            forward = *(int *)nla_data((struct nlattr*)rtatp);
            is_fwd_set = true;
        }
    }
    if ((is_if_index_set == false) || (is_fwd_set == false)) {
        /* intf or fwd attributes are present in the netlink msg, ignore the publish */
        EV_LOGGING(NETLINK, INFO,"NETLINK","NETCONF msg type:%d family:%d if-index:%d fwd:%d",
                   rt_msg_type, ncmsg->ncm_family, if_index, forward);
        return false;
    }
    EV_LOGGING(NETLINK, INFO,"NETLINK","NETCONF msg type:%d family:%d if-index:%d "
               "fwd:%d global ipv4:%d ipv6:%d",
               rt_msg_type, ncmsg->ncm_family, if_index, forward,
               is_global_ipv4_fwd_enable, is_global_ipv6_fwd_enable);
    if (if_index == 0) {
        /* Store the global forwarding status so that the same status
         * on individual interface netlink per intf can be avoided */
        if (ncmsg->ncm_family == AF_INET) {
            /* Ignore duplicate updates */
            if (is_global_ipv4_fwd_enable == forward)
                return false;

            is_global_ipv4_fwd_enable = forward ? true : false;
        }
        else if (ncmsg->ncm_family == AF_INET6) {
            /* Ignore duplicate updates */
            if (is_global_ipv6_fwd_enable == forward)
                return false;

            is_global_ipv6_fwd_enable = forward ? true : false;
        }
    } else if ((is_global_ipv4_fwd_enable && forward) ||
               ((is_global_ipv4_fwd_enable == false) && (forward == false))) {
        return false;
    }

    if (if_index != 0) {
        char intf_name[HAL_IF_NAME_SZ+1];
        if(cps_api_interface_if_index_to_name(if_index, intf_name,
                                              sizeof(intf_name))!=NULL) {
            /* @@TODO Enhance NAS-linux to Skip linux sub interfaces */
            if (strstr(intf_name,".")) {
                EV_LOGGING(NETLINK,DEBUG,"NAS-LINUX-INTERFACE", "Linux sub-intf:%s ignored!",
                           intf_name);
                return false;
            }

            if (nas_rt_is_reserved_intf(intf_name))
                return false;
        }
    }
    EV_LOGGING(NETLINK, INFO,"NETLINK","NETCONF msg type:%d family:%d if-index:%d fwd:%d",
               rt_msg_type, ncmsg->ncm_family, if_index, forward);
    cps_api_set_key_data(obj,_ipmap.at(ncmsg->ncm_family).at(IFINDEX), cps_api_object_ATTR_T_U32,
                         &if_index, sizeof(if_index));

    cps_api_object_attr_add_u32(obj, _ipmap.at(ncmsg->ncm_family).at(FWD), forward);

    return true;
}

bool nl_netconf_get_all_request(int sock, int family,int req_id) {
    struct netconfmsg   ncm;
    memset(&ncm,0,sizeof(ncm));
    ncm.ncm_family = family;
    return nl_send_request(sock,RTM_GETNETCONF, NLM_F_ROOT| NLM_F_DUMP|NLM_F_REQUEST,
                           req_id,&ncm,sizeof(ncm));
}

