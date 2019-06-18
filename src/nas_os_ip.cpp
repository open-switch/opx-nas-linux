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
#include "std_utils.h"
#include "std_time_tools.h"

#include <map>
#include <sstream>
#include <unordered_set>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <linux/netconf.h>

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

/* This provides the global IP forwarding status */
static bool is_global_ipv4_fwd_enable = true;
static bool is_global_ipv6_fwd_enable = true;

/* Store the IP address to detect and ignore the duplicate IP events from OS. */
typedef struct ip_addr_key_t_ {
    uint32_t vrf_id;
    uint32_t if_index;
    std::string ip_addr;
    bool operator== (const ip_addr_key_t_& key) const
    {
        if ((vrf_id == key.vrf_id) &&
            (if_index == key.if_index) &&
            (ip_addr == key.ip_addr)) {
            return true;
        }
        return false;
    }
}ip_addr_key_t;

typedef struct ip_addr_key_hash_t_ {
    std::size_t operator() (ip_addr_key_t const& key) const
    {
        std::size_t vrf_hash = std::hash<std::string>() (std::to_string(key.vrf_id));
        std::size_t if_index_hash = std::hash<std::string>() (std::to_string(key.if_index));
        std::size_t ip_hash = std::hash<std::string>() (key.ip_addr);
        return (vrf_hash ^ if_index_hash ^ ip_hash);
    }
}ip_addr_key_hash_t;

/* This map is used to store the IP address */
using nas_os_ip_addr_map_t = std::unordered_set<ip_addr_key_t, ip_addr_key_hash_t>;
static nas_os_ip_addr_map_t nas_os_ip_addr_map;

std::string nas_os_ip_addr_string (const hal_ip_addr_t& ip)
{
    char buff[INET6_ADDRSTRLEN + 1];
    return(std_ip_to_string(&ip, buff, INET6_ADDRSTRLEN));
}

/* Store the IP address and check if there is any duplicate IP, if yes, return dup flag */
static void nas_os_handle_dynamic_ipv6_addr(uint32_t vrf_id, bool is_del, uint32_t if_index,
                                            hal_ip_addr_t &ip_addr, bool &is_dup)
{
    ip_addr_key_t key;

    key.vrf_id = vrf_id;
    key.if_index = if_index;
    key.ip_addr = nas_os_ip_addr_string(ip_addr);

    auto ip_addr_itr = nas_os_ip_addr_map.find(key);

    if (ip_addr_itr == nas_os_ip_addr_map.end()) {
        if (is_del == false) {
            EV_LOGGING(NETLINK,DEBUG,"NAS-IP","IP added in the list");
            nas_os_ip_addr_map.emplace(key);
        } else {
            EV_LOGGING(NETLINK,DEBUG,"NAS-IP","IP not preset in the list");
        }
    } else {
        if (is_del) {
            EV_LOGGING(NETLINK,DEBUG,"NAS-IP","IP deleted from the list");
            nas_os_ip_addr_map.erase(ip_addr_itr);
        } else {
            EV_LOGGING(NETLINK,DEBUG,"NAS-IP","Duplicate IP detected!");
            is_dup = true;
        }
    }
}

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

typedef enum { IP_KEY, IFINDEX, PREFIX, ADDRESS, IFNAME, VRFNAME, DAD_FAILED, ENABLED, AUTOCONF_ADDR, VRFID} attr_t ;
static const std::map<uint32_t, std::map<int,cps_api_attr_id_t>> _ipmap = {
    {AF_INET,
        {
            {IP_KEY,  BASE_IP_IPV4_OBJ},
            {IFINDEX, BASE_IP_IPV4_IFINDEX},
            {PREFIX,  BASE_IP_IPV4_ADDRESS_PREFIX_LENGTH},
            {ADDRESS, BASE_IP_IPV4_ADDRESS_IP},
            {IFNAME,  BASE_IP_IPV4_NAME},
            {VRFNAME, BASE_IP_IPV4_VRF_NAME},
            {VRFID, BASE_IP_IPV4_VRF_ID}
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
            {VRFID, BASE_IP_IPV6_VRF_ID},
        }}
};

extern "C" bool nl_get_ip_info (int rt_msg_type, struct nlmsghdr *hdr, cps_api_object_t obj,
                                void *context, uint32_t vrf_id, cps_api_qualifier_t qual) {

    struct ifaddrmsg *ifmsg = (struct ifaddrmsg *)NLMSG_DATA(hdr);

    if(hdr->nlmsg_len < NLMSG_LENGTH(sizeof(*ifmsg)))
        return false;

    /* Ignore the IP events for other than IPv4 and Ipv6 families. */
    if ((ifmsg->ifa_family != AF_INET) && (ifmsg->ifa_family != AF_INET6)) {
        EV_LOGGING(NETLINK,INFO,"NAS-IP","IP events recd for the family:%d", ifmsg->ifa_family);
        return false;
    }

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),_ipmap.at(ifmsg->ifa_family).at(IP_KEY),
                                    qual);

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
    cps_api_object_attr_add_u32(obj, _ipmap.at(ifmsg->ifa_family).at(VRFID), vrf_id);
    cps_api_object_attr_add_u32(obj, _ipmap.at(ifmsg->ifa_family).at(IFINDEX), ifmsg->ifa_index);
    cps_api_object_attr_add_u32(obj, _ipmap.at(ifmsg->ifa_family).at(PREFIX), ifmsg->ifa_prefixlen);

    int nla_len = nlmsg_attrlen(hdr,sizeof(*ifmsg));
    struct nlattr *head = nlmsg_attrdata(hdr, sizeof(struct ifaddrmsg));

    struct nlattr *attrs[__IFLA_MAX];
    memset(attrs,0,sizeof(attrs));

    if (nla_parse(attrs,__IFLA_MAX,head,nla_len)!=0) {
        EV_LOGGING(NETLINK,ERR,"IP-NL-PARSE","Failed to parse attributes");
        return false;
    }
    char            addr_str[INET6_ADDRSTRLEN];
    char            local_addr_str[INET6_ADDRSTRLEN];
    EV_LOGGING(NETLINK,INFO,"NAS-OS-IP", "Operation:%s(%d) VRF:%s(%d) flags:0x%x if-index:%s(%d) IP:%s/%d if-flags:0x%x scope:%d local:%s",
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

    hal_ip_addr_t ip;
    memset(&ip, 0, sizeof(ip));
    if (attrs[IFA_ADDRESS]!=NULL) {
        size_t addr_len = (ifmsg->ifa_family == AF_INET)?HAL_INET4_LEN:HAL_INET6_LEN;
        ip.af_index = ifmsg->ifa_family;
        if (ifmsg->ifa_family == AF_INET) {
            struct in_addr *inp = (struct in_addr *) nla_data((struct nlattr*)attrs[IFA_ADDRESS]);
            std_ip_from_inet(&ip,inp);
            if (nas_os_is_reserved_ipv4(&ip)) {
                EV_LOGGING(NETLINK,DEBUG,"ROUTE-EVT","IPv4 address ignored - if-index:%d", ifmsg->ifa_index);
                return false;
            }
        } else if (ifmsg->ifa_family == AF_INET6) {
            struct in6_addr *inp6 = (struct in6_addr *) nla_data((struct nlattr*)attrs[IFA_ADDRESS]);
            std_ip_from_inet6(&ip,inp6);
            if (nas_os_is_reserved_ipv6(&ip)) {
                EV_LOGGING(NETLINK,DEBUG,"ROUTE-EVT","IPv6 address ignored - if-index:%d", ifmsg->ifa_index);
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
            /* Duplicate the dynamic ipv6 address publish */
            bool is_dup = false, is_del = (rt_msg_type == RTM_DELADDR) ? true : false;
            if ((ip.af_index == AF_INET6) &&
                (is_del || ((ifa_flags & IFA_F_DADFAILED) != IFA_F_DADFAILED))) {
                nas_os_handle_dynamic_ipv6_addr(vrf_id, is_del, ifmsg->ifa_index, ip, is_dup);
                if (is_dup) {
                    return false;
                }
            }
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
            EV_LOGGING(NETLINK, ERR, "IP-PUB",
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
                EV_LOGGING(NETLINK,ERR,"NAS-IP","IPv6 status read for the vrf-name:%s intf:%s failed!",
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

    /* Ignore the netconf events for other than IPv4 and Ipv6 families. */
    if ((ncmsg->ncm_family != AF_INET) && (ncmsg->ncm_family != AF_INET6))
        return false;

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

#define NL_MSG_BUFFER_LEN 9000

static cps_api_return_code_t nas_os_ip_key_info_get(uint32_t family, cps_api_object_t obj,
                          char *vrf_name, uint8_t vrf_name_len, char *if_name, uint8_t if_name_len, uint32_t *if_index)
{
    cps_api_object_attr_t if_name_attr = cps_api_get_key_data(obj, _ipmap.at(family).at(IFNAME));
    cps_api_object_attr_t if_index_attr = cps_api_object_attr_get(obj, _ipmap.at(family).at(IFINDEX));
    cps_api_object_attr_t vrf_attr = cps_api_object_attr_get(obj, _ipmap.at(family).at(VRFNAME));

    if ((if_name_attr == NULL) && (if_index_attr == NULL)) {
        EV_LOGGING(NAS_OS, ERR, "IFADDRESS","No If_name or if-index attr");
        return cps_api_ret_code_ERR;
    }

    if (vrf_attr != NULL)
        safestrncpy(vrf_name, (const char *)cps_api_object_attr_data_bin(vrf_attr), vrf_name_len);
    else
        safestrncpy(vrf_name, NAS_DEFAULT_VRF_NAME, vrf_name_len);

    interface_ctrl_t intf_ctrl;
    t_std_error rc = STD_ERR_OK;

    if (if_name_attr != NULL) {
        safestrncpy(if_name, (const char *)cps_api_object_attr_data_bin(if_name_attr), if_name_len);

        if ((if_index_attr == NULL) || (vrf_attr == NULL)) {
            memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
            intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
            safestrncpy(intf_ctrl.if_name, if_name, sizeof(intf_ctrl.if_name));
            if((rc= dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                EV_LOGGING(NAS_OS, ERR, "IFADDRESS",
                           "Interface %s to if_index returned error %d", intf_ctrl.if_name, rc);
                return cps_api_ret_code_ERR;
            }

            *if_index = intf_ctrl.if_index;

            if (vrf_attr == NULL) {
                if (NAS_DEFAULT_VRF_ID != intf_ctrl.vrf_id)
                   return cps_api_ret_code_ERR;

            }
        }
    } else if (if_index_attr != NULL) {
        *if_index = cps_api_object_attr_data_u32(if_index_attr);
        if (vrf_attr == NULL) {
            memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
            intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
            intf_ctrl.if_index = *if_index;

            if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                EV_LOGGING(NAS_OS, ERR, "IFADDRESS",
                                  "Failed in retrieving intf from cache, "
                                  "if_index:%d", *if_index);
                return cps_api_ret_code_ERR;
            }

            safestrncpy(if_name, intf_ctrl.if_name, if_name_len);

            if (vrf_attr == NULL) {
                if (NAS_DEFAULT_VRF_ID != intf_ctrl.vrf_id)
                    return cps_api_ret_code_ERR;
            }
        }
    }

    return cps_api_ret_code_OK;
}

static bool nas_os_ip_get_broadcast_ip(char *addr, uint32_t prefix_len, char *broadcast_addr)
{
   uint32_t mask = 0;
   uint32_t bcast_addr = 0;

   /* Broadcast domain is not there for /31 and /32 prefix length */
   if (prefix_len >= (HAL_INET4_LEN * 8) - 1){
       return false;
   }

   mask = ((prefix_len) ? ((1 << ((8 * sizeof(uint32_t) - prefix_len))) -1) : 0xffffffff);
   memcpy((char *)&bcast_addr, addr, HAL_INET4_LEN);

   char *ip = (char *)&bcast_addr;
   bcast_addr = (uint32_t)(ip[0] << 24 | ip[1] << 16 | ip[2] << 8 | ip[3])  |  mask;

   for (int i = 0; i < HAL_INET4_LEN ; i++)
       memcpy(&broadcast_addr[i], (char *)&ip[3-i], 1);

   return true;
}

static cps_api_return_code_t nas_os_ip_addr_write_function(cps_api_operation_types_t op, uint32_t family,
                                                         void *context, cps_api_object_t obj)
{
    char      vrf_name[NAS_VRF_NAME_SZ] = {0};
    char      if_name[HAL_IF_NAME_SZ] = {0};
    char      addr_str[INET6_ADDRSTRLEN];
    char      bcast_addr_str[INET6_ADDRSTRLEN];
    uint32_t  if_index = 0;
    char      bcast_addr[HAL_INET4_LEN] = {0};

    if (nas_os_ip_key_info_get (family, obj, vrf_name, sizeof(vrf_name),
        if_name, sizeof(if_name), &if_index) != cps_api_ret_code_OK) {
        EV_LOGGING(NAS_OS, ERR, "IFADDRESS", "Failed in retrieving base-ip key ");
        return cps_api_ret_code_ERR;
    }

    cps_api_object_attr_t pre_len_attr = cps_api_object_attr_get(obj, _ipmap.at(family).at(PREFIX));
    cps_api_object_attr_t ip_attr  = cps_api_get_key_data(obj, _ipmap.at(family).at(ADDRESS));
    if (ip_attr == NULL)
        return cps_api_ret_code_ERR;

    if (pre_len_attr == NULL)
       return cps_api_ret_code_ERR;

    uint32_t prefix_len =  cps_api_object_attr_data_uint(pre_len_attr);
    char  *buff = (char *)malloc(NL_MSG_BUFFER_LEN);

    if (NULL == buff)
       return cps_api_ret_code_ERR;

    memset(buff, 0, NL_MSG_BUFFER_LEN);

    struct nlmsghdr *nlh = (struct nlmsghdr *) nlmsg_reserve((struct nlmsghdr *)buff, NL_MSG_BUFFER_LEN, sizeof(struct nlmsghdr));
    struct ifaddrmsg *ifaddr = (struct ifaddrmsg *) nlmsg_reserve(nlh, NL_MSG_BUFFER_LEN, sizeof(struct ifaddrmsg));

    //sizeof structure + attrs nlh->nlmsg_len
    nlh->nlmsg_pid = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK ;
    nlh->nlmsg_type = RTM_NEWADDR;

    if (op==cps_api_oper_CREATE) {
        nlh->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL | NLM_F_APPEND;
    }
    if (op==cps_api_oper_SET) {
        nlh->nlmsg_flags |=NLM_F_REPLACE;
    }
    if (op==cps_api_oper_DELETE) {
        nlh->nlmsg_type = RTM_DELADDR;
    }

    ifaddr->ifa_family = family;
    ifaddr->ifa_prefixlen = prefix_len;
    ifaddr->ifa_flags = IFA_F_PERMANENT;
    ifaddr->ifa_index = if_index;
    ifaddr->ifa_scope = 0;

    nlmsg_add_attr(nlh, NL_MSG_BUFFER_LEN, IFA_LOCAL, cps_api_object_attr_data_bin(ip_attr), cps_api_object_attr_len(ip_attr));

    if (family == AF_INET) {
        nas_os_ip_get_broadcast_ip((char *)cps_api_object_attr_data_bin(ip_attr), prefix_len, &bcast_addr[0]);
        nlmsg_add_attr(nlh, NL_MSG_BUFFER_LEN, IFA_BROADCAST, &bcast_addr[0], cps_api_object_attr_len(ip_attr));
    }

    EV_LOGGING(NAS_OS, INFO, "IFADDRESS", "IP ADDRESS %s family:%s if_name:%s "
               "vrf %s ip %s bcast_ip %s prefix len %d ",
               (op == cps_api_oper_CREATE ? "ADD" : (op == cps_api_oper_DELETE ? "DEL" : "SET")),
               (family == AF_INET ? "IPv4" : "IPv6"), if_name, vrf_name,
               ((family == AF_INET) ? (inet_ntop(family, cps_api_object_attr_data_bin(ip_attr), addr_str, INET_ADDRSTRLEN)) :
                (inet_ntop(family, cps_api_object_attr_data_bin(ip_attr), addr_str, INET6_ADDRSTRLEN))),
               ((family == AF_INET) ? (inet_ntop(family, &bcast_addr[0], bcast_addr_str, INET_ADDRSTRLEN)) : ("na")),
               prefix_len);

    if (nl_do_set_request(vrf_name, nas_nl_sock_T_ROUTE, nlh, buff, NL_MSG_BUFFER_LEN) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "IFADDRESS", "Failed to set ip address on interface %s", if_name);
        free(buff);
        return cps_api_ret_code_ERR;
    }
    free(buff);
    return cps_api_ret_code_OK;
}

extern "C" bool nl_get_nas_os_ip_info (int sock, int rt_msg_type, struct nlmsghdr *hdr, void *context,
                                       uint32_t vrf_id) {
    struct ifaddrmsg *ifmsg = (struct ifaddrmsg *)NLMSG_DATA(hdr);
    nas_os_ip_info_t *p_ip_info = (nas_os_ip_info_t *)context;

    if(hdr->nlmsg_len < NLMSG_LENGTH(sizeof(*ifmsg))) {
        EV_LOGGING(NAS_OS, ERR, "IFADDRESS","hdr->nlmsg_len:%d", hdr->nlmsg_len);
        return false;
    }

    /* Ignore the IP events for other than IPv4 and Ipv6 families. */
    if ((ifmsg->ifa_family != AF_INET) && (ifmsg->ifa_family != AF_INET6)) {
        EV_LOGGING(NAS_OS, ERR,"IFADDRESS","IP events recd for the family:%d", ifmsg->ifa_family);
        return false;
    }

    EV_LOGGING(NAS_OS, INFO,"IFADDRESS","Get ip keys, family:(in: %d)%d if_index (in: %d)%d vrf_id %d",
               p_ip_info->ip_family, ifmsg->ifa_family,
               p_ip_info->if_index, ifmsg->ifa_index, vrf_id);

    /* Ignore the IP events for other than IPv4 and Ipv6 families. */
    if ((ifmsg->ifa_family != p_ip_info->ip_family) ||
        ((p_ip_info->filter_if_index == true) && (ifmsg->ifa_index != p_ip_info->if_index))) {
        EV_LOGGING(NAS_OS, INFO, "IFADDRESS","Skip. Keys not matched family:(in: %d)%d if_index (in: %d)%d vrf_id %d",
                   p_ip_info->ip_family, ifmsg->ifa_family, p_ip_info->if_index, ifmsg->ifa_index, vrf_id);
        return true;
    }

    cps_api_object_t obj = cps_api_object_create();
    if (obj == NULL) {
        EV_LOGGING(NAS_OS, ERR, "IFADDRESS","Failed to create object");
        return false;
    }

    if (nl_get_ip_info (rt_msg_type, hdr, obj, NULL, vrf_id, cps_api_qualifier_TARGET)) {
        if(cps_api_object_list_append(p_ip_info->param->list, obj) != true) {
            EV_LOGGING(NAS_OS, ERR, "IFADDRESS","Failed to appened object list");
            cps_api_object_delete(obj);
            return false;
        }
    } else {
      cps_api_object_delete(obj);
    }

    return true;
}

/* Read supported
 * - With out any keys - Will return all interfces ip address in all vrf's/
 * - if_name/If_idex with out VRF attribute - VRF is considered as default
 * - if_name/If_dex with non default VRF - VRF attribute is mandatory to get/set ip address
 */
cps_api_return_code_t nas_os_ip_addr_read_function (uint32_t ip_family, void *context,
                                                 cps_api_get_params_t *param,
                                                 size_t ix)
{
    cps_api_object_t in_obj = cps_api_object_list_get(param->filters,ix);

    if (in_obj == NULL)
        return cps_api_ret_code_ERR;

    char     vrf_name[NAS_VRF_NAME_SZ] = {0};
    char     if_name[HAL_IF_NAME_SZ] = {0};
    uint32_t if_index = 0;
    int      sock = 0;
    nas_os_ip_info_t ip_info = {0};
    cps_api_return_code_t ret = cps_api_ret_code_ERR;

    cps_api_object_attr_t vrf_attr = cps_api_object_attr_get(in_obj, _ipmap.at(ip_family).at(VRFNAME));
    cps_api_object_attr_t if_name_attr = cps_api_get_key_data(in_obj, _ipmap.at(ip_family).at(IFNAME));
    cps_api_object_attr_t if_index_attr = cps_api_object_attr_get(in_obj, _ipmap.at(ip_family).at(IFINDEX));


    if (((if_name_attr != NULL) || (if_index_attr != NULL)) &&
        (nas_os_ip_key_info_get (ip_family, in_obj, vrf_name, sizeof(vrf_name), if_name,
         sizeof(if_name), &if_index) != cps_api_ret_code_OK)) {
        EV_LOGGING(NAS_OS, ERR,"IFADDRESS", "BASE IP key not found, Read all interface ip's");
        return cps_api_ret_code_ERR;
    }

    EV_LOGGING(NAS_OS, INFO, "IFADDRESS", "GET IP ADDRESS family:%s if_name:%s vrf_name %s ",
                      (ip_family == AF_INET ? "IPv4" : "IPv6"), if_name, vrf_name);

    uint32_t vrf_id = NAS_DEFAULT_VRF_ID;

    char *buff = (char *)malloc(NL_MSG_BUFFER_LEN);

    if (NULL == buff)
        return cps_api_ret_code_ERR;

    do {
        if ((vrf_attr != NULL) || (if_name_attr != NULL) || (if_index_attr !=NULL)) {
            if (nas_os_get_vrf_id(vrf_name, &vrf_id)) {
                EV_LOGGING(NAS_OS, DEBUG, "IFADDRESS", "VRF-id get for VRF:%s VRF ID %d ",
                           vrf_name, vrf_id);
            } else {
                EV_LOGGING(NAS_OS,ERR,"IFADDRESS", "VRF-id get failed for VRF:%s ", vrf_name);
                ret = cps_api_ret_code_ERR;
                break;
            }
        } else {
            const char *name = nas_os_get_vrf_name(vrf_id);
            if (name == NULL) {
                vrf_id++;
                ret = cps_api_ret_code_OK;
                continue;
            }
            safestrncpy(vrf_name, name, sizeof(vrf_name));
        }

        do {
            if((sock = nas_nl_sock_create(vrf_name, nas_nl_sock_T_ROUTE,false)) < 0) {
                EV_LOGGING(NAS_OS, ERR, "IFADDRESS", "Socket create failure");
                break;
            }

            memset(buff, 0, NL_MSG_BUFFER_LEN);

            struct ifaddrmsg ifaddr;
            memset(&ifaddr,0,sizeof(ifaddrmsg));

            ifaddr.ifa_family = ip_family;
            ifaddr.ifa_index = if_index;

            ip_info.ip_family = ip_family;
            ip_info.if_index = if_index;
            /* TODO - Even after giving the filter NLM_F_MATCH  for family and interface index.
             * net link returns for all interfcaes in family. Filter is done in software now.
             * Revisit codein new linux version */
            if ((if_name_attr != NULL) || (if_index_attr != NULL))
                ip_info.filter_if_index = true;

            ip_info.param = param;

            int seq = (int)std_get_uptime(NULL);

            if (nl_send_request(sock, RTM_GETADDR, (NLM_F_REQUEST | NLM_F_ACK | NLM_F_MATCH),
                                seq, &ifaddr, sizeof(ifaddrmsg))) {
                netlink_tools_process_socket(sock, nl_get_nas_os_ip_info,
                                             (void *)&ip_info, buff, NL_MSG_BUFFER_LEN, &seq, NULL, vrf_id);
            }
            close(sock);
        } while(0);

        vrf_id++;

        ret = cps_api_ret_code_OK;
    } while(((if_name_attr == NULL) && (if_index_attr == NULL) && (vrf_attr == NULL) && (vrf_id <= NAS_MAX_VRF_ID)));

    free(buff);

    return ret;
}

static cps_api_return_code_t nas_os_ipv4_write_function(void * context,
                             cps_api_transaction_params_t * param, size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    if (obj == NULL)
        return cps_api_ret_code_ERR;

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    return nas_os_ip_addr_write_function(op, AF_INET, context,obj);
}

static cps_api_return_code_t nas_os_ipv6_write_function(void * context,
                             cps_api_transaction_params_t * param, size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    if (obj==NULL)
        return cps_api_ret_code_ERR;

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    return nas_os_ip_addr_write_function(op, AF_INET6, context,obj);
}

cps_api_return_code_t nas_os_ipv4_read_function (void * context,
                                               cps_api_get_params_t *param,
                                               size_t ix)
{
    return nas_os_ip_addr_read_function(AF_INET, context, param, ix);
}

cps_api_return_code_t nas_os_ipv6_read_function (void * context,
                                               cps_api_get_params_t *param,
                                               size_t ix)
{
    return nas_os_ip_addr_read_function(AF_INET6, context, param, ix);
}

t_std_error os_ip_addr_object_reg(cps_api_operation_handle_t handle) {

    cps_api_registration_functions_t f;
    cps_api_return_code_t cps_rc = 0;

    memset(&f,0,sizeof(f));
    f.handle = handle;
    f._read_function = nas_os_ipv4_read_function;
    f._write_function = nas_os_ipv4_write_function;

    if (!cps_api_key_from_attr_with_qual(&f.key, BASE_IP_IPV4_ADDRESS, cps_api_qualifier_TARGET)) {
        EV_LOGGING(NAS_OS, ERR, "IFADDRESS", "Cannot create a key for BASE_IP_IPV4_ADDRESS object");
        return STD_ERR(INTERFACE, FAIL, 0);
    } else {
        if ((cps_rc = cps_api_register(&f)) !=cps_api_ret_code_OK) {
            EV_LOGGING(NAS_OS, ERR, "IFADDRESS", "Failed to register callback for BASE_IP_IPV4_ADDRESS object");
            return STD_ERR(QOS, FAIL, cps_rc);
        }
    }

    memset(&f,0,sizeof(f));
    f.handle = handle;
    f._read_function = nas_os_ipv6_read_function;
    f._write_function = nas_os_ipv6_write_function;

    if (!cps_api_key_from_attr_with_qual(&f.key, BASE_IP_IPV6_ADDRESS, cps_api_qualifier_TARGET)) {
        EV_LOGGING(NAS_OS, ERR, "IFADDRESS", "Cannot create a key for BASE_IP_IPV6_ADDRESS object");
        return STD_ERR(INTERFACE, FAIL, 0);
    } else {
        if ((cps_rc = cps_api_register(&f)) !=cps_api_ret_code_OK) {
            EV_LOGGING(NETLINK, ERR, "IFADDRESS", "Failed to register callback for BASE_IP_IPV6_ADDRESS object");
            return STD_ERR(QOS, FAIL, cps_rc);
        }
    }

    return STD_ERR_OK;
}
