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

#include "nas_nlmsg_object_utils.h"
#include "standard_netlink_requests.h"

#include <map>
#include <sstream>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <linux/netconf.h>

/* This provides the global IP forwarding status */
static bool is_global_ipv4_fwd_enable = true;
static bool is_global_ipv6_fwd_enable = true;
/* @@TODO This is the work-around to flush the associated neighbors on IPv6 address del
 * until kernel supports it internally */
bool nas_os_flush_ip6_neigh(char *prefix, uint32_t prefix_len, char *dev) {
    /* This function builds the following linux command for IP neigh flush
     * ip neigh flush to <prefix> dev <intf> e.g ip neigh flush to 2222::1/64 dev br200 */
    std::stringstream str_stream;

    str_stream << "ip neigh flush to " << prefix << "/" << prefix_len << " dev " << dev;
    std::string neigh_flush_cmd = str_stream.str();
    if(system(neigh_flush_cmd.c_str()) != 0) {
        EV_LOGGING(NAS_OS, ERR, "NEIGH-UPD", "cmd:%s failed", neigh_flush_cmd.c_str());
        return false;
    }
    EV_LOGGING(NAS_OS, INFO, "NEIGH-UPD", "cmd:%s success", neigh_flush_cmd.c_str());
    return true;
}

extern "C" bool nl_get_ip_info (int rt_msg_type, struct nlmsghdr *hdr, cps_api_object_t obj) {

    struct ifaddrmsg *ifmsg = (struct ifaddrmsg *)NLMSG_DATA(hdr);

    if(hdr->nlmsg_len < NLMSG_LENGTH(sizeof(*ifmsg)))
        return false;

    typedef enum { IP_KEY, IFINDEX, PREFIX, ADDRESS, IFNAME } attr_t ;
    static const std::map<uint32_t, std::map<int,cps_api_attr_id_t>> _ipmap = {
      {AF_INET,
      {
        {IP_KEY,  BASE_IP_IPV4_OBJ},
        {IFINDEX, BASE_IP_IPV4_IFINDEX},
        {PREFIX,  BASE_IP_IPV4_ADDRESS_PREFIX_LENGTH},
        {ADDRESS, BASE_IP_IPV4_ADDRESS_IP},
        {IFNAME,  BASE_IP_IPV4_NAME}
      }},

      {AF_INET6,
      {
        {IP_KEY,  BASE_IP_IPV6_OBJ},
        {IFINDEX, BASE_IP_IPV6_IFINDEX},
        {PREFIX,  BASE_IP_IPV6_ADDRESS_PREFIX_LENGTH},
        {ADDRESS, BASE_IP_IPV6_ADDRESS_IP},
        {IFNAME,  BASE_IP_IPV6_NAME}
      }}
    };

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),_ipmap.at(ifmsg->ifa_family).at(IP_KEY),
                                    cps_api_qualifier_TARGET);

    cps_api_set_key_data(obj,_ipmap.at(ifmsg->ifa_family).at(IFINDEX), cps_api_object_ATTR_T_U32,
                         &ifmsg->ifa_index,sizeof(ifmsg->ifa_index));

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

    if(attrs[IFA_ADDRESS]!=NULL) {
        size_t addr_len = (ifmsg->ifa_family == AF_INET)?HAL_INET4_LEN:HAL_INET6_LEN;
        cps_api_attr_id_t ids[1] = {_ipmap.at(ifmsg->ifa_family).at(ADDRESS)};
        cps_api_object_e_add(obj, ids, 1, cps_api_object_ATTR_T_BIN,
                             (const void *)(nla_data(attrs[IFA_ADDRESS])),addr_len);
    }

    if(attrs[IFA_LABEL]!=NULL) {
      rta_add_name(attrs[IFA_LABEL], obj, _ipmap.at(ifmsg->ifa_family).at(IFNAME));
    }


    if (rt_msg_type == RTM_NEWADDR)  {
        cps_api_object_set_type_operation(cps_api_object_key(obj),cps_api_oper_CREATE);
    } else if (rt_msg_type == RTM_DELADDR)  {
        cps_api_object_set_type_operation(cps_api_object_key(obj),cps_api_oper_DELETE);
    } else {
        cps_api_object_set_type_operation(cps_api_object_key(obj),cps_api_oper_SET);
    }

    if ((ifmsg->ifa_family == AF_INET6) && (rt_msg_type == RTM_DELADDR)) {
        /* @@TODO This is the work-around to flush the associated neighbors on IPv6 address del
         * until kernel supports it internally */
        char addr_str[INET6_ADDRSTRLEN];
        if (inet_ntop(ifmsg->ifa_family, (const void *)(nla_data(attrs[IFA_ADDRESS])), addr_str,
                      INET6_ADDRSTRLEN) == NULL) {
            EV_LOGGING(NAS_OS,ERR,"NAS-IP","IP address get failed for intf:%d ",ifmsg->ifa_index);
            return true;
        }
        char intf_name[HAL_IF_NAME_SZ+1];
        if(cps_api_interface_if_index_to_name(ifmsg->ifa_index,intf_name,sizeof(intf_name))==NULL){
            EV_LOGGING(NAS_OS,INFO,"NAS-LINUX-INTERFACE","Invalid Interface Index %d ",ifmsg->ifa_index);
            return true;
        }

        nas_os_flush_ip6_neigh(addr_str, ifmsg->ifa_prefixlen, intf_name);
    }
    return true;
}

/* This function handles the netconf netlink messages from the kernel and constructs
 * the CPS object with the if-index and fwd attributes */
extern "C" bool nl_get_ip_netconf_info (int rt_msg_type, struct nlmsghdr *hdr, cps_api_object_t obj) {
    struct rtattr   *rtatp = NULL;
    struct netconfmsg *ncmsg = (struct netconfmsg*)NLMSG_DATA(hdr);
    typedef enum { IP_KEY, IFINDEX, FWD } attr_t ;
    static const std::map<uint32_t, std::map<int,cps_api_attr_id_t>> _ipmap = {
        {AF_INET,
            {
                {IP_KEY,  BASE_IP_IPV4_OBJ},
                {IFINDEX, BASE_IP_IPV4_IFINDEX},
                {FWD,     BASE_IP_IPV4_FORWARDING}
            }},

        {AF_INET6,
            {
                {IP_KEY,  BASE_IP_IPV6_OBJ},
                {IFINDEX, BASE_IP_IPV6_IFINDEX},
                {FWD,     BASE_IP_IPV6_FORWARDING}
            }}
    };
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),_ipmap.at(ncmsg->ncm_family).at(IP_KEY),
                                    cps_api_qualifier_TARGET);

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


