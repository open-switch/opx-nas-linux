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
#include "nas_os_int_utils.h"

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

extern "C" t_std_error nas_os_read_ipv6_status(char *name, int *ipv6_status) {
    const std::string NETCONF_IPV6_CONF = "/proc/sys/net/ipv6/conf/";

    std::string disabled_ipv6 = NETCONF_IPV6_CONF + std::string(name) + "/disable_ipv6";
    FILE *fp = fopen(disabled_ipv6.c_str(),"r");
    if(fp){
        int ret = fscanf(fp, "%d",ipv6_status);
        /*If data read from file returned not 1 (the no. of argument read), return failure */
        if (ret != 1) {
            fclose(fp);
            return (STD_ERR(NAS_OS,FAIL, 0));
        }

        /* ipv6_status now reflects the disable_ipv6 status,
         * so, to get the IPv6 enabled do the following. */
        if (*ipv6_status)
            *ipv6_status = false;
        else
            *ipv6_status = true;

        fclose(fp);
        return STD_ERR_OK;
    }
    return (STD_ERR(NAS_OS,FAIL, 0));
}
/* @@TODO This is the work-around to flush the associated neighbors
 * for a given subnet during following scenarios as kernel doesn't delete it.
 * 1) IPv6 address delete
 * 2) IPv4/IPv6 route delete
 */
extern "C" t_std_error nas_os_flush_ip_neigh(char *prefix, uint32_t prefix_len, bool is_intf_flush, char *dev) {
    /* This function builds the following linux command for IP neigh flush
     * ip neigh flush to <prefix> [dev <intf>] e.g ip neigh flush to 2222::1/64 dev br200 */
    std::stringstream str_stream;

    if (is_intf_flush)
        str_stream << "ip neigh flush to " << prefix << "/" << prefix_len << " dev " << dev;
    else
        str_stream << "ip neigh flush to " << prefix << "/" << prefix_len;

    std::string neigh_flush_cmd = str_stream.str();
    if(system(neigh_flush_cmd.c_str()) != 0) {
        EV_LOGGING(NAS_OS, ERR, "NEIGH-UPD", "cmd:%s failed", neigh_flush_cmd.c_str());
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    EV_LOGGING(NAS_OS, INFO, "NEIGH-UPD", "cmd:%s success", neigh_flush_cmd.c_str());
    return STD_ERR_OK;
}

extern "C" bool nl_get_ip_info (int rt_msg_type, struct nlmsghdr *hdr, cps_api_object_t obj, void *context) {

    struct ifaddrmsg *ifmsg = (struct ifaddrmsg *)NLMSG_DATA(hdr);

    if(hdr->nlmsg_len < NLMSG_LENGTH(sizeof(*ifmsg)))
        return false;

    typedef enum { IP_KEY, IFINDEX, PREFIX, ADDRESS, IFNAME, VRFNAME, DAD_FAILED, ENABLED } attr_t ;
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
        {ENABLED, BASE_IP_IPV6_ENABLED}
      }}
    };

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),_ipmap.at(ifmsg->ifa_family).at(IP_KEY),
                                    cps_api_qualifier_OBSERVED);

    cps_api_set_key_data(obj,_ipmap.at(ifmsg->ifa_family).at(IFINDEX), cps_api_object_ATTR_T_U32,
                         &ifmsg->ifa_index,sizeof(ifmsg->ifa_index));
    if (context) {
        cps_api_object_attr_add(obj, _ipmap.at(ifmsg->ifa_family).at(VRFNAME), (char*)context,
                                strlen((char*)context)+1);
    }
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
    EV_LOGGING(NAS_OS,INFO,"NAS-OS-IP", "Operation:%s(%d) VRF:%s flags:0x%x if-index:%s(%d) IP:%s/%d",
               ((rt_msg_type == RTM_NEWADDR) ? "Add" : ((rt_msg_type == RTM_DELADDR) ? "Del" : "Set")),
               rt_msg_type, (char*)context,
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
                            addr_str, INET6_ADDRSTRLEN))) : "NA"), ifmsg->ifa_prefixlen);


    if(attrs[IFA_ADDRESS]!=NULL) {
        size_t addr_len = (ifmsg->ifa_family == AF_INET)?HAL_INET4_LEN:HAL_INET6_LEN;
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
        if (nas_os_util_int_if_name_get((char*)context, ifmsg->ifa_index, intf_name) != STD_ERR_OK) {
            EV_LOGGING(NAS_OS, ERR, "IP-PUB",
                       "Interface %d to if_name from OS returned error",
                       ifmsg->ifa_index);
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
            if (nas_os_read_ipv6_status(intf_name, &ipv6_enabled) == STD_ERR_OK) {
                cps_api_object_attr_add_u32(obj, _ipmap.at(ifmsg->ifa_family).at(ENABLED),
                                            ipv6_enabled);
            } else {
                EV_LOGGING(NAS_OS,ERR,"NAS-IP","IPv6 status read for the intf:%s failed!", intf_name);
            }
        }
        if (rt_msg_type == RTM_DELADDR) {
            /* @@TODO This is the work-around to flush the associated neighbors on IPv6 address del
             * until kernel supports it internally */
            char addr_str[INET6_ADDRSTRLEN];
            if (inet_ntop(ifmsg->ifa_family, (const void *)(nla_data(attrs[IFA_ADDRESS])), addr_str,
                          INET6_ADDRSTRLEN) == NULL) {
                EV_LOGGING(NAS_OS,ERR,"NAS-IP","IP address get failed for intf:%d ",ifmsg->ifa_index);
                return true;
            }

            nas_os_flush_ip_neigh(addr_str, ifmsg->ifa_prefixlen, true, intf_name);
        }
    }
    return true;
}

/* This function handles the netconf netlink messages from the kernel and constructs
 * the CPS object with the if-index and fwd attributes */
extern "C" bool nl_get_ip_netconf_info (int rt_msg_type, struct nlmsghdr *hdr, cps_api_object_t obj, void *context) {
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
    if (context) {
        cps_api_object_attr_add(obj, _ipmap.at(ncmsg->ncm_family).at(VRFNAME), (char*)context,
                                strlen((char*)context)+1);
    }

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


