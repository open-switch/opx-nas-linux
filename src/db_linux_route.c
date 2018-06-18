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
 * db_linux_route.c
 */
#include "cps_api_route.h"
#include "cps_api_operation.h"
#include "cps_api_interface_types.h"

#include "cps_class_map.h"

#include "dell-base-routing.h"
#include "os-routing-events.h"

#include "standard_netlink_requests.h"
#include "std_error_codes.h"
#include "netlink_tools.h"
#include "event_log.h"
#include "nas_nlmsg.h"
#include "std_ip_utils.h"
#include "nas_nlmsg_object_utils.h"
#include "ds_common_types.h"
#include "ds_api_linux_interface.h"
#include "hal_if_mapping.h"
#include "std_utils.h"
#include "ds_api_linux_route.h"
#include "nas_os_l3_utils.h"

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    int family;
} route_filter_t;

#define NAS_RT_V4_PREFIX_LEN              (8 * HAL_INET4_LEN)
#define NAS_RT_V6_PREFIX_LEN              (8 * HAL_INET6_LEN)

bool nas_rt_is_reserved_intf(char *intf_name) {

    if (intf_name == NULL)
        return false;

    /* Skip eth0 and lo interfaces */
    if ((strncmp(intf_name, "eth", strlen("eth")) == 0) ||
        ((strncmp(intf_name, "lo", strlen("lo")) == 0) &&
         (strlen(intf_name) == strlen("lo")))) {
        return true;
    }

    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(intf_ctrl));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
    safestrncpy(intf_ctrl.if_name, intf_name, HAL_IF_NAME_SZ);

    if (dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
        EV_LOGGING(NETLINK,DEBUG,"NAS-LINUX-INTERFACE", "Interface (%s) not found", intf_name);
        return false;
    }
    if ((intf_ctrl.int_type == nas_int_type_VLAN)
        && (intf_ctrl.int_sub_type == BASE_IF_VLAN_TYPE_MANAGEMENT)) {
        return true;
    }

    return false;
}

/*
 * This function validates the given interface index for following:
 * Checks if its not a linux sub interface (only if input flag is true).
 */
bool nas_rt_is_reserved_intf_idx (unsigned int if_idx, bool sub_intf_check_required) {
    interface_ctrl_t intf_ctrl;

    memset(&intf_ctrl, 0, sizeof(intf_ctrl));

    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.if_index = if_idx;

    if (dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
        /* interface cache in nas is updated based on netlink events,
         * so there is a likely chance that when this is called i/f cache
         * may not be populated. Hence retrieving name from linux
         */
        if(cps_api_interface_if_index_to_name(if_idx, intf_ctrl.if_name,
                                              sizeof(intf_ctrl.if_name)) == NULL) {
            EV_LOGGING(NETLINK,DEBUG,"NAS-LINUX-INTERFACE", "Interface (%d) not found", if_idx);
            return false;
        }
    }
    /* Skip linux sub interfaces if caller asked for it */
    if (sub_intf_check_required && (strchr(intf_ctrl.if_name,'.'))) {
        EV_LOGGING(NETLINK,DEBUG,"NAS-LINUX-INTERFACE", "Linux sub-intf:%s ignored!",
                   intf_ctrl.if_name);
        return true;
    }
    /* Skip lo interface */
    if ((strncmp(intf_ctrl.if_name, "lo", strlen("lo")) == 0) &&
        (strlen(intf_ctrl.if_name) == strlen("lo"))) {
        return true;
    }
    return false;
}

// @TODO - This file has to conform to new yang model

static inline void nas_os_log_route_info(struct nlmsghdr *hdr, int rt_msg_type, struct rtmsg *rtmsg,
                                         struct nlattr **attrs, const char* vrf_name, uint32_t vrf_id) {

    char            addr_str[INET6_ADDRSTRLEN];
    char            addr_str1[INET6_ADDRSTRLEN];

    EV_LOGGING(NETLINK, INFO,"ROUTE-EVENT","NLM type:0x%x flags:0x%x Op:%s VRF:%s(%d) af:%s(%d) Prefix:%s/%d tbl:%d "
               "proto:%d scope:%d type:%d flags:%d multiPath:%s gateway:%s ifx:%d",
               hdr->nlmsg_type,
               hdr->nlmsg_flags,
               ((rt_msg_type == RTM_NEWROUTE) ? "Add" : "Del"), vrf_name, vrf_id,
               ((rtmsg->rtm_family == AF_INET) ? "IPv4" : "IPv6"),
               rtmsg->rtm_family,
               ((attrs[RTA_DST] != NULL) ?
                ((rtmsg->rtm_family == AF_INET) ?
                 (inet_ntop(rtmsg->rtm_family,
                            ((struct in_addr *) nla_data((struct nlattr*)attrs[RTA_DST])),
                            addr_str, INET_ADDRSTRLEN)) :
                 (inet_ntop(rtmsg->rtm_family,
                            ((struct in6_addr *) nla_data((struct nlattr*)attrs[RTA_DST])),
                            addr_str, INET6_ADDRSTRLEN))) : "NA"),
               rtmsg->rtm_dst_len,
               rtmsg->rtm_table,
               rtmsg->rtm_protocol,
               rtmsg->rtm_scope,
               rtmsg->rtm_type,
               rtmsg->rtm_flags,
               ((attrs[RTA_MULTIPATH]) ? "Yes" : "No"),
               ((attrs[RTA_GATEWAY]!=NULL) ?
                ((rtmsg->rtm_family == AF_INET) ?
                 (inet_ntop(rtmsg->rtm_family,
                            ((struct in_addr *) nla_data((struct nlattr*)attrs[RTA_GATEWAY])),
                            addr_str1, INET_ADDRSTRLEN)) :
                 (inet_ntop(rtmsg->rtm_family,
                            ((struct in6_addr *) nla_data((struct nlattr*)attrs[RTA_GATEWAY])),
                            addr_str1, INET6_ADDRSTRLEN))) : "NA"),
               ((attrs[RTA_OIF]!=NULL) ? *((unsigned int *)nla_data(attrs[RTA_OIF])): -1));
}

//db_route_t
bool nl_to_route_info(int rt_msg_type, struct nlmsghdr *hdr, cps_api_object_t obj, void *context, uint32_t vrf_id) {

    struct rtmsg    *rtmsg = (struct rtmsg *)NLMSG_DATA(hdr);
    char            addr_str[INET6_ADDRSTRLEN];

    if(hdr->nlmsg_len < NLMSG_LENGTH(sizeof(*rtmsg)))
        return false;

    if ((rtmsg->rtm_family != AF_INET) && (rtmsg->rtm_family != AF_INET6))
        return false;

    /* Ignore the unspecified route table updates, once the L3MDEV based VRF is supported,
     * check for RTA_TABLE presence in the msg if the rtm_table is RT_TABLE_UNSPEC,
     * if the above check fails, skip the netlink route update from kernel. */
    if (rtmsg->rtm_table == RT_TABLE_UNSPEC) {
        EV_LOGGING(NETLINK,DEBUG,"NL-ROUTE-PARSE","Invalid route table:%d ", rtmsg->rtm_table);
        return false;
    }

    cps_api_operation_types_t op;
    if(rt_msg_type == RTM_NEWROUTE) {
        /* NETLINK Header flags if received with NLM_F_REPLACE, send it as ROUTE_UPD instead of ROUTE_ADD */
        if (hdr->nlmsg_flags & NLM_F_REPLACE) {
            op = cps_api_oper_SET;
        } else {
            op = cps_api_oper_CREATE;
        }
    } else if(rt_msg_type == RTM_DELROUTE) {
        op = cps_api_oper_DELETE;
    } else {
        return false;
    }
    /* Get VRF name from VRF-id */
    const char *vrf_name = nas_os_get_vrf_name(vrf_id);
    if (vrf_name == NULL) {
        return false;
    }
    cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_VRF_NAME, vrf_name, strlen(vrf_name)+1);
    /* @@TODO all route netlink events expected to have the same VRF-name for both route and NH
     * since leaked routes are not programmed into the kernel for now. */
    cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_ENTRY_NH_VRF_NAME, vrf_name, strlen(vrf_name)+1);
    cps_api_object_attr_add_u32(obj, BASE_ROUTE_OBJ_VRF_ID, vrf_id);
    /* @@TODO all route netlink events expected to have the same VRF-id for both route and NH
     * since leaked routes are not programmed into the kernel for now. */
    cps_api_object_attr_add_u32(obj, BASE_ROUTE_OBJ_ENTRY_VRF_ID, vrf_id);
    cps_api_object_attr_add_u32(obj, BASE_ROUTE_OBJ_ENTRY_AF, rtmsg->rtm_family);
    cps_api_object_attr_add_u32(obj, BASE_ROUTE_OBJ_ENTRY_PROTOCOL, rtmsg->rtm_protocol);

    int attr_len = nlmsg_attrlen(hdr,sizeof(*rtmsg));
    struct nlattr *head = nlmsg_attrdata(hdr, sizeof(struct rtmsg));

    struct nlattr *attrs[__IFLA_MAX];
    memset(attrs,0,sizeof(attrs));

    if (nla_parse(attrs,__IFLA_MAX,head,attr_len)!=0) {
        EV_LOGGING(NETLINK,ERR,"NL-ROUTE-PARSE","Failed to parse attributes");
        return false;
    }

    if(attrs[RTA_DST]!=NULL) {
        /* Ignore the link local route here, we program the link local self IPv6
         * into the NPU thru IPv6 address publish flow */
        if (rtmsg->rtm_family == AF_INET6) {
            hal_ip_addr_t ip;
            struct in6_addr *inp6 = (struct in6_addr *) nla_data((struct nlattr*)attrs[RTA_DST]);
            std_ip_from_inet6(&ip,inp6);
            if (STD_IP_IS_ADDR_LINK_LOCAL(&ip)) {
                EV_LOGGING(NETLINK,DEBUG,"NL-ROUTE-PARSE","LLA skipped!");
                return false;
            }
        }

        cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,
                                nla_data((struct nlattr*)attrs[RTA_DST]),
                                nla_len((struct nlattr*)attrs[RTA_DST]));
    }
    nas_os_log_route_info(hdr,rt_msg_type, rtmsg, attrs, vrf_name, vrf_id);
    /* If the route is not local/unicast, dont handle it.
     * RTN_UNICAST - 1, RTN_LOCAL - 2
     * @@TODO see if some other route types to be supported */
    if ((rtmsg->rtm_type != RTN_UNICAST) && (rtmsg->rtm_type != RTN_LOCAL) &&
        (rtmsg->rtm_type != RTN_BLACKHOLE) && (rtmsg->rtm_type != RTN_UNREACHABLE) &&
        (rtmsg->rtm_type != RTN_PROHIBIT)) {
        EV_LOGGING(NETLINK,DEBUG,"NL-ROUTE-PARSE","Invalid route type:%d ", rtmsg->rtm_type);
        return false;
    }

    /* Ignore the local IP route programming into the NPU
     * since the IP subnet is good enough to punt the packets to CPU */
    if ((rtmsg->rtm_type == RTN_LOCAL) && (attrs[RTA_GATEWAY] == NULL) && (attrs[RTA_MULTIPATH] == NULL) &&
        (((rtmsg->rtm_family == AF_INET) && (rtmsg->rtm_dst_len == NAS_RT_V4_PREFIX_LEN)
          && (rtmsg->rtm_protocol == RTPROT_KERNEL)) ||
         ((rtmsg->rtm_family == AF_INET6) && (rtmsg->rtm_dst_len == NAS_RT_V6_PREFIX_LEN)
          && (rtmsg->rtm_protocol == RTPROT_UNSPEC)))) {
        char addr_str[INET6_ADDRSTRLEN];
        EV_LOGGING(NETLINK, INFO, "NL-ROUTE-PARSE", "Self IP route ignored, family:%d protocol:%d op:%s route:%s/%d",
                   rtmsg->rtm_family, rtmsg->rtm_protocol,
                   ((rt_msg_type == RTM_NEWROUTE) ? "Add" : "Del"),
                   ((attrs[RTA_DST] != NULL) ?
                    ((rtmsg->rtm_family == AF_INET) ?
                     (inet_ntop(rtmsg->rtm_family,
                                ((struct in_addr *) nla_data((struct nlattr*)attrs[RTA_DST])),
                                addr_str, INET_ADDRSTRLEN)) :
                     (inet_ntop(rtmsg->rtm_family,
                                ((struct in6_addr *) nla_data((struct nlattr*)attrs[RTA_DST])),
                                addr_str, INET6_ADDRSTRLEN))) : "NA"),
                   rtmsg->rtm_dst_len);

        return false;
    }
    /* @@TODO for IPv6 routes we should not program the invalid route into the NPU i.e
     * For 2::1/64 configurations, kernel generates three routes 1. 2::1/64 2. 2::1/128 3. 2::/128
     * We have to ignore the 2::/128 since it's of no use, but now not able
     * to differentiate the routes 2. and 3. with the netlink flags, to be explored further */

    if((rtmsg->rtm_flags & RTM_F_CLONED) && (rtmsg->rtm_family == AF_INET6)) {
        // Skip cloned route updates
        EV_LOGGING(NETLINK,DEBUG,"ROUTE-EVENT","Cache entry %s",
                (attrs[RTA_DST]!=NULL)?(inet_ntop(rtmsg->rtm_family,
                ((struct in6_addr *) nla_data((struct nlattr*)attrs[RTA_DST])),
                addr_str, INET6_ADDRSTRLEN)):"");
        return false;
    }

    cps_api_object_attr_add_u32(obj, BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN, rtmsg->rtm_dst_len);
    switch(rtmsg->rtm_type) {
        case RTN_BLACKHOLE:
        case RTN_UNREACHABLE:
        case RTN_PROHIBIT:
        case RTN_LOCAL:
            cps_api_object_attr_add_u32(obj, BASE_ROUTE_OBJ_ENTRY_SPECIAL_NEXT_HOP, rtmsg->rtm_type);
            break;
    }
    size_t hop_count = 0;

    cps_api_attr_id_t ids[3];

    const int ids_len = sizeof(ids)/sizeof(*ids);
    ids[0] = BASE_ROUTE_OBJ_ENTRY_NH_LIST;
    ids[1] = hop_count;

    if (attrs[RTA_GATEWAY]!=NULL) {
        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR;
        cps_api_object_e_add(obj, ids, ids_len, cps_api_object_ATTR_T_BIN,
                             nla_data((struct nlattr*)attrs[RTA_GATEWAY]),
                             nla_len((struct nlattr*)attrs[RTA_GATEWAY]));
    }

    /* netlink notifications for IPv6 blackhole/unreachable/prohibit routes
     * are sent with OIF as 'lo' ifindex. Those route notifications
     * should be sent to NAS for processing.
     */
    if ((rtmsg->rtm_type != RTN_BLACKHOLE) &&
        (rtmsg->rtm_type != RTN_UNREACHABLE) &&
        (rtmsg->rtm_type != RTN_PROHIBIT) &&
        (attrs[RTA_OIF]!=NULL)) {
        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
        unsigned int *x = (unsigned int *) nla_data(attrs[RTA_OIF]);

        if (nas_rt_is_reserved_intf_idx(*x, true))
            return false;

        cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,
                nla_data(attrs[RTA_OIF]),sizeof(uint32_t));

        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX,*x);
    }
    if (attrs[RTA_MULTIPATH]) {
        //array of next hops
        struct rtnexthop * rtnh = (struct rtnexthop * )nla_data(attrs[RTA_MULTIPATH]);
        int remaining = nla_len(attrs[RTA_MULTIPATH]);
        bool rc = false;
        while (RTNH_OK(rtnh, remaining)) {
            ids[1] = hop_count;
            ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
            uint32_t _int = rtnh->rtnh_ifindex;
            rc = cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,
                                      &rtnh->rtnh_ifindex,sizeof(uint32_t));
            if (!rc) {
                EV_LOGGING(NETLINK,ERR,"ROUTE-EVENT-MEM","Not enough memory to fill the route mulitpath info.!");
                return false;
            }
            ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_WEIGHT;
            _int = rtnh->rtnh_hops;
            rc = cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,
                    &_int,sizeof(uint32_t));
            if (!rc) {
                EV_LOGGING(NETLINK,ERR,"ROUTE-EVENT-MEM","Not enough memory to fill the route mulitpath info.!");
                return false;
            }

            struct nlattr *nhattr[__RTA_MAX];
            memset(nhattr,0,sizeof(nhattr));
            nhrt_parse(nhattr,__IFLA_MAX,rtnh);
            if (nhattr[RTA_GATEWAY]) {
                ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR;
                rc = cps_api_object_e_add(obj, ids, ids_len, cps_api_object_ATTR_T_BIN,
                                     nla_data((struct nlattr*)nhattr[RTA_GATEWAY]),
                                     nla_len((struct nlattr*)nhattr[RTA_GATEWAY]));
                if (!rc) {
                    EV_LOGGING(NETLINK,ERR,"ROUTE-EVENT-MEM","Not enough memory to fill the route mulitpath info.!");
                    return false;
                }

                EV_LOGGING(NETLINK, INFO,"ROUTE-EVENT","MultiPath nh-cnt:%lu gateway:%s ifIndex:%d nh-flags:0x%x weight:%d",
                       hop_count,
                       ((rtmsg->rtm_family == AF_INET) ?
                        (inet_ntop(rtmsg->rtm_family, ((struct in_addr *) nla_data((struct nlattr*)nhattr[RTA_GATEWAY])), addr_str,
                                   INET_ADDRSTRLEN)) :
                        (inet_ntop(rtmsg->rtm_family, ((struct in6_addr *) nla_data((struct nlattr*)nhattr[RTA_GATEWAY])),
                                   addr_str, INET6_ADDRSTRLEN))),
                        rtnh->rtnh_ifindex, rtnh->rtnh_flags, rtnh->rtnh_hops);
            } else {
                EV_LOGGING(NETLINK, INFO,"ROUTE-EVENT","MultiPath nh-cnt:%lu ifIndex:%d nh-flags:0x%x weight:%d",
                       hop_count, rtnh->rtnh_ifindex, rtnh->rtnh_flags, rtnh->rtnh_hops);
            }
            rtnh = rtnh_next(rtnh,&remaining);
            ++hop_count;
        }

    } else {
        if (attrs[RTA_OIF] || attrs[RTA_GATEWAY]) {
            ++hop_count;
        }
    }
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_NH_COUNT,hop_count);

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj), OS_RE_BASE_ROUTE_OBJ_ENTRY_OBJ,
                                    cps_api_qualifier_OBSERVED);
    cps_api_object_set_type_operation(cps_api_object_key(obj), op);
    EV_LOGGING(NETLINK,INFO,"ROUTE-EVENT", "Object size:%d", (int)cps_api_object_to_array_len(obj));
    return true;
}

static bool process_route_and_add_to_list(int sock, int rt_msg_type, struct nlmsghdr *nh,
        void *context, uint32_t vrf_id) {
    cps_api_object_list_t *list = (cps_api_object_list_t*) context;
    cps_api_object_t obj=cps_api_object_create();

    if (!cps_api_object_list_append(*list,obj)) {
        cps_api_object_delete(obj);
        return false;
    }

    if (!nl_to_route_info(nh->nlmsg_type,nh,obj,context, NAS_DEFAULT_VRF_ID)) {
        return false;
    }
    return true;
}

bool nl_request_existing_routes(int sock, int family, int req_id) {
    return nl_route_send_get_all(sock,RTM_GETROUTE,family,req_id);
}

bool read_all_routes(cps_api_object_list_t list, route_filter_t *filter) {
    int sock = nas_nl_sock_create(NL_DEFAULT_VRF_NAME, nas_nl_sock_T_ROUTE, false);
    const int RANDOM_REQ_ID = 0x101;
    if (sock==-1) return false;
    bool rc = nl_request_existing_routes(sock,filter->family, RANDOM_REQ_ID);

    if (rc) {
        char buff[1024];
        rc = netlink_tools_process_socket(sock,process_route_and_add_to_list,&list,
                buff,sizeof(buff),&RANDOM_REQ_ID,NULL, NL_DEFAULT_VRF_ID);
    }
    close(sock);
    return rc;
}


static cps_api_return_code_t db_read_function (void * context, cps_api_get_params_t * param, size_t key_ix) {
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    cps_api_key_t key;
    cps_api_key_init(&key,cps_api_qualifier_TARGET,
            cps_api_obj_cat_ROUTE, cps_api_route_obj_ROUTE, 0);
    if (cps_api_key_matches(&param->keys[key_ix], &key,false)!=0) {
        return cps_api_ret_code_OK;
    }

    route_filter_t rf;
    memset(&rf,0,sizeof(rf));
    //!TODO need to handle the filter requests (using the received key)
    read_all_routes(param->list,&rf);

    return rc;
}

static cps_api_return_code_t _op(cps_api_operation_types_t op,void * context, cps_api_object_t obj, cps_api_object_t prev) {

    char buff[1024];
    memset(buff,0,sizeof(buff));
    cps_api_object_attr_t list[cps_api_if_ROUTE_A_MAX];
    cps_api_object_attr_fill_list(obj,0,list,sizeof(list)/sizeof(*list));

    if (list[cps_api_if_ROUTE_A_PREFIX]==NULL) return cps_api_ret_code_ERR;
    if (list[cps_api_if_ROUTE_A_PREFIX_LEN]==NULL) return cps_api_ret_code_ERR;
    if (list[cps_api_if_ROUTE_A_FAMILY]==NULL) return cps_api_ret_code_ERR;

    uint32_t prefix_len =  cps_api_object_attr_data_u32(list[cps_api_if_ROUTE_A_PREFIX_LEN]);

    struct nlmsghdr *nlh = (struct nlmsghdr *) nlmsg_reserve((struct nlmsghdr *)buff,sizeof(buff),sizeof(struct nlmsghdr));
    struct rtmsg * rm = (struct rtmsg *) nlmsg_reserve(nlh,sizeof(buff),sizeof(struct rtmsg));

    //sizeof structure + attrs nlh->nlmsg_len
    nlh->nlmsg_pid = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_type =RTM_NEWROUTE;
    nlh->nlmsg_flags =  NLM_F_REQUEST | NLM_F_ACK ;

    if (op==cps_api_oper_CREATE) {
        nlh->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
    }
    if (op==cps_api_oper_SET) {
        nlh->nlmsg_flags |=NLM_F_REPLACE;
    }
    if (op==cps_api_oper_DELETE) {
        nlh->nlmsg_type =RTM_DELROUTE;
    }

    rm->rtm_table = RT_TABLE_MAIN;
    rm->rtm_protocol = RTPROT_BOOT;
    rm->rtm_dst_len = prefix_len;
    rm->rtm_scope = RT_SCOPE_UNIVERSE;
    rm->rtm_type = RTN_UNICAST;

    rm->rtm_family = (unsigned char) cps_api_object_attr_data_u32(list[cps_api_if_ROUTE_A_FAMILY]);

    EV_LOGGING(NETLINK,INFO,"ROUTEADD","Family is %d",rm->rtm_family);

    if (list[cps_api_if_ROUTE_A_PREFIX]!=NULL) nas_nl_add_attr_ip(nlh,sizeof(buff),RTA_DST,list[cps_api_if_ROUTE_A_PREFIX]);

    if (list[cps_api_if_ROUTE_A_HOP_COUNT]==NULL) return cps_api_ret_code_ERR;
    uint32_t hc =  cps_api_object_attr_data_u32(list[cps_api_if_ROUTE_A_HOP_COUNT]);
    EV_LOGGING(NETLINK,INFO,"ROUTEADD","hopcount is %d",hc);

    if (hc==1) {
        cps_api_attr_id_t ids[3] = { cps_api_if_ROUTE_A_NH, 0, cps_api_if_ROUTE_A_NEXT_HOP_ADDR};
        const int ids_len = sizeof(ids)/sizeof(*ids);
        cps_api_object_attr_t gw = cps_api_object_e_get(obj,ids,ids_len);

        EV_LOGGING(NETLINK,INFO,"ROUTEADD","nh addr is %d",(int)(size_t)gw);
        if (gw!=NULL) nas_nl_add_attr_ip(nlh,sizeof(buff),RTA_GATEWAY,gw);

        ids[2] = cps_api_if_ROUTE_A_NH_IFINDEX;
        cps_api_object_attr_t gwix = cps_api_object_e_get(obj,ids,ids_len);
        EV_LOGGING(NETLINK,INFO,"ROUTEADD","nh index is %d",(int)(size_t)gwix);
        if (gwix!=NULL) nas_nl_add_attr_int(nlh,sizeof(buff),RTA_OIF,gwix);

        ids[2] = cps_api_if_ROUTE_A_NEXT_HOP_WEIGHT;
        cps_api_object_attr_t weight = cps_api_object_e_get(obj,ids,ids_len);
        if (weight!=NULL) nas_nl_add_attr_int(nlh,sizeof(buff),RTA_PRIORITY,weight);

    } else {
        struct nlattr * attr_nh = nlmsg_nested_start(nlh, sizeof(buff));

        attr_nh->nla_len = 0;
        attr_nh->nla_type = RTA_MULTIPATH;
        size_t ix = 0;
        for (ix = 0; ix < hc ; ++ix) {
            struct rtnexthop * rtnh = (struct rtnexthop * )nlmsg_reserve(nlh,sizeof(buff), sizeof(struct rtnexthop));
            memset(rtnh,0,sizeof(*rtnh));

            cps_api_attr_id_t ids[3] = { cps_api_if_ROUTE_A_NH, ix, cps_api_if_ROUTE_A_NEXT_HOP_ADDR};
            const int ids_len = sizeof(ids)/sizeof(*ids);
            cps_api_object_attr_t attr = cps_api_object_e_get(obj,ids,ids_len);
            if (attr!=NULL) nas_nl_add_attr_ip(nlh,sizeof(buff),RTA_GATEWAY,attr);

            ids[2] = cps_api_if_ROUTE_A_NH_IFINDEX;
            attr = cps_api_object_e_get(obj,ids,ids_len);
            if (attr!=NULL) rtnh->rtnh_ifindex = (int)cps_api_object_attr_data_u32(attr);

            ids[2] = cps_api_if_ROUTE_A_NEXT_HOP_WEIGHT;
            attr = cps_api_object_e_get(obj,ids,ids_len);
            if (attr!=NULL) rtnh->rtnh_hops = (char)cps_api_object_attr_data_u32(attr);

            ids[2] = cps_api_if_ROUTE_A_NEXT_HOP_FLAGS;
            attr = cps_api_object_e_get(obj,ids,ids_len);
            if (attr!=NULL) rtnh->rtnh_flags = (char)cps_api_object_attr_data_u32(attr);


            rtnh->rtnh_len = (char*)nlmsg_tail(nlh) - (char*)rtnh;
        }
        nlmsg_nested_end(nlh,attr_nh);
    }
    return (cps_api_return_code_t) nl_do_set_request(NL_DEFAULT_VRF_NAME, nas_nl_sock_T_ROUTE,nlh,buff,sizeof(buff));
}

static cps_api_return_code_t _write_function(void * context, cps_api_transaction_params_t * param,size_t ix) {
    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    if (obj==NULL) return cps_api_ret_code_ERR;
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    cps_api_object_t prev = cps_api_object_create();
    if (prev==NULL) return cps_api_ret_code_ERR;
    if (!cps_api_object_list_append(param->prev,prev)) {
        cps_api_object_delete(prev);
        return cps_api_ret_code_ERR;
    }

    cps_api_key_t _local_key;
    cps_api_key_init(&_local_key,cps_api_qualifier_TARGET,cps_api_obj_cat_ROUTE,cps_api_route_obj_EVENT,0);
    if (cps_api_key_matches(&_local_key,cps_api_object_key(obj),true)) {
        os_send_refresh(nas_nl_sock_T_ROUTE, NL_DEFAULT_VRF_NAME, NL_DEFAULT_VRF_ID);
    } else {
        return _op(op,context,obj,prev);
    }
    return cps_api_ret_code_OK;
}



t_std_error ds_api_linux_route_init(cps_api_operation_handle_t handle) {
    cps_api_registration_functions_t f;
    memset(&f,0,sizeof(f));
    f.handle = handle;
    f._read_function = db_read_function;
    f._write_function = _write_function;

    cps_api_key_init(&f.key,cps_api_qualifier_TARGET,cps_api_obj_cat_ROUTE,cps_api_route_obj_ROUTE,0);
    cps_api_return_code_t rc = cps_api_register(&f);
    if (rc!=cps_api_ret_code_OK) {
        return STD_ERR(INTERFACE,FAIL,rc);
    }

    f._read_function = NULL;
    cps_api_key_init(&f.key,cps_api_qualifier_TARGET,cps_api_obj_cat_ROUTE,cps_api_route_obj_EVENT,0);
    rc = cps_api_register(&f);

    return STD_ERR_OK_IF_TRUE(rc==cps_api_ret_code_OK,STD_ERR(INTERFACE,FAIL,rc));
}
