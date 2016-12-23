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

/*!
 * \file   net_main.c
 * \brief  Thread for all notification from kernel
 * \date   11-2013
 */


#include "ds_api_linux_interface.h"
#include "ds_api_linux_neigh.h"

#include "nas_os_if_priv.h"
#include "os_if_utils.h"

#include "event_log.h"
#include "ds_api_linux_route.h"

#include "std_utils.h"

#include "db_linux_event_register.h"

#include "cps_api_interface_types.h"
#include "cps_api_object_category.h"
#include "cps_api_operation.h"

#include "std_socket_tools.h"
#include "netlink_tools.h"
#include "std_thread_tools.h"
#include "std_ip_utils.h"
#include "nas_nlmsg.h"

#include "dell-base-l2-mac.h"
#include "cps_api_route.h"
#include "nas_nlmsg_object_utils.h"

#include <limits.h>
#include <unistd.h>

#include <netinet/in.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <map>

/*
 * Global variables
 */

typedef bool (*fn_nl_msg_handle)(int type, struct nlmsghdr * nh, void *context);

static std::map<int,nas_nl_sock_TYPES> nlm_sockets;

static INTERFACE *g_if_db;
INTERFACE *os_get_if_db_hdlr() {
    return g_if_db;
}

static if_bridge *g_if_bridge_db;
if_bridge *os_get_bridge_db_hdlr() {
    return g_if_bridge_db;
}

static if_bond *g_if_bond_db;
if_bond *os_get_bond_db_hdlr() {
    return g_if_bond_db;
}

extern "C" {

/*
 * Pthread variables
 */
static uint64_t                     _local_event_count = 0;
static std_thread_create_param_t      _net_main_thr;
static cps_api_event_service_handle_t         _handle;

const static int MAX_CPS_MSG_SIZE=10000;

/* Netlink message counters */
struct nl_stats_desc {
    uint32_t num_events_rcvd;
    uint32_t num_bulk_events_rcvd;
    uint32_t max_events_rcvd_in_bulk;
    uint32_t min_events_rcvd_in_bulk;
    uint32_t num_add_events;
    uint32_t num_del_events;
    uint32_t num_get_events;
    uint32_t num_invalid_add_events;
    uint32_t num_invalid_del_events;
    uint32_t num_invalid_get_events;
    uint32_t num_add_events_pub;
    uint32_t num_del_events_pub;
    uint32_t num_get_events_pub;
    uint32_t num_add_events_pub_failed;
    uint32_t num_del_events_pub_failed;
    uint32_t num_get_events_pub_failed;
    void (*reset)(nas_nl_sock_TYPES type);
    void (*print)(nas_nl_sock_TYPES type);
    void (*print_msg_detail)(nas_nl_sock_TYPES type);
    void (*print_pub_detail)(nas_nl_sock_TYPES type);
};

static void nl_stats_reset(nas_nl_sock_TYPES type);
static void nl_stats_print(nas_nl_sock_TYPES type);
static void nl_stats_print_msg_detail (nas_nl_sock_TYPES type);
static void nl_stats_print_pub_detail (nas_nl_sock_TYPES type);
static std::map<nas_nl_sock_TYPES,nl_stats_desc > nlm_counters = {
    { nas_nl_sock_T_ROUTE , { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, &nl_stats_reset, &nl_stats_print,
                                &nl_stats_print_msg_detail, &nl_stats_print_pub_detail} } ,
    { nas_nl_sock_T_INT ,{ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, &nl_stats_reset, &nl_stats_print,
                             &nl_stats_print_msg_detail, &nl_stats_print_pub_detail} },
    { nas_nl_sock_T_NEI ,{ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, &nl_stats_reset, &nl_stats_print,
                             &nl_stats_print_msg_detail, &nl_stats_print_pub_detail} },
};

/*
 * Functions
 */

#define KN_DEBUG(x,...) EV_LOG_TRACE (ev_log_t_NETLINK,0,"NL-DBG",x, ##__VA_ARGS__)

cps_api_return_code_t net_publish_event(cps_api_object_t msg) {
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    ++_local_event_count;
    rc = cps_api_event_publish(_handle,msg);
    cps_api_object_delete(msg);
    return rc;
}

void cps_api_event_count_clear(void) {
    _local_event_count = 0;
}

uint64_t cps_api_event_count_get(void) {
    return _local_event_count;
}

void rta_add_mac( struct nlattr* rtatp, cps_api_object_t obj, uint32_t attr) {
    cps_api_object_attr_add(obj,attr,nla_data(rtatp),nla_len(rtatp));
}

void rta_add_mask(int family, uint_t prefix_len, cps_api_object_t obj, uint32_t attr) {
    hal_ip_addr_t mask;
    std_ip_get_mask_from_prefix_len(family,prefix_len,&mask);
    cps_api_object_attr_add(obj,attr,&mask,sizeof(mask));
}

void rta_add_e_ip( struct nlattr* rtatp,int family, cps_api_object_t obj,
        cps_api_attr_id_t *attr, size_t attr_id_len) {
    hal_ip_addr_t ip;

    if(family == AF_INET) {
        struct in_addr *inp = (struct in_addr *) nla_data(rtatp);
        std_ip_from_inet(&ip,inp);
    } else {
        struct in6_addr *inp6 = (struct in6_addr *) nla_data(rtatp);
        std_ip_from_inet6(&ip,inp6);
    }
    cps_api_object_e_add(obj,attr,attr_id_len, cps_api_object_ATTR_T_BIN,
            &ip,sizeof(ip));
}

unsigned int rta_add_name( struct nlattr* rtatp,cps_api_object_t obj, uint32_t attr_id) {
    char buff[PATH_MAX];
    memset(buff,0,sizeof(buff));
    size_t len = (size_t)nla_len(rtatp)  < (sizeof(buff)-1) ? nla_len(rtatp) : sizeof(buff)-1;
    memcpy(buff,nla_data(rtatp),len);
    len = strlen(buff)+1;
    cps_api_object_attr_add(obj,attr_id,buff,len);
    return len;
}

static inline void netlink_tot_msg_stat_update(nas_nl_sock_TYPES sock_type, int rt_msg_type) {
    if ((rt_msg_type == RTM_NEWLINK) ||  (rt_msg_type == RTM_NEWADDR) ||
        (rt_msg_type == RTM_NEWROUTE) || (rt_msg_type == RTM_NEWNEIGH)) {
        nlm_counters[sock_type].num_add_events++;
    } else if ((rt_msg_type == RTM_DELLINK) ||  (rt_msg_type == RTM_DELADDR) ||
               (rt_msg_type == RTM_DELROUTE) || (rt_msg_type == RTM_DELNEIGH)) {
        nlm_counters[sock_type].num_del_events++;
    } else if ((rt_msg_type == RTM_GETLINK) ||  (rt_msg_type == RTM_GETADDR) ||
               (rt_msg_type == RTM_GETROUTE) || (rt_msg_type == RTM_GETNEIGH)) {
        nlm_counters[sock_type].num_get_events++;
    }
}

static inline void netlink_invalid_msg_stat_update(nas_nl_sock_TYPES sock_type, int rt_msg_type) {
    if ((rt_msg_type == RTM_NEWLINK) ||  (rt_msg_type == RTM_NEWADDR) ||
        (rt_msg_type == RTM_NEWROUTE) || (rt_msg_type == RTM_NEWNEIGH)) {
        nlm_counters[sock_type].num_invalid_add_events++;
    } else if ((rt_msg_type == RTM_DELLINK) ||  (rt_msg_type == RTM_DELADDR) ||
               (rt_msg_type == RTM_DELROUTE) || (rt_msg_type == RTM_DELNEIGH)) {
        nlm_counters[sock_type].num_invalid_del_events++;
    } else if ((rt_msg_type == RTM_GETLINK) ||  (rt_msg_type == RTM_GETADDR) ||
               (rt_msg_type == RTM_GETROUTE) || (rt_msg_type == RTM_GETNEIGH)) {
        nlm_counters[sock_type].num_invalid_get_events++;
    }
}

static inline void netlink_pub_msg_stat_update(nas_nl_sock_TYPES sock_type, int rt_msg_type) {
    if ((rt_msg_type == RTM_NEWLINK) ||  (rt_msg_type == RTM_NEWADDR) ||
        (rt_msg_type == RTM_NEWROUTE) || (rt_msg_type == RTM_NEWNEIGH)) {
        nlm_counters[sock_type].num_add_events_pub++;
    } else if ((rt_msg_type == RTM_DELLINK) ||  (rt_msg_type == RTM_DELADDR) ||
               (rt_msg_type == RTM_DELROUTE) || (rt_msg_type == RTM_DELNEIGH)) {
        nlm_counters[sock_type].num_del_events_pub++;
    } else if ((rt_msg_type == RTM_GETLINK) ||  (rt_msg_type == RTM_GETADDR) ||
               (rt_msg_type == RTM_GETROUTE) || (rt_msg_type == RTM_GETNEIGH)) {
        nlm_counters[sock_type].num_get_events_pub++;
    }
}

static inline void netlink_pub_msg_failed_stat_update(nas_nl_sock_TYPES sock_type, int rt_msg_type) {
    if ((rt_msg_type == RTM_NEWLINK) ||  (rt_msg_type == RTM_NEWADDR) ||
        (rt_msg_type == RTM_NEWROUTE) || (rt_msg_type == RTM_NEWNEIGH)) {
        nlm_counters[sock_type].num_add_events_pub_failed++;
    } else if ((rt_msg_type == RTM_DELLINK) ||  (rt_msg_type == RTM_DELADDR) ||
               (rt_msg_type == RTM_DELROUTE) || (rt_msg_type == RTM_DELNEIGH)) {
        nlm_counters[sock_type].num_del_events_pub_failed++;
    } else if ((rt_msg_type == RTM_GETLINK) ||  (rt_msg_type == RTM_GETADDR) ||
               (rt_msg_type == RTM_GETROUTE) || (rt_msg_type == RTM_GETNEIGH)) {
        nlm_counters[sock_type].num_get_events_pub_failed++;
    }
}

static bool get_netlink_data(int rt_msg_type, struct nlmsghdr *hdr, void *data) {
    static char buff[MAX_CPS_MSG_SIZE];

    cps_api_object_t obj = cps_api_object_init(buff,sizeof(buff));

    if (rt_msg_type < RTM_BASE)
        return false;

    /*!
     * Range upto SET_LINK
     */
    if (rt_msg_type <= RTM_SETLINK) {
        netlink_tot_msg_stat_update(nas_nl_sock_T_INT, rt_msg_type);
        if (os_interface_to_object(rt_msg_type,hdr,obj)) {
            netlink_pub_msg_stat_update(nas_nl_sock_T_INT, rt_msg_type);
            if (net_publish_event(obj) != cps_api_ret_code_OK) {
                netlink_pub_msg_failed_stat_update(nas_nl_sock_T_INT, rt_msg_type);
            }
        } else {
            netlink_invalid_msg_stat_update(nas_nl_sock_T_INT, rt_msg_type);
        }
        return true;
    }

    /*!
     * Range upto GET_ADDRRESS
     */
    if (rt_msg_type <= RTM_GETADDR) {
        netlink_tot_msg_stat_update(nas_nl_sock_T_INT, rt_msg_type);
        if (nl_get_ip_info(rt_msg_type,hdr,obj)) {
            netlink_pub_msg_stat_update(nas_nl_sock_T_INT, rt_msg_type);
            if (net_publish_event(obj) != cps_api_ret_code_OK) {
                netlink_pub_msg_failed_stat_update(nas_nl_sock_T_INT, rt_msg_type);
            }
        } else {
            netlink_invalid_msg_stat_update(nas_nl_sock_T_INT, rt_msg_type);
        }
        return true;
    }

    /*!
     * Range upto GET_ROUTE
     */
    if (rt_msg_type <= RTM_GETROUTE) {
        netlink_tot_msg_stat_update(nas_nl_sock_T_ROUTE, rt_msg_type);
        if (nl_to_route_info(rt_msg_type,hdr, obj)) {
            netlink_pub_msg_stat_update(nas_nl_sock_T_ROUTE, rt_msg_type);
            if (net_publish_event(obj) != cps_api_ret_code_OK) {
                netlink_pub_msg_failed_stat_update(nas_nl_sock_T_ROUTE, rt_msg_type);
            }
        } else {
            netlink_invalid_msg_stat_update(nas_nl_sock_T_ROUTE, rt_msg_type);
        }
        return true;
    }

    /*!
     * Range upto GET_NEIGHBOR
     */
    if (rt_msg_type <= RTM_GETNEIGH) {
        netlink_tot_msg_stat_update(nas_nl_sock_T_NEI, rt_msg_type);
        if (nl_to_neigh_info(rt_msg_type, hdr,obj)) {
            cps_api_key_init(cps_api_object_key(obj),cps_api_qualifier_TARGET,
                             cps_api_obj_cat_ROUTE,cps_api_route_obj_NEIBH,0);
            netlink_pub_msg_stat_update(nas_nl_sock_T_NEI, rt_msg_type);
            if (net_publish_event(obj) != cps_api_ret_code_OK) {
                netlink_pub_msg_failed_stat_update(nas_nl_sock_T_NEI, rt_msg_type);
            }
        } else {
            netlink_invalid_msg_stat_update(nas_nl_sock_T_NEI, rt_msg_type);
        }
        return true;
    }

    return false;
}

static void publish_existing()
{
    struct ifaddrs *if_addr, *ifa;
    int    family, s;
    char   name[NI_MAXHOST];



    if(getifaddrs(&if_addr) == -1) {
        return;
    }

    for (ifa = if_addr; ifa; ifa = ifa->ifa_next)
    {
        if(ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET || family == AF_INET6)
        {
            KN_DEBUG("%s - family: %d%s, flags 0x%x",
                ifa->ifa_name, family,
                (family == AF_INET)?"(AF_INET)":
                (family == AF_INET6)?"(AF_INET6)":"", ifa->ifa_flags);

            s = getnameinfo(ifa->ifa_addr,
                            (family == AF_INET)? sizeof(struct sockaddr_in):
                                                 sizeof(struct sockaddr_in6),
                            name, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

            if (!s)
                KN_DEBUG("  Address %s", name);
            else
                KN_DEBUG("  get name failed");

            s = getnameinfo(ifa->ifa_netmask,
                            (family == AF_INET)? sizeof(struct sockaddr_in):
                                                 sizeof(struct sockaddr_in6),
                            name, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (!s)
                KN_DEBUG("  Mask %s strlen %d", name, (int)strlen(name));
            else
                KN_DEBUG("  get name failed");


            cps_api_object_t obj = cps_api_object_create();
            cps_api_object_attr_add(obj,cps_api_if_ADDR_A_NAME,
                    ifa->ifa_name,strlen(ifa->ifa_name)+1);

            if (family == AF_INET) {
                hal_ip_addr_t ip;
                std_ip_from_inet(&ip,&(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr));
                cps_api_object_attr_add(obj,cps_api_if_ADDR_A_IF_ADDR,
                                    &ip,sizeof(ip));

                std_ip_from_inet(&ip,&(((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr));
                cps_api_object_attr_add(obj,cps_api_if_ADDR_A_IF_MASK,
                                    &ip,sizeof(ip));
            }
            else {
                hal_ip_addr_t ip;
                std_ip_from_inet6(&ip,&(((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr));
                cps_api_object_attr_add(obj,cps_api_if_ADDR_A_IF_ADDR,
                                    &ip,sizeof(ip));
                std_ip_from_inet6(&ip,&(((struct sockaddr_in6 *)ifa->ifa_netmask)->sin6_addr));
                cps_api_object_attr_add(obj,cps_api_if_ADDR_A_IF_MASK,
                                    &ip,sizeof(ip));
            }
            cps_api_key_init(cps_api_object_key(obj),cps_api_qualifier_TARGET,
                    cps_api_obj_cat_INTERFACE,cps_api_int_obj_INTERFACE_ADDR,0);
            net_publish_event(obj);

        }
    }

    freeifaddrs(if_addr);
    return;
}

static char   buf[NL_SCRATCH_BUFFER_LEN];

static inline void add_fd_set(int fd, fd_set &fdset, int &max_fd) {
    FD_SET(fd, &fdset);
    if (fd>max_fd) max_fd = fd;
}

struct nl_event_desc {
    fn_nl_msg_handle process;
    bool (*trigger)(int sock, int id);
} ;

static bool trigger_route(int sock, int reqid);
static bool trigger_neighbour(int sock, int reqid);

static std::map<nas_nl_sock_TYPES,nl_event_desc > nlm_handlers = {
        { nas_nl_sock_T_ROUTE , { get_netlink_data, &trigger_route} } ,
        { nas_nl_sock_T_INT ,{ get_netlink_data, nl_interface_get_request} },
        { nas_nl_sock_T_NEI ,{ get_netlink_data,&trigger_neighbour } },
};

static bool trigger_route(int sock, int reqid) {
    if (nl_request_existing_routes(sock,AF_INET,++reqid)) {
        netlink_tools_process_socket(sock,nlm_handlers[nas_nl_sock_T_ROUTE].process,
                NULL,buf,sizeof(buf),&reqid,NULL);
    }

    if (nl_request_existing_routes(sock,AF_INET6,++reqid)) {
        netlink_tools_process_socket(sock,nlm_handlers[nas_nl_sock_T_ROUTE].process,
                NULL,buf,sizeof(buf),&reqid,NULL);
    }
    return true;
}
static bool trigger_neighbour(int sock, int reqid) {
    if (nl_neigh_get_all_request(sock,AF_INET,++reqid)) {
        netlink_tools_process_socket(sock,nlm_handlers[nas_nl_sock_T_NEI].process,
                NULL,buf,sizeof(buf),&reqid,NULL);
    }

    if (nl_neigh_get_all_request(sock,AF_INET6,++reqid)) {
        netlink_tools_process_socket(sock,nlm_handlers[nas_nl_sock_T_NEI].process,
                NULL,buf,sizeof(buf),&reqid,NULL);
    }
    return true;
}

void nl_stats_update (int sock, uint32_t bulk_msg_count) {
    for ( auto &it : nlm_sockets) {
        if (it.first == sock ) {
            nlm_counters[it.second].num_events_rcvd += bulk_msg_count;

            if (bulk_msg_count > 1) //increment bulk rcvd count only if the count is > 1.
            {
                nlm_counters[it.second].num_bulk_events_rcvd++;

                if (bulk_msg_count > nlm_counters[it.second].max_events_rcvd_in_bulk)
                    nlm_counters[it.second].max_events_rcvd_in_bulk =  bulk_msg_count;

                if (bulk_msg_count < nlm_counters[it.second].min_events_rcvd_in_bulk)
                    nlm_counters[it.second].min_events_rcvd_in_bulk =  bulk_msg_count;
                else if (nlm_counters[it.second].min_events_rcvd_in_bulk == 0)
                    nlm_counters[it.second].min_events_rcvd_in_bulk =  bulk_msg_count;
            }
        }
    }
    return;
}

static void nl_stats_reset (nas_nl_sock_TYPES type) {
    nlm_counters[type].num_events_rcvd = 0;
    nlm_counters[type].num_bulk_events_rcvd = 0;
    nlm_counters[type].max_events_rcvd_in_bulk = 0;
    nlm_counters[type].min_events_rcvd_in_bulk = 0;


    nlm_counters[type].num_add_events= 0;
    nlm_counters[type].num_del_events= 0;
    nlm_counters[type].num_get_events= 0;
    nlm_counters[type].num_invalid_add_events= 0;
    nlm_counters[type].num_invalid_del_events= 0;
    nlm_counters[type].num_invalid_get_events= 0;
    nlm_counters[type].num_add_events_pub= 0;
    nlm_counters[type].num_del_events_pub= 0;
    nlm_counters[type].num_get_events_pub= 0;
    nlm_counters[type].num_add_events_pub_failed= 0;
    nlm_counters[type].num_del_events_pub_failed= 0;
    nlm_counters[type].num_get_events_pub_failed= 0;
    return;
}

static const std::map<nas_nl_sock_TYPES, std::string> _sock_type_to_str = {
    { nas_nl_sock_T_ROUTE, "ROUTE" },
    { nas_nl_sock_T_INT, "INT" },
    { nas_nl_sock_T_NEI, "NEIGH" },
};

static void nl_stats_print (nas_nl_sock_TYPES type) {
    auto it = _sock_type_to_str.find(type);
    if (it == _sock_type_to_str.end()) {
        // invalid socket group for stats_print.
        return;
    }

    printf("\r %-10s | %-10d | %-10d | %-10d | %-10d\r\n",
            it->second.c_str(),
            nlm_counters[type].num_events_rcvd,
            nlm_counters[type].num_bulk_events_rcvd,
            nlm_counters[type].max_events_rcvd_in_bulk,
            nlm_counters[type].min_events_rcvd_in_bulk);
    return;
}

static void nl_stats_print_msg_detail (nas_nl_sock_TYPES type) {

    auto it = _sock_type_to_str.find(type);
    if (it == _sock_type_to_str.end()) {
        // invalid socket group for stats_print.
        return;
    }

    printf("\r %-10s | %-10d | %-10d | %-10d | %-12d | %-12d | %-12d\r\n",
           it->second.c_str(),
           nlm_counters[type].num_add_events,
           nlm_counters[type].num_del_events,
           nlm_counters[type].num_get_events,
           nlm_counters[type].num_invalid_add_events,
           nlm_counters[type].num_invalid_del_events,
           nlm_counters[type].num_invalid_get_events);

    return;
}

static void nl_stats_print_pub_detail (nas_nl_sock_TYPES type) {

    auto it = _sock_type_to_str.find(type);
    if (it == _sock_type_to_str.end()) {
        // invalid socket group for stats_print.
        return;
    }
    printf("\r %-10s | %-10d | %-10d | %-10d | %-13d | %-13d | %-13d\r\n",
           it->second.c_str(),
           nlm_counters[type].num_add_events_pub,
           nlm_counters[type].num_del_events_pub,
           nlm_counters[type].num_get_events_pub,
           nlm_counters[type].num_add_events_pub_failed,
           nlm_counters[type].num_del_events_pub_failed,
           nlm_counters[type].num_get_events_pub_failed);

    return;
}

void os_debug_nl_stats_reset () {
    for ( auto &it : nlm_sockets) {
        if (nlm_counters[it.second].reset !=NULL) {
            nlm_counters[it.second].reset(it.second);
        }
    }
}

void os_debug_nl_stats_print () {

    printf("\r\n NETLINK STATS INFORMATION socket-rx-buf-size:%d scratch buf-size:%d\r\n",
           NL_SOCKET_BUFFER_LEN, NL_SCRATCH_BUFFER_LEN);
    for ( auto &it : nlm_sockets) {
        printf("Socket type:%s sock-fd:%d\r\n",
               ((it.second == nas_nl_sock_T_ROUTE) ? "Route" :
                (it.second == nas_nl_sock_T_INT) ? "Intf" : "Nbr"), it.first);
    }

    printf("\r =========================\r\n");
    printf("\r\n %-10s | %-10s | %-10s | %-10s | %-10s\r\n", "Sock Type", "#events", "#bulk", "#max_bulk", "min_bulk");
    printf("\r %-10s | %-10s | %-10s | %-10s | %-10s\r\n",
           "==========",
           "==========",
           "==========",
           "==========",
           "==========");

    for ( auto &it : nlm_sockets) {
        if (nlm_counters[it.second].print!=NULL) {
            nlm_counters[it.second].print(it.second);
        }
    }
    printf(" \r\n===============================Netlink Message Details=========================================\r\n");
    printf("\r %-10s | %-10s | %-10s | %-10s | %-12s | %-12s | %-12s\r\n",
           "Sock Type", "#add", "#del", "#get", "#invalid_add", "#invalid_del", "#invalid_get");
    printf("\r %-10s | %-10s | %-10s | %-10s | %-12s | %-12s | %-12s\r\n",
           "==========", "==========", "==========", "==========", "============",
           "============", "============");

    for ( auto &it : nlm_sockets) {
        if (nlm_counters[it.second].print_msg_detail!=NULL) {
            nlm_counters[it.second].print_msg_detail(it.second);
        }
    }
    printf("  \r\n===============================Netlink Message Publish Details====================================\r\n");
    printf("\r %-10s | %-10s | %-10s | %-10s | %-13s | %-13s | %-13s\r\n",
           "Sock Type", "#add_pub", "#del_pub", "#get_pub", "#add_pub_fail", "#del_pub_fail", "#get_pub_fail");
    printf("\r %-10s | %-10s | %-10s | %-10s | %-13s | %-13s | %-13s\r\n",
           "==========", "==========", "==========", "==========", "=============",
           "=============", "=============");

    for ( auto &it : nlm_sockets) {
        if (nlm_counters[it.second].print_pub_detail!=NULL) {
            nlm_counters[it.second].print_pub_detail(it.second);
        }
    }
}

void os_send_refresh(nas_nl_sock_TYPES type) {
    int RANDOM_REQ_ID = 0xee00;

    for ( auto &it : nlm_sockets) {
        if (it.second == type && nlm_handlers[it.second].trigger!=NULL) {
            nlm_handlers[it.second].trigger(it.first,RANDOM_REQ_ID);
        }
    }
}

int net_main() {
    int max_fd = -1;
    struct sockaddr_nl sa;
    fd_set read_fds, sel_fds;

    FD_ZERO(&read_fds);
    memset(&sa, 0, sizeof(sa));

    size_t ix = nas_nl_sock_T_ROUTE;
    for ( ; ix < (size_t)nas_nl_sock_T_MAX; ++ix ) {
        int sock = nas_nl_sock_create((nas_nl_sock_TYPES)(ix),true);
        if(sock==-1) {
            EV_LOG(ERR,NETLINK,0,"INIT","Failed to initialize sockets...%d",errno);
            exit(-1);
        }
        EV_LOG(INFO,NETLINK,2, "NET-NOTIFY","Socket: ix %d, sock id %d", ix, sock);
        nlm_sockets[sock] = (nas_nl_sock_TYPES)(ix);
        add_fd_set(sock,read_fds,max_fd);
    }

    //Publish existing..
    publish_existing();

    nas_nl_sock_TYPES _refresh_list[] = {
            nas_nl_sock_T_INT,
            nas_nl_sock_T_NEI,
            nas_nl_sock_T_ROUTE
    };

    g_if_db = new (std::nothrow) (INTERFACE);
    g_if_bridge_db = new (std::nothrow) (if_bridge);
    g_if_bond_db = new (std::nothrow) (if_bond);

    if(g_if_db == nullptr || g_if_bridge_db == nullptr || g_if_bridge_db == nullptr)
        EV_LOG(ERR,NETLINK,0,"INIT","Allocation failed for class objects...");

    ix = 0;
    size_t refresh_mx = sizeof(_refresh_list)/sizeof(*_refresh_list);
    for ( ; ix < refresh_mx ; ++ix ) {
        os_send_refresh(_refresh_list[ix]);
    }

    while (1) {
        memcpy ((char *) &sel_fds, (char *) &read_fds, sizeof(fd_set));

        if(select((max_fd+1), &sel_fds, NULL, NULL, NULL) <= 0)
            continue;

        for ( auto &it : nlm_sockets) {
            if (FD_ISSET(it.first,&sel_fds)) {
                netlink_tools_receive_event(it.first,nlm_handlers[it.second].process,
                            NULL,buf,sizeof(buf),NULL);
            }
        }
    }

    return 0;
}

t_std_error cps_api_net_notify_init(void) {
    EV_LOG_TRACE(ev_log_t_NULL, 3, "NET-NOTIFY","Initializing Net Notify Thread");

    if (cps_api_event_client_connect(&_handle)!=STD_ERR_OK) {
        EV_LOG_ERR(ev_log_t_NULL, 3, "NET-NOTIFY","Failed to initialize");
        return STD_ERR(INTERFACE,FAIL,0);
    }

    std_thread_init_struct(&_net_main_thr);
    _net_main_thr.name = "db-api-linux-events";
    _net_main_thr.thread_function = (std_thread_function_t)net_main;
    t_std_error rc = std_thread_create(&_net_main_thr);
    if (rc!=STD_ERR_OK) {
        EV_LOG(ERR,INTERFACE,3,"db-api-linux-event-init-fail","Failed to "
                "initialize event service due");
    }
    cps_api_operation_handle_t handle;

    if (cps_api_operation_subsystem_init(&handle,1)!=STD_ERR_OK) {
        return STD_ERR(INTERFACE,FAIL,0);
    }

    if (os_interface_object_reg(handle)!=STD_ERR_OK) {
        return STD_ERR(INTERFACE,FAIL,0);
    }

    return rc;
}
}
