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
#include "nas_os_mcast_snoop.h"

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
#include "netlink_stats.h"

#include <limits.h>
#include <unistd.h>
#include <fstream>
#include <sstream>

#include <netinet/in.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <map>
#include <mutex>

/*
 * Global variables
 */

typedef bool (*fn_nl_msg_handle)(int sock, int type, struct nlmsghdr * nh, void *context);

typedef struct _nlm_sock_info {
    nas_nl_sock_TYPES sock_type;
    char vrf_name[HAL_IF_NAME_SZ+1];
}nlm_sock_info;

static auto nlm_sockets = new std::map<int, nlm_sock_info>;

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

/* This size should be increased incase the no. of path for a route increased beyond 128 */
const static int MAX_CPS_MSG_SIZE=12000;

static fd_set read_fds;
static int max_fd = -1;
static std::mutex _nl_sock_mutex;
/*
 * Functions
 */

#define KN_DEBUG(x,...) EV_LOG_TRACE (ev_log_t_NETLINK,0,"NL-DBG",x, ##__VA_ARGS__)

static t_std_error nas_os_create_publish_handle() {
    if (_handle != nullptr)
        return STD_ERR_OK;

    if (cps_api_event_client_connect(&_handle)!=STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "NET-NOTIFY","Failed to create the handle for event publish!");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    return STD_ERR_OK;
}

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

void rta_add_e_ip( struct nlattr* rtatp, cps_api_object_t obj,
        cps_api_attr_id_t *attr, size_t attr_id_len) {
    hal_ip_addr_t ip;
    size_t len = nla_len(rtatp);
    if(len == HAL_INET4_LEN) {
        struct in_addr *inp = (struct in_addr *) nla_data(rtatp);
        std_ip_from_inet(&ip,inp);
    } else if (len == HAL_INET6_LEN) {
        struct in6_addr *inp6 = (struct in6_addr *) nla_data(rtatp);
        std_ip_from_inet6(&ip,inp6);
    }else{
        EV_LOGGING(NETLINK,ERR,"ADD-IP","Invalied IP length %d",len);
        return;
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

static bool get_netlink_data(int sock, int rt_msg_type, struct nlmsghdr *hdr, void *data) {
    static char buff[MAX_CPS_MSG_SIZE];

    cps_api_object_t obj = cps_api_object_init(buff,sizeof(buff));

    if (rt_msg_type < RTM_BASE)
        return false;

    EV_LOGGING(NETLINK,INFO,"NL_EVT","VRF:%s sock:%d msg_type:%d(%s) ", (data ? data : ""), sock, rt_msg_type,
               ((rt_msg_type <= RTM_SETLINK) ? "Link" : ((rt_msg_type <= RTM_GETADDR) ? "Addr" :
                                                         ((rt_msg_type <= RTM_GETROUTE) ? "Route" :
                                                          ((rt_msg_type <= RTM_GETNEIGH) ? "Neigh" :
                                                           "Unknown")))));
    /*!
     * Range upto SET_LINK
     */
    if (rt_msg_type <= RTM_SETLINK) {
        nas_nl_stats_update_tot_msg (sock, rt_msg_type);
        if (os_interface_to_object(rt_msg_type,hdr,obj,data)) {
            nas_nl_stats_update_pub_msg (sock, rt_msg_type);
            if (net_publish_event(obj) != cps_api_ret_code_OK) {
                nas_nl_stats_update_pub_msg_failed (sock, rt_msg_type);
            }
        } else {
            nas_nl_stats_update_invalid_msg (sock, rt_msg_type);
        }
        return true;
    }

    /*!
     * Range upto GET_ADDRRESS
     */
    if (rt_msg_type <= RTM_GETADDR) {
        nas_nl_stats_update_tot_msg (sock, rt_msg_type);
        if (nl_get_ip_info(rt_msg_type,hdr,obj,data)) {
            nas_nl_stats_update_pub_msg (sock, rt_msg_type);
            if (net_publish_event(obj) != cps_api_ret_code_OK) {
                nas_nl_stats_update_pub_msg_failed (sock, rt_msg_type);
            }
        } else {
            nas_nl_stats_update_invalid_msg (sock, rt_msg_type);
        }
        return true;
    }

    /*!
     * Range upto GET_ROUTE
     */
    if (rt_msg_type <= RTM_GETROUTE) {
        nas_nl_stats_update_tot_msg (sock, rt_msg_type);
        if (nl_to_route_info(rt_msg_type,hdr, obj, data)) {
            nas_nl_stats_update_pub_msg (sock, rt_msg_type);
            if (net_publish_event(obj) != cps_api_ret_code_OK) {
                nas_nl_stats_update_pub_msg_failed (sock, rt_msg_type);
            }
        } else {
            nas_nl_stats_update_invalid_msg (sock, rt_msg_type);
        }
        return true;
    }

    /*!
     * Range upto GET_NEIGHBOR
     */
    if (rt_msg_type <= RTM_GETNEIGH) {
        nas_nl_stats_update_tot_msg (sock, rt_msg_type);
        if (nl_to_neigh_info(rt_msg_type, hdr,obj,data)) {
            nas_nl_stats_update_pub_msg (sock, rt_msg_type);
            if (net_publish_event(obj) != cps_api_ret_code_OK) {
                nas_nl_stats_update_pub_msg_failed (sock, rt_msg_type);
            }
        } else {
            nas_nl_stats_update_invalid_msg (sock, rt_msg_type);
        }
        return true;
    }
    /*!
     * Range upto GET_NETCONF
     */
    if (rt_msg_type <= RTM_GETNETCONF) {
        nas_nl_stats_update_tot_msg (sock, rt_msg_type);
        if (nl_get_ip_netconf_info(rt_msg_type,hdr, obj, data)) {
            nas_nl_stats_update_pub_msg (sock, rt_msg_type);
            if (net_publish_event(obj) != cps_api_ret_code_OK) {
                nas_nl_stats_update_pub_msg_failed (sock, rt_msg_type);
            }
        } else {
            nas_nl_stats_update_invalid_msg (sock, rt_msg_type);
        }
        return true;
    }
    /*!
     * Range upto GET_MDB
     */
    if (rt_msg_type <= RTM_GETMDB) {
        nas_nl_stats_update_tot_msg (sock, rt_msg_type);
        if (nl_to_mcast_snoop_info(rt_msg_type,hdr, obj, data)) {
            nas_nl_stats_update_pub_msg (sock, rt_msg_type);
            if (net_publish_event(obj) != cps_api_ret_code_OK) {
                nas_nl_stats_update_pub_msg_failed (sock, rt_msg_type);
            }
        } else {
            nas_nl_stats_update_invalid_msg (sock, rt_msg_type);
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
static bool trigger_netconf(int sock, int reqid);
static bool trigger_mcast_snoop(int sock, int reqid);

static auto nlm_handlers = new std::map<nas_nl_sock_TYPES,nl_event_desc >{
    { nas_nl_sock_T_ROUTE , { get_netlink_data, &trigger_route} } ,
    { nas_nl_sock_T_INT ,{ get_netlink_data, nl_interface_get_request} },
    { nas_nl_sock_T_NEI ,{ get_netlink_data,&trigger_neighbour } },
    { nas_nl_sock_T_NETCONF ,{ get_netlink_data, &trigger_netconf } },
    { nas_nl_sock_T_MCAST_SNOOP , { get_netlink_data, &trigger_mcast_snoop} }
};

static bool trigger_route(int sock, int reqid) {
    if (nl_request_existing_routes(sock,AF_INET,++reqid)) {
        netlink_tools_process_socket(sock,nlm_handlers->at(nas_nl_sock_T_ROUTE).process,
                NULL,buf,sizeof(buf),&reqid,NULL);
    }

    if (nl_request_existing_routes(sock,AF_INET6,++reqid)) {
        netlink_tools_process_socket(sock,nlm_handlers->at(nas_nl_sock_T_ROUTE).process,
                NULL,buf,sizeof(buf),&reqid,NULL);
    }
    return true;
}

static bool trigger_mcast_snoop(int sock, int reqid) {
    if (nl_request_existing_routes(sock,AF_INET,++reqid)) {
        netlink_tools_process_socket(sock,nlm_handlers->at(nas_nl_sock_T_MCAST_SNOOP).process,
                NULL,buf,sizeof(buf),&reqid,NULL);
    }

    if (nl_request_existing_routes(sock,AF_INET6,++reqid)) {
        netlink_tools_process_socket(sock,nlm_handlers->at(nas_nl_sock_T_MCAST_SNOOP).process,
                NULL,buf,sizeof(buf),&reqid,NULL);
    }
    return true;
}

static bool trigger_neighbour(int sock, int reqid) {
    if (nl_neigh_get_all_request(sock,AF_INET,++reqid)) {
        netlink_tools_process_socket(sock,nlm_handlers->at(nas_nl_sock_T_NEI).process,
                NULL,buf,sizeof(buf),&reqid,NULL);
    }

    if (nl_neigh_get_all_request(sock,AF_INET6,++reqid)) {
        netlink_tools_process_socket(sock,nlm_handlers->at(nas_nl_sock_T_NEI).process,
                NULL,buf,sizeof(buf),&reqid,NULL);
    }
    return true;
}

static bool trigger_netconf(int sock, int reqid) {
    if (nl_netconf_get_all_request(sock,AF_INET,++reqid)) {
        netlink_tools_process_socket(sock,nlm_handlers->at(nas_nl_sock_T_NETCONF).process,
                NULL,buf,sizeof(buf),&reqid,NULL);
    }
    if (nl_netconf_get_all_request(sock,AF_INET6,++reqid)) {
        netlink_tools_process_socket(sock,nlm_handlers->at(nas_nl_sock_T_NETCONF).process,
                NULL,buf,sizeof(buf),&reqid,NULL);
    }

    return true;
}


void os_debug_nl_stats_reset () {
    std::lock_guard<std::mutex> lock(_nl_sock_mutex);
    for ( auto it = nlm_sockets->begin(); it != nlm_sockets->end() ; ++it) {
        nas_nl_stats_reset(it->first);
    }
}

void os_debug_nl_stats_print () {
    printf("\r\n NETLINK STATS INFORMATION scratch buf-size: %d\r\n",
           NL_SCRATCH_BUFFER_LEN);

    std::lock_guard<std::mutex> lock(_nl_sock_mutex);
    for ( auto it = nlm_sockets->begin(); it != nlm_sockets->end() ; ++it) {
        printf("\r\n VRF:%s Socket type: %-10s sock-fd: %-10d socket-rx-buf-size: %-10d\r\n",
               it->second.vrf_name,
               ((it->second.sock_type == nas_nl_sock_T_ROUTE) ? "Route" :
                (it->second.sock_type == nas_nl_sock_T_INT) ? "Intf" :
                (it->second.sock_type == nas_nl_sock_T_NEI) ? "Nbr" : "NetConf"),
               it->first,
               ((it->second.sock_type == nas_nl_sock_T_ROUTE) ? NL_ROUTE_SOCKET_BUFFER_LEN :
                (it->second.sock_type == nas_nl_sock_T_INT) ? NL_INTF_SOCKET_BUFFER_LEN :
                (it->second.sock_type == nas_nl_sock_T_NEI) ? NL_NEIGH_SOCKET_BUFFER_LEN :
                (it->second.sock_type == nas_nl_sock_T_NETCONF) ? NL_NETCONF_SOCKET_BUFFER_LEN: 0));
        printf("\r=========================================================================\r\n");

        nas_nl_stats_print (it->first);
    }
}

void os_send_refresh(nas_nl_sock_TYPES type, const char *vrf_name) {
    int RANDOM_REQ_ID = 0xee00;

    for ( auto it = nlm_sockets->begin(); it != nlm_sockets->end(); ++it) {
        if (((it->second).sock_type == type) &&
            (strncmp(vrf_name, (it->second).vrf_name,
                     strlen((it->second).vrf_name)) == 0) &&
            (nlm_handlers->at((it->second).sock_type).trigger!=NULL)) {
            nlm_handlers->at((it->second).sock_type).trigger(it->first,RANDOM_REQ_ID);
        }
    }
}

int net_main() {
    fd_set sel_fds;

    //Publish existing..
    publish_existing();

    g_if_db = new (std::nothrow) (INTERFACE);
    g_if_bridge_db = new (std::nothrow) (if_bridge);
    g_if_bond_db = new (std::nothrow) (if_bond);

    if(g_if_db == nullptr || g_if_bridge_db == nullptr || g_if_bridge_db == nullptr)
        EV_LOGGING(NETLINK,ERR,"INIT","Allocation failed for class objects...");

    FD_ZERO(&read_fds);
    /* Create netlink sockets for listening events from default VRF (namespace) */
    if (os_create_netlink_sock(NL_DEFAULT_VRF_NAME) != STD_ERR_OK) {
        os_del_netlink_sock(NL_DEFAULT_VRF_NAME);
        return 0;
    }

    while (1) {
        {
            /* Take the lock and update the select fds from read fds */
            std::lock_guard<std::mutex> lock(_nl_sock_mutex);
            memcpy ((char *) &sel_fds, (char *) &read_fds, sizeof(fd_set));
        }
        if(select((max_fd+1), &sel_fds, NULL, NULL, NULL) <= 0)
            continue;

        std::lock_guard<std::mutex> lock(_nl_sock_mutex);
        for ( auto it = nlm_sockets->begin(); it != nlm_sockets->end() ; ++it) {
            if (FD_ISSET(it->first,&sel_fds)) {
                netlink_tools_receive_event(it->first,nlm_handlers->at((it->second).sock_type).process,
                                            (it->second).vrf_name,buf,sizeof(buf),NULL);
            }
        }
    }

    /* deinit the netlink stats on exit */
    std::lock_guard<std::mutex> lock(_nl_sock_mutex);
    for ( auto it = nlm_sockets->begin(); it != nlm_sockets->end() ; ++it) {
        nas_nl_stats_deinit (it->first);
    }

    return 0;
}

t_std_error cps_api_net_notify_init(void) {

    EV_LOG_TRACE(ev_log_t_NULL, 3, "NET-NOTIFY","Initializing Net Notify Thread");

    if (nas_os_create_publish_handle() != STD_ERR_OK) {
        return STD_ERR(INTERFACE,FAIL,0);
    }
    std_thread_init_struct(&_net_main_thr);
    _net_main_thr.name = "db-api-linux-events";
    _net_main_thr.thread_function = (std_thread_function_t)net_main;
    t_std_error rc = std_thread_create(&_net_main_thr);
    if (rc!=STD_ERR_OK) {
        EV_LOGGING(INTERFACE,ERR,"db-api-linux-event-init-fail","Failed to "
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

/*
 * Enable NFLOG for AF_BRIDGE
 * For bridging NFLOG is used to copy certain packet types (like ARP)
 * user socket for injecting to ingress pipeline.
 */
bool os_nflog_enable ()
{
    std::stringstream str_stream;

    str_stream << "/proc/sys/net/netfilter/nf_log/7";
    std::string path = str_stream.str();
    std::ofstream nflog_conf (path.c_str());
    if(!nflog_conf.good()) {
        EV_LOGGING(NAS_OS,ERR,"NAS-UPD-NFLOG", "NFLOG file :%s enable failed!!!", path.c_str());
        return false;
    }

    nflog_conf << "nfnetlink_log";
    EV_LOGGING(NAS_OS,INFO,"NAS-UPD-NFLOG", "NFLOG file :%s enabled", path.c_str());
    nflog_conf.close();
    return true;
}

void os_refresh_netlink_info(const char *vrf_name) {
    nas_nl_sock_TYPES _refresh_list[] = {
            nas_nl_sock_T_INT,
            nas_nl_sock_T_NEI,
            nas_nl_sock_T_ROUTE,
            nas_nl_sock_T_NETCONF
    };
    size_t ix = 0;
    size_t refresh_mx = sizeof(_refresh_list)/sizeof(*_refresh_list);
    for ( ; ix < refresh_mx ; ++ix ) {
        os_send_refresh(_refresh_list[ix], vrf_name);
    }
}

t_std_error os_create_netlink_sock(const char *vrf_name) {
    nlm_sock_info sock_info;
    size_t ix = nas_nl_sock_T_ROUTE;
    /* Incase of mgmt VRF, before NAS process spawns
     * the NAS-linux thread, NAS-linux is handling the mgmt VRF creation
     * from the CPS context (NAS-Intf) and then creating the sockets for listening
     * the events from mgmt namespace and then performing the get all from the mgmt namespace,
     * if the _handle is nullptr while publishing the events from mgmt namespace,
     * CPS is asserting, to avoid that,
     * getting the CPS handle here for event publish. */
    if (nas_os_create_publish_handle() != STD_ERR_OK) {
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    /* Take the lock to update the read_fds */
    std::lock_guard<std::mutex> lock(_nl_sock_mutex);

    for ( ; ix < (size_t)nas_nl_sock_T_MAX; ++ix ) {
        int sock = nas_nl_sock_create(vrf_name, (nas_nl_sock_TYPES)(ix),true);
        if(sock == -1) {
            EV_LOGGING(NETLINK,ERR,"NL_SOCK","Failed to initialize sockets for VRF:%s "
                       "sock-id:%d err-no:%d",vrf_name, ix, errno);
            return (STD_ERR(NAS_OS,FAIL, 0));
        }
        EV_LOGGING(NETLINK, INFO, "NL_SOCK","Socket: VRF:%s id:%d, sock-fd:%d",
                   vrf_name, ix, sock);
        /* Fill netlink socket information */
        memset(&sock_info, 0, sizeof(sock_info));
        sock_info.sock_type = (nas_nl_sock_TYPES)(ix);
        safestrncpy(sock_info.vrf_name, vrf_name, sizeof(sock_info.vrf_name));
        nlm_sockets->insert(std::make_pair(sock, sock_info));

        /* Add socket fds into select read_fds for listening events from
         * the particular VRF */
        add_fd_set(sock,read_fds,max_fd);
        nas_nl_stats_init (sock);
    }

    os_refresh_netlink_info(vrf_name);
    return STD_ERR_OK;
}

t_std_error os_del_netlink_sock(const char *vrf_name) {
    /* Take the lock to update the read_fds */
    std::lock_guard<std::mutex> lock(_nl_sock_mutex);

    for ( auto it = nlm_sockets->begin(); it != nlm_sockets->end();) {
        EV_LOGGING(NETLINK,DEBUG,"NL_SOCK","Existig VRF:%s sock:%d", it->second.vrf_name, it->first);
        if (strncmp(vrf_name, it->second.vrf_name, strlen(it->second.vrf_name)) == 0) {
            nas_nl_stats_deinit(it->first);
            EV_LOGGING(NETLINK,DEBUG,"NL_SOCK","Closing VRF:%s sock:%d", it->second.vrf_name, it->first);
            close(it->first);
            auto del_it = it;
            it++;
            nlm_sockets->erase(del_it->first);
        } else {
            it++;
        }
    }
    /* Reset max_fd and read fds and fill based on available sockets */
    max_fd = -1;
    FD_ZERO(&read_fds);
    for ( auto it = nlm_sockets->begin(); it != nlm_sockets->end() ; ++it) {
        EV_LOGGING(NETLINK,DEBUG,"NL_SOCK","New VRF:%s sock:%d", it->second.vrf_name, it->first);
        add_fd_set( it->first,read_fds,max_fd);
    }

    return STD_ERR_OK;
}

t_std_error os_sock_create(const char *vrf_name, e_std_socket_domain_t domain, e_std_sock_type_t type,
                           int protocol, int *sock) {
    /* If the VRF name is non-default, select the namespace before creating the socket. */
    if (vrf_name && (strncmp(vrf_name, NL_DEFAULT_VRF_NAME, strlen(NL_DEFAULT_VRF_NAME)) != 0)) {
        if (std_netns_socket_create(domain, type, protocol,
                                    NULL, vrf_name, sock) != STD_ERR_OK) {
            EV_LOG_ERRNO(ev_log_t_NETLINK,0,"NK-SOCKCR",errno);
            return (STD_ERR(NAS_OS,FAIL, 0));
        }
    } else {
        if (std_socket_create(domain, type, protocol,
                              NULL, sock) != STD_ERR_OK) {
            EV_LOG_ERRNO(ev_log_t_NETLINK,0,"NK-SOCKCR",errno);
            return (STD_ERR(NAS_OS,FAIL, 0));
        }
    }
    return STD_ERR_OK;
}


}

