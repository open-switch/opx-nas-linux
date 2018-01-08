/*
 * Copyright (c) 2017 Dell Inc.
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
 * filename: netlink_stats.cpp
 */

/*
 * netlink_stats.cpp
 */

#include "netlink_stats.h"
#include <map>

//NAS netlink stats table
static auto nlm_counters = new std::map<int, nas_nl_stats_desc_t>;

static inline bool nas_nl_is_rt_add_event (int rt_msg_type) {
    return ((rt_msg_type == RTM_NEWLINK) || (rt_msg_type == RTM_NEWADDR) ||
            (rt_msg_type == RTM_NEWROUTE) || (rt_msg_type == RTM_NEWNEIGH) ||
            (rt_msg_type == RTM_NEWNETCONF)  || (rt_msg_type == RTM_NEWMDB));
}

static inline bool nas_nl_is_rt_del_event (int rt_msg_type) {
    return ((rt_msg_type == RTM_DELLINK) || (rt_msg_type == RTM_DELADDR) ||
            (rt_msg_type == RTM_DELROUTE) || (rt_msg_type == RTM_DELNEIGH) ||
            (rt_msg_type == RTM_DELMDB) );
}

static inline bool nas_nl_is_rt_get_event (int rt_msg_type) {
    return ((rt_msg_type == RTM_GETLINK) || (rt_msg_type == RTM_GETADDR) ||
            (rt_msg_type == RTM_GETROUTE) || (rt_msg_type == RTM_GETNEIGH) ||
            (rt_msg_type == RTM_GETNETCONF) || (rt_msg_type == RTM_GETMDB));
}

static void nl_stats_print (int sock) {

    printf("\r %-10d | %-10d | %-10d | %-10d\r\n",
            nlm_counters->at(sock).num_events_rcvd,
            nlm_counters->at(sock).num_bulk_events_rcvd,
            nlm_counters->at(sock).max_events_rcvd_in_bulk,
            nlm_counters->at(sock).min_events_rcvd_in_bulk);
}

static void nl_stats_print_msg_detail (int sock) {

    printf("\r %-10d | %-10d | %-10d | %-12d | %-12d | %-12d\r\n",
           nlm_counters->at(sock).num_add_events,
           nlm_counters->at(sock).num_del_events,
           nlm_counters->at(sock).num_get_events,
           nlm_counters->at(sock).num_invalid_add_events,
           nlm_counters->at(sock).num_invalid_del_events,
           nlm_counters->at(sock).num_invalid_get_events);
}

static void nl_stats_print_pub_detail (int sock) {

    printf("\r %-10d | %-10d | %-10d | %-13d | %-13d | %-13d\r\n",
           nlm_counters->at(sock).num_add_events_pub,
           nlm_counters->at(sock).num_del_events_pub,
           nlm_counters->at(sock).num_get_events_pub,
           nlm_counters->at(sock).num_add_events_pub_failed,
           nlm_counters->at(sock).num_del_events_pub_failed,
           nlm_counters->at(sock).num_get_events_pub_failed);
}


/* function used to reset the nas netlink stats
 * for given netlink socket
 * This code can only be used from one thread - it is not thread safe
 */
extern "C" t_std_error nas_nl_stats_reset (int sock) {

    auto it = nlm_counters->find(sock);
    if (it == nlm_counters->end())
    {
        /* stats not initialized for fd */
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    it->second.num_events_rcvd = 0;
    it->second.num_bulk_events_rcvd = 0;
    it->second.max_events_rcvd_in_bulk = 0;
    it->second.min_events_rcvd_in_bulk = 0;

    it->second.num_add_events= 0;
    it->second.num_del_events= 0;
    it->second.num_get_events= 0;
    it->second.num_invalid_add_events= 0;
    it->second.num_invalid_del_events= 0;
    it->second.num_invalid_get_events= 0;
    it->second.num_add_events_pub= 0;
    it->second.num_del_events_pub= 0;
    it->second.num_get_events_pub= 0;
    it->second.num_add_events_pub_failed= 0;
    it->second.num_del_events_pub_failed= 0;
    it->second.num_get_events_pub_failed= 0;

    return STD_ERR_OK;
}

/* function used to print the nas netlink stats
 * for given netlink socket
 * This code can only be used from one thread - it is not thread safe
 */
extern "C" t_std_error nas_nl_stats_print (int sock) {

    auto it = nlm_counters->find(sock);
    if (it == nlm_counters->end())
    {
        /* stats not initialized for fd */
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    //printf("\r =========================\r\n");
    printf("\r %-10s | %-10s | %-10s | %-10s\r\n", "#events", "#bulk", "#max_bulk", "min_bulk");
    printf("\r %-10s | %-10s | %-10s | %-10s\r\n",
           "==========",
           "==========",
           "==========",
           "==========");
    /* dump netlink message rx stats information */
    nl_stats_print (sock);

    //printf("\r ============Netlink Message Details ===========\r\n");
    printf("\r %-10s | %-10s | %-10s | %-12s | %-12s | %-12s\r\n",
           "#add", "#del", "#get", "#invalid_add", "#invalid_del", "#invalid_get");
    printf("\r %-10s | %-10s | %-10s | %-12s | %-12s | %-12s\r\n",
           "==========", "==========", "==========", "============",
           "============", "============");
    /* dump netlink message stats information */
    nl_stats_print_msg_detail (sock);

    //printf("\r ============Netlink Message Publish Details ===========\r\n");
    printf("\r %-10s | %-10s | %-10s | %-13s | %-13s | %-13s\r\n",
           "#add_pub", "#del_pub", "#get_pub", "#add_pub_fail", "#del_pub_fail", "#get_pub_fail");
    printf("\r %-10s | %-10s | %-10s | %-13s | %-13s | %-13s\r\n",
           "==========", "==========", "==========", "=============",
           "=============", "=============");
    /* dump netlink message publish stats information */
    nl_stats_print_pub_detail (sock);

    return STD_ERR_OK;
}


/* function used to update the netlink stats for given rt_msg_type.
 * This code can only be used from one thread - it is not thread safe
 */
extern "C" t_std_error nas_nl_stats_update_tot_msg (int sock, int rt_msg_type) {

    auto it = nlm_counters->find(sock);
    if (it == nlm_counters->end())
    {
        /* stats not initialized for fd */
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    if (nas_nl_is_rt_add_event (rt_msg_type)) {
        it->second.num_add_events++;
    } else if (nas_nl_is_rt_del_event (rt_msg_type)) {
        it->second.num_del_events++;
    } else if (nas_nl_is_rt_get_event (rt_msg_type)) {
        it->second.num_get_events++;
    }
    return STD_ERR_OK;
}


/* function used to update the netlink stats for invalid evets
 * for given rt_msg_type.
 * This code can only be used from one thread - it is not thread safe
 */
extern "C" t_std_error nas_nl_stats_update_invalid_msg (int sock, int rt_msg_type) {

    auto it = nlm_counters->find(sock);
    if (it == nlm_counters->end())
    {
        /* stats not initialized for fd */
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    if (nas_nl_is_rt_add_event (rt_msg_type)) {
        it->second.num_invalid_add_events++;
    } else if (nas_nl_is_rt_del_event (rt_msg_type)) {
        it->second.num_invalid_del_events++;
    } else if (nas_nl_is_rt_get_event (rt_msg_type)) {
        it->second.num_invalid_get_events++;
    }
    return STD_ERR_OK;
}


/* function used to update the netlink event publish stats
 * for given rt_msg_type.
 * This code can only be used from one thread - it is not thread safe
 */
extern "C" t_std_error nas_nl_stats_update_pub_msg (int sock, int rt_msg_type) {

    auto it = nlm_counters->find(sock);
    if (it == nlm_counters->end())
    {
        /* stats not initialized for fd */
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    if (nas_nl_is_rt_add_event (rt_msg_type)) {
        it->second.num_add_events_pub++;
    } else if (nas_nl_is_rt_del_event (rt_msg_type)) {
        it->second.num_del_events_pub++;
    } else if (nas_nl_is_rt_get_event (rt_msg_type)) {
        it->second.num_get_events_pub++;
    }
    return STD_ERR_OK;
}


/* function used to update the netlink event publish failure stats
 * for given rt_msg_type.
 * This code can only be used from one thread - it is not thread safe
 */
extern "C" t_std_error nas_nl_stats_update_pub_msg_failed (int sock, int rt_msg_type) {

    auto it = nlm_counters->find(sock);
    if (it == nlm_counters->end())
    {
        /* stats not initialized for fd */
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    if (nas_nl_is_rt_add_event (rt_msg_type)) {
        it->second.num_add_events_pub_failed++;
    } else if (nas_nl_is_rt_del_event (rt_msg_type)) {
        it->second.num_del_events_pub_failed++;
    } else if (nas_nl_is_rt_get_event (rt_msg_type)) {
        it->second.num_get_events_pub_failed++;
    }
    return STD_ERR_OK;
}


/* function used to update the netlink event and bulk event receive stats.
 * This code can only be used from one thread - it is not thread safe
 */
extern "C" t_std_error nas_nl_stats_update (int sock, uint32_t bulk_msg_count) {

    auto it = nlm_counters->find(sock);
    if (it == nlm_counters->end())
    {
        /* stats not initialized for fd */
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    it->second.num_events_rcvd += bulk_msg_count;

    if (bulk_msg_count > 1) //increment bulk rcvd count only if the count is > 1.
    {
        it->second.num_bulk_events_rcvd++;

        if (bulk_msg_count > it->second.max_events_rcvd_in_bulk)
            it->second.max_events_rcvd_in_bulk =  bulk_msg_count;

        if (bulk_msg_count < it->second.min_events_rcvd_in_bulk)
            it->second.min_events_rcvd_in_bulk =  bulk_msg_count;
        else if (it->second.min_events_rcvd_in_bulk == 0)
            it->second.min_events_rcvd_in_bulk =  bulk_msg_count;
    }

    return STD_ERR_OK;
}


/* function used to initialize the nas netlink event stats
 * for given netlink socket.
 * This code can only be used from one thread - it is not thread safe
 */
extern "C" t_std_error nas_nl_stats_init (int sock) {

    auto it = nlm_counters->find(sock);
    if (it != nlm_counters->end())
    {
        /* stats already initialized for fd */
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    nas_nl_stats_desc_t nas_nl_stats;
    memset (&nas_nl_stats, 0, sizeof (nas_nl_stats_desc_t));

    nlm_counters->insert({sock,std::move(nas_nl_stats)});

    return STD_ERR_OK;
}


/* function used to de-init the nas netlink event stats
 * for given netlink socket
 * This code can only be used from one thread - it is not thread safe
 */
extern "C" t_std_error nas_nl_stats_deinit (int sock) {

    auto it = nlm_counters->find(sock);
    if (it == nlm_counters->end())
    {
        /* stats not initialized for fd */
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    nlm_counters->erase(sock);

    return STD_ERR_OK;
}
