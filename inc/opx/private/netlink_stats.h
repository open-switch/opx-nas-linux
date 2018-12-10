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
 * filename: netlink_stats.h
 */

#ifndef __NETLINK_STATS_H
#define __NETLINK_STATS_H


#include "netlink_tools.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Netlink message counters */
typedef struct {
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
} nas_nl_stats_desc_t;

/**
 * @brief Initialize the netlink stats for the given socket
 *
 * @param[in] sock  socket id
 *
 * @return STD_ERR_OK if successful otherwise error code
 *
 * @warning This code can only be used from one thread - it is not thread safe
 */
t_std_error nas_nl_stats_init (int sock);

/**
 * @brief De-init the netlink stats for the given socket
 *
 * @param[in] sock socket id
 *
 * @return STD_ERR_OK if successful otherwise error code
 *
 * @warning This code can only be used from one thread - it is not thread safe
 */
t_std_error nas_nl_stats_deinit (int sock);

/**
 * @brief Print the netlink stats for the given socket
 *
 * @param[in] sock socket id
 *
 * @return STD_ERR_OK if successful otherwise error code
 *
 * @warning This code can only be used from one thread - it is not thread safe
 */
t_std_error nas_nl_stats_print (int sock);

/**
 * @brief Reset the netlink stats for the given socket
 *
 * @param[in] sock socket id
 *
 * @return STD_ERR_OK if successful otherwise error code
 *
 * @warning This code can only be used from one thread - it is not thread safe
 */
t_std_error nas_nl_stats_reset (int sock);

/**
 * @brief Update the netlink event receive stats for the given socket
 *
 * @param[in] sock socket id
 * @param[in] bulk_msg_count netlink bulk msg count
 *
 * @return STD_ERR_OK if successful otherwise error code
 *
 * @warning This code can only be used from one thread - it is not thread safe
 */
t_std_error nas_nl_stats_update (int sock, uint32_t bulk_msg_count);

/**
 * @brief Update the netlink event stats for specific netlink message type
 *
 * @param[in] sock socket id
 * @param[in] rt_msg_type netlink msg type
 *
 * @return STD_ERR_OK if successful otherwise error code
 *
 * @warning This code can only be used from one thread - it is not thread safe
 */
t_std_error nas_nl_stats_update_tot_msg (int sock, int rt_msg_type);

/**
 * @brief Update the netlink event stats for netlink messages
 *        that NAS is not interested in.
 *
 * @param[in] sock socket id
 * @param[in] rt_msg_type netlink msg type
 *
 * @return STD_ERR_OK if successful otherwise error code
 *
 * @warning This code can only be used from one thread - it is not thread safe
 */
t_std_error nas_nl_stats_update_invalid_msg (int sock, int rt_msg_type);

/**
 * @brief Update the netlink event publish stats for the given socket
 *
 * @param[in] sock socket id
 * @param[in] rt_msg_type netlink msg type
 *
 * @return STD_ERR_OK if successful otherwise error code
 *
 * @warning This code can only be used from one thread - it is not thread safe
 */
t_std_error nas_nl_stats_update_pub_msg (int sock, int rt_msg_type);

/**
 * @brief Update the netlink event publish failure stats for the given socket
 *
 * @param[in] sock socket id
 * @param[in] rt_msg_type netlink msg type
 *
 * @return STD_ERR_OK if successful otherwise error code
 *
 * @warning This code can only be used from one thread - it is not thread safe
 */
t_std_error nas_nl_stats_update_pub_msg_failed (int sock, int rt_msg_type);

#ifdef __cplusplus
}
#endif

#endif
