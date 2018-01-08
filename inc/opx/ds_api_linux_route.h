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
 * ds_api_linux_route.h
 */

#ifndef DS_API_LINUX_ROUTE_H_
#define DS_API_LINUX_ROUTE_H_

#include "std_error_codes.h"
#include "cps_api_interface_types.h"
#include <linux/netlink.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This is the route handlers for the ds Api
 */
t_std_error ds_api_linux_route_init(cps_api_operation_handle_t handle);

bool nl_to_route_info(int rt_msg_type, struct nlmsghdr *hdr, cps_api_object_t data, void *context);

bool nl_request_existing_routes(int sock, int family, int req_id);

bool nas_rt_is_reserved_intf(char *intf_name);

bool nl_netconf_get_all_request(int sock, int family,int req_id);

/**
 * @brief flush neighbor entries for a given subnet in kernel
 *
 * @param[in] prefix ip prefix
 * @param[in] prefix_len prefix length
 * @param[in] is_intf_flush flag for interface based flush
 * @param[in] dev device name for interface based flush
 *
 * @return STD_ERR_OK if successful otherwise error code
 *
 */
t_std_error nas_os_flush_ip_neigh(char *prefix, uint32_t prefix_len, bool is_intf_flush, char *dev);
#ifdef __cplusplus
}
#endif

#endif /* DS_API_LINUX_ROUTE_H_ */
