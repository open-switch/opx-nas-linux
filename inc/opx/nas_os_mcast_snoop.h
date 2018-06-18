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
 * nas_os_mcast_snoop.h
 */

#ifndef NAS_OS_MCAST_SNOOP_H_
#define NAS_OS_MCAST_SNOOP_H_

#include "cps_api_object.h"
#include "ds_common_types.h"
#include <linux/netlink.h>

#ifdef __cplusplus
extern "C" {
#endif

bool nl_to_mcast_snoop_info(int sock, int rt_msg_type, struct nlmsghdr *hdr, void *context);

bool nas_os_refresh_mcast_querier_status(hal_vlan_id_t vlan_id);

#ifdef __cplusplus
}
#endif

#endif /* NAS_OS_MCAST_SNOOP_H_ */
