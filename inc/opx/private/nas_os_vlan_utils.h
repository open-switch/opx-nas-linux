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
 * filename : nas_os_vlan_utils.h
 */

#ifndef NAS_OS_VLAN_UTILS_H_
#define NAS_OS_VLAN_UTILS_H_


#include "ds_common_types.h"
#include <stdbool.h>
#include "std_error_codes.h"

#ifdef __cplusplus
extern "C" {
#endif


void nas_os_get_vlan_if_name(char *if_name, int len, hal_vlan_id_t vlan_id, char *vlan_name);

bool nas_os_physical_to_vlan_ifindex(hal_ifindex_t intf_index, hal_vlan_id_t vlan_id,
                                            bool to_vlan,hal_ifindex_t * index);
bool nas_os_sub_intf_name_to_intf_ifindex(char *sub_intf_name, hal_ifindex_t * index);
bool nas_os_sub_intf_to_phy_intf_name(char *sub_intf_name,  char * phy_intf_name);

bool nas_os_is_port_part_of_vlan(hal_ifindex_t vlan_ifindex, hal_ifindex_t port_ifindex);

t_std_error nas_os_handle_mac_port_chg(const char *vlan_name, const char *mac_str, hal_mac_addr_t *mac,
                                              uint32_t mbr_if_index, bool is_static);

t_std_error nas_os_mac_add_pending_mac_if_event(hal_ifindex_t ifindex);

t_std_error nas_os_mac_init();

#ifdef __cplusplus
}
#endif


#endif /* NAS_OS_VLAN_UTILS_H_ */
