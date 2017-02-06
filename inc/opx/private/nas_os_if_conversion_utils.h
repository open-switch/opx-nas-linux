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

#ifndef NAS_OS_IF_CONVERSION_UTILS_H_
#define NAS_OS_IF_CONVERSION_UTILS_H_

#include "ds_common_types.h"
#include <unordered_set>

bool get_tagged_intf_list(hal_ifindex_t intf_name,std::unordered_set<hal_ifindex_t> & intf_list);

bool get_tagged_intf_index_from_name(const char * intf_name,hal_ifindex_t & intf_index);

bool nas_os_update_tagged_intf_mac_learning(hal_ifindex_t ifindex, hal_ifindex_t vlan_ifindex);



#endif /* NAS_OS_IF_CONVERSION_UTILS_H_ */
