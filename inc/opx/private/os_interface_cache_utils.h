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
 * filename : os_interface_cache_utils.h
 */

#ifndef OS_INTERFACE_CACHE_UTILS_H_
#define OS_INTERFACE_CACHE_UTILS_H_


#include "ds_common_types.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

t_std_error nas_os_check_intf_exists(hal_ifindex_t if_index, bool *present);

t_std_error nas_os_ifindex_to_intf_name_get(char *if_name, hal_ifindex_t if_index, size_t len);

#ifdef __cplusplus
}
#endif


#endif /* OS_INTERFACE_CACHE_UTILS_H_ */
