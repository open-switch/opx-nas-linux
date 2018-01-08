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
 * filename : nas_os_l3_utils.h
 */

#ifndef NAS_OS_L3_UTILS_H_
#define NAS_OS_L3_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _nas_rt_msg_type {
    NAS_RT_ADD,
    NAS_RT_DEL,
    NAS_RT_SET,
    NAS_RT_REFRESH,
    NAS_RT_RESOLVE
}nas_rt_msg_type;

t_std_error nas_os_update_vrf(cps_api_object_t obj, nas_rt_msg_type m_type);
t_std_error nas_os_handle_intf_to_vrf(cps_api_object_t obj, nas_rt_msg_type m_type);
#ifdef __cplusplus
}
#endif

#endif /* NAS_OS_L3_UTILS_H_ */
