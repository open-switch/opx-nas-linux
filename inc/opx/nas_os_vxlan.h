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
 * nas_os_vxlan.h
 *
 */


#ifndef NAS_OS_VXLAN_H_
#define NAS_OS_VXLAN_H_

#include "cps_api_object.h"
#include "std_error_codes.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Create a VxLAN interface in the OS
 *
 * @param obj - CPS object which should contain following attributes
 *
 *     Input Attribute IDs                                     Description
 *
 *     IF_INTERFACES_INTERFACE_NAME                            VxLAN interface name
 *     DELL_IF_IF_INTERFACES_INTERFACE_VNI                     VxLAN interface vni
 *     DELL_IF_IF_INTERFACES_INTERFACE_SOURCE_IP_ADDR          VxLAN interface source IP address
 *     DELL_IF_IF_INTERFACES_INTERFACE_SOURCE_IP_ADDR_FAMILY   VxLAN interface source IP address family
 *
 *  Output Attribute Ids
 *
 *  DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX       VxLAN interface index returned by OS
 *
 * @return STD_ERR_OK if successful otherwise different return error code
 */
t_std_error nas_os_create_vxlan_interface(cps_api_object_t obj);


/**
 *  \}
 */

#ifdef __cplusplus
}
#endif


#endif /* NAS_OS_VXLAN_H_ */
