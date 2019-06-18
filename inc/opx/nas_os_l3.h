/*
 * Copyright (c) 2019 Dell Inc.
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
 * filename: nas_os_l3.h
 */


#ifndef NAS_OS_L3_H_
#define NAS_OS_L3_H_

#include "cps_api_object.h"
#include "std_error_codes.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief This adds an IPv4/v6 unicast route in kernel
 *
 * @param obj CPS API object which contains route params
 *
 * @return STD_ERR_OK if successful, otherwise different error code
 */
t_std_error nas_os_add_route (cps_api_object_t obj);

/**
 * @brief This deletes an IPv4/v6 unicast route in kernel
 *
 * @param obj CPS API object which contains route params
 *
 * @return STD_ERR_OK if successful, otherwise different error code
 */
t_std_error nas_os_del_route (cps_api_object_t obj);

/**
 * @brief This replaces an IPv4/v6 unicast route in kernel
 *
 * @param obj CPS API object which contains route params
 *
 * @return STD_ERR_OK if successful, otherwise different error code
 */
t_std_error nas_os_set_route (cps_api_object_t obj);

/**
 * @brief Update Route Nexthop(s): This is used to apped/delete nexthop(s) of an existing IPv4/v6 unicast route in kernel
 *
 * @param obj CPS API object which contains route params
 *
 * @return STD_ERR_OK if successful, otherwise different error code
 */
t_std_error nas_os_update_route_nexthop (cps_api_object_t obj);

/**
 * @brief This adds a neighbor entry in kernel
 *
 * @param obj CPS API object which contains arp/nd params
 *
 * @return STD_ERR_OK if successful, otherwise different error code
 */
t_std_error nas_os_add_neighbor (cps_api_object_t obj);

/**
 * @brief This deletes a neighbor entry in kernel
 *
 * @param obj CPS API object which contains arp/nd params
 *
 * @return STD_ERR_OK if successful, otherwise different error code
 */
t_std_error nas_os_del_neighbor (cps_api_object_t obj);

/**
 * @brief This replaces a neighbor entry in kernel
 *
 * @param obj CPS API object which contains arp/nd params
 *
 * @return STD_ERR_OK if successful, otherwise different error code
 */
t_std_error nas_os_set_neighbor (cps_api_object_t obj);

/**
 * @brief This refreshes the neighbor entry in kernel
 *
 * @param obj CPS API object which contains arp/nd params
 *
 * @return STD_ERR_OK if successful, otherwise different error code
 */
t_std_error nas_os_refresh_neighbor (cps_api_object_t obj);

/**
 * @brief This resolves the neighbor entry in kernel
 *
 * @param obj CPS API object which contains arp/nd params
 *
 * @return STD_ERR_OK if successful, otherwise different error code
 */
t_std_error nas_os_resolve_neighbor (cps_api_object_t obj);

/**
 * @brief This sets the neighbor entry state in kernel
 *
 * @param obj CPS API object which contains arp/nd params
 *
 * @return STD_ERR_OK if successful, otherwise different error code
 */
t_std_error nas_os_set_neighbor_state (cps_api_object_t obj);

/**
 * @brief : This creates the VRF in the kernel
 *
 * @param obj : CPS API object which contains VRF params
 *
 * @return : STD_ERR_OK if successful, otherwise different error code
 */
t_std_error nas_os_add_vrf (cps_api_object_t obj);

/**
 * @brief : This updates the VRF info. in the kernel
 *
 * @param obj : CPS API object which contains VRF params
 *
 * @return : STD_ERR_OK if successful, otherwise different error code
 */
t_std_error nas_os_set_vrf (cps_api_object_t obj);

/**
 * @brief : This deletes the VRF in the kernel
 *
 * @param obj : CPS API object which contains VRF params
 *
 * @return : STD_ERR_OK if successful, otherwise different error code
 */
t_std_error nas_os_del_vrf (cps_api_object_t obj);

/**
 * @brief : This binds the mgmt VRF with L3 interface in the kernel
 *
 * @param obj : CPS API object which contains VRF name and if name
 *
 * @return : STD_ERR_OK if successful, otherwise different error code
 */
t_std_error nas_os_bind_if_name_to_mgmt_vrf (cps_api_object_t obj);

/**
 * @brief : This unbinds the L3 interface from mgmt VRF in the kernel
 *
 * @param obj : CPS API object which contains VRF name and if name
 *
 * @return : STD_ERR_OK if successful, otherwise different error code
 */
t_std_error nas_os_unbind_if_name_from_mgmt_vrf (cps_api_object_t obj);

/**
 * @brief : This binds the VRF with L3 interface in the kernel
 *
 * @param obj : CPS API object which contains VRF name and if name
 *
 * @return : STD_ERR_OK if successful, otherwise different error code
 */
t_std_error nas_os_bind_if_name_to_vrf (cps_api_object_t obj);

/**
 * @brief : This unbinds the L3 interface from VRF in the kernel
 *
 * @param obj : CPS API object which contains VRF name and if name
 *
 * @return : STD_ERR_OK if successful, otherwise different error code
 */
t_std_error nas_os_unbind_if_name_from_vrf (cps_api_object_t obj);


#ifdef __cplusplus
}
#endif

#endif //NAS_OS_L3_H_
