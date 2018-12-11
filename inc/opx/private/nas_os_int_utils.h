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
 * nas_os_int_utils.h
 *
 *  Created on: May 19, 2015
 */

#ifndef CPS_API_LINUX_INC_PRIVATE_NAS_OS_INT_UTILS_H_
#define CPS_API_LINUX_INC_PRIVATE_NAS_OS_INT_UTILS_H_

#include "std_error_codes.h"
#include "cps_api_interface_types.h"
#include "ds_common_types.h"
#include "cps_api_object.h"
#include "dell-base-common.h"
#include "dell-base-interface-common.h"
#include "ietf-interfaces.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    OS_IF_CHANGE_NONE = 0x0,
    OS_IF_ADM_CHANGE  = 0x1,
    OS_IF_MTU_CHANGE  = 0x2,
    OS_IF_PHY_CHANGE  = 0x4,
    OS_IF_MASTER_CHANGE  = 0x5,
    OS_IF_OPER_CHANGE = 0x8,
    OS_IF_CHANGE_ALL  = 0xf
}if_change_t;

typedef struct ethtool_cmd_data {
    BASE_IF_SPEED_t          speed;
    BASE_CMN_DUPLEX_TYPE_t   duplex;
    bool                     autoneg;
    bool                     supported_speed[BASE_IF_SPEED_MAX];
} ethtool_cmd_data_t;

typedef struct os_int_stats {
    uint64_t     input_packets;
    uint64_t     input_bytes;
    uint64_t     input_multicast;
    uint64_t     input_errors;
    uint64_t     input_discards;
    uint64_t     output_packets;
    uint64_t     output_bytes;
    uint64_t     output_multicast;
    uint64_t     output_errors;
    uint64_t     output_invalid_protocol;
} os_int_stats_t;

t_std_error nas_os_util_int_admin_state_get(const char *name,
        db_interface_state_t *state, db_interface_operational_state_t *ostate) ;
t_std_error nas_os_util_int_admin_state_set(const char *name,
        db_interface_state_t state, db_interface_operational_state_t ostate);

t_std_error nas_os_util_int_mac_addr_get(const char *name, hal_mac_addr_t *macAddr);
t_std_error nas_os_util_int_mac_addr_set(const char *name, hal_mac_addr_t *macAddr);

t_std_error nas_os_util_int_mtu_set(const char *name, unsigned int mtu);
t_std_error nas_os_util_int_mtu_get(const char *name, unsigned int *mtu);

t_std_error nas_os_util_int_get_if(cps_api_object_t obj, hal_ifindex_t ifix);

t_std_error nas_os_util_int_flags_get(const char *vrf_name, const char *name, unsigned *flags);

t_std_error nas_os_util_int_get_if_details(const char *name, cps_api_object_t obj);

bool os_interface_mask_event(hal_ifindex_t ifix, if_change_t mask_val);

t_std_error os_intf_admin_state_get(hal_ifindex_t ifix, bool *p_admin_status);

t_std_error os_intf_mac_addr_get(hal_ifindex_t ifix, hal_mac_addr_t mac);

t_std_error nas_os_util_int_if_index_get(const char *vrf_name, const char *if_name, int *if_index);

t_std_error nas_os_util_int_if_name_get(const char *vrf_name, int if_index, char *if_name);

t_std_error nas_os_util_int_oper_status_get (const char *vrf_name, const char *name,
        IF_INTERFACES_STATE_INTERFACE_OPER_STATUS_t *oper_state);

t_std_error nas_os_util_int_ethtool_cmd_data_get (const char *vrf_name, const char *name, ethtool_cmd_data_t *eth_cmd);

t_std_error nas_os_util_int_ethtool_cmd_data_set (const char *vrf_name, const char *name, ethtool_cmd_data_t *eth_cmd);
t_std_error nas_os_util_int_stats_get (const char *vrf_name, const char *name, os_int_stats_t *stats);
#ifdef __cplusplus
}
#endif

#endif /* CPS_API_LINUX_INC_PRIVATE_NAS_OS_INT_UTILS_H_ */
