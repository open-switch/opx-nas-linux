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
 * filename: nas_os_l3.c
 */


#include "cps_api_object_attr.h"
#include "cps_api_operation.h"
#include "cps_api_object.h"
#include "std_error_codes.h"
#include "dell-base-routing.h"
#include "os-routing-events.h"
#include "standard_netlink_requests.h"
#include "std_error_codes.h"
#include "netlink_tools.h"
#include "nas_os_l3.h"
#include "event_log.h"
#include "cps_api_operation.h"
#include "cps_api_route.h"
#include "cps_class_map.h"
#include "nas_nlmsg.h"
#include "net_publish.h"
#include "std_ip_utils.h"
#include "nas_nlmsg_object_utils.h"
#include "hal_if_mapping.h"
#include "std_utils.h"
#include "std_mac_utils.h"
#include "ietf-network-instance.h"
#include "vrf-mgmt.h"
#include "nas_os_int_utils.h"
#include "nas_os_l3_utils.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

/* To support the IPv6 route with 256 NHs - 8K buffer is required */
#define NL_RT_MSG_BUFFER_LEN  8192 /* Buffer len to update the route to kernel */
#define NL_RT_RMSG_BUFFER_LEN 1024 /* Buffer len to receive reply for the route from kernel */
#define NL_RT_NBR_MSG_BUFFER_LEN 1024 /* Buffer len to update the neighbor to kernel */
#define MAX_NL_NH_ECMP_COUNT  256
#define MAC_STRING_LEN 20

static inline uint16_t nas_os_get_nl_flags(nas_rt_msg_type m_type)
{
    uint16_t flags = (NLM_F_REQUEST | NLM_F_ACK);
    if(m_type == NAS_RT_ADD) {
        flags |= NLM_F_CREATE | NLM_F_EXCL;
    } else if (m_type == NAS_RT_SET) {
        flags |= NLM_F_CREATE | NLM_F_REPLACE;
    }
    return flags;
}

#define MAX_CPS_MSG_SIZE 10000

/*
 * Publish route from here is mainly to handle route delete cases.
 * When application try to delete a route and if it is already deleted in kernel
 * (e.g interface down scenario), then NAS-L3 need to get this delete message.
 * NH and other related info is currently not needed. (Please check the invocation below)
 *
 * @Todo, This has to be revisited for any generic solution. This approach is to handle
 * the current open issues related to interface "shutdown"
 */

static t_std_error nas_os_publish_route(int rt_msg_type, cps_api_object_t obj, bool is_rt_route_replace)
{
    static char buff[MAX_CPS_MSG_SIZE];
    hal_vrf_id_t rt_vrf_id = 0;
    hal_vrf_id_t nh_vrf_id = 0;

    cps_api_operation_types_t op;
    if(rt_msg_type == RTM_NEWROUTE) {
        op = (is_rt_route_replace) ? cps_api_oper_SET : cps_api_oper_CREATE;
    } else if(rt_msg_type == RTM_DELROUTE) {
        op = cps_api_oper_DELETE;
    } else {
        EV_LOGGING (NAS_OS, ERR, "ROUTE-PUBLISH", "Invalid rt_msg_type:%d", rt_msg_type);
        return (STD_ERR(NAS_OS, FAIL, 0));
    }

    cps_api_object_t new_obj = cps_api_object_init(buff,sizeof(buff));

    cps_api_key_from_attr_with_qual(cps_api_object_key(new_obj), OS_RE_BASE_ROUTE_OBJ_ENTRY_OBJ,
                                    cps_api_qualifier_OBSERVED);
    cps_api_object_set_type_operation(cps_api_object_key(new_obj), op);

    cps_api_object_attr_t prefix   = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX);
    if (prefix == CPS_API_ATTR_NULL) {
        EV_LOGGING (NAS_OS, ERR, "ROUTE-PUBLISH", "Prefix is not present!");
        return (STD_ERR(NAS_OS, FAIL, 0));
    }
    cps_api_object_attr_t af       = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_AF);
    cps_api_object_attr_t pref_len = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN);
    cps_api_object_attr_t nh_count = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_NH_COUNT);

    const char *rt_vrf_name           = cps_api_object_get_data(obj,BASE_ROUTE_OBJ_VRF_NAME);
    const char *nh_vrf_name           = cps_api_object_get_data(obj,BASE_ROUTE_OBJ_ENTRY_NH_VRF_NAME);

    if (rt_vrf_name) {
        cps_api_object_attr_add(new_obj, BASE_ROUTE_OBJ_VRF_NAME, rt_vrf_name, strlen(rt_vrf_name)+1);
        if (nas_get_vrf_internal_id_from_vrf_name(rt_vrf_name, &rt_vrf_id) != STD_ERR_OK) {
            EV_LOGGING (NAS_OS, ERR, "ROUTE-PUBLISH", "Route VRF name:%s to id mapping is not present!",
                        rt_vrf_name);
            return (STD_ERR(NAS_OS, FAIL, 0));
        }
        cps_api_object_attr_add_u32(new_obj, BASE_ROUTE_OBJ_VRF_ID, rt_vrf_id);
        if (nh_vrf_name == CPS_API_ATTR_NULL) {
            cps_api_object_attr_add_u32(new_obj, BASE_ROUTE_OBJ_ENTRY_VRF_ID, rt_vrf_id);
            cps_api_object_attr_add(new_obj, BASE_ROUTE_OBJ_ENTRY_NH_VRF_NAME, rt_vrf_name, strlen(rt_vrf_name)+1);
        }
    } else {
        /* If VRF-name is not present, assume default VRF-id and also if NH VRF_name is not present,
         * use route VRF_id for NH VRF-id as well.*/
        cps_api_object_attr_add_u32(new_obj, BASE_ROUTE_OBJ_VRF_ID, rt_vrf_id);
        if (nh_vrf_name == CPS_API_ATTR_NULL) {
            cps_api_object_attr_add_u32(new_obj, BASE_ROUTE_OBJ_ENTRY_VRF_ID, rt_vrf_id);
            cps_api_object_attr_add(new_obj, BASE_ROUTE_OBJ_ENTRY_NH_VRF_NAME, NAS_DEFAULT_VRF_NAME, strlen(NAS_DEFAULT_VRF_NAME)+1);
        }
    }
    if (nh_vrf_name) {
        cps_api_object_attr_add(new_obj, BASE_ROUTE_OBJ_ENTRY_NH_VRF_NAME, nh_vrf_name, strlen(nh_vrf_name)+1);
        if (nas_get_vrf_internal_id_from_vrf_name(nh_vrf_name, &nh_vrf_id) != STD_ERR_OK) {
            EV_LOGGING (NAS_OS, ERR, "ROUTE-PUBLISH", "Nexthop VRF name:%s to id mapping is not present!",
                        nh_vrf_name);
            return (STD_ERR(NAS_OS, FAIL, 0));
        }
        cps_api_object_attr_add_u32(new_obj, BASE_ROUTE_OBJ_ENTRY_VRF_ID, nh_vrf_id);
    }
    cps_api_object_attr_add_u32(new_obj,BASE_ROUTE_OBJ_ENTRY_AF,
                                cps_api_object_attr_data_u32(af));

    uint32_t addr_len;
    if(cps_api_object_attr_data_u32(af) == AF_INET) {
        addr_len = HAL_INET4_LEN;
    } else {
        addr_len = HAL_INET6_LEN;
    }
    cps_api_object_attr_add(new_obj, BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,
                            cps_api_object_attr_data_bin(prefix),
                            cps_api_object_attr_len(prefix));

    cps_api_object_attr_add_u32(new_obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,
            cps_api_object_attr_data_u32(pref_len));

    uint32_t nhc = 0;
    if (nh_count != CPS_API_ATTR_NULL) {
        nhc = cps_api_object_attr_data_u32(nh_count);

        cps_api_object_attr_add_u32(new_obj,BASE_ROUTE_OBJ_ENTRY_NH_COUNT,nhc);
        size_t ix = 0;
        for (ix = 0; ix < nhc ; ++ix) {
            cps_api_attr_id_t ids[3] = { BASE_ROUTE_OBJ_ENTRY_NH_LIST,
                ix, BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR};
            const int ids_len = sizeof(ids)/sizeof(*ids);

            cps_api_object_attr_t gw = cps_api_object_e_get(obj,ids,ids_len);

            ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
            cps_api_object_attr_t gwix = cps_api_object_e_get(obj,ids,ids_len);

            ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFNAME;
            cps_api_object_attr_t gw_ifname = cps_api_object_e_get(obj,ids,ids_len);

            cps_api_attr_id_t new_ids[3];
            new_ids[0] = BASE_ROUTE_OBJ_ENTRY_NH_LIST;
            new_ids[1] = ix;

            if (gw != CPS_API_ATTR_NULL) {
                new_ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR;

                hal_ip_addr_t ip;
                if(addr_len == HAL_INET4_LEN) {
                    ip.af_index = AF_INET;
                    memcpy(&(ip.u.v4_addr), cps_api_object_attr_data_bin(gw),addr_len);
                } else {
                    ip.af_index = AF_INET6;
                    memcpy(&(ip.u.v6_addr), cps_api_object_attr_data_bin(gw),addr_len);
                }
                cps_api_object_e_add(new_obj, new_ids, ids_len, cps_api_object_ATTR_T_BIN,
                                     &ip,sizeof(ip));
            }

            if (gwix != CPS_API_ATTR_NULL) {
                new_ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
                uint32_t gw_idx = cps_api_object_attr_data_u32(gwix);
                cps_api_object_e_add(new_obj,new_ids,ids_len,cps_api_object_ATTR_T_U32,
                                     (void *)&gw_idx, sizeof(uint32_t));
            } else if (gw_ifname != CPS_API_ATTR_NULL) {
                /* If the if-index is not present in the obj,
                 * get if-index from if-name */
                interface_ctrl_t intf_ctrl;
                t_std_error rc = STD_ERR_OK;
                memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
                intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
                safestrncpy(intf_ctrl.if_name, (const char *)cps_api_object_attr_data_bin(gw_ifname),
                            cps_api_object_attr_len(gw_ifname));

                if((rc= dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                    EV_LOGGING(NAS_OS, ERR, "ROUTE-UPD",
                               "Interface %s to if_index returned error %d",
                               intf_ctrl.if_name, rc);
                    return (STD_ERR(NAS_OS, FAIL, 0));
                }
                new_ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
                cps_api_object_e_add(new_obj,new_ids,ids_len,cps_api_object_ATTR_T_U32,
                                     (void *)&intf_ctrl.if_index, sizeof(uint32_t));
            }
        }
    }

    EV_LOGGING(NAS_OS, INFO,"ROUTE-UPD","Publishing object");

    net_publish_event(new_obj);

    return STD_ERR_OK;
}

/*
 * Publish route from here is mainly to handle route nexthop delete cases.
 * When application try to delete a route,nexthop and if it is already deleted in kernel
 * (e.g interface down scenario), then NAS-L3 need to get this delete message.
 *
 * @Todo, This has to be revisited for any generic solution. This approach is to handle
 * the current open issues related to interface "shutdown"
 */
static t_std_error nas_os_publish_route_nexthop (int rt_msg_type, cps_api_object_t obj, bool is_rt_route_replace)
{
    static char buff[MAX_CPS_MSG_SIZE];
    hal_vrf_id_t rt_vrf_id = 0;
    hal_vrf_id_t nh_vrf_id = 0;

    cps_api_operation_types_t op;
    if(rt_msg_type == RTM_NEWROUTE) {
        op = (is_rt_route_replace) ? cps_api_oper_SET : cps_api_oper_CREATE;
    } else if(rt_msg_type == RTM_DELROUTE) {
        op = cps_api_oper_DELETE;
    } else {
        EV_LOGGING (NAS_OS, ERR, "ROUTE-PUBLISH", "Invalid rt_msg_type:%d", rt_msg_type);
        return (STD_ERR(NAS_OS, FAIL, 0));
    }

    cps_api_object_t new_obj = cps_api_object_init(buff,sizeof(buff));

    cps_api_key_from_attr_with_qual(cps_api_object_key(new_obj), OS_RE_BASE_ROUTE_OBJ_ENTRY_OBJ,
                                    cps_api_qualifier_OBSERVED);
    cps_api_object_set_type_operation(cps_api_object_key(new_obj), op);

    cps_api_object_attr_t prefix   = cps_api_object_attr_get(obj, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_ROUTE_PREFIX);
    if (prefix == CPS_API_ATTR_NULL) {
        EV_LOGGING (NAS_OS, ERR, "ROUTE-PUBLISH", "Prefix is not present!");
        return (STD_ERR(NAS_OS, FAIL, 0));
    }
    cps_api_object_attr_t af       = cps_api_object_attr_get(obj, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_AF);
    cps_api_object_attr_t pref_len = cps_api_object_attr_get(obj, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_PREFIX_LEN);
    cps_api_object_attr_t nh_count = cps_api_object_attr_get(obj, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_COUNT);

    const char *rt_vrf_name = cps_api_object_get_data(obj,BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_VRF_NAME);
    const char *nh_vrf_name = cps_api_object_get_data(obj,BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_VRF_NAME);

    if (rt_vrf_name) {
        cps_api_object_attr_add(new_obj, BASE_ROUTE_OBJ_VRF_NAME, rt_vrf_name, strlen(rt_vrf_name)+1);
        if (nas_get_vrf_internal_id_from_vrf_name(rt_vrf_name, &rt_vrf_id) != STD_ERR_OK) {
            EV_LOGGING (NAS_OS, ERR, "ROUTE-PUBLISH", "Route VRF name:%s to id mapping is not present!",
                        rt_vrf_name);
            return (STD_ERR(NAS_OS, FAIL, 0));
        }
        cps_api_object_attr_add_u32(new_obj, BASE_ROUTE_OBJ_VRF_ID, rt_vrf_id);
        if (nh_vrf_name == CPS_API_ATTR_NULL) {
            cps_api_object_attr_add_u32(new_obj, BASE_ROUTE_OBJ_ENTRY_VRF_ID, rt_vrf_id);
            cps_api_object_attr_add(new_obj, BASE_ROUTE_OBJ_ENTRY_NH_VRF_NAME, rt_vrf_name, strlen(rt_vrf_name)+1);
        }
    } else {
        /* If VRF-name is not present, assume default VRF-id and also if NH VRF_name is not present,
         * use route VRF_id for NH VRF-id as well.*/
        cps_api_object_attr_add_u32(new_obj, BASE_ROUTE_OBJ_VRF_ID, rt_vrf_id);
        if (nh_vrf_name == CPS_API_ATTR_NULL) {
            cps_api_object_attr_add_u32(new_obj, BASE_ROUTE_OBJ_ENTRY_VRF_ID, rt_vrf_id);
            cps_api_object_attr_add(new_obj, BASE_ROUTE_OBJ_ENTRY_NH_VRF_NAME, NAS_DEFAULT_VRF_NAME, strlen(NAS_DEFAULT_VRF_NAME)+1);
        }
    }
    if (nh_vrf_name) {
        cps_api_object_attr_add(new_obj, BASE_ROUTE_OBJ_ENTRY_NH_VRF_NAME, nh_vrf_name, strlen(nh_vrf_name)+1);
        if (nas_get_vrf_internal_id_from_vrf_name(nh_vrf_name, &nh_vrf_id) != STD_ERR_OK) {
            EV_LOGGING (NAS_OS, ERR, "ROUTE-PUBLISH", "Nexthop VRF name:%s to id mapping is not present!",
                        nh_vrf_name);
            return (STD_ERR(NAS_OS, FAIL, 0));
        }
        cps_api_object_attr_add_u32(new_obj, BASE_ROUTE_OBJ_ENTRY_VRF_ID, nh_vrf_id);
    }
    cps_api_object_attr_add_u32(new_obj,BASE_ROUTE_OBJ_ENTRY_AF,
                                cps_api_object_attr_data_u32(af));

    uint32_t addr_len;
    if(cps_api_object_attr_data_u32(af) == AF_INET) {
        addr_len = HAL_INET4_LEN;
    } else {
        addr_len = HAL_INET6_LEN;
    }
    cps_api_object_attr_add(new_obj, BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,
                            cps_api_object_attr_data_bin(prefix),
                            cps_api_object_attr_len(prefix));

    cps_api_object_attr_add_u32(new_obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,
            cps_api_object_attr_data_u32(pref_len));

    uint32_t nhc = 0;
    if (nh_count != CPS_API_ATTR_NULL) {
        nhc = cps_api_object_attr_data_u32(nh_count);

        cps_api_object_attr_add_u32(new_obj,BASE_ROUTE_OBJ_ENTRY_NH_COUNT,nhc);
        size_t ix = 0;
        for (ix = 0; ix < nhc ; ++ix) {
            cps_api_attr_id_t ids[3] = { BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST,
                ix, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_NH_ADDR};
            const int ids_len = sizeof(ids)/sizeof(*ids);

            cps_api_object_attr_t gw = cps_api_object_e_get(obj,ids,ids_len);

            ids[2] = BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_IFINDEX;
            cps_api_object_attr_t gwix = cps_api_object_e_get(obj,ids,ids_len);

            ids[2] = BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_IFNAME;
            cps_api_object_attr_t gw_ifname = cps_api_object_e_get(obj,ids,ids_len);

            cps_api_attr_id_t new_ids[3];
            new_ids[0] = BASE_ROUTE_OBJ_ENTRY_NH_LIST;
            new_ids[1] = ix;

            if (gw != CPS_API_ATTR_NULL) {
                new_ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR;

                hal_ip_addr_t ip;
                if(addr_len == HAL_INET4_LEN) {
                    ip.af_index = AF_INET;
                    memcpy(&(ip.u.v4_addr), cps_api_object_attr_data_bin(gw),addr_len);
                } else {
                    ip.af_index = AF_INET6;
                    memcpy(&(ip.u.v6_addr), cps_api_object_attr_data_bin(gw),addr_len);
                }
                cps_api_object_e_add(new_obj, new_ids, ids_len, cps_api_object_ATTR_T_BIN,
                                     &ip,sizeof(ip));
            }

            if (gwix != CPS_API_ATTR_NULL) {
                new_ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
                uint32_t gw_idx = cps_api_object_attr_data_u32(gwix);
                cps_api_object_e_add(new_obj,new_ids,ids_len,cps_api_object_ATTR_T_U32,
                                     (void *)&gw_idx, sizeof(uint32_t));
            } else if (gw_ifname != CPS_API_ATTR_NULL) {
                /* If the if-index is not present in the obj,
                 * get if-index from if-name */
                interface_ctrl_t intf_ctrl;
                t_std_error rc = STD_ERR_OK;
                memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
                intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
                safestrncpy(intf_ctrl.if_name, (const char *)cps_api_object_attr_data_bin(gw_ifname),
                            cps_api_object_attr_len(gw_ifname));

                if((rc= dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                    EV_LOGGING(NAS_OS, ERR, "ROUTE-UPD",
                               "Interface %s to if_index returned error %d",
                               intf_ctrl.if_name, rc);
                    return (STD_ERR(NAS_OS, FAIL, 0));
                }
                new_ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
                cps_api_object_e_add(new_obj,new_ids,ids_len,cps_api_object_ATTR_T_U32,
                                     (void *)&intf_ctrl.if_index, sizeof(uint32_t));
            }

        }
    }

    EV_LOGGING (NAS_OS, INFO, "ROUTE-NH-UPD","Publishing object");

    net_publish_event(new_obj);

    return STD_ERR_OK;
}


/* Ensure for any changes made to nas_os_update_route() related to netlink route
 * processing, nas_os_update_route_nexthop() has to be updated accordingly.
 */
cps_api_return_code_t nas_os_update_route (cps_api_object_t obj, nas_rt_msg_type m_type)
{
    static char buff[NL_RT_MSG_BUFFER_LEN], buff1[NL_RT_RMSG_BUFFER_LEN]; // Allocate from DS
    char            addr_str[INET6_ADDRSTRLEN];
    int         nhm_count = 0;
    bool        repeat_delete = false;

    memset(buff,0,sizeof(struct nlmsghdr));

    const char *vrf_name           = cps_api_object_get_data(obj,BASE_ROUTE_OBJ_VRF_NAME);
    cps_api_object_attr_t prefix   = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX);
    cps_api_object_attr_t af       = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_AF);
    cps_api_object_attr_t nh_count = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_NH_COUNT);
    cps_api_object_attr_t pref_len = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN);
    cps_api_object_attr_t spl_nexthop_option =
                            cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_SPECIAL_NEXT_HOP);

    if (prefix == CPS_API_ATTR_NULL || af == CPS_API_ATTR_NULL ||  pref_len == CPS_API_ATTR_NULL
        || (m_type != NAS_RT_DEL && (nh_count == CPS_API_ATTR_NULL && spl_nexthop_option == CPS_API_ATTR_NULL))) {
        EV_LOGGING(NAS_OS, ERR, "ROUTE-UPD", "Missing route params");
        return cps_api_ret_code_ERR;
    }

    uint32_t nhc = 0;
    if (nh_count != CPS_API_ATTR_NULL) nhc = cps_api_object_attr_data_u32(nh_count);

    /* Check whether route and NH are in the different VRF, if yes, it's leaked route,
     * do local publish to handle it in the NAS-L3 for NPU programming only. */
    const char *nh_vrf_name = cps_api_object_get_data(obj,BASE_ROUTE_OBJ_ENTRY_NH_VRF_NAME);
    if (nh_vrf_name) {
        if (((vrf_name == NULL) && (strncmp(nh_vrf_name, NAS_DEFAULT_VRF_NAME, NAS_VRF_NAME_SZ))) ||
            (vrf_name && (strncmp(vrf_name, nh_vrf_name, NAS_VRF_NAME_SZ)))) {
            nas_os_publish_route((m_type == NAS_RT_DEL)?RTM_DELROUTE:RTM_NEWROUTE,
                                 obj, false);
            return STD_ERR_OK;
        }
    }
    uint32_t spl_nh_type = 0;

    if (spl_nexthop_option != CPS_API_ATTR_NULL) {
        spl_nh_type = cps_api_object_attr_data_u32(spl_nexthop_option);

        if (nhc > 1) {
            EV_LOGGING (NAS_OS, ERR, "NAS-RT-CPS-SET",
                        "Invalid route params for "
                        "special next hop option: %d, nh_count: %d",
                        spl_nh_type, nhc);
            return cps_api_ret_code_ERR;
        }
    }

    struct nlmsghdr *nlh = (struct nlmsghdr *)
                         nlmsg_reserve((struct nlmsghdr *)buff,sizeof(buff),sizeof(struct nlmsghdr));
    struct rtmsg * rm = (struct rtmsg *) nlmsg_reserve(nlh,sizeof(buff),sizeof(struct rtmsg));
    memset(rm, 0, sizeof(struct rtmsg));

    uint16_t flags = nas_os_get_nl_flags(m_type);
    uint16_t type = (m_type == NAS_RT_DEL)?RTM_DELROUTE:RTM_NEWROUTE;

    nas_os_pack_nl_hdr(nlh, type, flags);

    rm->rtm_table = RT_TABLE_MAIN;
    rm->rtm_protocol = RTPROT_UNSPEC; // This could be assigned to correct owner in future

    /* For route delete, initialize scope to no-where and
     * this will get updated to link when Nh addr/ifx is provided.
     */
    if (type != RTM_DELROUTE)
        rm->rtm_scope = RT_SCOPE_UNIVERSE;
    else
        rm->rtm_scope = RT_SCOPE_NOWHERE;


    if (spl_nexthop_option == CPS_API_ATTR_NULL) {
        rm->rtm_type = RTN_UNICAST;
    } else {
        switch (spl_nh_type) {
            case BASE_ROUTE_SPECIAL_NEXT_HOP_BLACKHOLE:
                rm->rtm_type = RTN_BLACKHOLE;
                rm->rtm_scope = RT_SCOPE_NOWHERE;
                rm->rtm_protocol = RTPROT_STATIC;
            break;
            case BASE_ROUTE_SPECIAL_NEXT_HOP_UNREACHABLE:
                rm->rtm_type = RTN_UNREACHABLE;
            break;
            case BASE_ROUTE_SPECIAL_NEXT_HOP_PROHIBIT:
                rm->rtm_type = RTN_PROHIBIT;
            break;
            case BASE_ROUTE_SPECIAL_NEXT_HOP_RECEIVE:
                rm->rtm_type = RTN_LOCAL;
                rm->rtm_scope = RT_SCOPE_HOST;
            break;
            default:
                EV_LOGGING(NAS_OS, ERR, "ROUTE-UPD",
                           "Invalid special nexthop option (%d) specified",
                           spl_nh_type);
                return cps_api_ret_code_ERR;
        }
    }

    rm->rtm_dst_len = cps_api_object_attr_data_u32(pref_len);
    rm->rtm_family = (unsigned char) cps_api_object_attr_data_u32(af);

    uint32_t addr_len = (rm->rtm_family == AF_INET)?HAL_INET4_LEN:HAL_INET6_LEN;
    nlmsg_add_attr(nlh,sizeof(buff),RTA_DST,cps_api_object_attr_data_bin(prefix),addr_len);

    EV_LOGGING (NAS_OS,INFO, "ROUTE-UPD","VRF:%s NH count:%d family:%s msg:%s for prefix:%s len:%d proto:%d scope:%d type:%d",
                (vrf_name ? vrf_name : ""), nhc,
           ((rm->rtm_family == AF_INET) ? "IPv4" : "IPv6"), ((m_type == NAS_RT_ADD) ? "Route-Add" : ((m_type == NAS_RT_DEL) ? "Route-Del" : "Route-Set")),
           ((rm->rtm_family == AF_INET) ?
            (inet_ntop(rm->rtm_family, cps_api_object_attr_data_bin(prefix), addr_str, INET_ADDRSTRLEN)) :
            (inet_ntop(rm->rtm_family, cps_api_object_attr_data_bin(prefix), addr_str, INET6_ADDRSTRLEN))),
           rm->rtm_dst_len, rm->rtm_protocol, rm->rtm_scope, rm->rtm_type);

    if (nhc == 1) {
        cps_api_attr_id_t ids[3] = { BASE_ROUTE_OBJ_ENTRY_NH_LIST,
                                     0, BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR};
        const int ids_len = sizeof(ids)/sizeof(*ids);
        cps_api_object_attr_t gw = cps_api_object_e_get(obj,ids,ids_len);
        if (gw != CPS_API_ATTR_NULL) {
            nlmsg_add_attr(nlh,sizeof(buff),RTA_GATEWAY,cps_api_object_attr_data_bin(gw),addr_len);
            rm->rtm_scope = RT_SCOPE_UNIVERSE; // set scope to universe when gateway is specified
            EV_LOGGING(NAS_OS, INFO,"ROUTE-UPD","NH:%s scope:%d",
                   ((rm->rtm_family == AF_INET) ?
                    (inet_ntop(rm->rtm_family, cps_api_object_attr_data_bin(gw), addr_str, INET_ADDRSTRLEN)) :
                    (inet_ntop(rm->rtm_family, cps_api_object_attr_data_bin(gw), addr_str, INET6_ADDRSTRLEN))),
                   rm->rtm_scope);
        } else {
            EV_LOGGING(NAS_OS, INFO, "ROUTE-UPD", "Missing Gateway, could be intf route");
            /*
             * This could be an interface route, do not return from here!
             */
        }

        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
        cps_api_object_attr_t gwix = cps_api_object_e_get(obj,ids,ids_len);
        if (gwix != CPS_API_ATTR_NULL) {
            if ((gw == CPS_API_ATTR_NULL) && (rm->rtm_type != RTN_LOCAL)) {
                rm->rtm_scope = RT_SCOPE_LINK;
                /* For route create with link scope, change the flags to route replace.
                 * This is needed inorder to overwrite the connected route with RTM created route,
                 * so that the netlink event will be generated for the RTM route instead of going
                 * via local event publish for failures during route programming.
                 * This is done to avoid any possible race conditions b/w netmain thread
                 * (which handles netlink event and does event publish to NAS) and
                 * CPS handler for route programming which does local event publish on
                 * netlink config failures.
                 */
                if (m_type == NAS_RT_ADD) {
                    nlh->nlmsg_flags &= ~NLM_F_EXCL;
                    nlh->nlmsg_flags |= NLM_F_REPLACE;
                    EV_LOGGING(NAS_OS, INFO, "ROUTE-UPD", "modified from route create to replace: flags:0x%x", nlh->nlmsg_flags);
                }
            }

            EV_LOGGING(NAS_OS, INFO,"ROUTE-UPD","out-intf: %d scope:%d",
                   (int)cps_api_object_attr_data_u32(gwix), rm->rtm_scope);
            nas_nl_add_attr_int(nlh,sizeof(buff),RTA_OIF,gwix);
        } else {
            ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFNAME;
            cps_api_object_attr_t gw_if_name = cps_api_object_e_get(obj,ids,ids_len);

            if (gw_if_name != CPS_API_ATTR_NULL) {
                interface_ctrl_t intf_ctrl;
                t_std_error rc = STD_ERR_OK;
                memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
                intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
                safestrncpy(intf_ctrl.if_name, (const char *)cps_api_object_attr_data_bin(gw_if_name),
                            cps_api_object_attr_len(gw_if_name));

                if((rc= dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                    EV_LOGGING(NAS_OS, ERR, "ROUTE-UPD",
                               "Interface %s to if_index returned error %d", intf_ctrl.if_name, rc);
                    return cps_api_ret_code_ERR;
                }
                if (intf_ctrl.int_type == nas_int_type_MGMT) {
                    int if_index = 0;
                    if (nas_os_util_int_if_index_get((vrf_name ? vrf_name : NAS_DEFAULT_VRF_NAME),
                                                     intf_ctrl.if_name, &if_index) != STD_ERR_OK) {
                        EV_LOGGING(NAS_OS, ERR, "ROUTE-UPD",
                                   "Interface %s to if_index from OS returned error",
                                   intf_ctrl.if_name);
                        return cps_api_ret_code_ERR;
                    }
                    EV_LOGGING(NAS_OS,INFO,"ROUTE-UPD","out-intf: %s(%d) OS-intf:%d",
                               intf_ctrl.if_name, intf_ctrl.if_index, if_index);
                    intf_ctrl.if_index = if_index;
                }
                if ((gw == CPS_API_ATTR_NULL) && (rm->rtm_type != RTN_LOCAL)) {
                    rm->rtm_scope = RT_SCOPE_LINK;
                    /* For route create with link scope, change the flags to route replace.
                     * This is needed inorder to overwrite the connected route with RTM created route,
                     * so that the netlink event will be generated for the RTM route instead of going
                     * via local event publish for failures during route programming.
                     * This is done to avoid any possible race conditions b/w netmain thread
                     * (which handles netlink event and does event publish to NAS) and
                     * CPS handler for route programming which does local event publish on
                     * netlink config failures.
                     */
                    if (m_type == NAS_RT_ADD) {
                        nlh->nlmsg_flags &= ~NLM_F_EXCL;
                        nlh->nlmsg_flags |= NLM_F_REPLACE;
                        EV_LOGGING(NAS_OS, INFO, "ROUTE-UPD", "modified from route create to replace: flags:0x%x",
                                   nlh->nlmsg_flags);
                    }
                }

                EV_LOGGING(NAS_OS,INFO,"ROUTE-UPD","out-intf: %s(%d)",
                           intf_ctrl.if_name, intf_ctrl.if_index);
                nlmsg_add_attr(nlh,sizeof(buff),RTA_OIF,&(intf_ctrl.if_index), sizeof(intf_ctrl.if_index));
            }
        }
        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_WEIGHT;
        cps_api_object_attr_t weight = cps_api_object_e_get(obj,ids,ids_len);
        if (weight != CPS_API_ATTR_NULL) nas_nl_add_attr_int(nlh,sizeof(buff),RTA_PRIORITY,weight);

    } else if (nhc > 1){
        struct nlattr * attr_nh = nlmsg_nested_start(nlh, sizeof(buff));

        attr_nh->nla_len = 0;
        attr_nh->nla_type = RTA_MULTIPATH;
        size_t ix = 0;
        for (ix = 0; ix < nhc ; ++ix) {
            struct rtnexthop * rtnh =
                (struct rtnexthop * )nlmsg_reserve(nlh,sizeof(buff), sizeof(struct rtnexthop));
            memset(rtnh,0,sizeof(*rtnh));

            cps_api_attr_id_t ids[3] = { BASE_ROUTE_OBJ_ENTRY_NH_LIST,
                                         ix, BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR};
            const int ids_len = sizeof(ids)/sizeof(*ids);
            cps_api_object_attr_t attr = cps_api_object_e_get(obj,ids,ids_len);
            if (attr != CPS_API_ATTR_NULL) {
                nlmsg_add_attr(nlh,sizeof(buff),RTA_GATEWAY,
                               cps_api_object_attr_data_bin(attr),addr_len);
                rm->rtm_scope = RT_SCOPE_UNIVERSE; // set scope to universe when gateway is specified
                EV_LOGGING(NAS_OS, INFO,"ROUTE-UPD","MP-NH:%lu %s scope:%d",ix,
                       ((rm->rtm_family == AF_INET) ?
                        (inet_ntop(rm->rtm_family, cps_api_object_attr_data_bin(attr), addr_str, INET_ADDRSTRLEN)) :
                        (inet_ntop(rm->rtm_family, cps_api_object_attr_data_bin(attr), addr_str, INET6_ADDRSTRLEN))),
                       rm->rtm_scope);
            } else {
                EV_LOGGING(NAS_OS, ERR, "ROUTE-UPD", "Error - Missing Gateway");
                return cps_api_ret_code_ERR;
            }

            ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
            attr = cps_api_object_e_get(obj,ids,ids_len);
            if (attr != CPS_API_ATTR_NULL) {
                rtnh->rtnh_ifindex = (int)cps_api_object_attr_data_u32(attr);
            } else {
                ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFNAME;
                attr = cps_api_object_e_get(obj,ids,ids_len);

                if (attr != CPS_API_ATTR_NULL) {
                    interface_ctrl_t intf_ctrl;
                    t_std_error rc = STD_ERR_OK;
                    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
                    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
                    safestrncpy(intf_ctrl.if_name, (const char *)cps_api_object_attr_data_bin(attr),
                                cps_api_object_attr_len(attr));

                    if((rc= dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                        EV_LOGGING(NAS_OS, ERR, "ROUTE-UPD",
                                   "Interface %s to if_index returned error %d", intf_ctrl.if_name, rc);
                        return cps_api_ret_code_ERR;
                    }
                    if (intf_ctrl.int_type == nas_int_type_MGMT) {
                        int if_index = 0;
                        if (nas_os_util_int_if_index_get((vrf_name ? vrf_name : NAS_DEFAULT_VRF_NAME),
                                                         intf_ctrl.if_name, &if_index) != STD_ERR_OK) {
                            EV_LOGGING(NAS_OS, ERR, "ROUTE-UPD",
                                       "Interface %s to if_index from OS returned error",
                                       intf_ctrl.if_name);
                            return cps_api_ret_code_ERR;
                        }
                        EV_LOGGING(NAS_OS,INFO,"ROUTE-UPD","out-intf: %s(%d) OS-intf:%d",
                                   intf_ctrl.if_name, intf_ctrl.if_index, if_index);
                        intf_ctrl.if_index = if_index;
                    }

                    EV_LOGGING(NAS_OS,INFO,"ROUTE-UPD","out-intf: %s(%d) ",
                               intf_ctrl.if_name, intf_ctrl.if_index);
                    rtnh->rtnh_ifindex = intf_ctrl.if_index;
                }
            }

            ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_WEIGHT;
            attr = cps_api_object_e_get(obj,ids,ids_len);
            if (attr != CPS_API_ATTR_NULL) rtnh->rtnh_hops = (char)cps_api_object_attr_data_u32(attr);

            rtnh->rtnh_len = (char*)nlmsg_tail(nlh) - (char*)rtnh;
        }
        nlmsg_nested_end(nlh,attr_nh);
    } else     if ((type == RTM_DELROUTE) && (rm->rtm_family == AF_INET6)){
        /*
         * For V6 route delete, we need to delete the route repeatedly
         * the number of nexthops times to completely remove the route
         * from the kernel
         * @@TODO This is currently a workaround to clean multiple nexthops for
         * v6 routes in kernel until the kernel is fixed for removing all
         * nexthops with just one route delete
         */
        repeat_delete = true;
        nhm_count = MAX_NL_NH_ECMP_COUNT;
    }

    t_std_error rc;
    int err_code;

    do  {

        rc = nl_do_set_request((vrf_name ? vrf_name : NAS_DEFAULT_VRF_NAME), nas_nl_sock_T_ROUTE,nlh,buff1,sizeof(buff1));
        nhm_count--;
        err_code = STD_ERR_EXT_PRIV (rc);
        EV_LOGGING(NAS_OS, INFO,"ROUE_UPD","Netlink error_code %d", err_code);
        /*
         * Return success if the error is exist, in case of addition, or
         * no-exist, in case of deletion. This is because, kernel might have
         * deleted the route entries (when interface goes down) but has not sent netlink
         * events for those routes and RTM is trying to delete after that.
         * Similarly, during ip address configuration, kernel may add the routes
         * before RTM tries to configure kernel.
         *
         */
        if(err_code == ESRCH || err_code == EEXIST ) {
            EV_LOGGING(NAS_OS, INFO,"ROUTE-UPD","No such process or Entry already exists, error_code= %d",err_code);
            /*
             * Kernel may or may not have the routes but NAS routing needs to be informed
             * as is from kernel netlink to program NPU for the route addition/deletion to
             * ensure stale routes are cleaned
             */
            if(err_code == ESRCH)
                nas_os_publish_route(RTM_DELROUTE, obj, false);
            else
                nas_os_publish_route(RTM_NEWROUTE, obj, false);
            rc = STD_ERR_OK;
            repeat_delete = false;
        }

    } while ((repeat_delete == true) && (nhm_count > 0));

    return rc;

}

/* This function is used to process the config for route nexthop append/delete.
 * Ensure any changes made to nas_os_update_route() related to netlink route
 * processing, take care of updating nas_os_update_route_nexthop() accordingly.
 */
t_std_error nas_os_update_route_nexthop (cps_api_object_t obj)
{
    static char buff[NL_RT_MSG_BUFFER_LEN], buff1[NL_RT_RMSG_BUFFER_LEN]; // Allocate from DS
    char        addr_str[INET6_ADDRSTRLEN];
    uint32_t    nhc = 0;
    int         op = 0;
    nas_rt_msg_type    m_type;
    t_std_error rc = STD_ERR_OK;

    memset(buff,0,sizeof(struct nlmsghdr));

    const char *vrf_name           = cps_api_object_get_data(obj, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_VRF_NAME);
    cps_api_object_attr_t prefix   = cps_api_object_attr_get(obj, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_ROUTE_PREFIX);
    cps_api_object_attr_t af       = cps_api_object_attr_get(obj, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_AF);
    cps_api_object_attr_t pref_len = cps_api_object_attr_get(obj, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_PREFIX_LEN);
    cps_api_object_attr_t nh_count = cps_api_object_attr_get(obj, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_COUNT);
    cps_api_object_attr_t op_attr  = cps_api_object_attr_get(obj, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_OPERATION);

    if (prefix == CPS_API_ATTR_NULL || af == CPS_API_ATTR_NULL ||  pref_len == CPS_API_ATTR_NULL
        || nh_count == NULL || op_attr == NULL) {
        EV_LOGGING (NAS_OS, ERR, "ROUTE-NH-UPD", "Missing route nh update params");
        return (STD_ERR(NAS_OS, FAIL, 0));
    }

    op = cps_api_object_attr_data_u32(op_attr);
    m_type = (op == BASE_ROUTE_RT_OPERATION_TYPE_DELETE) ? NAS_RT_DEL:NAS_RT_SET;
    /* Check whether route and NH are in the different VRF, if yes, it's leaked route,
     * do local publish to handle it in the NAS-L3 for NPU programming only. */
    const char *nh_vrf_name = cps_api_object_get_data(obj,BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_VRF_NAME);
    if (nh_vrf_name) {
        if (((vrf_name == NULL) && (strncmp(nh_vrf_name, NAS_DEFAULT_VRF_NAME, NAS_VRF_NAME_SZ) != 0)) ||
            (vrf_name && (strncmp(vrf_name, nh_vrf_name, NAS_VRF_NAME_SZ)))) {
            nas_os_publish_route_nexthop((m_type == NAS_RT_DEL)?RTM_DELROUTE:RTM_NEWROUTE,
                                         obj, false);
            return STD_ERR_OK;
        }
    }

    nhc = cps_api_object_attr_data_u32(nh_count);

    struct nlmsghdr *nlh = (struct nlmsghdr *)
                         nlmsg_reserve((struct nlmsghdr *)buff,sizeof(buff),sizeof(struct nlmsghdr));
    struct rtmsg * rm = (struct rtmsg *) nlmsg_reserve(nlh,sizeof(buff),sizeof(struct rtmsg));
    memset(rm, 0, sizeof(struct rtmsg));

    uint16_t type = (m_type == NAS_RT_DEL) ? RTM_DELROUTE:RTM_NEWROUTE;

    /* NH delete is sent as route delete with next hop to kernel */
    uint16_t flags = nas_os_get_nl_flags(m_type);

    /* if op is append then update the flags and reset replace flag */
    if (op == BASE_ROUTE_RT_OPERATION_TYPE_APPEND) {
        flags &= ~NLM_F_REPLACE;
        flags |= NLM_F_APPEND;
    }

    nas_os_pack_nl_hdr(nlh, type, flags);

    rm->rtm_table = RT_TABLE_MAIN;
    rm->rtm_protocol = RTPROT_UNSPEC; // This could be assigned to correct owner in future

    /* For route delete, initialize scope to no-where and
     * this will get updated to link when Nh addr/ifx is provided.
     */
    if (type != RTM_DELROUTE)
        rm->rtm_scope = RT_SCOPE_UNIVERSE;
    else
        rm->rtm_scope = RT_SCOPE_NOWHERE;

    rm->rtm_type = RTN_UNICAST;

    rm->rtm_dst_len = cps_api_object_attr_data_u32(pref_len);
    rm->rtm_family = (unsigned char) cps_api_object_attr_data_u32(af);

    uint32_t addr_len = (rm->rtm_family == AF_INET)?HAL_INET4_LEN:HAL_INET6_LEN;
    nlmsg_add_attr(nlh,sizeof(buff),RTA_DST,cps_api_object_attr_data_bin(prefix),addr_len);

    EV_LOGGING(NAS_OS, INFO, "ROUTE-NH-UPD","VRF:%s NH count:%d family:%s msg:%s for prefix:%s len:%d proto:%d scope:%d type:%d",
               (vrf_name ? vrf_name : ""), nhc,
               ((rm->rtm_family == AF_INET) ? "IPv4" : "IPv6"),
               ((m_type == NAS_RT_DEL) ? "Route-Delete-NH" : "Route-Append-NH"),
               ((rm->rtm_family == AF_INET) ?
                (inet_ntop(rm->rtm_family, cps_api_object_attr_data_bin(prefix), addr_str, INET_ADDRSTRLEN)) :
                (inet_ntop(rm->rtm_family, cps_api_object_attr_data_bin(prefix), addr_str, INET6_ADDRSTRLEN))),
               rm->rtm_dst_len, rm->rtm_protocol, rm->rtm_scope, rm->rtm_type);

    if (nhc == 1) {
        cps_api_attr_id_t ids[3] = { BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST,
                                     0, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_NH_ADDR};
        const int ids_len = sizeof(ids)/sizeof(*ids);
        cps_api_object_attr_t gw = cps_api_object_e_get(obj,ids,ids_len);
        if (gw != CPS_API_ATTR_NULL) {
            nlmsg_add_attr(nlh,sizeof(buff),RTA_GATEWAY,cps_api_object_attr_data_bin(gw),addr_len);
            rm->rtm_scope = RT_SCOPE_UNIVERSE; // set scope to universe when gateway is specified
            EV_LOGGING (NAS_OS, INFO, "ROUTE-NH-UPD","NH:%s scope:%d",
                        ((rm->rtm_family == AF_INET) ?
                         (inet_ntop(rm->rtm_family, cps_api_object_attr_data_bin(gw), addr_str, INET_ADDRSTRLEN)) :
                         (inet_ntop(rm->rtm_family, cps_api_object_attr_data_bin(gw), addr_str, INET6_ADDRSTRLEN))),
                        rm->rtm_scope);
        } else {
            EV_LOGGING (NAS_OS, INFO, "ROUTE-NH-UPD", "Missing Gateway, could be intf route");
            /*
             * This could be an interface route, do not return from here!
             */
        }

        ids[2] = BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_IFINDEX;
        cps_api_object_attr_t gwix = cps_api_object_e_get(obj,ids,ids_len);
        if (gwix != CPS_API_ATTR_NULL) {
            if (gw == CPS_API_ATTR_NULL) {
                rm->rtm_scope = RT_SCOPE_LINK;
            }

            EV_LOGGING (NAS_OS, INFO, "ROUTE-NH-UPD","out-intf: %d scope:%d",
                        (int)cps_api_object_attr_data_u32(gwix), rm->rtm_scope);
            nas_nl_add_attr_int(nlh,sizeof(buff),RTA_OIF,gwix);
        } else {
            ids[2] = BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_IFNAME;
            cps_api_object_attr_t gw_if_name = cps_api_object_e_get(obj,ids,ids_len);

            if (gw_if_name != CPS_API_ATTR_NULL) {
                interface_ctrl_t intf_ctrl;
                t_std_error rc = STD_ERR_OK;
                memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
                intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
                safestrncpy(intf_ctrl.if_name, (const char *)cps_api_object_attr_data_bin(gw_if_name),
                            cps_api_object_attr_len(gw_if_name));

                if((rc= dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                    EV_LOGGING(NAS_OS, ERR, "ROUTE-UPD",
                               "Interface %s to if_index returned error %d", intf_ctrl.if_name, rc);
                    return cps_api_ret_code_ERR;
                }
                EV_LOGGING(NAS_OS,INFO,"ROUTE-UPD","out-intf: %s(%d)",
                           intf_ctrl.if_name, intf_ctrl.if_index);
                nlmsg_add_attr(nlh,sizeof(buff),RTA_OIF,&(intf_ctrl.if_index), sizeof(intf_ctrl.if_index));
            }
        }

        ids[2] = BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_WEIGHT;
        cps_api_object_attr_t weight = cps_api_object_e_get(obj,ids,ids_len);
        if (weight != CPS_API_ATTR_NULL) nas_nl_add_attr_int(nlh,sizeof(buff),RTA_PRIORITY,weight);

    } else if (nhc > 1){
        struct nlattr * attr_nh = nlmsg_nested_start(nlh, sizeof(buff));

        attr_nh->nla_len = 0;
        attr_nh->nla_type = RTA_MULTIPATH;
        size_t ix = 0;
        for (ix = 0; ix < nhc ; ++ix) {
            struct rtnexthop * rtnh =
                (struct rtnexthop * )nlmsg_reserve(nlh,sizeof(buff), sizeof(struct rtnexthop));
            memset(rtnh,0,sizeof(*rtnh));

            cps_api_attr_id_t ids[3] = { BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST,
                                         ix, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_NH_ADDR};
            const int ids_len = sizeof(ids)/sizeof(*ids);
            cps_api_object_attr_t attr = cps_api_object_e_get(obj,ids,ids_len);
            if (attr != CPS_API_ATTR_NULL) {
                nlmsg_add_attr(nlh,sizeof(buff),RTA_GATEWAY,
                               cps_api_object_attr_data_bin(attr),addr_len);
                rm->rtm_scope = RT_SCOPE_UNIVERSE; // set scope to universe when gateway is specified
                EV_LOGGING (NAS_OS, INFO, "ROUTE-NH-UPD","MP-NH:%lu %s scope:%d",ix,
                            ((rm->rtm_family == AF_INET) ?
                             (inet_ntop(rm->rtm_family, cps_api_object_attr_data_bin(attr), addr_str, INET_ADDRSTRLEN)) :
                             (inet_ntop(rm->rtm_family, cps_api_object_attr_data_bin(attr), addr_str, INET6_ADDRSTRLEN))),
                            rm->rtm_scope);
            } else {
                EV_LOGGING (NAS_OS, ERR, "ROUTE-NH-UPD", "Error - Missing Gateway");
                return (STD_ERR(NAS_OS, FAIL, 0));
            }

            ids[2] = BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_IFINDEX;
            attr = cps_api_object_e_get(obj,ids,ids_len);
            if (attr != CPS_API_ATTR_NULL) {
                rtnh->rtnh_ifindex = (int)cps_api_object_attr_data_u32(attr);
            } else {
                ids[2] = BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_IFNAME;
                attr = cps_api_object_e_get(obj,ids,ids_len);

                if (attr != CPS_API_ATTR_NULL) {
                    interface_ctrl_t intf_ctrl;
                    t_std_error rc = STD_ERR_OK;
                    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
                    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
                    safestrncpy(intf_ctrl.if_name, (const char *)cps_api_object_attr_data_bin(attr),
                                cps_api_object_attr_len(attr));

                    if((rc= dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                        EV_LOGGING(NAS_OS, ERR, "ROUTE-UPD",
                                   "Interface %s to if_index returned error %d", intf_ctrl.if_name, rc);
                        return cps_api_ret_code_ERR;
                    }

                    EV_LOGGING(NAS_OS,INFO,"ROUTE-UPD","out-intf: %s(%d) ",
                               intf_ctrl.if_name, intf_ctrl.if_index);
                    rtnh->rtnh_ifindex = intf_ctrl.if_index;
                }
            }

            ids[2] = BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_WEIGHT;
            attr = cps_api_object_e_get(obj,ids,ids_len);
            if (attr != CPS_API_ATTR_NULL) rtnh->rtnh_hops = (char)cps_api_object_attr_data_u32(attr);

            rtnh->rtnh_len = (char*)nlmsg_tail(nlh) - (char*)rtnh;
        }
        nlmsg_nested_end(nlh,attr_nh);
    }

    int err_code;

    rc = nl_do_set_request((vrf_name ? vrf_name : NAS_DEFAULT_VRF_NAME), nas_nl_sock_T_ROUTE,nlh,buff1,sizeof(buff1));

    err_code = STD_ERR_EXT_PRIV (rc);
    EV_LOGGING (NAS_OS, INFO, "ROUE-NH-UPD","Netlink error_code %d", err_code);

    /*
     * Return success if the error is exist, in case of addition, or
     * no-exist, in case of deletion. This is because, kernel might have
     * deleted the route entries (when interface goes down) but has not sent netlink
     * events for those routes and RTM is trying to delete after that.
     */
    if(err_code == ESRCH || err_code == EEXIST ) {
        EV_LOGGING (NAS_OS, INFO, "ROUTE-NH-UPD","No such process or Entry already exists, error_code= %d", err_code);
        /*
         * Kernel may or may not have the routes but NAS routing needs to be informed
         * as is from kernel netlink to program NPU for the route nexthop addition/deletion to
         * ensure stale route nexthops are cleaned
         */
        if(err_code == ESRCH)
            nas_os_publish_route_nexthop (RTM_DELROUTE, obj, false);
        else
            nas_os_publish_route_nexthop (RTM_NEWROUTE, obj, false);

        rc = STD_ERR_OK;
    }

    if (rc != STD_ERR_OK) {
        EV_LOGGING (NAS_OS, ERR, "ROUTE-NH-UPD", "Kernel write failed");
        return (STD_ERR(NAS_OS, FAIL, 0));
    }

    return rc;
}

t_std_error nas_os_add_route (cps_api_object_t obj)
{

    if (nas_os_update_route(obj, NAS_RT_ADD) != cps_api_ret_code_OK) {
        EV_LOGGING(NAS_OS, ERR, "ROUTE-ADD", "Kernel write failed");
        return (STD_ERR(NAS_OS, FAIL, 0));
    }

    return STD_ERR_OK;
}

t_std_error nas_os_set_route (cps_api_object_t obj)
{
    if (nas_os_update_route(obj, NAS_RT_SET) != cps_api_ret_code_OK) {
        EV_LOGGING(NAS_OS, ERR, "ROUTE-SET", "Kernel write failed");
        return (STD_ERR(NAS_OS, FAIL, 0));
    }

    return STD_ERR_OK;
}

t_std_error nas_os_del_route (cps_api_object_t obj)
{

    if (nas_os_update_route(obj, NAS_RT_DEL) != cps_api_ret_code_OK) {
        EV_LOGGING(NAS_OS, ERR, "ROUTE-DEL", "Kernel write failed");
        return (STD_ERR(NAS_OS, FAIL, 0));
    }

    return STD_ERR_OK;
}

cps_api_return_code_t nas_os_update_neighbor(cps_api_object_t obj, nas_rt_msg_type m_type)
{
    char buff[NL_RT_NBR_MSG_BUFFER_LEN];
    hal_mac_addr_t mac_addr;
    char            addr_str[INET6_ADDRSTRLEN];
    memset(buff,0,sizeof(struct nlmsghdr));
    memset(mac_addr, 0, sizeof(mac_addr));

    const char *vrf_name      = cps_api_object_get_data(obj,BASE_ROUTE_OBJ_VRF_NAME);
    cps_api_object_attr_t ip  = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_NBR_ADDRESS);
    cps_api_object_attr_t af  = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_NBR_AF);
    cps_api_object_attr_t mac = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_NBR_MAC_ADDR);
    cps_api_object_attr_t if_index = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_NBR_IFINDEX);
    cps_api_object_attr_t if_name = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_NBR_IFNAME);
    cps_api_object_attr_t nbr_type = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_NBR_TYPE);

    if (ip == CPS_API_ATTR_NULL || af == CPS_API_ATTR_NULL ||
        (if_index == CPS_API_ATTR_NULL && if_name == CPS_API_ATTR_NULL)
        || (m_type != NAS_RT_DEL && mac == CPS_API_ATTR_NULL)) {
        EV_LOGGING(NAS_OS, ERR, "NEIGH-UPD", "Missing neighbor params");
        return cps_api_ret_code_ERR;
    }

    struct nlmsghdr *nlh = (struct nlmsghdr *)
                         nlmsg_reserve((struct nlmsghdr *)buff,sizeof(buff),sizeof(struct nlmsghdr));
    struct ndmsg * ndm = (struct ndmsg *) nlmsg_reserve(nlh,sizeof(buff),sizeof(struct ndmsg));
    memset(ndm, 0, sizeof(struct ndmsg));

    if (if_index != CPS_API_ATTR_NULL) {
        ndm->ndm_ifindex = cps_api_object_attr_data_u32(if_index);
    } else if (if_name != CPS_API_ATTR_NULL) {
        interface_ctrl_t intf_ctrl;
        t_std_error rc = STD_ERR_OK;

        memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
        intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
        safestrncpy(intf_ctrl.if_name, (const char *)cps_api_object_attr_data_bin(if_name),
                    cps_api_object_attr_len(if_name));

        if((rc= dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
            EV_LOGGING(NAS_OS, ERR, "NEIGH-UPD",
                       "Interface %s to if_index returned error %d", intf_ctrl.if_name, rc);
            return cps_api_ret_code_ERR;
        }
        if (intf_ctrl.int_type == nas_int_type_MGMT) {
            int if_index = 0;
            if (nas_os_util_int_if_index_get((vrf_name ? vrf_name : NAS_DEFAULT_VRF_NAME), intf_ctrl.if_name, &if_index) != STD_ERR_OK) {
                EV_LOGGING(NAS_OS, ERR, "NEIGH-UPD",
                           "Interface %s to if_index from OS returned error",
                           intf_ctrl.if_name);
                return cps_api_ret_code_ERR;
            }
            EV_LOGGING(NAS_OS,INFO,"NEIGH-UPD","out-intf: %s(%d) OS-intf:%d",
                       intf_ctrl.if_name, intf_ctrl.if_index, if_index);
            intf_ctrl.if_index = if_index;
        }


        EV_LOGGING(NAS_OS, INFO, "NEIGH-UPD",
                   "Interface %s to if_index:%d success", intf_ctrl.if_name, intf_ctrl.if_index);
        ndm->ndm_ifindex = intf_ctrl.if_index;
    }
    ndm->ndm_family = (unsigned char) cps_api_object_attr_data_u32(af);

    if ((m_type == NAS_RT_REFRESH) || (m_type == NAS_RT_RESOLVE)) {
        /* Set the state to DELAY in order for the kernel to refresh the ARP */
        ndm->ndm_state = NUD_DELAY;
        if (m_type == NAS_RT_RESOLVE)
            ndm->ndm_flags = NTF_USE;

        m_type = NAS_RT_SET;
    } else if (nbr_type != CPS_API_ATTR_NULL) {
        if (((unsigned char) cps_api_object_attr_data_u32(nbr_type))
            == BASE_ROUTE_RT_TYPE_STATIC){
            /* Static ARP handling */
            ndm->ndm_state = NUD_PERMANENT;
            /* Set this flag to replace the dynamic ARP to static if exists */
            if (m_type == NAS_RT_ADD)
                m_type = NAS_RT_SET;
        }else{
            ndm->ndm_state = NUD_REACHABLE;
        }
    } else {
        /* if NH type is not given, assume the state as permanent */
        ndm->ndm_state = NUD_PERMANENT;
        /* Set this flag to replace the dynamic ARP to static if exists */
        if (m_type == NAS_RT_ADD)
            m_type = NAS_RT_SET;
    }
    /* @@TODO the m_type is overriden always to replace the ARP entry (if exists)
     * in the kernel with this ARP entry, The kernel does not override the ARP entry
     * if exists (could be there in the FAILED because of the IP neigh flush all)
     * when the RTM_NEWNEIGH is sent with NLM_F_EXCL flag,
     * so, marking the ARP entry for replace always, revisit in the future to see
     * if we can set the flags based on the ARP entry status in the kernel */
    if (m_type == NAS_RT_ADD)
        m_type = NAS_RT_SET;

    uint16_t flags = nas_os_get_nl_flags(m_type);
    uint16_t type = (m_type == NAS_RT_DEL)?RTM_DELNEIGH:RTM_NEWNEIGH;
    nas_os_pack_nl_hdr(nlh, type, flags);

    ndm->ndm_type = RTN_UNICAST;

    uint32_t addr_len = (ndm->ndm_family == AF_INET)?HAL_INET4_LEN:HAL_INET6_LEN;
    nlmsg_add_attr(nlh,sizeof(buff),NDA_DST,cps_api_object_attr_data_bin(ip),addr_len);

    /* Dont set the MAC for ARP resolve case */
    if (!(ndm->ndm_flags & NTF_USE) && (mac != CPS_API_ATTR_NULL)) {
        std_string_to_mac(&mac_addr,cps_api_object_attr_data_bin(mac),
                          cps_api_object_attr_len(mac));
        nlmsg_add_attr(nlh,sizeof(buff),NDA_LLADDR, &mac_addr, HAL_MAC_ADDR_LEN);
    }

    t_std_error rc = nl_do_set_request((vrf_name ? vrf_name : NAS_DEFAULT_VRF_NAME), nas_nl_sock_T_NEI,nlh,buff,sizeof(buff));
    int err_code = STD_ERR_EXT_PRIV (rc);
    char mac_buff[MAC_STRING_LEN];
    memset(mac_buff, '\0', sizeof(mac_buff));
    std_mac_to_string((const hal_mac_addr_t *)mac_addr ,mac_buff,sizeof(mac_buff));
    EV_LOGGING(NAS_OS, INFO,"NEIGH-UPD","Operation:%s VRF:%s family:%s NH:%s MAC:%s out-intf:%d state:%s rc:%d",
               ((m_type == NAS_RT_DEL) ? "Arp-Del" : ((m_type == NAS_RT_ADD) ? "Arp-Add" :
                                                      ((m_type == NAS_RT_REFRESH) ? "Arp-Refresh" : "Arp-Replace"))),
               (vrf_name ? vrf_name : ""),
               ((ndm->ndm_family == AF_INET) ? "IPv4" : "IPv6"),
               ((ndm->ndm_family == AF_INET) ?
                (inet_ntop(ndm->ndm_family, cps_api_object_attr_data_bin(ip), addr_str, INET_ADDRSTRLEN)) :
                (inet_ntop(ndm->ndm_family, cps_api_object_attr_data_bin(ip), addr_str, INET6_ADDRSTRLEN))),
               mac_buff, ndm->ndm_ifindex,
               ((ndm->ndm_state == NUD_REACHABLE) ? "Dynamic" : "Static"), err_code);
    return rc;
}

t_std_error nas_os_add_neighbor (cps_api_object_t obj)
{

    if (nas_os_update_neighbor(obj, NAS_RT_ADD) != cps_api_ret_code_OK) {
        EV_LOGGING(NAS_OS, ERR, "NEIGH-ADD", "Kernel write failed");
        return (STD_ERR(NAS_OS, FAIL, 0));
    }

    return STD_ERR_OK;
}

t_std_error nas_os_set_neighbor (cps_api_object_t obj)
{

    if (nas_os_update_neighbor(obj, NAS_RT_SET) != cps_api_ret_code_OK) {
        EV_LOGGING(NAS_OS, ERR, "NEIGH-SET", "Kernel write failed");
        return (STD_ERR(NAS_OS, FAIL, 0));
    }

    return STD_ERR_OK;
}

t_std_error nas_os_del_neighbor (cps_api_object_t obj)
{

    if (nas_os_update_neighbor(obj, NAS_RT_DEL) != cps_api_ret_code_OK) {
        EV_LOGGING(NAS_OS, ERR, "NEIGH-DEL", "Kernel write failed");
        return (STD_ERR(NAS_OS, FAIL, 0));
    }

    return STD_ERR_OK;
}

t_std_error nas_os_refresh_neighbor (cps_api_object_t obj)
{
    if (nas_os_update_neighbor(obj, NAS_RT_REFRESH) != cps_api_ret_code_OK) {
        EV_LOGGING(NAS_OS, ERR, "NEIGH-REFRESH", "Kernel write failed");
        return (STD_ERR(NAS_OS, FAIL, 0));
    }

    return STD_ERR_OK;
}

t_std_error nas_os_resolve_neighbor (cps_api_object_t obj)
{
    if (nas_os_update_neighbor(obj, NAS_RT_RESOLVE) != cps_api_ret_code_OK) {
        EV_LOGGING(NAS_OS, ERR, "NEIGH-RESOLVE", "Kernel write failed");
        return (STD_ERR(NAS_OS, FAIL, 0));
    }

    return STD_ERR_OK;
}

t_std_error nas_os_add_vrf (cps_api_object_t obj)
{
    if (nas_os_update_vrf(obj, NAS_RT_ADD) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "VRF-OS-ADD", "Kernel write failed");
        return (STD_ERR(NAS_OS, FAIL, 0));
    }

    return STD_ERR_OK;
}

t_std_error nas_os_set_vrf (cps_api_object_t obj)
{
    if (nas_os_update_vrf(obj, NAS_RT_SET) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "VRF-OS-SET", "Kernel write failed");
        return (STD_ERR(NAS_OS, FAIL, 0));
    }

    return STD_ERR_OK;
}

t_std_error nas_os_del_vrf (cps_api_object_t obj)
{
    if (nas_os_update_vrf(obj, NAS_RT_DEL) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "VRF-OS-DEL", "Kernel write failed");
        return (STD_ERR(NAS_OS, FAIL, 0));
    }

    return STD_ERR_OK;
}

/* This function will be obsoleted once the migration is complete
 * with new API nas_os_bind_if_name_to_vrf for mgmt VRF. */
t_std_error nas_os_bind_if_name_to_mgmt_vrf (cps_api_object_t obj)
{
    if (nas_os_handle_intf_to_mgmt_vrf(obj, NAS_RT_ADD) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "VRF-OS-BIND", "Kernel write failed");
        return (STD_ERR(NAS_OS, FAIL, 0));
    }

    return STD_ERR_OK;
}

/* This function will be obsoleted once the migration is complete
 * with new API nas_os_unbind_if_name_from_vrf for mgmt VRF. */
t_std_error nas_os_unbind_if_name_from_mgmt_vrf (cps_api_object_t obj)
{
    if (nas_os_handle_intf_to_mgmt_vrf(obj, NAS_RT_DEL) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "VRF-OS-UNBIND", "Kernel write failed");
        return (STD_ERR(NAS_OS, FAIL, 0));
    }

    return STD_ERR_OK;
}

t_std_error nas_os_bind_if_name_to_vrf (cps_api_object_t obj)
{
    if (nas_os_handle_intf_to_vrf(obj, NAS_RT_ADD) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "VRF-OS-BIND", "Kernel write failed");
        return (STD_ERR(NAS_OS, FAIL, 0));
    }

    return STD_ERR_OK;
}

t_std_error nas_os_unbind_if_name_from_vrf (cps_api_object_t obj)
{
    if (nas_os_handle_intf_to_vrf(obj, NAS_RT_DEL) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "VRF-OS-UNBIND", "Kernel write failed");
        return (STD_ERR(NAS_OS, FAIL, 0));
    }

    return STD_ERR_OK;
}

