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
 * ds_api_linux_neigh.c
 */

#include "standard_netlink_requests.h"
#include "cps_api_route.h"
#include "cps_api_operation.h"
#include "cps_api_interface_types.h"
#include "std_error_codes.h"
#include "nas_nlmsg_object_utils.h"
#include "event_log.h"
#include "nas_if_utils.h"
#include "std_mac_utils.h"
#include "nas_os_int_utils.h"
#include "nas_os_vlan_utils.h"
#include "nas_linux_l2.h"
#include "ds_api_linux_interface.h"
#include "ds_api_linux_route.h"
#include "dell-base-routing.h"
#include "os-routing-events.h"
#include "cps_class_map.h"
#include "nas_os_l3_utils.h"
#include "hal_if_mapping.h"

#include <sys/socket.h>
#include <stdbool.h>
#include <unistd.h>

#include <stdio.h>
#include <arpa/inet.h>

#define MAC_STRING_LEN 20
char *nl_neigh_state_to_str (int state) {
    static char str[18];
        if (state == NUD_INCOMPLETE)
            snprintf (str, sizeof(str), "Incomplete");
        else if (state == NUD_REACHABLE)
            snprintf (str, sizeof(str), "Reachable");
        else if (state == NUD_STALE)
            snprintf (str, sizeof(str), "Stale");
        else if (state == NUD_DELAY)
            snprintf (str, sizeof(str), "Delay");
        else if (state == NUD_PROBE)
            snprintf (str, sizeof(str), "Probe");
        else if (state == NUD_FAILED)
            snprintf (str, sizeof(str), "Failed");
        else if (state == NUD_NOARP)
            snprintf (str, sizeof(str), "NoArp");
        else if (state == NUD_PERMANENT)
            snprintf (str, sizeof(str), "Static");
        else
            snprintf (str, sizeof(str), "None");

    return str;
}

bool nl_neigh_get_all_request(int sock, int family,int req_id) {
    struct ifinfomsg ifm;
    memset(&ifm,0,sizeof(ifm));
    ifm.ifi_family = family;
    return nl_send_request(sock,RTM_GETNEIGH,
            NLM_F_ROOT| NLM_F_DUMP|NLM_F_REQUEST,
            req_id,&ifm,sizeof(ifm));
}

bool nl_to_neigh_info(int rt_msg_type, struct nlmsghdr *hdr, cps_api_object_t obj, void *context, uint32_t vrf_id) {
    struct ndmsg    *ndmsg = (struct ndmsg *)NLMSG_DATA(hdr);
    struct rtattr   *rtatp = NULL;
    unsigned int     attrlen;
    char             addr_str[INET6_ADDRSTRLEN];
    bool             is_bridge = false, admin_status = false;
    t_std_error      rc = STD_ERR_OK;
    char if_name[HAL_IF_NAME_SZ+1];

    if(hdr->nlmsg_len < NLMSG_LENGTH(sizeof(*ndmsg)))
        return false;

    if ((ndmsg->ndm_family != AF_INET) && (ndmsg->ndm_family != AF_INET6) &&
        (ndmsg->ndm_family != AF_BRIDGE)) {
        return false;
    }
    /* Ignore the FDB netlink events with bridge from non-default VRF, since non-default VRFs
     * are used only for L3 operations. */
    if ((vrf_id != NAS_DEFAULT_VRF_ID) && (ndmsg->ndm_family == AF_BRIDGE)) {
        return false;
    }

    char intf_name[HAL_IF_NAME_SZ+1];
    if(cps_api_interface_if_index_to_name(ndmsg->ndm_ifindex, intf_name,
                                          sizeof(intf_name))!=NULL) {
        if (nas_rt_is_reserved_intf(intf_name))
            return false;
    }

    attrlen = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*ndmsg));

    /* RTM_GETNEIGH - message is received with NUD_INCOMPLETE to blockhole
     * the neighbor entry while ARP resolution is progress, this message is being
     * received after enabling the option app_solicit=1*/
    cps_api_operation_types_t op;
    if ((rt_msg_type == RTM_NEWNEIGH) || (rt_msg_type == RTM_GETNEIGH)) {
        op = cps_api_oper_CREATE;
    } else if(rt_msg_type == RTM_DELNEIGH) {
        if ((ndmsg->ndm_family == AF_INET) || (ndmsg->ndm_family == AF_INET6)) {
            /* If the interface is admin down/not present, simply ignore message here,
             * NAS-l3 will handle the admin down and cleanup all the Nbr entries internally */
            rc = os_intf_admin_state_get(ndmsg->ndm_ifindex, &admin_status);
            if ((rc != STD_ERR_OK) || (admin_status == false)) {
                EV_LOGGING(NETLINK, INFO,"NH-EVENT", "Nbr del rc:%d admin:%d", rc, admin_status);
                return false;
            }
        }
        op = cps_api_oper_DELETE;
    } else {
        return false;
    }

    /* Get VRF name from VRF id */
    const char *vrf_name = nas_os_get_vrf_name(vrf_id);
    if (vrf_name == NULL) {
        return false;
    }
    cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_VRF_NAME, vrf_name, strlen(vrf_name)+1);
    cps_api_object_attr_add_u32(obj, OS_RE_BASE_ROUTE_OBJ_NBR_VRF_ID, vrf_id);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_FLAGS,ndmsg->ndm_flags);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_STATE,ndmsg->ndm_state);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,ndmsg->ndm_family);

    EV_LOGGING(NETLINK, INFO,"NH-EVENT","Op:%s VRF: %s(%d) family:%s(%d) flags:0x%x state:%s(%d) ifx:%d",
           ((rt_msg_type == RTM_NEWNEIGH) ? "Add-NH" :
            ((rt_msg_type == RTM_DELNEIGH) ? "Del-NH" : "Get-NH")), vrf_name, vrf_id,
           ((ndmsg->ndm_family == AF_INET) ? "IPv4" : "IPv6"), ndmsg->ndm_family,
           ndmsg->ndm_flags, nl_neigh_state_to_str(ndmsg->ndm_state), ndmsg->ndm_state,
           ndmsg->ndm_ifindex);

    //Skip publishing probe messages
    if(NUD_PROBE == ndmsg->ndm_state) return false;

    rtatp = ((struct rtattr*)(((char*)(ndmsg)) + NLMSG_ALIGN(sizeof(struct ndmsg))));

    hal_mac_addr_t *mac_addr=NULL;
    int ifix;
    char mac_buff[MAC_STRING_LEN];
    for (; RTA_OK(rtatp, attrlen); rtatp = RTA_NEXT (rtatp, attrlen)) {

        if(rtatp->rta_type == NDA_DST) {
            cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_NBR_ADDRESS,
                                    nla_data((struct nlattr*)rtatp),
                                    nla_len((struct nlattr*)rtatp));

            EV_LOGGING(NETLINK, INFO,"NH-EVENT","NextHop IP:%s",
                       ((ndmsg->ndm_family == AF_INET) ?
                        (inet_ntop(ndmsg->ndm_family, ((struct in_addr *) nla_data((struct nlattr*)rtatp)),
                                   addr_str, INET_ADDRSTRLEN)) :
                        (inet_ntop(ndmsg->ndm_family, ((struct in6_addr *) nla_data((struct nlattr*)rtatp)),
                                   addr_str, INET6_ADDRSTRLEN))));
        }

        if(rtatp->rta_type == NDA_LLADDR) {
            mac_addr = (hal_mac_addr_t *) nla_data((struct nlattr*)rtatp);
            memset(mac_buff, '\0', sizeof(mac_buff));
            std_mac_to_string((const hal_mac_addr_t *)mac_addr ,mac_buff,sizeof(mac_buff));
            cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_NBR_MAC_ADDR, mac_buff, strlen(mac_buff)+1);
            EV_LOGGING(NETLINK, INFO,"NH-EVENT","NextHop MAC:%s", mac_buff);
        }
        if(rtatp->rta_type == NDA_MASTER) {
            ifix = *(int *)nla_data((struct nlattr*)rtatp);
            cps_api_interface_if_index_to_name(ifix,if_name,  sizeof(if_name));

            int mbr_ifindex = 0; /* VLAN member port */
            nas_os_physical_to_vlan_ifindex(ndmsg->ndm_ifindex, 0, false, &mbr_ifindex);
            char mbr_name[HAL_IF_NAME_SZ+1];
            cps_api_interface_if_index_to_name(mbr_ifindex,mbr_name, sizeof(mbr_name));
            cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_IFINDEX,ifix);

            //Populate the physical index only if mac learning is enabled
            if(nas_os_mac_get_learning(ndmsg->ndm_ifindex))
                cps_api_object_attr_add_u32(obj,OS_RE_BASE_ROUTE_OBJ_NBR_MBR_IFINDEX,mbr_ifindex);
            is_bridge = true;
            EV_LOGGING(NETLINK, INFO,"NH-EVENT","VLAN:%s(%d) mbr:%s(%d) tag-intf:%d",
                       if_name, ifix, mbr_name, mbr_ifindex, ndmsg->ndm_ifindex);
        }
    }
    /* Incase of the bridge FDB(L2 FDB Nbr), the VLAN and port information have been added into
     * the CPS object above and for non-bridge case(IP nbr), add the L3 out intf below. */
    if (is_bridge == false) {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_IFINDEX,ndmsg->ndm_ifindex);
        uint32_t lower_layer_intf = 0;
        if (vrf_id == NAS_DEFAULT_VRF_ID) {
            lower_layer_intf = ndmsg->ndm_ifindex;
        } else {
            interface_ctrl_t intf_ctrl;
            memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
            intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
            intf_ctrl.vrf_id = vrf_id;
            intf_ctrl.if_index = ndmsg->ndm_ifindex;

            if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                EV_LOGGING(NETLINK, ERR,"NH-NBR-EVENT", "VRF-id:%d if-index:%d not present in intf DB",
                           vrf_id, ndmsg->ndm_ifindex);
                return false;
            }
            if(intf_ctrl.int_type == nas_int_type_MACVLAN) {
                lower_layer_intf = intf_ctrl.l3_intf_info.if_index;
            }
        }
        cps_api_object_attr_add_u32(obj, OS_RE_BASE_ROUTE_OBJ_NBR_LOWER_LAYER_IF, lower_layer_intf);
    } else {
        // Ignore self-mac address during FDB learning.
        if(ndmsg->ndm_family == AF_BRIDGE) {
            if ((ndmsg->ndm_state == NUD_NOARP) && (rt_msg_type != RTM_DELNEIGH)) {
                nas_os_handle_static_mac_port_chg(if_name, mac_buff, mac_addr, ndmsg->ndm_ifindex);
            }

            hal_mac_addr_t self_mac;
            if(mac_addr && os_intf_mac_addr_get(ifix, self_mac) == STD_ERR_OK) {
                if(!memcmp(mac_addr,self_mac, HAL_MAC_ADDR_LEN)) {
                    EV_LOGGING(NETLINK, INFO,"NH-EVENT","Self mac learn on %d, ignore", ifix);
                    return false;
                }
            }
        }
    }

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj), OS_RE_BASE_ROUTE_OBJ_NBR_OBJ,
                                    cps_api_qualifier_OBSERVED);
    cps_api_object_set_type_operation(cps_api_object_key(obj),op);
    return true;
}

static bool process_neigh_and_add_to_list(int sock, int rt_msg_type, struct nlmsghdr *nh, void *context, uint32_t vrf_id) {
    cps_api_object_list_t *list = (cps_api_object_list_t*) context;
    cps_api_object_t obj=cps_api_object_create();
    if (!cps_api_object_list_append(*list,obj)) {
        cps_api_object_delete(obj);
        return false;
    }
    if (!nl_to_neigh_info(nh->nlmsg_type,nh,obj,context, vrf_id)) {
        return false;
    }
    return true;
}

static bool read_all_neighbours(cps_api_object_list_t list, uint32_t vrf_id) {
    int sock = nas_nl_sock_create(NL_DEFAULT_VRF_NAME, nas_nl_sock_T_NEI,false);
    if (sock<0) return false;

    bool rc = false;
    int RANDOM_ID=21323;
    if (nl_neigh_get_all_request(sock,AF_INET,RANDOM_ID)) {
        char buff[1024];
        rc = netlink_tools_process_socket(sock,
                process_neigh_and_add_to_list,&list,
                buff,sizeof(buff),&RANDOM_ID,NULL, vrf_id);
    }

    if (rc && nl_neigh_get_all_request(sock,AF_INET6,++RANDOM_ID)) {
        char buff[1024];
        rc = netlink_tools_process_socket(sock,
                process_neigh_and_add_to_list,&list,
                buff,sizeof(buff),&RANDOM_ID,NULL, vrf_id);
    }

    close(sock);
    return rc;
}

static cps_api_return_code_t db_read_function (void * context, cps_api_get_params_t * param,
        size_t key_ix) {

    cps_api_return_code_t rc = cps_api_ret_code_OK;
    cps_api_key_t key;
    cps_api_key_init(&key,cps_api_qualifier_TARGET,
            cps_api_obj_cat_ROUTE, cps_api_route_obj_NEIBH, 0);
    if (cps_api_key_matches(&param->keys[key_ix], &key,false)!=0) {
        return cps_api_ret_code_OK;
    }

    /* @@TODO Use the appropriate vrf-id to read the neighbors from non-default VRF context */
    read_all_neighbours(param->list, NL_DEFAULT_VRF_ID);

    return rc;
}

static cps_api_return_code_t db_write_function(void * context, cps_api_transaction_params_t * param,size_t ix) {
    return cps_api_ret_code_ERR;
}

t_std_error ds_api_linux_neigh_init(cps_api_operation_handle_t handle) {
    cps_api_registration_functions_t f;
    memset(&f,0,sizeof(f));
    f.handle = handle;
    f._read_function = db_read_function;
    f._write_function = db_write_function;
    cps_api_key_init(&f.key,cps_api_qualifier_TARGET,cps_api_obj_cat_ROUTE,cps_api_route_obj_NEIBH,0);

    cps_api_return_code_t rc = cps_api_register(&f);

    return STD_ERR_OK_IF_TRUE(rc==cps_api_ret_code_OK,STD_ERR(ROUTE,FAIL,rc));
}
