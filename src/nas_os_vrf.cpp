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
 * filename: nas_os_vrf.cpp
 */


#include "cps_api_object_attr.h"
#include "cps_api_operation.h"
#include "cps_api_object.h"
#include "cps_class_map.h"
#include "std_error_codes.h"
#include "nas_os_l3.h"
#include "event_log.h"
#include "cps_api_operation.h"
#include "ietf-network-instance.h"
#include "vrf-mgmt.h"
#include "nas_os_l3_utils.h"
#include "netlink_tools.h"
#include "std_utils.h"
#include "nas_base_utils.h"
#include "ds_api_linux_interface.h"
#include "private/nas_os_if_priv.h"
#include "hal_if_mapping.h"
#include "nas_vrf_utils.h"
#include "net_publish.h"

#include <unordered_map>

static std_rw_lock_t vrf_lock = PTHREAD_RWLOCK_INITIALIZER;
static auto &vrf_map = *new std::unordered_map<std::string, uint32_t>;
static auto &vrf_id_map = *new std::unordered_map<uint32_t, std::string>;

#define NAS_VRF_OP_VRF_UPDATE             1
#define NAS_VRF_OP_MGMT_VRF_INTF_UPDATE   2
#define NAS_VRF_OP_DATA_VRF_INTF_UPDATE   3

static bool nas_vrf_notify_vrf_config (uint32_t vrf_id, const char * vrf_name, bool is_add)
{
    cps_api_transaction_params_t params;
    cps_api_object_t             obj;
    cps_api_key_t                keys;
    bool                         rc = true;

    EV_LOGGING(NAS_OS, INFO, "NAS-RT-RPC", "Vrf: %d(%s) is_add:%d", vrf_id, vrf_name, is_add);
    do {
        if ((obj = cps_api_object_create()) == NULL) {
            EV_LOGGING(NAS_OS, ERR, "NAS-RT-RPC", "Object created failed for Vrf:%s is_add:%d", vrf_name, is_add);
            rc = false;
            break;
        }
        cps_api_object_guard obj_g (obj);
        if (cps_api_transaction_init(&params) != cps_api_ret_code_OK) {
            rc = false;
            break;
        }
        cps_api_transaction_guard tgd(&params);
        cps_api_key_from_attr_with_qual(&keys, VRF_MGMT_VRF_CONFIG_OBJ,
                                        cps_api_qualifier_TARGET);
        cps_api_object_set_key(obj, &keys);

        cps_api_object_attr_add_u32(obj, VRF_MGMT_VRF_CONFIG_INPUT_VRF_ID, vrf_id);
        cps_api_object_attr_add(obj, VRF_MGMT_VRF_CONFIG_INPUT_NI_NAME,
                                vrf_name, strlen(vrf_name) + 1);
        cps_api_object_attr_add_u32(obj, VRF_MGMT_VRF_CONFIG_INPUT_OPERATION,
                                    (is_add ? BASE_CMN_OPERATION_TYPE_CREATE : BASE_CMN_OPERATION_TYPE_DELETE));

        if (cps_api_action(&params, obj) != cps_api_ret_code_OK) {
            rc = false;
            break;
        }

        obj_g.release();

        if (cps_api_commit(&params) != cps_api_ret_code_OK) {
            rc = false;
            break;
        }

    } while (false);

    EV_LOGGING(NAS_OS, INFO, "NAS-RT-RPC", "Vrf:%s is_add:%d ret:%d", vrf_name, is_add, rc);
    return rc;
}

/* This function commits the VRF configurations to OS and also,
 * updates the interface object with the router interface information. */
static t_std_error nas_os_cps_commit(int msg_type, cps_api_object_t vrf_intf_obj,
                                     cps_api_object_t cps_obj_os, nas_rt_msg_type op) {
    cps_api_transaction_params_t tran;
    cps_api_return_code_t err_code = cps_api_ret_code_ERR;
    t_std_error rc = (STD_ERR(NAS_OS, FAIL, 0));

    cps_api_object_guard obj_g (cps_obj_os);

    if ((err_code = cps_api_transaction_init(&tran)) != cps_api_ret_code_OK)
    {
        EV_LOGGING(NAS_OS, ERR,"VRF-OS-CFG","CPS Transaction Init failed %d", err_code);
        return rc;
    }
    cps_api_transaction_guard tr_g (&tran);


    EV_LOGGING(NAS_OS, INFO,"VRF-OS-CFG","CPS Transaction Init Success. Operation %d", op);

    switch (op)
    {
        case NAS_RT_ADD:
            if ((err_code = cps_api_create(&tran, cps_obj_os)) != cps_api_ret_code_OK)
            {
                EV_LOGGING(NAS_OS, ERR,"VRF-OS-CFG","Failed to add CREATE Object to Transaction");
                return rc;
            }
            break;

        case NAS_RT_DEL:
            if ((err_code = cps_api_delete(&tran, cps_obj_os)) != cps_api_ret_code_OK)
            {
                EV_LOGGING(NAS_OS, ERR,"VRF-OS-CFG","Failed to add DELETE Object to Transaction");
                return rc;
            }
            break;

        case NAS_RT_SET:
            if ((err_code = cps_api_set (&tran, cps_obj_os)) != cps_api_ret_code_OK)
            {
                EV_LOGGING(NAS_OS, ERR,"VRF-OS-CFG","Failed to add SET Object to Transaction");
                return rc;
            }
            break;
        default:
            EV_LOGGING(NAS_OS, ERR, "VRF-OS-CFG","Invalid CPS Operation %d", op);
            return rc;
    }

    obj_g.release ();

    /** API Commit */
    if ((err_code = cps_api_commit(&tran)) != cps_api_ret_code_OK)
    {
        EV_LOGGING(NAS_OS, ERR, "VRF-OS-CFG","CPS API Commit failed %d", err_code);
        return rc;
    }
    /* Return return code with success and MAC-VLAN information or
     * return code with failure to application only for add case,
     * delete case, just return success/failure */
    if (((msg_type == NAS_VRF_OP_DATA_VRF_INTF_UPDATE) || (msg_type == NAS_VRF_OP_MGMT_VRF_INTF_UPDATE))
        && (op != NAS_RT_DEL)) {
        uint32_t if_index = 0;
        cps_api_object_attr_t if_index_attr =
            cps_api_object_attr_get(cps_obj_os, VRF_MGMT_NI_IF_INTERFACES_INTERFACE_IFINDEX);
        if (if_index_attr) {
            if_index = cps_api_object_attr_data_u32(if_index_attr);
        } else {
            EV_LOGGING(NAS_OS, ERR, "VRF-OS-CFG","If-index is not present");
            return rc;
        }
        const char *if_name = (const char *)cps_api_object_get_data(cps_obj_os, VRF_MGMT_NI_IF_INTERFACES_INTERFACE_IFNAME);
        const char *mac_addr = (const char *)cps_api_object_get_data(cps_obj_os, VRF_MGMT_NI_IF_INTERFACES_INTERFACE_MAC_ADDR);
        if ((if_name == nullptr) || (mac_addr == nullptr)) {
            EV_LOGGING(NAS_OS, ERR, "VRF-OS-CFG","If-name or MAC not present");
            return rc;
        }
        if (msg_type == NAS_VRF_OP_DATA_VRF_INTF_UPDATE) {
            cps_api_object_attr_add_u32(vrf_intf_obj, VRF_MGMT_INTF_BIND_NI_OUTPUT_IFINDEX, if_index);
            cps_api_object_attr_add(vrf_intf_obj, VRF_MGMT_INTF_BIND_NI_OUTPUT_IFNAME, (const char*)if_name,
                                    strlen(if_name)+1);
            cps_api_object_attr_add(vrf_intf_obj, VRF_MGMT_INTF_BIND_NI_OUTPUT_MAC_ADDR, (const char*)mac_addr,
                                    strlen(mac_addr)+1);
        } else {
            cps_api_object_attr_add_u32(vrf_intf_obj, VRF_MGMT_NI_IF_INTERFACES_INTERFACE_IFINDEX, if_index);
            cps_api_object_attr_add(vrf_intf_obj, VRF_MGMT_NI_IF_INTERFACES_INTERFACE_IFNAME, (const char*)if_name,
                                    strlen(if_name)+1);
            cps_api_object_attr_add(vrf_intf_obj, VRF_MGMT_NI_IF_INTERFACES_INTERFACE_MAC_ADDR, (const char*)mac_addr,
                                    strlen(mac_addr)+1);
        }
        EV_LOGGING(NAS_OS, INFO, "VRF-OS-CFG","Router interface info. name:%s index:%d mac:%s", if_name, if_index, mac_addr);
    }
    cps_api_key_set(cps_api_object_key(cps_obj_os),CPS_OBJ_KEY_INST_POS,
                    cps_api_qualifier_OBSERVED);
    if (nas_os_publish_event(cps_obj_os) != cps_api_ret_code_OK) {
        EV_LOGGING(NAS_OS, ERR, "VRF-OS-CFG", "VRF publish failed!");
    }
    cps_api_key_set(cps_api_object_key(cps_obj_os),CPS_OBJ_KEY_INST_POS,
                    cps_api_qualifier_TARGET);

    return STD_ERR_OK;
}

static t_std_error nas_os_program_vrf(const char *ni_name, nas_rt_msg_type op, uint32_t vrf_id) {
    t_std_error rc = (STD_ERR(NAS_OS, FAIL, 0));

    auto cps_obj = cps_api_object_create();
    if (cps_obj == NULL) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF","CPS Object Create failed");
        return rc;
    }
    if(cps_api_key_from_attr_with_qual(cps_api_object_key(cps_obj),
                                       VRF_MGMT_NI_NETWORK_INSTANCES_NETWORK_INSTANCE_OBJ,
                                       cps_api_qualifier_TARGET) != true)
    {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF","Key extraction from Attribute ID %d failed",
                   VRF_MGMT_NI_NETWORK_INSTANCES_NETWORK_INSTANCE_OBJ);
        cps_api_object_delete(cps_obj);
        return rc;
    }
    cps_api_object_attr_add(cps_obj, NI_NETWORK_INSTANCES_NETWORK_INSTANCE_NAME, (const char*)ni_name,
                            strlen(ni_name)+1);
    cps_api_object_attr_add_u32(cps_obj, VRF_MGMT_NI_NETWORK_INSTANCES_NETWORK_INSTANCE_VRF_ID, vrf_id);
    if (nas_os_cps_commit(NAS_VRF_OP_VRF_UPDATE, nullptr, cps_obj, op) != STD_ERR_OK) {
        return rc;
    }
    EV_LOGGING(NAS_OS, INFO,"VRF-OS-CFG","Transaction Successfully completed. Exit");
    return STD_ERR_OK;
}

t_std_error nas_os_program_vrf_mgmt_intf(cps_api_object_t obj, const char *ni_name, const char *if_name, nas_rt_msg_type op) {
    t_std_error rc = (STD_ERR(NAS_OS, FAIL, 0));

    auto cps_obj = cps_api_object_create();
    if (cps_obj == NULL) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF","CPS Object Create failed");
        return rc;
    }

    if(cps_api_key_from_attr_with_qual(cps_api_object_key(cps_obj),
                                       VRF_MGMT_NI_IF_INTERFACES_INTERFACE_OBJ,cps_api_qualifier_TARGET) != true)
    {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF","Key extraction from Attribute ID %d failed",
                   VRF_MGMT_NI_IF_INTERFACES_INTERFACE_OBJ);
        cps_api_object_delete(cps_obj);
        return rc;
    }
    cps_api_object_attr_add(cps_obj, IF_INTERFACES_INTERFACE_NAME, (const char*)if_name,
                            strlen(if_name)+1);
    cps_api_object_attr_add(cps_obj, NI_IF_INTERFACES_INTERFACE_BIND_NI_NAME, (const char*)ni_name,
                            strlen(ni_name)+1);
    if (nas_os_cps_commit(NAS_VRF_OP_MGMT_VRF_INTF_UPDATE, obj, cps_obj, op) != STD_ERR_OK) {
        return rc;
    }

    EV_LOGGING(NAS_OS, INFO,"VRF-OS-CFG","Transaction Successfully completed. Exit");
    return STD_ERR_OK;
}

t_std_error nas_os_program_vrf_intf(cps_api_object_t obj, const char *ni_name, const char *if_name, nas_rt_msg_type op) {
    t_std_error rc = (STD_ERR(NAS_OS, FAIL, 0));

    auto cps_obj = cps_api_object_create();
    if (cps_obj == NULL) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF","CPS Object Create failed");
        return rc;
    }

    if(cps_api_key_from_attr_with_qual(cps_api_object_key(cps_obj),
                                       VRF_MGMT_NI_IF_INTERFACES_INTERFACE_OBJ,cps_api_qualifier_TARGET) != true)
    {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF","Key extraction from Attribute ID %d failed",
                   VRF_MGMT_INTF_BIND_NI_OBJ);
        cps_api_object_delete(cps_obj);
        return rc;
    }
    cps_api_object_attr_t type_attr = cps_api_object_attr_get(obj, IF_INTERFACES_INTERFACE_TYPE);
    if (type_attr == nullptr) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF","Failed to find the interface type ");
        cps_api_object_delete(cps_obj);
        return rc;
    }

    char *if_ietf_type = (char *)cps_api_object_attr_data_bin(type_attr);

    cps_api_object_attr_add(cps_obj, IF_INTERFACES_INTERFACE_NAME, (const char*)if_name,
                            strlen(if_name)+1);
    cps_api_object_attr_add(cps_obj, NI_IF_INTERFACES_INTERFACE_BIND_NI_NAME, (const char*)ni_name,
                            strlen(ni_name)+1);
    cps_api_object_attr_add(cps_obj, IF_INTERFACES_INTERFACE_TYPE, (const char*)if_ietf_type,
                            strlen(if_ietf_type)+1);

    if (nas_os_cps_commit(NAS_VRF_OP_DATA_VRF_INTF_UPDATE, obj, cps_obj, op) != STD_ERR_OK) {
        return rc;
    }

    EV_LOGGING(NAS_OS, INFO,"VRF-OS-CFG","Transaction Successfully completed. Exit");
    return STD_ERR_OK;
}

bool nas_os_get_vrf_id(const char *vrf_name, uint32_t *p_vrf_id) {

    if (strncmp(vrf_name, NAS_DEFAULT_VRF_NAME, NAS_VRF_NAME_SZ) == 0) {
        *p_vrf_id = NAS_DEFAULT_VRF_ID;
        return true;
    }

    std_rw_lock_read_guard l(&vrf_lock);
    auto it = vrf_map.find(vrf_name);
    if (it != vrf_map.end()) {
        *p_vrf_id = it->second;
        return true;
    }
    return false;
}

nas::id_generator_t vrf_id_gen {NAS_MAX_DATA_VRF_ID};
static t_std_error nas_os_update_vrf_id(bool is_add, const char *vrf_name, uint32_t *p_vrf_id) {
    std_rw_lock_write_guard l(&vrf_lock);
    std::string vrf_name_str(vrf_name);
    if (is_add == false) {
        auto it = vrf_map.find(vrf_name_str);
        if (it != vrf_map.end()) {
            EV_LOGGING(NAS_OS, INFO, "NAS-OS-VRF", "VRF name:%s id:%d deleted successfully!",
                       vrf_name, it->second);
            /* Remove the vrf-id to VRF-name map entry */
            auto id_it = vrf_id_map.find(it->second);
            if (id_it != vrf_id_map.end()) {
                vrf_id_map.erase(id_it);
            }
            vrf_map.erase(it);
            vrf_id_gen.release_id(it->second);
        } else {
            EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF", "VRF %s not present!", vrf_name);
        }
        return STD_ERR_OK;
    }
    auto it = vrf_map.find(vrf_name_str);
    if (it != vrf_map.end()) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF", "VRF %s already exists!", vrf_name);
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    uint32_t vrf_id = 0;
    if (strncmp(vrf_name, NAS_MGMT_VRF_NAME, NAS_VRF_NAME_SZ) == 0) {
        vrf_id = NAS_MGMT_VRF_ID;
    } else {
        try {
            vrf_id = (uint32_t) vrf_id_gen.alloc_id();
        } catch (nas::base_exception& e) {
            EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF", "Max VRFs:%d reached!", NAS_MAX_DATA_VRF_ID);
            return (STD_ERR(NAS_OS,FAIL, 0));
        }
    }
    vrf_map[vrf_name_str] = vrf_id;
    vrf_id_map[vrf_id] = vrf_name_str;
    *p_vrf_id = vrf_id;
    return STD_ERR_OK;
}

const char* nas_os_get_vrf_name(uint32_t vrf_id) {
    /* Return the VRF name from VRF-id */
    if (vrf_id == NAS_DEFAULT_VRF_ID) {
        return NAS_DEFAULT_VRF_NAME;
    } else if (vrf_id == NAS_MGMT_VRF_ID) {
        return NAS_MGMT_VRF_NAME;
    } else {
        std_rw_lock_read_guard l(&vrf_lock);
        auto it = vrf_id_map.find(vrf_id);
        if (it != vrf_id_map.end()) {
            return((it->second).c_str());
        }
    }
    return NULL;
}

t_std_error nas_remove_intf_to_vrf_binding(uint32_t if_index) {
    t_std_error rc = (STD_ERR(NAS_OS, FAIL, 0));
    interface_ctrl_t intf_ctrl;

    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.if_index = if_index;
    if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
        return STD_ERR_OK;
    }
    if (intf_ctrl.l3_intf_info.if_index == 0) {
        return STD_ERR_OK;
    }
    const char *ni_name = nas_os_get_vrf_name(intf_ctrl.l3_intf_info.vrf_id);
    if (ni_name == NULL) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF","If-index:%d, VRF id:%d to name mapping is not present",
                   if_index, intf_ctrl.l3_intf_info.vrf_id);
        return STD_ERR_OK;
    }

    auto cps_obj = cps_api_object_create();
    if (cps_obj == NULL) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF","CPS Object Create failed for intf-VRF dissociation");
        return rc;
    }
    cps_api_object_guard obj_g (cps_obj);

    if(cps_api_key_from_attr_with_qual(cps_api_object_key(cps_obj),
                                       VRF_MGMT_NI_IF_INTERFACES_INTERFACE_OBJ,
                                       cps_api_qualifier_TARGET) != true)
    {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF","Key extraction from Attribute ID %d failed",
                   VRF_MGMT_NI_IF_INTERFACES_INTERFACE_OBJ);
        return rc;
    }
    cps_api_object_attr_add(cps_obj, VRF_MGMT_INTF_BIND_NI_INPUT_INTERFACE, (const char*)intf_ctrl.if_name,
                            strlen(intf_ctrl.if_name)+1);
    cps_api_object_attr_add(cps_obj, VRF_MGMT_INTF_BIND_NI_INPUT_NI_NAME, (const char*)ni_name,
                            strlen(ni_name)+1);
    nas_os_handle_intf_to_vrf(cps_obj, NAS_RT_DEL);
    /* App should send the intf to VRF binding removal first and then the parent interface delete,
     * fix this from App perspective. */
    EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF", "Parent del has triggered the intf:%s to VRF:%s binding removal",
               intf_ctrl.if_name, ni_name);
    return STD_ERR_OK;
}


#ifdef __cplusplus
extern "C" {
#endif
/* This function updates the NAS-common interface DB with the router interface specific to
 * non-default VRF context and also updates the parent interface with the router interface information. */
t_std_error nas_os_update_intf_db(cps_api_object_t obj, const char *ni_name,
                                  const char *parent_if_name, nas_rt_msg_type op)
{
    interface_ctrl_t details, router_intf;
    interface_ctrl_t parent_intf_ctrl;
    hal_intf_reg_op_type_t reg_op = HAL_INTF_OP_REG;
    l3_intf_info_t l3_intf_info;

    memset(&parent_intf_ctrl, 0, sizeof(parent_intf_ctrl));
    parent_intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
    safestrncpy(parent_intf_ctrl.if_name, parent_if_name, HAL_IF_NAME_SZ);

    if (dn_hal_get_interface_info(&parent_intf_ctrl) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS,ERR,"NAS-VRF-INTF", "Interface (%s) not found",
                   parent_if_name);
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    memset(&l3_intf_info, 0, sizeof(l3_intf_info));
    memset(&details,0,sizeof(details));
    if (op == NAS_RT_ADD) {
        /* Create router interface info. specific to VRF context along with parent information
         * in the NAS-common interface DB */
        const char *if_name = (const char *)cps_api_object_get_data(obj,
                                                                    VRF_MGMT_INTF_BIND_NI_OUTPUT_IFNAME);
        if (if_name == nullptr) {
            EV_LOGGING(NAS_OS,ERR,"NAS-VRF-INTF", "Sub intf on interface (%s) not found",
                       parent_if_name);
            return (STD_ERR(NAS_OS,FAIL, 0));
        }
        cps_api_object_attr_t if_index_attr =
            cps_api_object_attr_get(obj, VRF_MGMT_INTF_BIND_NI_OUTPUT_IFINDEX);
        if (if_index_attr == nullptr) {
            EV_LOGGING(NAS_OS,ERR,"NAS-VRF-INTF", "Sub intf-index on interface (%s) not found",
                       if_name);
            return (STD_ERR(NAS_OS,FAIL, 0));
        }
        details.if_index = cps_api_object_attr_data_u32(if_index_attr);
        /* If both if-name and if-index are same, it will be for the default VRF. */
        if ((strncmp(if_name, parent_if_name, HAL_IF_NAME_SZ) == 0) &&
            (details.if_index == parent_intf_ctrl.if_index)) {
            EV_LOGGING(NAS_OS, INFO,"NAS-VRF-INTF", "Both Parent and L3 interface are same"
                       "parent intf:%s(%d) L3 intf:%s(%d)", parent_if_name, parent_intf_ctrl.if_index,
                       if_name, details.if_index);
            return STD_ERR_OK;
        }
        safestrncpy(details.vrf_name,ni_name,sizeof(details.vrf_name));
        safestrncpy(details.if_name,if_name,sizeof(details.if_name));
        details.int_type = nas_int_type_MACVLAN;
        const char *mac_addr = (const char *)cps_api_object_get_data(obj,
                                                                     VRF_MGMT_INTF_BIND_NI_OUTPUT_MAC_ADDR);
        if (mac_addr == nullptr) {
            EV_LOGGING(NAS_OS,ERR,"NAS-VRF-INTF", "Sub intf-index on interface (%s) not found",
                       if_name);
            return (STD_ERR(NAS_OS,FAIL, 0));
        }
        safestrncpy(details.mac_addr,mac_addr,sizeof(details.mac_addr));

        EV_LOGGING(INTERFACE,INFO,"NAS-VRF-INTF", "interface register event for %s",
                   details.if_name);

        /* L3 interface to parent interface binding */
        details.l3_intf_info.vrf_id = NAS_DEFAULT_VRF_ID;
        details.l3_intf_info.if_index = parent_intf_ctrl.if_index;
        /* Parent interface to L3 interface binding */
        uint32_t vrf_id = NAS_DEFAULT_VRF_ID;
        if (nas_os_get_vrf_id(ni_name, &vrf_id)) {
            details.vrf_id = vrf_id;
            l3_intf_info.vrf_id = vrf_id;
            l3_intf_info.if_index = details.if_index;
        } else {
            EV_LOGGING(NAS_OS,ERR,"NAS-VRF-INTF", "VRF-id get failed for VRF:%s intf:%s ",
                       ni_name, parent_if_name);
            return (STD_ERR(NAS_OS,FAIL, 0));
        }
        memset(&router_intf, 0, sizeof(router_intf));
        router_intf.q_type = HAL_INTF_INFO_FROM_IF_NAME;
        safestrncpy(router_intf.if_name, if_name, HAL_IF_NAME_SZ);
        if (dn_hal_get_interface_info(&router_intf) == STD_ERR_OK) {
            /* Looks like netlink event created the router interface
             * before creating the router interface in this flow, delete it.
             * @@TODO Optimize this. */
            reg_op = HAL_INTF_OP_DEREG;
            if (dn_hal_if_register(reg_op,&router_intf) != STD_ERR_OK) {
                EV_LOGGING(NAS_OS,ERR,"NAS-VRF-INTF", "t failed for VRF:%s intf:%s ",
                           ni_name, if_name);
            }
        }
        reg_op = HAL_INTF_OP_REG;
    } else if (op == NAS_RT_DEL) {
        EV_LOGGING(NAS_OS, INFO, "NAS-VRF-INTF", "interface de-register event for VRF-id:%d if-index:%d ",
                   parent_intf_ctrl.l3_intf_info.vrf_id, parent_intf_ctrl.l3_intf_info.if_index);
        if (parent_intf_ctrl.l3_intf_info.if_index == 0) {
            return STD_ERR_OK;
        }
        details.vrf_id = parent_intf_ctrl.l3_intf_info.vrf_id;
        details.if_index = parent_intf_ctrl.l3_intf_info.if_index;
        details.q_type = HAL_INTF_INFO_FROM_IF;
        reg_op = HAL_INTF_OP_DEREG;
    } else {
        return STD_ERR_OK;
    }
    if (dn_hal_if_register(reg_op,&details) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS,ERR,"NAS-VRF-INTF", "VRF:%s intf:%s add in common DB failed",
                   ni_name, details.if_name);
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    /* Parent interface to MAC-VLAN interface binding */
    if (nas_cmn_update_router_intf_info(NAS_DEFAULT_VRF_ID, parent_intf_ctrl.if_index,
                                        &l3_intf_info) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR ,"NAS-VRF-INTF", "Failed to update the sub interface %d(%s)",
                   parent_intf_ctrl.if_index, parent_if_name);
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    return STD_ERR_OK;
}

t_std_error nas_os_update_vrf(cps_api_object_t obj, nas_rt_msg_type m_type)
{
    const char *vrf_name = (const char *)cps_api_object_get_data(obj,
                                                   NI_NETWORK_INSTANCES_NETWORK_INSTANCE_NAME);
    if (vrf_name == nullptr) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF", "Missing VRF Name attribute");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    const char *vrf_desc = (const char *)cps_api_object_get_data(obj,
                                                   NI_NETWORK_INSTANCES_NETWORK_INSTANCE_DESCRIPTION);
    cps_api_object_attr_t ni_enabled_attr =
        cps_api_object_attr_get(obj, NI_NETWORK_INSTANCES_NETWORK_INSTANCE_ENABLED);
    int is_enabled = false;
    if (ni_enabled_attr) {
        /* @@TODO if we use the L3MDEV approach for VRF, use this enabled attribute
           for admin up/down on VRF device */
        is_enabled = cps_api_object_attr_data_u32(ni_enabled_attr);
    }
    EV_LOGGING(NAS_OS, INFO, "NAS-OS-VRF", "VRF device:%s desc:%s enabled:%d",
               vrf_name, (vrf_desc ? vrf_desc : ""), is_enabled);

    t_std_error rc = STD_ERR_OK;
    uint32_t vrf_id = 0;
    if (m_type == NAS_RT_ADD) {
        /* Allocate new VRF-id */
        if (nas_os_update_vrf_id(true, vrf_name, &vrf_id) != STD_ERR_OK) {
            return (STD_ERR(NAS_OS,FAIL, 0));
        }
        EV_LOGGING(NAS_OS, INFO, "NAS-OS-VRF", "VRF name:%s mapped with VRF-id:%d desc:%s enabled:%d",
                   vrf_name, vrf_id, (vrf_desc ? vrf_desc : ""), is_enabled);

        /* Update the VRF-name to VRF-id mapping for NAS module to use for faster look-up */
        nas_vrf_ctrl_t vrf_info;
        memset(&vrf_info, 0, sizeof(vrf_info));

        safestrncpy(vrf_info.vrf_name, vrf_name, sizeof(vrf_info.vrf_name));
        vrf_info.vrf_int_id = vrf_id;
        if (nas_update_vrf_info(NAS_VRF_OP_UPD, &vrf_info) != STD_ERR_OK) {
            EV_LOGGING(NAS_OS, INFO, "NAS-OS-VRF", "VRF id:%d update failed for VRF:%s ",
                       vrf_id, vrf_name);
            return (STD_ERR(NAS_OS,FAIL, 0));
        }
        /* Update this VRF info. to NAS-L3 for initialising the VRF DB for handling
         * the route/neighbors from that VRF context. */
        if (nas_vrf_notify_vrf_config(vrf_id, vrf_name, true) == false) {
            EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF", "VRF id:%d VRF:%s config add notification failed",
                       vrf_id, vrf_name);
            return (STD_ERR(NAS_OS,FAIL, 0));
        }
        /* Create the VRF in the kernel */
        rc = nas_os_program_vrf(vrf_name, m_type, vrf_id);
        if (rc != STD_ERR_OK) {
            /* Release the VRF-id */
            nas_os_update_vrf_id(false, vrf_name, NULL);
            nas_vrf_notify_vrf_config(vrf_id, vrf_name, false);
        }
    } else if (m_type == NAS_RT_DEL) {
        /* Delete the VRF in the kernel */
        if (nas_os_get_vrf_id(vrf_name, &vrf_id)) {
            rc = nas_os_program_vrf(vrf_name, m_type, vrf_id);
        }
        if (rc == STD_ERR_OK) {
            /* Update this VRF info. to NAS-L3 for de-initialising the VRF DB for handling
             * the route/neighbors from that VRF context. */
            if (nas_vrf_notify_vrf_config(vrf_id, vrf_name, false) == false) {
                EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF", "VRF id:%d VRF:%s config del notification failed",
                           vrf_id, vrf_name);
                return (STD_ERR(NAS_OS,FAIL, 0));
            }
            nas_os_update_vrf_id(false, vrf_name, NULL);
        }
    }
    return rc;
}

t_std_error nas_os_handle_intf_to_mgmt_vrf(cps_api_object_t obj, nas_rt_msg_type m_type)
{
    const char *vrf_name = (const char *)cps_api_object_get_data(obj,
                                                                 NI_IF_INTERFACES_INTERFACE_BIND_NI_NAME);
    const char *if_name = (const char *)cps_api_object_get_data(obj,
                                                                IF_INTERFACES_INTERFACE_NAME);

    if ((vrf_name == nullptr) || (if_name == nullptr)) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF", "Missing mgmt VRF Name/If Name attribute");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    EV_LOGGING(NAS_OS, INFO, "NAS-OS-VRF", "Binding/Unbinding mgmt VRF device:%s with intf:%s m_type:%d",
               vrf_name, if_name, m_type);
    if (nas_os_program_vrf_mgmt_intf(obj, vrf_name, if_name, m_type) != STD_ERR_OK) {
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    return STD_ERR_OK;
}

t_std_error nas_os_handle_intf_to_vrf(cps_api_object_t obj, nas_rt_msg_type m_type)
{
    t_std_error rc = STD_ERR(NAS_OS,FAIL, 0);
    const char *vrf_name = (const char *)cps_api_object_get_data(obj,
                                                                 VRF_MGMT_INTF_BIND_NI_INPUT_NI_NAME);
    const char *if_name = (const char *)cps_api_object_get_data(obj,
                                                                VRF_MGMT_INTF_BIND_NI_INPUT_INTERFACE);

    if ((vrf_name == nullptr) || (if_name == nullptr)) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF", "Missing VRF Name/If Name attribute");
        return rc;
    }

    EV_LOGGING(NAS_OS, INFO, "NAS-OS-VRF", "%s(%d) VRF name:%s with intf:%s",
               ((m_type == NAS_RT_ADD) ? "Binding" : "Unbinding"), m_type,
               vrf_name, if_name);
    rc = nas_os_program_vrf_intf(obj, vrf_name, if_name, m_type);
    if (rc != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF", "%s(%d) VRF name:%s with intf:%s failed!",
                   ((m_type == NAS_RT_ADD) ? "Binding" : "Unbinding"), m_type,
                   vrf_name, if_name);
    }
    if (strncmp(vrf_name, NAS_DEFAULT_VRF_NAME, NAS_VRF_NAME_SZ) != 0) {
        nas_os_update_intf_db(obj, vrf_name, if_name, m_type);
    }
    return rc;
}
#ifdef __cplusplus
}
#endif
