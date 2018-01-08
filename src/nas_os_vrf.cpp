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

static t_std_error nas_os_cps_commit(cps_api_object_t cps_obj, cps_api_object_guard obj_g, nas_rt_msg_type op) {
    cps_api_transaction_params_t tran;
    cps_api_return_code_t err_code = cps_api_ret_code_ERR;
    t_std_error rc = (STD_ERR(NAS_OS, FAIL, 0));

    cps_api_transaction_guard tr_g (&tran);

    if ((err_code = cps_api_transaction_init(&tran)) != cps_api_ret_code_OK)
    {
        EV_LOGGING(NAS_OS, ERR,"VRF-OS-CFG","CPS Transaction Init failed %d", err_code);
        return rc;
    }


    EV_LOGGING(NAS_OS, INFO,"VRF-OS-CFG","CPS Transaction Init Success. Operation %d", op);

    switch (op)
    {
        case NAS_RT_ADD:
            if ((err_code = cps_api_create(&tran, cps_obj)) != cps_api_ret_code_OK)
            {
                EV_LOGGING(NAS_OS, ERR,"VRF-OS-CFG","Failed to add CREATE Object to Transaction");
                return rc;
            }
            break;

        case NAS_RT_DEL:
            if ((err_code = cps_api_delete(&tran, cps_obj)) != cps_api_ret_code_OK)
            {
                EV_LOGGING(NAS_OS, ERR,"VRF-OS-CFG","Failed to add DELETE Object to Transaction");
                return rc;
            }
            break;

        case NAS_RT_SET:
            if ((err_code = cps_api_set (&tran, cps_obj)) != cps_api_ret_code_OK)
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
    return STD_ERR_OK;
}

static t_std_error nas_os_program_vrf(const char *ni_name, nas_rt_msg_type op) {
    t_std_error rc = (STD_ERR(NAS_OS, FAIL, 0));

    auto cps_obj = cps_api_object_create();
    if (cps_obj == NULL) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF","CPS Object Create failed");
        return rc;
    }
    cps_api_object_guard obj_g (cps_obj);
    if(cps_api_key_from_attr_with_qual(cps_api_object_key(cps_obj),
                                       VRF_MGMT_NI_NETWORK_INSTANCES_NETWORK_INSTANCE_OBJ,
                                       cps_api_qualifier_TARGET) != true)
    {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF","Key extraction from Attribute ID %d failed",
                   VRF_MGMT_NI_NETWORK_INSTANCES_NETWORK_INSTANCE_OBJ);
        return rc;
    }
    cps_api_object_attr_add(cps_obj, NI_NETWORK_INSTANCES_NETWORK_INSTANCE_NAME, (const char*)ni_name,
                            strlen(ni_name)+1);
    if (nas_os_cps_commit(cps_obj, obj_g, op) != STD_ERR_OK) {
        return rc;
    }
    EV_LOGGING(NAS_OS, INFO,"VRF-OS-CFG","Transaction Successfully completed. Exit");
    return STD_ERR_OK;
}

t_std_error nas_os_program_vrf_intf(const char *ni_name, const char *if_name, nas_rt_msg_type op) {
    t_std_error rc = (STD_ERR(NAS_OS, FAIL, 0));

    auto cps_obj = cps_api_object_create();
    if (cps_obj == NULL) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF","CPS Object Create failed");
        return rc;
    }

    cps_api_object_guard obj_g (cps_obj);
    if(cps_api_key_from_attr_with_qual(cps_api_object_key(cps_obj),
                                       VRF_MGMT_NI_IF_INTERFACES_INTERFACE_OBJ,cps_api_qualifier_TARGET) != true)
    {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF","Key extraction from Attribute ID %d failed",
                   VRF_MGMT_NI_IF_INTERFACES_INTERFACE_OBJ);
        return rc;
    }
    cps_api_object_attr_add(cps_obj, IF_INTERFACES_INTERFACE_NAME, (const char*)if_name,
                            strlen(if_name)+1);
    cps_api_object_attr_add(cps_obj, NI_IF_INTERFACES_INTERFACE_BIND_NI_NAME, (const char*)ni_name,
                            strlen(ni_name)+1);

    if (nas_os_cps_commit(cps_obj, obj_g, op) != STD_ERR_OK) {
        return rc;
    }

    EV_LOGGING(NAS_OS, INFO,"VRF-OS-CFG","Transaction Successfully completed. Exit");
    return STD_ERR_OK;
}

#ifdef __cplusplus
extern "C" {
#endif
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
    if (m_type == NAS_RT_ADD) {
        /* Create the namespace and then create the netlink sockets */
        rc = nas_os_program_vrf(vrf_name, m_type);
        if ((rc == STD_ERR_OK) && (os_create_netlink_sock(vrf_name) != STD_ERR_OK)) {
            os_del_netlink_sock(vrf_name);
            return (STD_ERR(NAS_OS, FAIL, 0));
        }
    } else if (m_type == NAS_RT_DEL) {
        os_del_netlink_sock(vrf_name);
        rc = nas_os_program_vrf(vrf_name, m_type);
    }
    return rc;
}

t_std_error nas_os_handle_intf_to_vrf(cps_api_object_t obj, nas_rt_msg_type m_type)
{
    const char *vrf_name = (const char *)cps_api_object_get_data(obj,
                                                                 NI_IF_INTERFACES_INTERFACE_BIND_NI_NAME);
    const char *if_name = (const char *)cps_api_object_get_data(obj,
                                                                IF_INTERFACES_INTERFACE_NAME);

    if ((vrf_name == nullptr) || (if_name == nullptr)) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-VRF", "Missing VRF Name/If Name attribute");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    EV_LOGGING(NAS_OS, INFO, "NAS-OS-VRF", "Binding/Unbinding VRF device:%s with intf:%s m_type:%d",
               vrf_name, if_name, m_type);
    if (nas_os_program_vrf_intf(vrf_name, if_name, m_type) != STD_ERR_OK) {
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    return STD_ERR_OK;
}

#ifdef __cplusplus
}
#endif
