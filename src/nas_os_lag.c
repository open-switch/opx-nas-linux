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
 * filename: nas_os_lag.c
 */

#include "event_log.h"
#include "ietf-interfaces.h"
#include "dell-interface.h"
#include "dell-base-if.h"
#include "hal_if_mapping.h"

#include "nas_os_lag.h"
#include "nas_os_interface.h"
#include "nas_os_int_utils.h"
#include "cps_api_object_attr.h"
#include "netlink_tools.h"
#include "nas_nlmsg.h"
#include "cps_api_object_key.h"
#include "ds_api_linux_interface.h"

#include "std_utils.h"
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>

#define NL_MSG_BUFF 4096
//Link detect in 100 msec by kernel
#define BOND_MIIMON 100
const static int MAX_CPS_MSG_BUFF=4096;
static t_std_error nas_os_delete_dummy(const char *dummy_intf)
{

    hal_ifindex_t if_index = cps_api_interface_name_to_if_index(dummy_intf);
    if(nas_os_del_interface(if_index) != STD_ERR_OK){
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-LAG", "Failure DEL Dummy from kernel %s",dummy_intf);
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    EV_LOGGING(NAS_OS, INFO, "NAS-OS-LAG",
            "Delete Dummy index %d name %s Successful",if_index, dummy_intf);

    return STD_ERR_OK;
}
static t_std_error nas_os_create_dummy(const char *dummy_intf)
{
    char buff[NL_MSG_BUFF];
    hal_ifindex_t if_index = 0;
    const char *info_kind = "dummy";

    memset(buff,0,NL_MSG_BUFF);
    struct nlmsghdr *nlh = (struct nlmsghdr *) nlmsg_reserve((struct nlmsghdr *)buff,sizeof(buff),
            sizeof(struct nlmsghdr));
    struct ifinfomsg *ifmsg = (struct ifinfomsg *) nlmsg_reserve(nlh,sizeof(buff),
            sizeof(struct ifinfomsg));

    EV_LOGGING(NAS_OS, INFO, "NAS-OS-LAG", "Create Dummy intf name %s in Kernel",dummy_intf);

    unsigned int flags = (IFF_BROADCAST | IFF_NOARP);
    flags &= ~IFF_UP;

    nas_os_pack_nl_hdr(nlh, RTM_NEWLINK, (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL));
    nas_os_pack_if_hdr(ifmsg, AF_PACKET, flags, if_index);

    nlmsg_add_attr(nlh,sizeof(buff),IFLA_IFNAME, dummy_intf, (strlen(dummy_intf)+1));
    struct nlattr *attr_nh = nlmsg_nested_start(nlh, sizeof(buff));
    attr_nh->nla_len = 0;
    attr_nh->nla_type = IFLA_LINKINFO;
    nlmsg_add_attr(nlh,sizeof(buff),IFLA_INFO_KIND, info_kind, (strlen(info_kind)+1));
    nlmsg_nested_end(nlh,attr_nh);
    if(nl_do_set_request(NL_DEFAULT_VRF_NAME, nas_nl_sock_T_INT,nlh,buff,sizeof(buff)) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR,  "NAS-OS-LAG", "Failure to create DUMMY in kernel");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    return STD_ERR_OK;
}
static t_std_error nas_add_del_dummy_to_lag(hal_ifindex_t if_index, bool add) {

     char buff[MAX_CPS_MSG_BUFF];
     char bond_dummy_name[HAL_IF_NAME_SZ];

    snprintf(bond_dummy_name,sizeof(bond_dummy_name)-1,"%s-%d","dummy-bo",if_index);

    if (add) {
        /*  create a dummy interface and add it to the lag  */
        if (nas_os_create_dummy((const char *)bond_dummy_name) != STD_ERR_OK) {
            EV_LOGGING(NAS_OS, ERR, "NAS-OS-LAG",
                   "Error dummy interface %s creation failed in the Kernel", bond_dummy_name);
            return (STD_ERR(NAS_OS, FAIL, 0));
        }
    }
    hal_ifindex_t ifix = cps_api_interface_name_to_if_index(bond_dummy_name);

    cps_api_object_t name_obj = cps_api_object_init(buff, sizeof(buff));
    cps_api_object_attr_add_u32(name_obj,DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX, if_index);
    cps_api_object_attr_add_u32(name_obj,DELL_IF_IF_INTERFACES_INTERFACE_MEMBER_PORTS, ifix);

    if (add && (nas_os_add_port_to_lag(name_obj) != STD_ERR_OK)) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-LAG",
               "Error adding dummy port %d to lag %d in the Kernel", ifix, if_index);
        return (STD_ERR(NAS_OS, FAIL, 0));
    } else if (!add) {
       if (nas_os_delete_port_from_lag(name_obj) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-LAG",
               "Error deleting  dummy port %d from lag %d in the Kernel", ifix, if_index);
       }
       /*  delete the dummy interface  */
        if (nas_os_delete_dummy((const char *)bond_dummy_name) != STD_ERR_OK) {
            EV_LOGGING(NAS_OS, ERR, "NAS-OS-LAG",
               "Error deleting  dummy port %s in the Kernel", ifix, if_index);
            return (STD_ERR(NAS_OS, FAIL, 0));
        }
    }

    return STD_ERR_OK;

}

t_std_error nas_os_create_lag(cps_api_object_t obj, hal_ifindex_t *lag_index)
{
    char buff[NL_MSG_BUFF];
    hal_ifindex_t if_index = 0;
    const char *info_kind = "bond";

    memset(buff,0,NL_MSG_BUFF);
    struct nlmsghdr *nlh = (struct nlmsghdr *) nlmsg_reserve((struct nlmsghdr *)buff,sizeof(buff),
            sizeof(struct nlmsghdr));
    struct ifinfomsg *ifmsg = (struct ifinfomsg *) nlmsg_reserve(nlh,sizeof(buff),
            sizeof(struct ifinfomsg));

    cps_api_object_attr_t lag_attr = cps_api_get_key_data(obj, IF_INTERFACES_INTERFACE_NAME);
    if(lag_attr == CPS_API_ATTR_NULL) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-LAG",
                "Missing Lag Intf name for adding to kernel");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    const char *lag_name = cps_api_object_attr_data_bin(lag_attr);

    EV_LOGGING(NAS_OS, INFO, "NAS-OS-LAG",
            "Create LAG name %s in Kernel",lag_name);

    nas_os_pack_nl_hdr(nlh, RTM_NEWLINK, (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL));
    nas_os_pack_if_hdr(ifmsg, AF_PACKET, (IFF_BROADCAST | IFF_MULTICAST), if_index);

    nlmsg_add_attr(nlh,sizeof(buff),IFLA_IFNAME, lag_name, (strlen(lag_name)+1));
    struct nlattr *attr_nh = nlmsg_nested_start(nlh, sizeof(buff));
    attr_nh->nla_len = 0;
    attr_nh->nla_type = IFLA_LINKINFO;
    nlmsg_add_attr(nlh,sizeof(buff),IFLA_INFO_KIND, info_kind, (strlen(info_kind)+1));

    //Nested BOND info IFLA_INFO_DATA
    struct nlattr *attr_nh_data = nlmsg_nested_start(nlh, sizeof(buff));
    attr_nh_data->nla_len = 0;
    attr_nh_data->nla_type = IFLA_INFO_DATA;
    int miimon= BOND_MIIMON;
    nlmsg_add_attr(nlh,sizeof(buff),IFLA_BOND_MIIMON,&miimon, sizeof(miimon));
    nlmsg_nested_end(nlh,attr_nh_data);
    nlmsg_nested_end(nlh,attr_nh);

    if(nl_do_set_request(NL_DEFAULT_VRF_NAME, nas_nl_sock_T_INT,nlh,buff,sizeof(buff)) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-LAG", "Failure to create LAG in kernel");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    if((*lag_index = cps_api_interface_name_to_if_index(lag_name)) == 0) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-LAG", "Error finding the ifindex of lag");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    if (nas_add_del_dummy_to_lag(*lag_index, true) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-LAG", "Error adding dummy to the lag");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    return STD_ERR_OK;
}

t_std_error nas_os_delete_lag(cps_api_object_t obj)
{

    cps_api_object_attr_t lag_attr = cps_api_object_attr_get(obj, DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);

    if(lag_attr == NULL) {
        EV_LOGGING( NAS_OS, ERR, "NAS-OS-LAG",
                "pameters missing for lag deletion in kernel %d",DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    hal_ifindex_t if_index = (hal_ifindex_t)cps_api_object_attr_data_u32(lag_attr);

    char if_lag_name[HAL_IF_NAME_SZ+1];
    if (cps_api_interface_if_index_to_name(if_index,if_lag_name,
                sizeof(if_lag_name))==NULL) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-LAG", "Invalid Lag Name from kernel");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }
    if (nas_add_del_dummy_to_lag(if_index, false) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-LAG", "Error deleting dummy from the lag");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    if(nas_os_del_interface(if_index) != STD_ERR_OK){
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-LAG", "Failure DEL LAG from kernel %s",if_lag_name);
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    EV_LOGGING(NAS_OS, INFO, "NAS-OS-LAG", "Delete Lag index %d Successful",if_index);

    return STD_ERR_OK;
}

t_std_error nas_os_process_ports(hal_ifindex_t lag_index,hal_ifindex_t if_index)
{
    char buff[NL_MSG_BUFF];
    memset(buff,0,sizeof(buff));

    struct nlmsghdr *nlh = (struct nlmsghdr *) nlmsg_reserve((struct nlmsghdr *)buff,sizeof(buff),
            sizeof(struct nlmsghdr));
    struct ifinfomsg *ifmsg = (struct ifinfomsg *) nlmsg_reserve(nlh,sizeof(buff),
            sizeof(struct ifinfomsg));

    nas_os_pack_nl_hdr(nlh, RTM_SETLINK, (NLM_F_REQUEST | NLM_F_ACK));
    ifmsg->ifi_family = AF_PACKET;
    ifmsg->ifi_index = if_index;

    nlmsg_add_attr(nlh,sizeof(buff), IFLA_MASTER, &lag_index, sizeof(int));
    if(nl_do_set_request(NL_DEFAULT_VRF_NAME, nas_nl_sock_T_INT,nlh,buff,sizeof(buff)) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS, ERR,"NAS-OS-LAG",
                "Failure Add/Dell interface in kernel for LAG");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    return STD_ERR_OK;
}

t_std_error nas_os_add_port_to_lag(cps_api_object_t obj)
{

    EV_LOGGING(NAS_OS, INFO, "CPS Interface", "ADD Port to LAG");

    cps_api_object_attr_t lag_index_attr = cps_api_object_attr_get(obj, DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);
    cps_api_object_attr_t lag_port_attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_MEMBER_PORTS);

    if((lag_index_attr == NULL) || (lag_port_attr == NULL)) {
        EV_LOGGING(NAS_OS, ERR,"NAS-OS-LAG",
                "Key parameters missing for lag addition in kernel");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    hal_ifindex_t lag_index = (hal_ifindex_t)cps_api_object_attr_data_u32(lag_index_attr);
    hal_ifindex_t if_index = (hal_ifindex_t)cps_api_object_attr_data_u32(lag_port_attr);

    EV_LOGGING(NAS_OS, INFO,"NAS-OS-LAG",
            "Add Port to Lag master_index %d and ifindex %d",lag_index,if_index);

    cps_api_object_t if_obj = cps_api_object_create();
    if(if_obj == NULL) {
        EV_LOGGING(NAS_OS, ERR,"NAS-OS-LAG","Failure creating object");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    t_std_error rc = STD_ERR_OK;
    bool state = true;
    do {
        cps_api_object_attr_add_u32(if_obj, DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX, if_index);
        db_interface_state_t astate;
        db_interface_operational_state_t ostate;
        char if_name[HAL_IF_NAME_SZ+1];
        cps_api_interface_if_index_to_name(if_index, if_name, sizeof(if_name));

        // get admin state information from kernel for the given member port
        if (nas_os_util_int_admin_state_get(if_name,&astate,&ostate)==STD_ERR_OK) {
            state = (astate == DB_ADMIN_STATE_UP)? true: false;
        } else {
            EV_LOGGING(NAS_OS,ERR,"NAS-IF-REG","Get admin failed for idx %s", if_name);
        }

        EV_LOGGING(NAS_OS, INFO, "NET-MAIN", "Masking admin state event for %d", if_index);
        os_interface_mask_event(if_index, OS_IF_ADM_CHANGE);

        // If admin state as returned by kernel is UP, explicitly set it to ADMIN DOWN
        if(state) {
            cps_api_object_attr_delete(if_obj,IF_INTERFACES_INTERFACE_ENABLED);
            cps_api_object_attr_add_u32(if_obj,IF_INTERFACES_INTERFACE_ENABLED, false);
            if(nas_os_interface_set_attribute(if_obj,IF_INTERFACES_INTERFACE_ENABLED)!=STD_ERR_OK) {
                EV_LOGGING(NAS_OS,ERR,"NAS-IF-REG","Set admin failed for idx %d", if_index);
                rc = STD_ERR(NAS_OS,FAIL, 0);
                break;
            }
        }

        if(nas_os_process_ports(lag_index,if_index) != STD_ERR_OK) {
            EV_LOGGING(NAS_OS, ERR,"NAS-OS-LAG", "Failure  Adding interface in kernel");
            rc = (STD_ERR(NAS_OS,FAIL, 0));
            break;
        }

        if(!state) {
            cps_api_object_attr_delete(if_obj,IF_INTERFACES_INTERFACE_ENABLED);
            cps_api_object_attr_add_u32(if_obj,IF_INTERFACES_INTERFACE_ENABLED, false);
            if(nas_os_interface_set_attribute(if_obj,IF_INTERFACES_INTERFACE_ENABLED)!=STD_ERR_OK) {
                EV_LOGGING(NAS_OS,ERR,"NAS-IF-REG","Set admin failed for idx %d", if_index);
                rc = STD_ERR(NAS_OS,FAIL, 0);
                break;
            }
        }
    } while (0);

    cps_api_object_delete(if_obj);

    return rc;
}

t_std_error nas_os_delete_port_from_lag(cps_api_object_t obj)
{
    cps_api_object_attr_t lag_port_attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_MEMBER_PORTS);

    if(lag_port_attr == NULL) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-LAG",
                "Key parameters missing for lag addition in kernel");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    hal_ifindex_t lag_index = 0;
    hal_ifindex_t if_index = (hal_ifindex_t)cps_api_object_attr_data_u32(lag_port_attr);

    EV_LOGGING(NAS_OS, INFO,"NAS-OS-LAG",
            "Delete Port to Lag master_index %d and ifindex %d",lag_index,if_index);

    cps_api_object_t if_obj = cps_api_object_create();
    if(if_obj == NULL) {
        EV_LOGGING(NAS_OS, ERR,"NAS-OS-LAG","Failure creating object");
        return (STD_ERR(NAS_OS,FAIL, 0));
    }

    t_std_error rc = STD_ERR_OK;
    bool state;
    do {
        if (nas_os_get_interface_obj(if_index, if_obj)!=STD_ERR_OK) {
            rc = STD_ERR(NAS_OS,FAIL, 0);
            break;
        }
        cps_api_object_attr_t admin_attr = cps_api_object_attr_get(if_obj, IF_INTERFACES_INTERFACE_ENABLED);
        if(admin_attr == NULL) {
            EV_LOGGING(NAS_OS, ERR,"NAS-OS-LAG","Admin attribute missing!");
            rc = STD_ERR(NAS_OS,FAIL, 0);
            break;
        }

        state = (bool) cps_api_object_attr_data_u32(admin_attr);

        if(nas_os_process_ports(lag_index,if_index) != STD_ERR_OK) {
            EV_LOGGING(NAS_OS, ERR,"NAS-OS-LAG","Failure Deleting interface in kernel");
            rc = STD_ERR(NAS_OS,FAIL, 0);
            break;
        }

        /*
         * Kernel makes the port down after removing it from lag. Bring it back up
         * if the admin-state was originally up for the port
         */
        if(state) {
            cps_api_object_attr_delete(if_obj,IF_INTERFACES_INTERFACE_ENABLED);
            cps_api_object_attr_add_u32(if_obj,IF_INTERFACES_INTERFACE_ENABLED, true);
            if(nas_os_interface_set_attribute(if_obj,IF_INTERFACES_INTERFACE_ENABLED)!=STD_ERR_OK) {
                EV_LOGGING(NAS_OS, ERR,"NAS-OS-LAG","Set admin failed for idx %d", if_index);
                rc = STD_ERR(NAS_OS,FAIL, 0);
                break;
            }
        }
    }while(0);

    cps_api_object_delete(if_obj);

    return rc;
}
