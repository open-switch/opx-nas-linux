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

/*!
 * \file   os_interface_lag.cpp
 */

#include "private/nas_os_if_priv.h"
#include "private/os_if_utils.h"
#include "dell-base-if.h"
#include "dell-base-if-lag.h"
#include "dell-interface.h"
#include "ds_api_linux_interface.h"

#include "nas_nlmsg.h"

#include "nas_os_int_utils.h"

#include "event_log.h"
#include "std_mac_utils.h"

#include <linux/if_link.h>
#include <linux/if.h>

static inline bool os_interface_lag_add_member_name(hal_ifindex_t ifix, cps_api_object_t obj)
{
    char if_name[HAL_IF_NAME_SZ+1];
    if (cps_api_interface_if_index_to_name(ifix,if_name,  sizeof(if_name))==NULL) {
        return false;
    }

    cps_api_object_attr_add(obj, DELL_IF_IF_INTERFACES_INTERFACE_MEMBER_PORTS_NAME, if_name, strlen(if_name)+1);
    return true;
}

static void os_interface_lag_reset_mac(hal_ifindex_t ifix)
{
    char if_name[HAL_IF_NAME_SZ+1];
    if (cps_api_interface_if_index_to_name(ifix,if_name,  sizeof(if_name))==NULL) {
        return;
    }

    INTERFACE *fill = os_get_if_db_hdlr();
    if (!fill) return;

    if_info_t ifinfo;
    if(!fill->if_info_get(ifix, ifinfo))
        return;

    char mac_str[40] = {0};
    EV_LOGGING(NAS_OS, DEBUG, "NET-MAIN", "Resetting mac address %s to %s",
                               if_name, std_mac_to_string(&ifinfo.phy_addr,mac_str,sizeof(mac_str)));

    nas_os_util_int_mac_addr_set(if_name, &ifinfo.phy_addr);

    return;
}

bool INTERFACE::os_interface_lag_attrs_handler(if_details *details, cps_api_object_t obj)
{
    if(details->_type == BASE_CMN_INTERFACE_TYPE_LAG) {
        // Netlink event for bond interface

        EV_LOG(INFO, NAS_OS,3, "NET-MAIN", "Bond interface index is %d ",
                details->_ifindex);
        if (details->_attrs[IFLA_MASTER]!=nullptr) {
            // this is for bond addition/deletion to the bridge
            EV_LOGGING(NAS_OS, INFO, "NET-MAIN", "Bond %s adddition/deletion to the bridge", details->if_name);
            return true;
        }
        return true;
    } // bond interface

    // Else check if netlink event is for slave addition or deletion to the bond
    if_bond *bond_hdlr = os_get_bond_db_hdlr();
    hal_ifindex_t master_idx = (details->_attrs[IFLA_MASTER]!=NULL)?
                                *(int *)nla_data(details->_attrs[IFLA_MASTER]):0;

    if (details->_info_kind!=nullptr && !strncmp(details->_info_kind, "tun", 3)) {
         if(details->_attrs[IFLA_MASTER]!=NULL  && ((details->_flags & IFF_SLAVE)!=0)) {
            EV_LOG(INFO, NAS_OS,3, "NET-MAIN", "Received tun %d and state 0x%x",
                        details->_ifindex,details->_flags);
            if(bond_hdlr && bond_hdlr->bond_mbr_present(master_idx, details->_ifindex)){
                EV_LOG(INFO, NAS_OS,3, "NET-MAIN", "Bond mbr present in master %d, slave %d",
                            master_idx, details->_ifindex);
                return true;
            }
            if(bond_hdlr) bond_hdlr->bond_mbr_add(master_idx, details->_ifindex);
            // Unmask the event publish for this interface after lag addition
            os_interface_mask_event(details->_ifindex, OS_IF_CHANGE_NONE);

            if(!os_interface_lag_add_member_name(details->_ifindex, obj)) return false;
            details->_type = BASE_CMN_INTERFACE_TYPE_LAG;
            details->_op = cps_api_oper_CREATE;

         } else if ((details->_flags & IFF_SLAVE)!=0) {
             if(bond_hdlr && (master_idx = bond_hdlr->bond_master_get(details->_ifindex))) {
                 bond_hdlr->bond_mbr_del(master_idx, details->_ifindex);
                 /*
                  * Kernel sets a random MAC to bond interface when the last member
                  * is removed from Bond. Resetting it back to previous MAC
                  */
                 if(bond_hdlr->bond_mbr_list_chk_empty(master_idx))
                     os_interface_lag_reset_mac(master_idx);
             }

             if(!master_idx) {
                 EV_LOGGING(NAS_OS, DEBUG, "NET-MAIN", "No master found, this could be an if update for %d",
                             details->_ifindex);
                 return true;
             }

             EV_LOG(INFO, NAS_OS,3, "NET-MAIN", "Lag member delete: tun %d and state 0x%x",
                         details->_ifindex,details->_flags);

             if(!os_interface_lag_add_member_name(details->_ifindex, obj)) return false;

             cps_api_object_attr_delete(obj, DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);
             cps_api_object_attr_delete(obj, IF_INTERFACES_INTERFACE_NAME);
             cps_api_object_attr_add_u32(obj, DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX,master_idx);

             details->_type = BASE_CMN_INTERFACE_TYPE_LAG;
             details->_op = cps_api_oper_DELETE;
         }
    }
    return true;
}
