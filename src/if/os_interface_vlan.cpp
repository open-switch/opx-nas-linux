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
 * \file   os_interface_vlan.cpp
 */

#include "dell-base-if-vlan.h"
#include "dell-interface.h"
#include "private/nas_os_if_priv.h"
#include "private/nas_nlmsg_object_utils.h"
#include "nas_os_if_conversion_utils.h"
#include "event_log.h"
#include <linux/if_link.h>
#include <string>

/* A container to store the tagged/untagged member ports with VLANs mapping */
bool INTERFACE::os_interface_vlan_attrs_handler(if_details *details, cps_api_object_t obj)
{
    if(details->_type == BASE_CMN_INTERFACE_TYPE_VLAN_SUBINTF) {

        if ((details->_attrs[IFLA_MASTER]== NULL) && (details->_op == cps_api_oper_CREATE)) {
            details->parent_idx = *(hal_ifindex_t *)nla_data(details->_attrs[IFLA_LINK]);
            std::string parent_name =  nas_os_if_name_get(details->parent_idx);
            cps_api_object_attr_add(obj, DELL_IF_IF_INTERFACES_INTERFACE_PARENT_INTERFACE,
                    parent_name.c_str() , strlen(parent_name.c_str())+1);
            EV_LOGGING(NAS_OS, INFO, "NET-MAIN", "VLAN sub interface create %s parent name %s",
                                            details->if_name.c_str(), parent_name.c_str());

            struct nlattr *vlan[IFLA_VLAN_MAX];
            memset(vlan,0,sizeof(vlan));
            nla_parse_nested(vlan,IFLA_VLAN_MAX,details->_linkinfo[IFLA_INFO_DATA]);
            if (vlan[IFLA_VLAN_ID]) {
                EV_LOG(INFO, NAS_OS, 3, "NET-MAIN", "Received VLAN %d", details->_ifindex);
                cps_api_object_attr_add_u32(obj,BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID,
                        *(uint16_t*)nla_data(vlan[IFLA_VLAN_ID]));
            }
        }
    }
    return true;
}


