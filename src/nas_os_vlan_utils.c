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
 * nas_os_vlan_utils.c
 *
 *  Created on: June 5, 2015
 */

#include "ds_common_types.h"
#include "nas_os_vlan_utils.h"
#include "ds_api_linux_interface.h"
#include "event_log.h"
#include "std_utils.h"
#include <stdio.h>
#include <string.h>

// TODO deprecate all calls to this function
void nas_os_get_vlan_if_name(char *if_name, int len, hal_vlan_id_t vlan_id, char *vlan_name)
{
    if(vlan_id != 0) {
        snprintf(vlan_name, HAL_IF_NAME_SZ, "%s.%d", if_name, vlan_id);
    }
    else {
        strncpy(vlan_name, if_name, len);
    }
}

// TODO deprecate all calls to this function
bool nas_os_physical_to_vlan_ifindex(hal_ifindex_t intf_index, hal_vlan_id_t vlan_id,
                                            bool to_vlan,hal_ifindex_t * index){
    char intf_name[HAL_IF_NAME_SZ+1];
    char vlan_intf_name[HAL_IF_NAME_SZ+1];
    char *converted_intf_name = NULL;

    if(cps_api_interface_if_index_to_name(intf_index,intf_name,sizeof(intf_name))==NULL){
        EV_LOG(ERR,NAS_OS,0,"NAS-LINUX-INTERFACE","Invalid Interface Index %d ",intf_index);
        return false;
    }

    if(to_vlan){
        snprintf(vlan_intf_name,sizeof(vlan_intf_name),"%s.%d",intf_name,vlan_id);
        converted_intf_name = vlan_intf_name;
    }else{
        char * saveptr;
        converted_intf_name = strtok_r(intf_name,".",&saveptr);
    }

    if(((*index) = cps_api_interface_name_to_if_index(converted_intf_name)) == 0){
        EV_LOG(ERR,NAS_OS,0,"NAS-LINUX-INTERFACE","Invalid Interface name %s ",converted_intf_name);
        return false;
    }

    return true;
}

/* This utility converts the sub interface name to phy if_index i.e e101-001-0.202 to ifindex of e101-001-0 */
bool nas_os_sub_intf_to_phy_intf_name(char *sub_intf_name,  char * phy_intf_name) {

    if (( sub_intf_name == NULL ) || (phy_intf_name == NULL)) {
        return false;
    }
    char *converted_intf_name = NULL;
    char *saveptr = NULL;

    converted_intf_name = strtok_r(sub_intf_name,".",&saveptr);
    if(converted_intf_name == NULL)
        return false;
    safestrncpy(phy_intf_name, converted_intf_name, HAL_IF_NAME_SZ);
    return true;
}
/* This utility converts the sub interface name to if_index i.e e101-001-0.202 to ifindex of e101-001-0 */
// TODO To be deprecated
bool nas_os_sub_intf_name_to_intf_ifindex(char *sub_intf_name, hal_ifindex_t * index){
    char *converted_intf_name = NULL;
    char *saveptr = NULL;

    if (sub_intf_name == NULL)
        return false;

    converted_intf_name = strtok_r(sub_intf_name,".",&saveptr);
    if(converted_intf_name == NULL)
        return false;

    if(((*index) = cps_api_interface_name_to_if_index(converted_intf_name)) == 0){
        EV_LOG(ERR,NAS_OS,0,"NAS-LINUX-INTERFACE","Invalid Interface name %s ",converted_intf_name);
        return false;
    }

    return true;
}






