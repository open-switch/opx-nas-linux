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

/*!
 * \file  os_interface_mgmt.cpp 
 */

#include "private/nas_os_if_priv.h"
#include "dell-base-common.h"
#include "cps_api_object.h"

#include <string.h>

#define MGMT_INTF_NAME      "eth0"

bool INTERFACE::os_interface_mgmt_attrs_handler(if_details *details, cps_api_object_t obj)
{

    if ((details->if_name.c_str() != nullptr)
            && (strncmp(details->if_name.c_str(), MGMT_INTF_NAME, strlen(MGMT_INTF_NAME)) == 0)) {
        details->_type = BASE_CMN_INTERFACE_TYPE_MANAGEMENT;
    }

    return true;
}
