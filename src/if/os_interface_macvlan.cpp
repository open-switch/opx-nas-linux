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
 * \file   os_interface_macvlan.cpp
 */

#include "private/nas_os_if_priv.h"
#include "dell-base-common.h"
#include "cps_api_object.h"
#include "event_log.h"

#include <string.h>

#define MV_LEN 7

bool INTERFACE::os_interface_macvlan_attrs_handler(if_details *details, cps_api_object_t obj)
{
    if (details->_info_kind == nullptr) {
        return true;
    }

    if (!strncmp(details->_info_kind, "macvlan", MV_LEN)) {
        details->_type = BASE_CMN_INTERFACE_TYPE_MACVLAN;
        EV_LOGGING(NAS_OS,INFO,"NAS-LINUX-INTERFACE"," In IFLA_INFO_KIND macvlan set for %s index %d name:%s",
            details->_info_kind, details->_ifindex, details->if_name.c_str());

    }
    return true;
}
