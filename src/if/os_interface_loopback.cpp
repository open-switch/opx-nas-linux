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

/*!
 * \file   os_interface_loopback.cpp
 */

#include "private/nas_os_if_priv.h"
#include "dell-base-common.h"
#include "cps_api_object.h"
#include "event_log.h"

#include <string.h>

#define LPBK_INFO_KIND      "dummy"

// The "dummy" interface was used as OS implementation for our manually created loopback
// interface type per CPS request.
// If we are trying to read loopback interfaces, we need to browse "dummy" interfaces
// from OS by netlink request. But below two types of "dummy" interfaces are not counted
// as loopback type and need to be removed from the read list:
//   1. Dummy interface "dummy0", that is created by OS during initiation.
//   2. Dummy interface created as default member of lag when new lag interface created,
//      with name format as "dummy-bo-<ifindex>"
static bool os_interface_is_valid_loopback_intf(const std::string& if_name)
{
    if (if_name == "dummy0") {
        // OS dummy interface
        return false;
    }
    std::string dummy_prefix = "dummy-bo-";
    if (if_name.substr(0, dummy_prefix.size()) == dummy_prefix) {
        std::string num_str = if_name.substr(dummy_prefix.size());
        try {
            std::size_t pos;
            (void)std::stol(num_str, &pos);
            if (pos == num_str.size()) {
                // sub-name after prefix contains all number characters
                return false;
            }
        } catch (std::exception& e) {
            // no action needed, just fall-through to return TRUE
        }
    }

    return true;
}

bool INTERFACE::os_interface_dummy_attrs_handler(if_details *details, cps_api_object_t obj)
{
    if (details->_info_kind == nullptr) {
        return true;
    }

    if (strncmp(details->_info_kind, LPBK_INFO_KIND, strlen(LPBK_INFO_KIND)) == 0 &&
        os_interface_is_valid_loopback_intf(details->if_name)) {
        details->_type = BASE_CMN_INTERFACE_TYPE_LOOPBACK;
        EV_LOGGING(NAS_OS,DEBUG,"NAS-LINUX-INTERFACE"," In IFLA_INFO_KIND set for %s index %d name:%s",
            details->_info_kind, details->_ifindex, details->if_name.c_str());
    }
    return true;
}
