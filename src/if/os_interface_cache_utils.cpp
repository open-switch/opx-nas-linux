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
 * \file   os_interface_cache_utils.cpp
 */


#include "private/nas_os_if_priv.h"
#include "private/os_interface_cache_utils.h"
#include "os_if_utils.h"
#include "std_utils.h"
#include <string>


#ifdef __cplusplus
extern "C" {
#endif

t_std_error nas_os_check_intf_exists(hal_ifindex_t if_index, bool *present) {

    INTERFACE *fill = os_get_if_db_hdlr();
    if (!fill) return STD_ERR(INTERFACE,FAIL,0);
    *present = fill->if_info_present(if_index);
    return STD_ERR_OK;
}

t_std_error nas_os_ifindex_to_intf_name_get(char *if_name, hal_ifindex_t if_index, size_t len)
{
    if ((len<HAL_IF_NAME_SZ) || (!if_name)) return STD_ERR(INTERFACE,FAIL,0);

    INTERFACE *fill = os_get_if_db_hdlr();
    if (!fill) return STD_ERR(INTERFACE,FAIL,0);
    std::string _name = fill->if_info_get_name(if_index);
    safestrncpy(if_name, (char*)_name.c_str(), HAL_IF_NAME_SZ);
    return STD_ERR_OK;
}


#ifdef __cplusplus
}
#endif

