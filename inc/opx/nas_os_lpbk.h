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
 * filename: nas_os_lpbk.h
 */
#ifndef NAS_OS_LPBK_H_
#define NAS_OS_LPBK_H_

#include "cps_api_object.h"
#include "std_error_codes.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief : Deletes a loopback interface
 *
 * @obj : CPS API object for delete operation
 *
 * @return : Returns cps_api_ret_code_OK on success, or error code
 */
t_std_error nas_os_lpbk_delete(cps_api_object_t obj);

/**
 * @brief : Creates a loopback interface
 *
 * @obj : CPS API object for create operation
 *
 * @return : Returns cps_api_ret_code_OK on success, or error code
 */
t_std_error nas_os_lpbk_create(cps_api_object_t obj);


#ifdef __cplusplus
}
#endif

#endif /* NAS_OS_LPBK_H_ */
