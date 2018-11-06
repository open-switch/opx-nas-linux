/*
 * nas_vxlan_unittest.cpp
 *
 *  Created on: May 22, 2018
 */


#include "dell-interface.h"
#include "nas_os_vxlan.h"
#include "ds_common_types.h"
#include "dell-base-if.h"
#include "nas_os_interface.h"
#include <gtest/gtest.h>

static hal_ifindex_t ifindex=0;

bool vxlan_create_test(){
    cps_api_object_t obj = cps_api_object_create();
    uint32_t vni = 100;
    uint32_t ip = 16843009;
    uint32_t fam = AF_INET;
    const char * name = "vxlan100";

    cps_api_object_attr_add_u32(obj,DELL_IF_IF_INTERFACES_INTERFACE_VNI,vni);
    cps_api_object_attr_add_u32(obj,DELL_IF_IF_INTERFACES_INTERFACE_SOURCE_IP_ADDR,ip);
    cps_api_object_attr_add_u32(obj,DELL_IF_IF_INTERFACES_INTERFACE_SOURCE_IP_ADDR_FAMILY,fam);
    cps_api_object_attr_add(obj, IF_INTERFACES_INTERFACE_NAME, name, strlen(name) + 1);

    if(nas_os_create_vxlan_interface(obj) != STD_ERR_OK){
        return false;
    }

    cps_api_object_attr_t ifindex_attr = cps_api_object_attr_get(obj,DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);
    if(ifindex_attr){
        ifindex = cps_api_object_attr_data_uint(ifindex_attr);
    }

    return true;
}

bool vxlan_invalid_create_test(){
    cps_api_object_t obj = cps_api_object_create();
    const char * name = "vxlan100";
    cps_api_object_attr_add(obj, IF_INTERFACES_INTERFACE_NAME, name, strlen(name) + 1);
    return nas_os_create_vxlan_interface(obj) == STD_ERR_OK;

}

bool vxlan_delete_test(){
    if(ifindex){
        if(nas_os_del_interface(ifindex)==STD_ERR_OK){
            return true;
        }
    }

    return false;
}


TEST(nas_vxlan_test, nas_vxlan_basic_test) {
    ASSERT_TRUE(vxlan_create_test());
    ASSERT_FALSE(vxlan_invalid_create_test());
    ASSERT_TRUE(vxlan_delete_test());
}


int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
