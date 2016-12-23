#include "nas_linux_l2.h"
#include "dell-base-l2-mac.h"
#include "std_error_codes.h"
#include "ds_common_types.h"
#include "cps_api_object.h"

#include <netinet/in.h>
#include <linux/if_bridge.h>
#include <net/if.h>
#include <gtest/gtest.h>

TEST(nas_os_mac_test,change_learning) {

    hal_ifindex_t index = if_nametoindex("e101-001-0");
    ASSERT_EQ(nas_os_mac_change_learning(index,true), STD_ERR_OK);
    ASSERT_EQ(nas_os_mac_change_learning(index,false), STD_ERR_OK);
}

TEST(nas_os_mac_test,add_entry) {
    static char buff[10000];

    //Create a FDB entry in the kernel

    cps_api_object_t obj = cps_api_object_init(buff,sizeof(buff));
    cps_api_object_set_type_operation(cps_api_object_key(obj),cps_api_oper_CREATE);
    cps_api_object_attr_add_u32(obj,BASE_MAC_TABLE_IFINDEX,if_nametoindex("e101-001-0"));
    cps_api_object_attr_add_u32(obj,BASE_MAC_TABLE_STATIC,1);
    uint8_t mac_addr[6]={0x00,0x02,0x03,0x04,0x05,0x05};
    cps_api_object_attr_add(obj,BASE_MAC_TABLE_MAC_ADDRESS,(void *)&mac_addr,sizeof(mac_addr));
    ASSERT_EQ(nas_os_mac_update_entry(obj),STD_ERR_OK);


    // Replace the FDB entry to different interface in case of mac move
    memset(buff,0,sizeof(buff));
    cps_api_object_t obj1 = cps_api_object_init(buff,sizeof(buff));
    cps_api_object_set_type_operation(cps_api_object_key(obj1),cps_api_oper_SET);
    cps_api_object_attr_add_u32(obj1,BASE_MAC_TABLE_IFINDEX,if_nametoindex("e101-002-0"));
    cps_api_object_attr_add(obj1,BASE_MAC_TABLE_MAC_ADDRESS,(void *)&mac_addr,sizeof(mac_addr));
    ASSERT_EQ(nas_os_mac_update_entry(obj1),STD_ERR_OK);

    // Delete the FDB entry from kernel
    memset(buff,0,sizeof(buff));
    cps_api_object_t obj2 = cps_api_object_init(buff,sizeof(buff));
    cps_api_object_set_type_operation(cps_api_object_key(obj2),cps_api_oper_DELETE);
    cps_api_object_attr_add_u32(obj2,BASE_MAC_TABLE_IFINDEX,if_nametoindex("e101-002-0"));
    cps_api_object_attr_add(obj2,BASE_MAC_TABLE_MAC_ADDRESS,(void *)&mac_addr,sizeof(mac_addr));
    ASSERT_EQ(nas_os_mac_update_entry(obj2),STD_ERR_OK);

}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);

  return RUN_ALL_TESTS();
}
