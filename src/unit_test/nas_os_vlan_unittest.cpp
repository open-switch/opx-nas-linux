#include "std_error_codes.h"
#include "ds_common_types.h"
#include "cps_api_object.h"
#include "dell-base-if-vlan.h"
#include "dell-base-if.h"
#include "dell-interface.h"
#include "nas_os_vlan.h"
#include <netinet/in.h>
#include <linux/if_bridge.h>
#include <net/if.h>
#include <gtest/gtest.h>
#include <iostream>

using namespace std;



TEST(nas_vlan_create, VLAN_OS_create) {
   char buff[10000];
   memset (buff, 0, sizeof(buff));
   int idx;
   std::string bridge_name("bridge20");
   cps_api_object_t obj = cps_api_object_init(buff,sizeof(buff));
   cps_api_object_attr_add(obj, IF_INTERFACES_INTERFACE_NAME, bridge_name.c_str(),
                    strlen(bridge_name.c_str())+1);
   ASSERT_EQ(nas_os_add_vlan(obj, &idx), STD_ERR_OK);
   std::cout <<"bridge20 created with index "<< idx << std::endl;
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);

  return RUN_ALL_TESTS();
}
