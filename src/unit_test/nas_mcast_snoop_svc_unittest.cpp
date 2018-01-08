/*
 * Copyright (c) 2017 Dell Inc.
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
 * nas_mcast_snoop_svc_unittest.cpp
 *
 */

#include <stdlib.h>
#include <gtest/gtest.h>

#include "cps_class_map.h"
#include "cps_api_operation.h"
#include "ietf-igmp-mld-snooping.h"

static std::string mem_port1 = "e101-010-1";
static std::string mem_port2 = "e101-012-1";
static std::string mem_port3 = "e101-003-0";
static uint16_t vlan_id = 100;
static std::string vlan_name = "br100";

static uint32_t mcast_enable = 1;
static uint16_t mcast_query_interval = 175;
static uint16_t mcast_last_member_query_interval = 125; 
static char mcast_querier[25] = "10.11.56.55";

TEST(std_mcast_snoop_test, mcast_snoop_prereq) {
    /*  Create a bridge and add member ports */

    // Create a tagged port
    std::string tagged_mem_port3 = mem_port3+'.'+std::to_string(vlan_id);

    system( ("ip link add link "+ mem_port3 + " name "+ tagged_mem_port3 + " type vlan id "+ std::to_string(vlan_id)).c_str());
    // Create a bridge
    system( ("brctl addbr "+ vlan_name).c_str());

    // Add member ports to a bridge
    system( ("brctl addif " +vlan_name+ " " + tagged_mem_port3).c_str() );
    system( ("brctl addif " +vlan_name+ " " + mem_port2).c_str() );
    system( ("brctl addif " +vlan_name+ " " + mem_port1).c_str() );

    // Make bridge and member ports admin up
    system( ("ifconfig " + vlan_name +" up").c_str() );
    system( ("ifconfig " + mem_port1 +" up").c_str() );
    system( ("ifconfig " + mem_port2 +" up").c_str() );
    system( ("ifconfig " + mem_port3 +" up").c_str() );
}

bool cps_commit(cps_api_object_t obj) {
    bool ret = false;
    cps_api_transaction_params_t tr;
    if(cps_api_transaction_init(&tr)!=cps_api_ret_code_OK) return false;
    cps_api_create(&tr,obj);
    std::cout << "Input object for COMMIT: " << std::endl;
    cps_api_object_print(obj);

    if(cps_api_commit(&tr)==cps_api_ret_code_OK) ret = true;

    cps_api_transaction_close(&tr);
    return ret;
}

bool cps_get(cps_api_object_t obj, cps_api_object_t result) {
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);

    if(!cps_api_object_list_append(gp.filters, obj)) return false;
    std::cout << "Input object for GET: " << std::endl;
    cps_api_object_print(obj);
    std::cout << "Input list size: " << cps_api_object_list_size(gp.filters) << std::endl;

    if (cps_api_get(&gp)==cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);
        std::cout << "Result Size: " << mx << std::endl;

        for (size_t ix = 0 ; ix < mx ; ++ix ) {
            cps_api_object_t res = cps_api_object_list_get(gp.list,ix);
            // cps_get is called with a specific vlan-id in this UT.Hence the result from GET will have only 1 object
            if(!cps_api_object_clone(result, res)) return false;
        }
    }
    cps_api_get_request_close(&gp);
    return true;

}

void igmp_obj(cps_api_object_t obj, uint16_t id, bool config) {
    cps_api_attr_id_t vlans_attr_id, vlan_attr_id;
    if(config) { 
        vlans_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN;
        vlan_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_VLAN_ID;
        cps_api_key_from_attr_with_qual(cps_api_object_key(obj), vlans_attr_id, cps_api_qualifier_TARGET);
    }
    else {
        vlans_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN;
        vlan_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_VLAN_ID;
        cps_api_key_from_attr_with_qual(cps_api_object_key(obj), vlans_attr_id, cps_api_qualifier_OBSERVED);
    }

    cps_api_object_attr_add_u16(obj, vlan_attr_id, id);

}

TEST(std_mcast_snoop_test, mcast_snoop_query_interval) {

    // Set multicast query interval on a VLAN
    cps_api_object_guard commit_og(cps_api_object_create());
    igmp_obj(commit_og.get(), vlan_id, true);
    cps_api_object_attr_add_u16(commit_og.get(), IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_QUERY_INTERVAL_QUERY_INTERVAL_BASIC_QUERY_INTERVAL_BASIC, mcast_query_interval);
    
    ASSERT_TRUE( cps_commit(commit_og.get()));
  
    // Verify the SET using CPS GET
    cps_api_object_guard get_og(cps_api_object_create());
    igmp_obj(get_og.get(), vlan_id, false);
    
    cps_api_object_guard get_result_og(cps_api_object_create());
    ASSERT_TRUE( cps_get(get_og.get(), get_result_og.get()));
    cps_api_object_print(get_result_og.get());

    // Check query interval attribute
    cps_api_object_attr_t query_interval_attr = cps_api_object_attr_get(get_result_og.get(), IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_QUERY_INTERVAL_QUERY_INTERVAL_BASIC_QUERY_INTERVAL_BASIC);
    ASSERT_TRUE(query_interval_attr != nullptr);
    ASSERT_TRUE(cps_api_object_attr_data_u16(query_interval_attr) == mcast_query_interval);


}

TEST(std_mcast_snoop_test, mcast_snoop_last_member_query_interval) {

    // Set multicast last memeber query interval on a VLAN
    cps_api_object_guard commit_og(cps_api_object_create());
    igmp_obj(commit_og.get(), vlan_id, true);
    cps_api_object_attr_add_u16(commit_og.get(), IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_LAST_MEMBER_QUERY_INTERVAL_LAST_MEMBER_QUERY_INTERVAL_BASIC_LAST_MEMBER_QUERY_INTERVAL_BASIC, mcast_last_member_query_interval);

    ASSERT_TRUE( cps_commit(commit_og.get()));

    // Verify the SET using CPS GET
    cps_api_object_guard get_og(cps_api_object_create());
    igmp_obj(get_og.get(), vlan_id, false);
    
    cps_api_object_guard get_result_og(cps_api_object_create());
    ASSERT_TRUE( cps_get(get_og.get(), get_result_og.get()));
    cps_api_object_print(get_result_og.get());

    // Check last member query interval attribute
    cps_api_object_attr_t last_member_query_interval_attr = cps_api_object_attr_get(get_result_og.get(), IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_LAST_MEMBER_QUERY_INTERVAL_LAST_MEMBER_QUERY_INTERVAL_BASIC_LAST_MEMBER_QUERY_INTERVAL_BASIC);
    ASSERT_TRUE(last_member_query_interval_attr != nullptr);
    ASSERT_TRUE(cps_api_object_attr_data_u16(last_member_query_interval_attr) == mcast_last_member_query_interval);
    
}

TEST(std_mcast_snoop_test, mcast_snoop_querier) {

    // Set querier functionality on a VLAN
    cps_api_object_t obj = cps_api_object_create();
    igmp_obj(obj, vlan_id, true);
    cps_api_object_attr_add(obj, IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_QUERIER, (const char *)mcast_querier, sizeof(mcast_querier));

    ASSERT_TRUE( cps_commit(obj));

    // Verify the SET using CPS GET
    cps_api_object_guard get_og(cps_api_object_create());
    igmp_obj(get_og.get(), vlan_id, false);

    cps_api_object_guard get_result_og(cps_api_object_create());
    ASSERT_TRUE( cps_get(get_og.get(), get_result_og.get()));
    cps_api_object_print(get_result_og.get());

    // Check querier attribute
    cps_api_object_attr_t querier_attr = cps_api_object_attr_get(get_result_og.get(), IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_QUERIER);
    ASSERT_TRUE(querier_attr != nullptr);

}

TEST(std_mcast_snoop_test, mcast_snoop_status) {

    // Enable/Disable multicast snooping on a VLAN
    cps_api_object_guard commit_og(cps_api_object_create());
    igmp_obj(commit_og.get(), vlan_id, true);
    cps_api_object_attr_add_u32(commit_og.get(),IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_ENABLE, mcast_enable);
    
    ASSERT_TRUE( cps_commit(commit_og.get()));

    // Verify the SET using CPS GET
    cps_api_object_guard get_og(cps_api_object_create());
    igmp_obj(get_og.get(), vlan_id, false);
    
    cps_api_object_guard get_result_og(cps_api_object_create());
    ASSERT_TRUE( cps_get(get_og.get(), get_result_og.get()));
    cps_api_object_print(get_result_og.get());

    // Check vlan enable attribute
    cps_api_object_attr_t vlan_enable_attr = cps_api_object_attr_get(get_result_og.get(), IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_ENABLE);
    ASSERT_TRUE(vlan_enable_attr != nullptr);
    ASSERT_TRUE(cps_api_object_attr_data_u32(vlan_enable_attr) == mcast_enable);

}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);

  return RUN_ALL_TESTS();
}
