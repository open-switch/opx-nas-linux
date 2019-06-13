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
 * nas_mcast_snoop_svc_unittest.cpp
 *
 */

#include <stdlib.h>
#include <gtest/gtest.h>

#include "std_utils.h"
#include "cps_class_map.h"
#include "cps_api_operation.h"
#include "cps_api_object_key.h"
#include "cps_api_events.h"
#include "ietf-igmp-mld-snooping.h"

#define KEY_PRINT_BUF_LEN 100
#define IFNAME_LEN 16

static std::string mem_port1 = "e101-005-0";
static std::string mem_port2 = "e101-006-0";
static std::string mem_port3 = "e101-003-0";
static uint16_t vlan_id = 100;
static std::string vlan_name = "br100";

static uint32_t mcast_enable = 1;
static uint16_t mcast_query_interval = 175;
static uint16_t mcast_last_member_query_interval = 125;
static char mcast_querier[25] = "10.11.56.55";
static const char *mrouter_ifname = "e101-003-0";
static char received_igmp_mrouter_ifname[IFNAME_LEN] = {0};
static char received_mld_mrouter_ifname[IFNAME_LEN] = {0};
static char received_igmp_vlan = 0;
static char received_igmp_op = 0;
static char received_mld_vlan = 0;
static char received_mld_op = 0;
static int event_reg = false;
static int event_type = 0;
static cps_api_key_t mc_igmp_obj_key;
static cps_api_key_t mc_mld_obj_key;

static bool mc_event_handler(cps_api_object_t evt_obj, void *param)
{
    cps_api_object_attr_t vlan_id_attr;
    cps_api_attr_id_t mrouter_id;

    std::cout<<"IGMP/MLD event back handler"<<std::endl;
    if (cps_api_key_matches(&mc_igmp_obj_key,
                    cps_api_object_key(evt_obj), 1) == 0) {
        event_type = 1;

        vlan_id_attr = cps_api_get_key_data(evt_obj,
                IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_VLAN_ID);

        mrouter_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_MROUTER_INTERFACE;
    } else if (cps_api_key_matches(&mc_mld_obj_key,
                    cps_api_object_key(evt_obj), 1) == 0) {
        event_type = 2;

        vlan_id_attr = cps_api_get_key_data(evt_obj,
                IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_VLAN_ID);

        mrouter_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_MROUTER_INTERFACE;
    } else {
        char key_buf[KEY_PRINT_BUF_LEN];
        std::cout<<"Unsupported object key: "<<cps_api_key_print(cps_api_object_key(evt_obj), key_buf, sizeof(key_buf))<<std::endl;
        return false;
    }

    if (vlan_id_attr == nullptr) {
        std::cout<<"VLAN ID attribute not found"<<std::endl;
        return false;
    }

    int received_vlan = cps_api_object_attr_data_u16(vlan_id_attr);
    cps_api_operation_types_t received_op = cps_api_object_type_operation(cps_api_object_key(evt_obj));

    if (event_type == 1) {
        std::cout<<"Received IGMP event for VLAN "<<received_vlan<<
                   " operation : "<<received_op<<std::endl;
    }
    else if (event_type == 2) {
        std::cout<<"Received MLD event for VLAN "<<received_vlan<<
                   " operation : "<<received_op<<std::endl;
    }

    cps_api_object_it_t it;
    for (cps_api_object_it_begin(evt_obj, &it); cps_api_object_it_valid(&it);
         cps_api_object_it_next(&it)) {
        cps_api_attr_id_t attr_id = cps_api_object_attr_id(it.attr);
        if (attr_id == mrouter_id) {
            if (event_type == 1) {
                safestrncpy(received_igmp_mrouter_ifname, (const char *)cps_api_object_attr_data_bin(it.attr),
                        sizeof(received_igmp_mrouter_ifname));
                std::cout<<"Handling mrouter event VLAN: "<<received_vlan<<
                         " mrouter interface: "<<received_igmp_mrouter_ifname<<std::endl;
            } else if (event_type == 2) {
                safestrncpy(received_mld_mrouter_ifname, (const char *)cps_api_object_attr_data_bin(it.attr),
                        sizeof(received_mld_mrouter_ifname));
                std::cout<<"Handling mrouter event VLAN: "<<received_vlan<<
                         " mrouter interface: "<<received_mld_mrouter_ifname<<std::endl;

            }
        }
    }

    return true;
}

static bool _ut_event_reg_init(void)
{
    cps_api_event_reg_t reg;

    if (event_reg == 1)
       return true;

    std::cout<<"Register for IGMP/MLD event thread"<<std::endl;
    cps_api_event_service_init();

    memset(&reg, 0, sizeof(reg));
    const uint_t NUM_KEYS = 2;
    cps_api_key_t key[NUM_KEYS];

    cps_api_key_from_attr_with_qual(&key[0],
                    IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN,
                    cps_api_qualifier_OBSERVED);
    memcpy(&mc_igmp_obj_key, &key[0], sizeof(cps_api_key_t));

    cps_api_key_from_attr_with_qual(&key[1],
                    IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN,
                    cps_api_qualifier_OBSERVED);
    memcpy(&mc_mld_obj_key, &key[1], sizeof(cps_api_key_t));

    reg.number_of_objects = NUM_KEYS;
    reg.objects = key;
    if (cps_api_event_thread_reg(&reg, mc_event_handler, NULL)
            != cps_api_ret_code_OK) {
        std::cout<<"Failed to register for IGMP/MLD event thread"<<std::endl;
        return false;
    }
    event_reg = 1;
    return true;
}

static bool _ut_event_reg_destory()
{
    if (event_reg)
    {
        if (cps_api_event_thread_shutdown() == cps_api_ret_code_OK)
        {
            event_reg = false;
            std::cout<<"De-register for IGMP/MLD event thread"<<std::endl;
        }
    }
    return true;
}


TEST(std_mcast_snoop_test, mcast_snoop_prereq) {
    /*  Create a bridge and add member ports */

    // Create a tagged port
    std::string tagged_mem_port3 = mem_port3+'.'+std::to_string(vlan_id);

    system( ("ip link add link "+ mem_port3 + " name "+ tagged_mem_port3 + " type vlan id "+ std::to_string(vlan_id)).c_str());
    // Create a bridge
    system( ("brctl addbr "+ vlan_name).c_str());

    system( ("brctl delif br1 " + mem_port1).c_str() );
    system( ("brctl delif br1 " + mem_port2).c_str() );

    // Add member ports to a bridge
    system( ("brctl addif " +vlan_name+ " " + tagged_mem_port3).c_str() );
    system( ("brctl addif " +vlan_name+ " " + mem_port2).c_str() );
    system( ("brctl addif " +vlan_name+ " " + mem_port1).c_str() );

    // Make bridge and member ports admin up
    system( ("ifconfig " + vlan_name +" up").c_str() );
    system( ("ifconfig " + mem_port1 +" up").c_str() );
    system( ("ifconfig " + mem_port2 +" up").c_str() );
    system( ("ifconfig " + mem_port3 +" up").c_str() );

    //Register for IGMP/MLD events.
    if (_ut_event_reg_init() != 1) {
      std::cout<<"Reg init failed"<<std::endl;
      ASSERT_TRUE(0);
    }
}

bool cps_commit(cps_api_object_t obj, cps_api_operation_types_t op) {
    bool ret = false;
    cps_api_return_code_t cps_ret;
    cps_api_transaction_params_t tr;
    if(cps_api_transaction_init(&tr)!=cps_api_ret_code_OK) return false;

    cps_api_object_t tr_obj = cps_api_object_create_clone(obj);

    if(tr_obj == NULL) {
      cps_api_transaction_close(&tr);
      return false;
    }

    if (op == cps_api_oper_CREATE)
      cps_ret = cps_api_create(&tr,tr_obj);
    else
      cps_ret = cps_api_delete(&tr,tr_obj);

    if (cps_ret == cps_api_ret_code_OK) {
      std::cout << "Input object for COMMIT: " << std::endl;
      cps_api_object_print(tr_obj);

      if(cps_api_commit(&tr)==cps_api_ret_code_OK) ret = true;
    }
    cps_api_transaction_close(&tr);
    return ret;
}

bool cps_get(cps_api_object_t obj, cps_api_object_t result) {
    bool ret = true;
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);

    cps_api_object_t get_obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if (get_obj == NULL) {
      cps_api_get_request_close(&gp);
      return false;
    }

    if (cps_api_object_clone(get_obj, obj)) {
      std::cout << "Input object for GET: " << std::endl;
      cps_api_object_print(get_obj);
      std::cout << "Input list size: " << cps_api_object_list_size(gp.filters) << std::endl;

      if (cps_api_get(&gp)==cps_api_ret_code_OK) {
          size_t mx = cps_api_object_list_size(gp.list);
          std::cout << "Result Size: " << mx << std::endl;

          for (size_t ix = 0 ; ix < mx ; ++ix ) {
              cps_api_object_t res = cps_api_object_list_get(gp.list,ix);
              // cps_get is called with a specific vlan-id in this UT.Hence the result from GET will have only 1 object
              if(!cps_api_object_clone(result, res)) ret = false;
          }
      }
    }
    cps_api_get_request_close(&gp);
    return ret;

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

static bool _set_snoop_mrouter(int vlan, const char *name, cps_api_operation_types_t op)
{
   // set mrouter port
   cps_api_object_guard commit_og(cps_api_object_create());
   igmp_obj(commit_og.get(), vlan_id, true);
   cps_api_object_attr_add(commit_og.get(),IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_STATIC_MROUTER_INTERFACE, name, strlen(name)+1);

   if (cps_commit(commit_og.get(),op) == false)
     return false;

   sleep(5);

   if((strcmp(name,received_igmp_mrouter_ifname) != 0) && (received_igmp_vlan != vlan) &&
      (received_igmp_op != op)) {
     std::cout<<"Failed to match IGMP mrouter: "<<received_igmp_mrouter_ifname<<
                " configured: "<<name<<std::endl;
     return false;
   }
   else
     std::cout<<"IGMP Mrouter matched: "<<received_igmp_mrouter_ifname<<std::endl;

   if((strcmp(name,received_mld_mrouter_ifname) != 0) && (received_mld_vlan != vlan) &&
      (received_mld_op != op)) {
     std::cout<<"Failed to match MLD mrouter: "<<received_mld_mrouter_ifname<<
                " configured: "<<name<<std::endl;
     return false;
   }
   else
     std::cout<<"MLD Mrouter matched: "<<received_mld_mrouter_ifname<<std::endl;

   received_igmp_vlan = received_igmp_op = received_mld_vlan = received_mld_op = 0;
   memset(received_igmp_mrouter_ifname, 0, sizeof(received_igmp_mrouter_ifname));
   memset(received_mld_mrouter_ifname, 0, sizeof(received_mld_mrouter_ifname));

   return true;
}


/* mrouter port add */
TEST(std_mcast_snoop_test, mcast_base_snoop_mrouter_set) {
    int vlan;

    vlan = 100;

    if(_set_snoop_mrouter(vlan, mrouter_ifname, cps_api_oper_CREATE) == 0) {
       ASSERT_TRUE(0);
    }
}

/* mrouter port delete */
TEST(std_mcast_snoop_test, mcast_base_snoop_mrouter_delete) {

    int vlan;

    vlan = 100;

    if(_set_snoop_mrouter(vlan, mrouter_ifname, cps_api_oper_DELETE) == 0) {
       ASSERT_TRUE(0);
    }
}

TEST(std_mcast_snoop_test, mcast_snoop_query_interval) {

    // Set multicast query interval on a VLAN
    cps_api_object_guard commit_og(cps_api_object_create());
    igmp_obj(commit_og.get(), vlan_id, true);
    cps_api_object_attr_add_u16(commit_og.get(), IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_QUERY_INTERVAL_QUERY_INTERVAL_BASIC_QUERY_INTERVAL_BASIC, mcast_query_interval);

    ASSERT_TRUE( cps_commit(commit_og.get(),cps_api_oper_CREATE));

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

    ASSERT_TRUE( cps_commit(commit_og.get(),cps_api_oper_CREATE));

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

    ASSERT_TRUE( cps_commit(obj, cps_api_oper_CREATE));

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

    ASSERT_TRUE( cps_commit(commit_og.get(),cps_api_oper_CREATE));

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

TEST(std_mcast_snoop_test, mcast_base_snoop_cleanup) {

    std::string tagged_mem_port3 = mem_port3+'.'+std::to_string(vlan_id);

    system( ("ip link delete " + tagged_mem_port3 ).c_str());
    system( ("ip link set "+ vlan_name + " down").c_str());
    system( ("brctl delbr "+ vlan_name).c_str());

    /* Add it back to br 1*/
    system( ("brctl addif br1 " + mem_port1).c_str() );
    system( ("brctl addif br1 " + mem_port2).c_str() );

    ASSERT_TRUE(_ut_event_reg_destory);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);

  return RUN_ALL_TESTS();
}
