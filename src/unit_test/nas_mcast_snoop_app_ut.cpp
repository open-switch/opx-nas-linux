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
 * nas_mcast_snoop_app_ut.cpp
 *
 */

#include <stdlib.h>
#include <gtest/gtest.h>

#include "cps_class_map.h"
#include "cps_api_operation.h"
#include "cps_api_object_key.h"
#include "cps_api_events.h"
#include "ietf-igmp-mld-snooping.h"
#include "bridge-model.h"
#include "std_utils.h"
#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <exception>
#include <stdio.h>
#include <time.h>

#define KEY_PRINT_BUF_LEN 100
#define CMD_BUF_LEN 256
#define IFNAME_LEN 16
#define cmd_out_buf 1024
using namespace std;

static string mem_ports = "e101-001-0,e101-002-0";
static cps_api_key_t mc_igmp_obj_key;
static cps_api_key_t mc_mld_obj_key;
static bool received_status = 0;
static const char *mrouter_ifname = "e101-002-0";
static char received_mrouter_ifname[IFNAME_LEN] = {0};
static const char *grp_ip = "225.1.1.1";
static const char *src_ip = "5.5.5.5";
static const char *oif  = "e101-001-0";
/* to hold IPv4/v6 address in string format */
static char received_grp_ip[50] = {0};
static char received_src_ip[50] = {0};
static char received_oif[IFNAME_LEN] = {0};
static char received_vlan = 0;
static char received_op = 0;
static int event_reg = false;


static inline bool cps_commit(cps_api_object_t obj,cps_api_operation_types_t op) {
    bool ret = 0;

    cps_api_transaction_params_t tr;
    if(cps_api_transaction_init(&tr)!=cps_api_ret_code_OK) {
      cps_api_object_delete(obj);
      return false;
    }
    if(op == cps_api_oper_CREATE)
      cps_api_create(&tr,obj);
    else if (op == cps_api_oper_DELETE)
      cps_api_delete(&tr,obj);

    cout << "Input object for COMMIT: " << endl;
    cps_api_object_print(obj);

    if(cps_api_commit(&tr)==cps_api_ret_code_OK) ret = 1;

    cps_api_transaction_close(&tr);
    return ret;
}


static inline void igmp_obj(cps_api_object_t obj, uint16_t id, bool config) {
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

static inline void mld_obj(cps_api_object_t obj, uint16_t id, bool config) {
    cps_api_attr_id_t vlans_attr_id, vlan_attr_id;
    if(config) {
        vlans_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN;
        vlan_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_VLAN_ID;
        cps_api_key_from_attr_with_qual(cps_api_object_key(obj), vlans_attr_id, cps_api_qualifier_TARGET);
    }
    else {
        vlans_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN;
        vlan_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_VLAN_ID;
        cps_api_key_from_attr_with_qual(cps_api_object_key(obj), vlans_attr_id, cps_api_qualifier_OBSERVED);
    }

    cps_api_object_attr_add_u16(obj, vlan_attr_id, id);
}


static bool _create_vlans (int start_vlan, int num_vlans)
{
    char cmd [CMD_BUF_LEN];
    for (int vlan = start_vlan;vlan <start_vlan +num_vlans;vlan++) {
       memset(cmd,'\0',sizeof(cmd));
       snprintf(cmd, CMD_BUF_LEN-1, "cps_config_vlan.py  --add --id %d  --vlantype 1 -t --port %s", vlan, mem_ports.c_str());
       if (system(cmd) == -1) {
          cout<< "Failed to create VLAN " <<vlan<<endl;
          return false;
       }
    }
    return true;
}
static bool _delete_vlans (int start_vlan, int num_vlans)
{
    char cmd [CMD_BUF_LEN];
    for (int vlan = start_vlan;vlan <start_vlan +num_vlans;vlan++) {
       memset(cmd,'\0',sizeof(cmd));
       sprintf(cmd, "cps_config_vlan.py  --del --name br%d", vlan);
       if (system(cmd) == -1)
          cout<< "Failed to delete VLAN " <<vlan<<endl;
    }
    return true;
}
static bool _create_1dBridge (int start_vlan, int num_vlans)
{
   char name [CMD_BUF_LEN];
   for (int vlan = start_vlan;vlan <start_vlan +num_vlans;vlan++) {
      memset(name,'\0',sizeof(name));
      sprintf(name, "vn%d", vlan);
      cps_api_object_t commit_obj = cps_api_object_create();
      cps_api_key_from_attr_with_qual(cps_api_object_key(commit_obj),BRIDGE_DOMAIN_BRIDGE_OBJ, cps_api_qualifier_TARGET);      cps_api_object_attr_add(commit_obj,BRIDGE_DOMAIN_BRIDGE_NAME,name, sizeof(name));

      if(cps_commit(commit_obj, cps_api_oper_CREATE) == false) {
        cout<<"Commit Failed for status"<<endl;
        return false;
      }
   }

    return true;
}
static bool _delete_1dBridge (int start_vlan, int num_vlans)
{
   char name [CMD_BUF_LEN];
   for (int vlan = start_vlan;vlan <start_vlan +num_vlans;vlan++) {
      memset(name,'\0',sizeof(name));
      sprintf(name, "vn%d", vlan);
      cps_api_object_t commit_obj = cps_api_object_create();
      cps_api_key_from_attr_with_qual(cps_api_object_key(commit_obj),BRIDGE_DOMAIN_BRIDGE_OBJ, cps_api_qualifier_TARGET);
      cps_api_object_attr_add(commit_obj,BRIDGE_DOMAIN_BRIDGE_NAME,name, sizeof(name));

      if(cps_commit(commit_obj, cps_api_oper_DELETE) == false) {
        cout<<"Commit Failed for status"<<endl;
        return false;
      }
   }
   return true;
}
static bool _validate_snoop_status_in_os(bool is_1dBridge, int start_vlan, int num_vlans)
{
    char file_path[CMD_BUF_LEN];
    int fail_count = 0;
    FILE *fp = NULL;

    for (int vlan = start_vlan;vlan < start_vlan + num_vlans;vlan++) {
       memset(file_path,'\0',sizeof(file_path));
       if (is_1dBridge){
          sprintf(file_path, "/sys/devices/virtual/net/vn%d/bridge/multicast_snooping",vlan);
       }else {
          sprintf(file_path, "/sys/devices/virtual/net/br%d/bridge/multicast_snooping",vlan);
       }
       fp = fopen(file_path, "r");
       if (fp == NULL) {
           cout<< "File not found " <<file_path<<endl;
           fail_count++;
           continue;
       }
       int status = 1;
       status = fgetc(fp);
       status = atoi((const char *) &status);
       if (status != 0) {
          cout<< "Failed to disable snooping on VLAN " <<vlan<<endl;
          fail_count++;
       }
       fclose(fp);
    }

    if (fail_count > 0)
       return false;

    cout<< "Succesfully validated snooping disabled status in kernel " <<endl;
    return true;
}

static void _parse_snoop_routes(cps_api_object_it_t &itor, int event_type)
{
    cps_api_attr_id_t group_addr_id, group_src_id, group_src_addr_id, group_if_id;

    if (event_type == 1) {
           group_addr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_ADDRESS;
           group_if_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_INTERFACE;
           group_src_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_SOURCE;
           group_src_addr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_SOURCE_ADDRESS;
       } else if (event_type == 2) {
           group_addr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_ADDRESS;
           group_if_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_INTERFACE;
           group_src_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_SOURCE;
           group_src_addr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_SOURCE_ADDRESS;
    }
    else {
      return;
    }

    cps_api_object_it_t in_it = itor;
    cps_api_object_it_inside(&in_it);
    for (; cps_api_object_it_valid(&in_it); cps_api_object_it_next(&in_it)) {
        cps_api_object_it_t grp_it = in_it;
        cps_api_object_it_inside(&grp_it);

        for(; cps_api_object_it_valid(&grp_it); cps_api_object_it_next(&grp_it)) {
            cps_api_attr_id_t grp_attr_id = cps_api_object_attr_id(grp_it.attr);
            if (grp_attr_id == group_if_id) {
                const char *if_name = (char *)cps_api_object_attr_data_bin(grp_it.attr);
                cout<<"Multicast route OIF "<< if_name<<endl;
                safestrncpy(received_oif, if_name,sizeof(received_oif));
            } else if (grp_attr_id == group_addr_id) {
                const char *ip_addr_str = (const char *)cps_api_object_attr_data_bin(grp_it.attr);
                cout<<"Multicast route group address "<<ip_addr_str<<endl;
                safestrncpy(received_grp_ip, ip_addr_str,sizeof(received_grp_ip));
            } else if (grp_attr_id == group_src_id) {
                cps_api_object_it_t in_grp_it = grp_it;
                cps_api_object_it_inside(&in_grp_it);
                for(; cps_api_object_it_valid(&in_grp_it); cps_api_object_it_next(&in_grp_it)) {
                    cps_api_object_it_t src_it = in_grp_it;
                    cps_api_object_it_inside(&src_it);
                    for(; cps_api_object_it_valid(&src_it); cps_api_object_it_next(&src_it)) {
                        cps_api_attr_id_t src_attr_id = cps_api_object_attr_id(src_it.attr);
                        if (src_attr_id == group_src_addr_id) {
                            const char *src_ip_str = (const char *)cps_api_object_attr_data_bin(src_it.attr);
                            cout<<"Multicast route group source address :"<< src_ip_str<<endl;
                            safestrncpy(received_src_ip, src_ip_str,sizeof(received_src_ip));
                        }
                    }
                }
            }
        }
    }
}
static int event_type = 0;
static bool _ut_mc_event_handler(cps_api_object_t evt_obj, void *param)
{
    cps_api_object_attr_t vlan_id_attr;
    cps_api_object_attr_t status_attr;

    cps_api_attr_id_t mrouter_id;
    cps_api_attr_id_t group_id;

    cout<<"IGMP/MLD event back handler"<<endl;
    if (cps_api_key_matches(&mc_igmp_obj_key,
                    cps_api_object_key(evt_obj), 1) == 0) {
        event_type = 1;

        vlan_id_attr = cps_api_get_key_data(evt_obj,
                IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_VLAN_ID);

        mrouter_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_MROUTER_INTERFACE;
        group_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP;

        status_attr = cps_api_object_attr_get(evt_obj,
                IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_ENABLE);
    } else if (cps_api_key_matches(&mc_mld_obj_key,
                    cps_api_object_key(evt_obj), 1) == 0) {
        event_type = 2;

        vlan_id_attr = cps_api_get_key_data(evt_obj,
                IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_VLAN_ID);

        mrouter_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_MROUTER_INTERFACE;
        group_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP;

        status_attr = cps_api_object_attr_get(evt_obj,
                IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_ENABLE);
    } else {
        char key_buf[KEY_PRINT_BUF_LEN];
        cout<<"Unsupported object key: "<<cps_api_key_print(cps_api_object_key(evt_obj), key_buf, sizeof(key_buf))<<endl;
        return false;
    }

    if (vlan_id_attr == nullptr) {
        cout<<"VLAN ID attribute not found"<<endl;
        return false;
    }

    int received_vlan = cps_api_object_attr_data_u16(vlan_id_attr);
    cps_api_operation_types_t received_op = cps_api_object_type_operation(cps_api_object_key(evt_obj));

    if (event_type == 1) {
        cout<<"Received IGMP event for VLAN "<<received_vlan<<
                   " operation : "<<received_op<<endl;
    }
    else if (event_type == 2) {
        cout<<"Received MLD event for VLAN "<<received_vlan<<
                   " operation : "<<received_op<<endl;
    }

    if (status_attr != nullptr) {
        int snp_status = cps_api_object_attr_data_u32(status_attr);
        cout<<"Received Multicast snooping status "<< snp_status<<
                    " for vlan "<<received_vlan<<endl;
        received_status = snp_status;
    }

    cps_api_object_it_t it;
    for (cps_api_object_it_begin(evt_obj, &it); cps_api_object_it_valid(&it);
         cps_api_object_it_next(&it)) {
        cps_api_attr_id_t attr_id = cps_api_object_attr_id(it.attr);
        if (attr_id == mrouter_id) {
                safestrncpy(received_mrouter_ifname, (const char *)cps_api_object_attr_data_bin(it.attr),
                        sizeof(received_mrouter_ifname));
                cout<<"Handling mrouter event VLAN: "<<received_vlan<<
                         " mrouter interface: "<<received_mrouter_ifname<<endl;
        } else if (attr_id == group_id) {
                cout<<"Handling mcast route event"<<endl;
                _parse_snoop_routes(it, event_type);
        }
    }

    return true;
}
static bool _ut_event_reg_init(void)
{
    cps_api_event_reg_t reg;

    if (event_reg == 1)
       return true;

    cout<<"Register for IGMP/MLD event thread"<<endl;
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
    if (cps_api_event_thread_reg(&reg, _ut_mc_event_handler, NULL)
            != cps_api_ret_code_OK) {
        cout<<"Failed to register for IGMP/MLD event thread"<<endl;
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
            cout<<"De-register for IGMP/MLD event thread"<<endl;
        }
    }
    return true;
}

static bool _set_snoop_global_status(bool is_igmp, bool status, cps_api_operation_types_t op)
{

   // set multicast snooping on a VLAN
   cps_api_object_t commit_obj = cps_api_object_create();
   if(is_igmp) {
     cps_api_key_from_attr_with_qual(cps_api_object_key(commit_obj),IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_GLOBAL, cps_api_qualifier_TARGET);
     cps_api_object_attr_add_u32(commit_obj,IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_GLOBAL_ENABLE , status);
   }
   else {
     cps_api_key_from_attr_with_qual(cps_api_object_key(commit_obj),IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_GLOBAL, cps_api_qualifier_TARGET);
     cps_api_object_attr_add_u32(commit_obj,IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_GLOBAL_ENABLE , status);

   }

   if(cps_commit(commit_obj, op) == false) {
     cout<<"Commit Failed for status"<<endl;
     return false;
   }

   return true;
}
static bool _set_snoop_status(int vlan, bool status, cps_api_operation_types_t op)
{

   // set multicast snooping on a VLAN
   cps_api_object_t commit_obj = cps_api_object_create();
   igmp_obj(commit_obj, vlan, true);
   cps_api_object_attr_add_u32(commit_obj,IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_ENABLE, status);

   if(cps_commit(commit_obj, op) == false) {
     cout<<"Commit Failed for status"<<endl;
     return false;
   }
   sleep(2);

   if(received_status != status) {
     cout<<"Failed status"<<endl;
     return false;
   }
    cout<<"Snoop status matched"<<endl;

   return true;
}

static bool _set_snoop_mrouter(int vlan, const char *name, cps_api_operation_types_t op)
{
   // set mrouter port
   cps_api_object_t commit_obj = cps_api_object_create();
   igmp_obj(commit_obj, vlan, true);
   cps_api_object_attr_add(commit_obj,IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_STATIC_MROUTER_INTERFACE, name, strlen(name)+1);

   if(cps_commit(commit_obj, op) == false) {
     cout<<"Commit failed for mrouter"<<endl;
     return false;
   }
   sleep(1);

   if((strcmp(name,received_mrouter_ifname) != 0) && (received_vlan != vlan) &&
      (received_op != op)) {
     cout<<"Failed to match mrouter: "<<received_mrouter_ifname<<
                " configured: "<<name<<endl;
     return false;
   }
   cout<<"Mrouter matched: "<<received_mrouter_ifname<<endl;

   received_vlan = 0;
   received_op = 0;
   memset(received_mrouter_ifname, 0, sizeof(received_mrouter_ifname));

   return true;
}

static bool _set_snoop_igmp_route(int vlan, const char *grp, const char *src,
                                    const char *rt_oif,cps_api_operation_types_t op)
{
   // populate snoop routes port
   cps_api_object_t commit_obj = cps_api_object_create();
   igmp_obj(commit_obj, vlan, true);

   /* group is mandatory */
   cps_api_attr_id_t ids[3] = {IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_STATIC_L2_MULTICAST_GROUP, 0, IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_STATIC_L2_MULTICAST_GROUP_GROUP};
   if (!cps_api_object_e_add(commit_obj, ids, 3, cps_api_object_ATTR_T_BIN, grp, strlen(grp)+ 1)) {
       cout << "Failed to set mc entry group IP address" <<endl;
       cps_api_object_delete(commit_obj);
       return false;
   }
   /* OIF can be NULL */
   if (rt_oif) {
      ids[2] = IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_STATIC_L2_MULTICAST_GROUP_INTERFACE;
      if (!cps_api_object_e_add(commit_obj, ids, 3, cps_api_object_ATTR_T_BIN, rt_oif, strlen(rt_oif)+ 1)){
          cout << "Failed to set mc entry interface name" <<endl;
          cps_api_object_delete(commit_obj);
          return false;
      }
   }
   if (src != NULL) {
      ids[2] = IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_STATIC_L2_MULTICAST_GROUP_SOURCE_ADDR;
      if (!cps_api_object_e_add(commit_obj, ids, 3, cps_api_object_ATTR_T_BIN, src, strlen(src) + 1)) {
          cout << "Failed to set mc entry src IP address" <<endl;
          cps_api_object_delete(commit_obj);
          return false;
      }
   }

   if(cps_commit(commit_obj, op) == false) {
     cout<<"Commit Failed for route"<<endl;
     return false;
   }
   sleep(1);

   if((received_op != op) && (strcmp(grp,received_grp_ip) != 0) && (vlan != received_vlan) &&
      ((rt_oif != NULL) && (strcmp(rt_oif, received_oif) != 0)) && ((src != NULL) && (strcmp(src,received_src_ip) != 0))) {
     cout<<"Failed to match VLAN "<<vlan<<" Grp: "<<grp<<" Src: "<<src<<" OIF: "<<rt_oif<<" Op: "<<op<<endl;
     return false;
   }

   if (src) {
     if (rt_oif)
       cout<<"Matched VLAN "<<vlan<<" Grp: "<<grp<<" Src: "<<src <<" OIF: "<<rt_oif <<" Op: "<<op<<endl;
     else
       cout<<"Matched VLAN "<<vlan<<" Grp: "<<grp<<" Src: "<<src <<" OIF: "<< "NULL" <<" Op: "<<op<<endl;
   }
   else {
     cout<<"Matched VLAN "<<vlan<<" Grp: "<<grp<<" OIF: "<<rt_oif<<" Op: "<<op<<endl;
   }

   /* Reset all global values */
   received_vlan = 0;
   received_op = 0;
   memset(received_grp_ip, 0, sizeof(received_grp_ip));
   memset(received_src_ip, 0, sizeof(received_src_ip));
   memset(received_oif, 0, sizeof(received_oif));
   return true;
}
TEST(std_mcast_snoop_app_test, mcast_snoop_default_status_in_os) {
    /*  Create few bridge/vlans and check in linux snooping gets disabled */

    int start_vlan, num_vlans;

    start_vlan = 100;
    num_vlans = 5;

    //Register for IGMP/MLD events.
    if (_ut_event_reg_init() != 1) {
      cout<<"Reg init failed"<<endl;
      ASSERT_TRUE(0);
    }
    sleep(1);

    if (_create_vlans(start_vlan, num_vlans) == 0) {
        ASSERT_TRUE(0);
    }

    sleep(1);

    if(_validate_snoop_status_in_os(0, start_vlan, num_vlans) == 0) {
       ASSERT_TRUE(0);
    }
}

TEST(std_mcast_snoop_app_test, mcast_snoop_status_set) {
    /*  Create few bridge/vlans and check in linux snooping gets disabled */

    int vlan;

    vlan = 100;

    /* IGMP snoop enable */
    if(_set_snoop_status(vlan, 1, cps_api_oper_CREATE) == 0) {
       ASSERT_TRUE(0);
    }
}

TEST(std_mcast_snoop_app_test, mcast_snoop_mrouter_set) {
    /*  Create few bridge/vlans and check in linux snooping gets disabled */

    int vlan;

    vlan = 100;

    if(_set_snoop_mrouter(vlan, mrouter_ifname, cps_api_oper_CREATE) == 0) {
       ASSERT_TRUE(0);
    }
}

TEST(std_mcast_snoop_app_test, mcast_snoop_igmp_route) {

    int vlan;

    vlan = 100;

    /* (*,G) route */
    if(_set_snoop_igmp_route(vlan, grp_ip,NULL, oif, cps_api_oper_CREATE) == 0) {
       ASSERT_TRUE(0);
    }

    /* (S,G) route */
    if(_set_snoop_igmp_route(vlan, grp_ip,src_ip, oif, cps_api_oper_CREATE) == 0) {
       ASSERT_TRUE(0);
    }

    /* (S,G) route with NULL OIF */
    if(_set_snoop_igmp_route(vlan, grp_ip,src_ip, NULL, cps_api_oper_CREATE) == 0) {
       ASSERT_TRUE(0);
    }

    /* (*,G) route */
    if(_set_snoop_igmp_route(vlan, grp_ip,NULL, oif, cps_api_oper_DELETE) == 0) {
       ASSERT_TRUE(0);
    }

    /* (S,G) route */
    if(_set_snoop_igmp_route(vlan, grp_ip,src_ip, oif, cps_api_oper_DELETE) == 0) {
       ASSERT_TRUE(0);
    }

    /* (S,G) route with NULL OIF */
    if(_set_snoop_igmp_route(vlan, grp_ip,src_ip, NULL, cps_api_oper_DELETE) == 0) {
       ASSERT_TRUE(0);
    }
}

TEST(std_mcast_snoop_app_test, mcast_snoop_cleanup) {
    /*  Create few bridge/vlans and check in linux snooping gets disabled */

    int vlan, num_vlans;
    bool pass = true;

    vlan = 100;
    num_vlans = 5;

    if (_set_snoop_mrouter(vlan, mrouter_ifname, cps_api_oper_DELETE) == 0){
        pass = false;
    }

    if (_set_snoop_status(vlan, 0, cps_api_oper_CREATE) == 0){
        pass = false;
    }

    if (_delete_vlans(vlan, num_vlans) == 0){
        pass = false;
    }
    if(_ut_event_reg_destory() ==0) {
        pass = false;
    }

    ASSERT_TRUE(pass);
}
/* Dot1d Bridge test */
TEST(std_mcast_snoop_app_test, mcast_snoop_default_1d_status_in_os) {
    /*  Create few 1d bridge and check in linux snooping gets disabled */

    int start_vlan, num_vlans;

    start_vlan = 100;
    num_vlans = 5;

    sleep(1);

    if (_create_1dBridge(start_vlan, num_vlans) == 0) {
       ASSERT_TRUE(0);
    }

    sleep(1);

    if(_validate_snoop_status_in_os(1, start_vlan, num_vlans) == 0) {
       ASSERT_TRUE(0);
    }

    if (_delete_1dBridge(start_vlan, num_vlans) == 0) {
       ASSERT_TRUE(0);
    }
}

/*IGMP EBTABLES,IPTABLES rules */
const string eb_broute_igmp {"-p IPv4 --logical-in br200 --ip-proto igmp -j mark --mark-set 0x64 --mark-target ACCEPT"};
const string eb_nat_igmp {"-p IPv4 --ip-proto igmp --mark 0x1 -j ACCEPT"};
const string ip_raw_mark_igmp {"-A PREROUTING -p igmp -m mark --mark 0x64 -j IGMPSNOOP"};
const string ip_raw_igmp_snoop1 {"-A IGMPSNOOP -p igmp -m u32 --u32 \"0x0>>0x16&0x3c@0x0>>0x10&0xff00=0x1200\" -j ACCEPT"};
const string ip_raw_igmp_snoop2 {"-A IGMPSNOOP -p igmp -m u32 --u32 \"0x0>>0x16&0x3c@0x0>>0x10&0xff00=0x1600\" -j ACCEPT"};
const string ip_raw_igmp_snoop3 {"-A IGMPSNOOP -p igmp -m u32 --u32 \"0x0>>0x16&0x3c@0x0>>0x10&0xff00=0x1700\" -j ACCEPT"};
const string ip_raw_igmp_snoop4 {"-A IGMPSNOOP -p igmp -m u32 --u32 \"0x0>>0x16&0x3c@0x0>>0x10&0xff00=0x2200\" -j ACCEPT"};
const string ip_raw_igmp_snoop5 {"-A IGMPSNOOP ! -d 224.0.0.1/32 -p igmp -m u32 --u32 \"0x0>>0x16&0x3c@0x0>>0x10&0xff00=0x1100\" -j ACCEPT"};
const string ip_raw_igmp_remove_mark {"-A IGMPSNOOP -j MARK --set-xmark 0x0/0xffffffff"};

/*MLD EBTABLES,IPTABLES rules */
const string eb_nat_mld_query {"-p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type 132/0:255 --mark 0x1 -j ACCEPT"};
const string eb_nat_mld_v1report {"-p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type 131/0:255 --mark 0x1 -j ACCEPT"};
const string eb_nat_mld_v2report {"-p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type 143/0:255 --mark 0x1 -j ACCEPT"};
const string eb_nat_mld_done {"-p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type 130/0:255 --mark 0x1 -j ACCEPT"};


const string eb_broute_mld {"-p IPv6 --logical-in br200 --ip6-proto ipv6-icmp -j mark --mark-set 0x64 --mark-target ACCEPT"};
const string ip6_raw_mark_mld {"-A PREROUTING -p ipv6-icmp -m mark --mark 0x64 -j MLDSNOOP"};
const string ip6_raw_mld_snoop1 {"-A MLDSNOOP -p ipv6-icmp -m icmp6 --icmpv6-type 131 -j ACCEPT"};
const string ip6_raw_mld_snoop2 {"-A MLDSNOOP -p ipv6-icmp -m icmp6 --icmpv6-type 132 -j ACCEPT"};
const string ip6_raw_mld_snoop3 {"-A MLDSNOOP -p ipv6-icmp -m icmp6 --icmpv6-type 143 -j ACCEPT"};
const string ip6_raw_mld_snoop4 {"-A MLDSNOOP ! -d ff02::1/128 -p ipv6-icmp -m icmp6 --icmpv6-type 130 -j ACCEPT"};
const string ip6_raw_mld_remove_mark {"-A MLDSNOOP -p ipv6-icmp -j MARK --set-xmark 0x0/0xffffffff"};


using verify_function = function<bool(vector<string>&, bool, bool)>;

static bool verify_globalEB_nat_rules(vector<string>& list_lines, bool is_igmp, bool status){

    if( list_lines.empty() )
      return false;

    bool rule_found = false;
    int count = 0;
    try {
      if (is_igmp) {
        while(!list_lines.empty()) {
          string line = list_lines.back();
          cout<<"Line: " <<line.c_str() <<endl;
          if (line.compare(0, eb_nat_igmp.size(), eb_nat_igmp) == 0) {
               rule_found = true;
               break;
          }
          list_lines.pop_back();
        }
      }else {
        while(!list_lines.empty()) {
          string line = list_lines.back();
          cout<<"Line: " <<line.c_str() <<endl;
          if ((line.compare(0,eb_nat_mld_query.size(), eb_nat_mld_query) == 0) ||
             (line.compare(0,eb_nat_mld_v1report.size(), eb_nat_mld_v1report) == 0) ||
             (line.compare(0,eb_nat_mld_v2report.size(), eb_nat_mld_v2report) == 0) ||
             (line.compare(0,eb_nat_mld_done.size(), eb_nat_mld_done) == 0)) {
            count++;
          }
          if (count == 4){
             rule_found = true;
             break;
          }
          list_lines.pop_back();
        }
      }
      if (status) {
         if (rule_found) return true;
      }
      else {
        if (count == 0) return true;
      }
    }catch (exception& e) {
       cout<<"Exception: " <<e.what() <<endl;
    }

    return false;
}

static bool verify_globalIP_RawPreRoute_rules(vector<string>& list_lines, bool is_igmp, bool status){

    if( list_lines.empty() )
      return false;

    bool rule_found = false;
    int count = 0;
    try {
      if (is_igmp) {
        while(!list_lines.empty()) {
          string line = list_lines.back();
          cout<<"Line: " <<line.c_str() <<endl;
          if ((line.compare(0, ip_raw_mark_igmp.size(), ip_raw_mark_igmp) == 0) ||
              (line.compare(0, ip_raw_igmp_remove_mark.size(), ip_raw_igmp_remove_mark) == 0) ||
              (line.compare(0, ip_raw_igmp_snoop1.size(), ip_raw_igmp_snoop1) == 0) ||
              (line.compare(0, ip_raw_igmp_snoop2.size(), ip_raw_igmp_snoop2) == 0) ||
              (line.compare(0, ip_raw_igmp_snoop3.size(), ip_raw_igmp_snoop3) == 0) ||
              (line.compare(0, ip_raw_igmp_snoop4.size(), ip_raw_igmp_snoop4) == 0) ||
              (line.compare(0, ip_raw_igmp_snoop5.size(), ip_raw_igmp_snoop5) == 0)) {
               count++;
          }
          if (count == 7){
            rule_found = true;
            break;
          }
          list_lines.pop_back();
        }
      }else {
        while(!list_lines.empty()) {
          string line = list_lines.back();
          cout<<"Line: " <<line.c_str() <<endl;
          if ((line.compare(0,ip6_raw_mark_mld.size(), ip6_raw_mark_mld) == 0) ||
             (line.compare(0,ip6_raw_mld_snoop1.size(), ip6_raw_mld_snoop1) == 0) ||
             (line.compare(0,ip6_raw_mld_snoop2.size(), ip6_raw_mld_snoop2) == 0) ||
             (line.compare(0,ip6_raw_mld_snoop3.size(), ip6_raw_mld_snoop3) == 0) ||
             (line.compare(0,ip6_raw_mld_snoop4.size(), ip6_raw_mld_snoop4) == 0) ||
             (line.compare(0,ip6_raw_mld_remove_mark.size(), ip6_raw_mld_remove_mark) == 0)) {
            count++;
          }
          if (count == 6){
             rule_found = true;
             break;
          }
          list_lines.pop_back();
        }
      }
      if (status) {
         if (rule_found) return true;
      }
      else {
        if (count == 0) return true;
      }
    }catch (exception& e) {
       cout<<"Exception: " <<e.what() <<endl;
    }

    return false;
}

static bool verify_PerVlanEB_Broute_rules(vector<string>& list_lines, bool is_igmp, bool status){

    if( list_lines.empty() )
      return false;

    bool rule_found = false;
    try {
      if (is_igmp) {
        while(!list_lines.empty()) {
          string line = list_lines.back();
          cout<<"Line: " <<line.c_str() <<endl;
          if (line.compare(0, eb_broute_igmp.size(), eb_broute_igmp) == 0) {
               rule_found = true;
               break;
          }
          list_lines.pop_back();
        }
      }else {
        while(!list_lines.empty()) {
          string line = list_lines.back();
          cout<<"Line: " <<line.c_str() <<endl;
          if ((line.compare(0,eb_broute_mld.size(), eb_broute_mld) == 0)) {
             rule_found = true;
             break;
          }
          list_lines.pop_back();
        }
      }
      if (status) {
         if (rule_found) return true;
      }
      else {
        if (!rule_found) return true;
      }
    }catch (exception& e) {
       cout<<"Exception: " <<e.what() <<endl;
    }

    return false;
}

static bool verify_globalBrNFFile_rules(vector<string>& list_lines, bool is_igmp, bool status){

    while(!list_lines.empty()) {
      string line = list_lines.back();
      cout<<"Line: " <<line.c_str() <<endl;
      if ((line.compare(0, 1, "1") == 0) && (status)) {
           return true;
      }else if ((line.compare(0, 1, "0") == 0) && (!status)) {
           return true;
      }
      list_lines.pop_back();
    }

    return false;
}

static bool snoop_run_command(const string& cmd, verify_function verify, bool is_igmp, bool status)
{

    bool ret = true;
    FILE *fp = popen(cmd.c_str(), "r");
    char lnbuf[cmd_out_buf];
    if (fp == nullptr) {
        cout << "Snoop failed to open file to run command" << endl;
        return false;
    }

    vector<string> line_buf;
    string s;
    while(fgets(lnbuf, cmd_out_buf, fp)) {
        s = string{lnbuf};
        line_buf.push_back(s);
    }
    if(verify (line_buf, is_igmp, status) == false)
      ret = false;

    line_buf.clear();
    pclose(fp);
    return ret;
}


TEST(std_mcast_snoop_app_test, mcast_snoop_rules_global_disable_igmp) {

    ASSERT_TRUE(_set_snoop_global_status(true,0,cps_api_oper_CREATE));
    ASSERT_TRUE(snoop_run_command("ebtables -t nat -L POSTROUTING ", verify_globalEB_nat_rules, true, false));
    ASSERT_TRUE(snoop_run_command("iptables -t raw -S", verify_globalIP_RawPreRoute_rules, true, false));
    ASSERT_TRUE(snoop_run_command("cat /proc/sys/net/bridge/bridge-nf-call-iptables", verify_globalBrNFFile_rules, true, false));
}

TEST(std_mcast_snoop_app_test, mcast_snoop_rules_global_enable_igmp) {

    ASSERT_TRUE(_set_snoop_global_status(true,1,cps_api_oper_CREATE));
    ASSERT_TRUE(snoop_run_command("ebtables -t nat -L POSTROUTING ", verify_globalEB_nat_rules, true, true));
    ASSERT_TRUE(snoop_run_command("iptables -t raw -S", verify_globalIP_RawPreRoute_rules, true, true));
    ASSERT_TRUE(snoop_run_command("cat /proc/sys/net/bridge/bridge-nf-call-iptables", verify_globalBrNFFile_rules, true, true));
}
TEST(std_mcast_snoop_app_test, mcast_snoop_rules_global_disable_mld) {

    ASSERT_TRUE(_set_snoop_global_status(false,0,cps_api_oper_CREATE));
    ASSERT_TRUE(snoop_run_command("ebtables -t nat -L POSTROUTING ", verify_globalEB_nat_rules, false, false));
    ASSERT_TRUE(snoop_run_command("ip6tables -t raw -S", verify_globalIP_RawPreRoute_rules, false, false));
    ASSERT_TRUE(snoop_run_command("cat /proc/sys/net/bridge/bridge-nf-call-ip6tables", verify_globalBrNFFile_rules, false, false));
}

TEST(std_mcast_snoop_app_test, mcast_snoop_rules_global_enable_mld) {

    ASSERT_TRUE(_set_snoop_global_status(false,1,cps_api_oper_CREATE));
    ASSERT_TRUE(snoop_run_command("ebtables -t nat -L POSTROUTING ", verify_globalEB_nat_rules, false, true));
    ASSERT_TRUE(snoop_run_command("ip6tables -t raw -S", verify_globalIP_RawPreRoute_rules, false, true));
    ASSERT_TRUE(snoop_run_command("cat /proc/sys/net/bridge/bridge-nf-call-ip6tables", verify_globalBrNFFile_rules, false, true));
}

TEST(std_mcast_snoop_app_test, mcast_snoop_rules_global_cleanup) {

    ASSERT_TRUE(_set_snoop_global_status(true,0,cps_api_oper_CREATE));
    ASSERT_TRUE(_set_snoop_global_status(false,0,cps_api_oper_CREATE));
}

TEST(std_mcast_snoop_app_test, mcast_snoop_rules_per_vlan_igmp) {

    /*Global enable */
    ASSERT_TRUE(_set_snoop_global_status(true,1,cps_api_oper_CREATE));
    sleep(1);
    /*create VLAN */
    ASSERT_TRUE(_create_vlans(200, 1));

    sleep(1);

    /*Enable snooping on VLAN */
    cps_api_object_t enable_commit_obj = cps_api_object_create();
    igmp_obj(enable_commit_obj, 200, true);
    cps_api_object_attr_add_u32(enable_commit_obj,IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_ENABLE, 1);

    ASSERT_TRUE(cps_commit(enable_commit_obj, cps_api_oper_CREATE));

    sleep(1);
    /* check Rules */
    ASSERT_TRUE(snoop_run_command("ebtables -t broute -L BROUTING ", verify_PerVlanEB_Broute_rules, true, true));
    sleep(1);
    /*Disable snooping on VLAN */
    cps_api_object_t disable_commit_obj = cps_api_object_create();
    igmp_obj(disable_commit_obj, 200, true);
    cps_api_object_attr_add_u32(disable_commit_obj,IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_ENABLE, 0);

    ASSERT_TRUE(cps_commit(disable_commit_obj, cps_api_oper_CREATE));

    ASSERT_TRUE(snoop_run_command("ebtables -t broute -L BROUTING ", verify_PerVlanEB_Broute_rules, true, false));
    sleep(1);
    ASSERT_TRUE(_delete_vlans(200, 1));
    sleep(1);
    ASSERT_TRUE(_set_snoop_global_status(true,0,cps_api_oper_CREATE));
    sleep (2);
}

TEST(std_mcast_snoop_app_test, mcast_snoop_rules_per_vlan_mld) {

    /*Global enable */
    ASSERT_TRUE(_set_snoop_global_status(false,1,cps_api_oper_CREATE));
    sleep(1);
    /*create VLAN */
    ASSERT_TRUE(_create_vlans(200, 1));

    sleep(1);

    /*Enable snooping on VLAN */
    cps_api_object_t enable_commit_obj = cps_api_object_create();
    mld_obj(enable_commit_obj, 200, true);
    cps_api_object_attr_add_u32(enable_commit_obj,IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_ENABLE, 1);

    ASSERT_TRUE(cps_commit(enable_commit_obj, cps_api_oper_CREATE));

    sleep(1);
    /* check Rules */
    ASSERT_TRUE(snoop_run_command("ebtables -t broute -L BROUTING ", verify_PerVlanEB_Broute_rules, false, true));
    sleep(1);
    /*Disable snooping on VLAN */
    cps_api_object_t disable_commit_obj = cps_api_object_create();
    mld_obj(disable_commit_obj, 200, true);
    cps_api_object_attr_add_u32(disable_commit_obj,IGMP_MLD_SNOOPING_RT_ROUTING_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_ENABLE, 0);

    ASSERT_TRUE(cps_commit(disable_commit_obj, cps_api_oper_CREATE));

    ASSERT_TRUE(snoop_run_command("ebtables -t broute -L BROUTING ", verify_PerVlanEB_Broute_rules, false, false));
    sleep(1);
    ASSERT_TRUE(_delete_vlans(200, 1));
    sleep(1);
    ASSERT_TRUE(_set_snoop_global_status(false,0,cps_api_oper_CREATE));
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);

  return RUN_ALL_TESTS();
}
