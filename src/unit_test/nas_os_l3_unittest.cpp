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

/*
 * nas_os_l3_unittest.cpp
 *
 *  Created on: May 20, 2015
 *      Author: prince
 */

#include <gtest/gtest.h>
#include <iostream>
#include <fstream>

#include "std_mac_utils.h"

#include "cps_api_operation.h"
#include "cps_class_map.h"
#include "cps_api_object.h"
#include "cps_api_object_key.h"

#include "dell-base-routing.h"
#include "ietf-network-instance.h"
#include "nas_os_l3.h"
#include "ds_api_linux_neigh.h"
#include "ds_common_types.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

static bool run_test_mode = false;

#define FIB_DEFAULT_VRF_NAME           "default"
static const char *test_phy_intf_1  = "e101-007-0";
static const char *test_vlan_intf_1 = "br121";
static int         test_vlan_id_1   = 121;
static const char *test_vlan_intf_mem_port_1 = "e101-009-0";


static cps_api_return_code_t nas_ut_os_rt_cfg (bool is_add, const char *ip_addr, uint32_t prefix_len,
                            uint8_t af, const char *nh_addr, const char *if_name)
{
    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
           BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME, FIB_DEFAULT_VRF_NAME,
                            sizeof(FIB_DEFAULT_VRF_NAME));


    if (af == AF_INET) {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF,AF_INET);

        uint32_t ip;
        struct in_addr a;
        inet_aton(ip_addr, &a);
        ip=a.s_addr;

        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&ip,sizeof(ip));
    } else if (af == AF_INET6) {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF,AF_INET6);

        struct in6_addr a6;
        inet_pton(AF_INET6, ip_addr, &a6);

        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&a6,sizeof(struct in6_addr));
    }

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,prefix_len);

    cps_api_attr_id_t ids[3];
    const int ids_len = sizeof(ids)/sizeof(*ids);
    ids[0] = BASE_ROUTE_OBJ_ENTRY_NH_LIST;

    if (if_name) {
        uint32_t gw_idx = if_nametoindex(if_name);
        ids[1] = 0;
        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
        cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,
                             (void *)&gw_idx, sizeof(uint32_t));
    }
    if (nh_addr) {
        ids[1] = 0;
        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR;

        if (af == AF_INET) {
            uint32_t ip;
            struct in_addr a;
            inet_aton(nh_addr, &a);
            ip=a.s_addr;

            cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                                 &ip, sizeof(ip));
        } else if (af == AF_INET6) {

            struct in6_addr a6;
            inet_pton(AF_INET6, nh_addr, &a6);

            cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                                 &a6, sizeof(struct in6_addr));
        }
    }

    if (if_name || nh_addr)
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_NH_COUNT,1);

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    cps_api_transaction_init(&tr);

    if (is_add)
        cps_api_create(&tr,obj);
    else
        cps_api_delete(&tr,obj);

    cps_api_commit(&tr);
    cps_api_transaction_close(&tr);

    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_ut_os_neigh_cfg (cps_api_operation_types_t op, const char *ip_addr, uint8_t af, const char *if_name, hal_mac_addr_t *hw_addr)
{
    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
              BASE_ROUTE_OBJ_NBR,cps_api_qualifier_TARGET);

    if (af == AF_INET) {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,AF_INET);

        uint32_t ip;
        struct in_addr a;
        inet_aton(ip_addr, &a);
        ip=a.s_addr;

        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,&ip,sizeof(ip));
    } else if (af == AF_INET6) {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,AF_INET6);

        struct in6_addr a6;
        inet_pton(AF_INET6, ip_addr, &a6);

        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,&a6,sizeof(struct in6_addr));
    }

    //cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_TYPE,BASE_ROUTE_RT_TYPE_STATIC);
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_IFNAME, if_name, strlen(if_name)+1);

    if (op != cps_api_oper_DELETE) {
        char mac_addr[256];
        memset(mac_addr, '\0', sizeof(mac_addr));
        std_mac_to_string (hw_addr, mac_addr, 256);
        cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_NBR_MAC_ADDR, (const void *)mac_addr,
                strlen(mac_addr)+1);
    }

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    cps_api_transaction_init(&tr);

    if (op == cps_api_oper_CREATE)
        cps_api_create(&tr,obj);
    else if (op == cps_api_oper_SET)
        cps_api_set(&tr,obj);
    else
        cps_api_delete(&tr,obj);

    cps_api_commit(&tr);

    cps_api_transaction_close(&tr);

    return cps_api_ret_code_OK;
}

static void nas_route_dump_route_object_content(cps_api_object_t obj) {

    char str[INET6_ADDRSTRLEN];
    char if_name[IFNAMSIZ];
    uint32_t addr_len = 0, af_data = 0;
    uint32_t nhc = 0, nh_itr = 0;

    cps_api_object_it_t it;
    cps_api_object_it_begin(obj,&it);

    cps_api_object_attr_t af       = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_AF);
    af_data = cps_api_object_attr_data_u32(af) ;

    addr_len = ((af_data == AF_INET) ? INET_ADDRSTRLEN: INET6_ADDRSTRLEN);

    cps_api_object_attr_t prefix   = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX);
    if (prefix == NULL) return;
    cps_api_object_attr_t pref_len = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN);
    cps_api_object_attr_t nh_count = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_NH_COUNT);
    std::cout<<"AF "<<((af_data == AF_INET) ? "IPv4" : "IPv6")<<","<<
        inet_ntop(af_data, cps_api_object_attr_data_bin(prefix), str,addr_len)<<"/"<<
        cps_api_object_attr_data_u32(pref_len)<<std::endl;
    if (nh_count != CPS_API_ATTR_NULL) {
        nhc = cps_api_object_attr_data_u32(nh_count);
        std::cout<<"NHC "<<nhc<<std::endl;
    }

    for (nh_itr = 0; nh_itr < nhc; nh_itr++)
    {
        cps_api_attr_id_t ids[3] = { BASE_ROUTE_OBJ_ENTRY_NH_LIST,
            0, BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR};
        const int ids_len = sizeof(ids)/sizeof(*ids);
        ids[1] = nh_itr;

        cps_api_object_attr_t attr = cps_api_object_e_get(obj,ids,ids_len);
        if (attr != CPS_API_ATTR_NULL)
            std::cout<<"NextHop "<<inet_ntop(af_data,cps_api_object_attr_data_bin(attr),str,addr_len)<<std::endl;

        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
        attr = cps_api_object_e_get(obj,ids,ids_len);
        if (attr != CPS_API_ATTR_NULL)
            if_indextoname((int)cps_api_object_attr_data_u32(attr), if_name);
        std::cout<<"IfIndex "<<if_name<<"("<<cps_api_object_attr_data_u32(attr)<<")"<<std::endl;

        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_WEIGHT;
        attr = cps_api_object_e_get(obj,ids,ids_len);
        if (attr != CPS_API_ATTR_NULL)
            std::cout<<"Weight "<<cps_api_object_attr_data_u32(attr)<<std::endl;

        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_RESOLVED;
        attr = cps_api_object_e_get(obj,ids,ids_len);
        if (attr != CPS_API_ATTR_NULL)
            std::cout<<"Is Next Hop Resolved "<<cps_api_object_attr_data_u32(attr)<<std::endl;
    }
}

static cps_api_return_code_t nas_ut_validate_nas_rt_cfg (const char *ip_addr, uint32_t prefix_len,
                            uint32_t af, const char *nh_addr, const char *if_name, bool should_exist_in_npu)
{
    cps_api_return_code_t rc = cps_api_ret_code_ERR;
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_ROUTE_OBJ_ENTRY,
            cps_api_qualifier_TARGET);
    cps_api_set_key_data(obj,BASE_ROUTE_OBJ_VRF_NAME,
            cps_api_object_ATTR_T_BIN, FIB_DEFAULT_VRF_NAME, sizeof(FIB_DEFAULT_VRF_NAME));
    cps_api_set_key_data(obj,BASE_ROUTE_OBJ_ENTRY_AF,cps_api_object_ATTR_T_U32, &af,sizeof(af));
    if (af == AF_INET) {
        uint32_t ip;
        struct in_addr a;
        inet_aton(ip_addr, &a);
        ip=a.s_addr;
        cps_api_set_key_data(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,cps_api_object_ATTR_T_BIN, &ip,sizeof(ip));
    } else if (af == AF_INET6) {
        struct in6_addr a6;
        inet_pton(AF_INET6, ip_addr, &a6);
        cps_api_set_key_data (obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,cps_api_object_ATTR_T_BIN, &a6,sizeof(struct in6_addr));
    }

    cps_api_set_key_data (obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN, cps_api_object_ATTR_T_U32, &prefix_len, sizeof (prefix_len));
    if (cps_api_get(&gp)==cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);
        if (mx)
        {
            rc = cps_api_ret_code_OK;

            std::cout<<"IP FIB Entries, Family:"<<af<<std::endl;
            std::cout<<"================================="<<std::endl;
            for ( size_t ix = 0 ; ix < mx ; ++ix ) {
                obj = cps_api_object_list_get(gp.list,ix);
                if (should_exist_in_npu == false) {
                    cps_api_object_attr_t prg_done = cps_api_object_attr_get(obj,
                                                                             BASE_ROUTE_OBJ_ENTRY_NPU_PRG_DONE);
                    if (prg_done && (cps_api_object_attr_data_u32(prg_done))) {
                        std::cout<<"IP route exists in NPU:"<<std::endl;
                        rc = cps_api_ret_code_ERR;
                    } else {
                        std::cout<<"IP route not exist in NPU:"<<std::endl;
                    }
                }
                nas_route_dump_route_object_content(obj);
                std::cout<<std::endl;
            }
        }
    }

    cps_api_get_request_close(&gp);
    return rc;
}

static cps_api_return_code_t nas_rt_lnx_ip_addr_cfg (bool is_add, const char *ip_addr, uint32_t prefix_len, const char *dev)
{
    char cmd_str[300];
    snprintf (cmd_str, 300, "ip address %s %s/%d  dev %s", (is_add ? "add":"del"), ip_addr, prefix_len, dev);
    if (system(cmd_str));
    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_rt_lnx_intf_admin_cfg (bool is_up, const char *dev)
{
    char cmd_str[300];

    snprintf (cmd_str, 300, "ip link set dev %s %s", dev, (is_up)?"up":"down");
    if(system(cmd_str));
    /* wait for few seconds after making admin up */
    if (is_up)
        sleep (5);
    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_rt_lnx_vlan_intf_cfg (bool is_add, const char* vlan_intf, int vlan_id, const char *vlan_mem_port)
{
    char cmd_str[300];
    if (is_add)
    {
        snprintf (cmd_str, 300, "ip link set dev %s up", vlan_mem_port);
        if(system(cmd_str));
        snprintf (cmd_str, 300, "brctl addbr %s", vlan_intf);
        if(system(cmd_str));
        snprintf (cmd_str, 300, "ip link add link %s name %s.%d type vlan id %d", vlan_mem_port, vlan_mem_port, vlan_id, vlan_id);
        if(system(cmd_str));
        snprintf (cmd_str, 300, "brctl addif %s %s.%d", vlan_intf, vlan_mem_port, vlan_id);
        if(system(cmd_str));
        snprintf (cmd_str, 300, "ip link set dev %s.%d up", vlan_mem_port, vlan_id);
        if(system(cmd_str));
    }
    else
    {
        snprintf (cmd_str, 300, "ip link set dev %s.%d down", vlan_mem_port, vlan_id);
        if(system(cmd_str));
        snprintf (cmd_str, 300, "brctl delif %s %s.%d", vlan_intf, vlan_mem_port, vlan_id);
        if(system(cmd_str));
        snprintf (cmd_str, 300, "ip link set dev %s down", vlan_mem_port);
        if(system(cmd_str));
        snprintf (cmd_str, 300, "ip link del dev %s.%d ", vlan_mem_port, vlan_id);
        if(system(cmd_str));
        snprintf (cmd_str, 300, "brctl delbr %s", vlan_intf);
        if(system(cmd_str));
    }
    return cps_api_ret_code_OK;
}


void add_ipv4_route () {
    cps_api_object_t obj = cps_api_object_create();
    cps_api_key_init(cps_api_object_key(obj),cps_api_qualifier_TARGET,
            cps_api_obj_CAT_BASE_ROUTE, BASE_ROUTE_OBJ_OBJ,0 );

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF,AF_INET);

    uint32_t ip;
    struct in_addr a;
    inet_aton("1.2.3.5",&a);
    ip=a.s_addr;

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&ip,sizeof(ip));
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,32);
    cps_api_attr_id_t ids[3];
    const int ids_len = sizeof(ids)/sizeof(*ids);
    ids[0] = BASE_ROUTE_OBJ_ENTRY_NH_LIST;
    ids[1] = 0;
    ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR;


    inet_aton("6.6.6.10",&a);
    ip=a.s_addr;

    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                    &ip,sizeof(ip));
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_NH_COUNT,1);

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    cps_api_transaction_init(&tr);

    cps_api_create(&tr,obj);

    cps_api_commit(&tr);
    cps_api_transaction_close(&tr);
}

TEST(std_route_test, add_route) {
    add_ipv4_route();
}

TEST(std_route_test, del_nh_route) {
    cps_api_return_code_t rc;

    rc  = nas_ut_os_rt_cfg (0, "1.2.3.5", 32, AF_INET, "6.6.6.10", NULL);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
}

TEST(std_route_test, add_ifx_route) {
    cps_api_return_code_t rc;

    rc  = nas_ut_os_rt_cfg (1, "2.2.3.5", 32, AF_INET, NULL, "e101-005-0");
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
}

TEST(std_route_test, del_ifx_route) {
    cps_api_return_code_t rc;

    rc  = nas_ut_os_rt_cfg (0, "2.2.3.5", 32, AF_INET, NULL, "e101-005-0");
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
}

TEST(std_route_test, set_route) {
    add_ipv4_route();

    cps_api_object_t obj = cps_api_object_create();
    cps_api_key_init(cps_api_object_key(obj),cps_api_qualifier_TARGET,
            cps_api_obj_CAT_BASE_ROUTE, BASE_ROUTE_OBJ_OBJ,0 );

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF,AF_INET);

    uint32_t ip;
    struct in_addr a;
    inet_aton("1.2.3.5",&a);
    ip=a.s_addr;

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&ip,sizeof(ip));
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,32);
    cps_api_attr_id_t ids[3];
    const int ids_len = sizeof(ids)/sizeof(*ids);
    ids[0] = BASE_ROUTE_OBJ_ENTRY_NH_LIST;
    ids[1] = 0;
    ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR;


    inet_aton("127.0.0.2",&a);
    ip=a.s_addr;

    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                    &ip,sizeof(ip));

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_NH_COUNT,1);

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    cps_api_transaction_init(&tr);

    cps_api_set(&tr,obj);

    cps_api_commit(&tr);
    cps_api_transaction_close(&tr);
}

TEST(std_route_test, del_route) {
    cps_api_return_code_t rc;

    rc  = nas_ut_os_rt_cfg (0, "1.2.3.5", 32, AF_INET, NULL, NULL);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
}

TEST(std_route_test, add_neighbor) {
    cps_api_return_code_t rc;
    hal_mac_addr_t mac_addr = {0x00, 0x00, 0x00, 0x1c, 0x1b, 0x1a};

    rc  = nas_ut_os_neigh_cfg (cps_api_oper_CREATE, "6.6.6.20", AF_INET, "e101-005-0", &mac_addr);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
}

TEST(std_route_test, set_neighbor) {
    cps_api_return_code_t rc;
    hal_mac_addr_t mac_addr = {0x00, 0x00, 0x00, 0x1c, 0x1b, 0x1b};

    rc  = nas_ut_os_neigh_cfg (cps_api_oper_CREATE, "6.6.6.20", AF_INET, "e101-005-0", &mac_addr);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
}

TEST(std_route_test, del_neighbor) {
    cps_api_return_code_t rc;

    rc  = nas_ut_os_neigh_cfg (cps_api_oper_DELETE, "6.6.6.20", AF_INET, "e101-005-0", NULL);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
}

TEST(std_route_test, add_ip_and_check_self_ip_pub) {
    char cmd_str[200];

    if(system("opx-logging enable NETLINK info"));
    if(system("kill -USR1 `pidof base_nas`"));

    memset(cmd_str, 0, sizeof(cmd_str));
    system("ip addr add 8.1.1.2/24 dev e101-008-0");
    sleep(3);
    snprintf (cmd_str, 150, "journalctl -u base_nas_svc --since \"4 seconds ago\" | grep \"Self IP route ignored\" | grep \"op:Add route:8.1.1.2/32\"");
    int ret = system(cmd_str);
    ASSERT_TRUE (ret == 0);

    /* In Stretch kernel doesn't notify IPv6 route with /128 prefix length,
     * hence this test is not valid anymore in Stretch.
     */
    /*
    memset(cmd_str, 0, sizeof(cmd_str));
    system("ip -6 addr add 1::1/64 dev e101-008-0");
    sleep(3);
    snprintf (cmd_str, 150, "journalctl -u base_nas_svc --since \"4 seconds ago\" | grep \"Self IP route ignored\" | grep \"op:Add route:1::1/128\"");
    ret = system(cmd_str);
    ASSERT_TRUE (ret == 0);
    */

    memset(cmd_str, 0, sizeof(cmd_str));
    system("ip addr del 8.1.1.2/24 dev e101-008-0");
    sleep(3);
    snprintf (cmd_str, 150, "journalctl -u base_nas_svc --since \"4 seconds ago\" | grep \"Self IP route ignored\" | grep \"op:Del route:8.1.1.2/32\"");
    ret = system(cmd_str);
    ASSERT_TRUE (ret == 0);

    /* In Stretch kernel doesn't notify IPv6 route with /128 prefix length,
     * hence this test is not valid anymore in Stretch.
     */
    /*
    memset(cmd_str, 0, sizeof(cmd_str));
    system("ip -6 addr del 1::1/64 dev e101-008-0");
    sleep(3);
    snprintf (cmd_str, 150, "journalctl -u base_nas_svc --since \"4 seconds ago\" | grep \"Self IP route ignored\" | grep \"op:Del route:1::1/128\"");
    ret = system(cmd_str);
    ASSERT_TRUE (ret == 0);
    */

    if(system("opx-logging disable NETLINK info"));
    if(system("kill -USR1 `pidof base_nas`"));
}


//validate connected route add & delete
TEST(std_nas_route_test, nas_os_rt_cfg_ut_1) {
    cps_api_return_code_t rc;

    /* config test pre-requisite */
    nas_rt_lnx_intf_admin_cfg (1, test_phy_intf_1);

    /* configure ip address and connected route */
    nas_rt_lnx_ip_addr_cfg(1, "7.1.1.1", 24, test_phy_intf_1);
    /* simulate connected route add from RTM */
    nas_ut_os_rt_cfg (1, "7.1.1.0", 24, AF_INET, NULL, test_phy_intf_1);

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7.1.1.0", 24, AF_INET, NULL, test_phy_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    nas_rt_lnx_ip_addr_cfg(0, "7.1.1.1", 24, test_phy_intf_1);
    /* simulate connected route delete from RTM */
    nas_ut_os_rt_cfg (0, "7.1.1.0", 24, AF_INET, NULL, NULL);

    /* wait for few secs after config delete, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7.1.1.0", 24, AF_INET, NULL, test_phy_intf_1, false);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

    /* test clean-up */
    nas_rt_lnx_intf_admin_cfg (0, test_phy_intf_1);
}

//validate connected route after IP address change
TEST(std_nas_route_test, nas_os_rt_cfg_ut_2) {
    cps_api_return_code_t rc;

    /* config test pre-requisite */
    nas_rt_lnx_intf_admin_cfg (1, test_phy_intf_1);

    /* configure ip address and connected route */
    nas_rt_lnx_ip_addr_cfg(1, "7.2.1.1", 24, test_phy_intf_1);
    nas_ut_os_rt_cfg (1, "7.2.1.0", 24, AF_INET, NULL, test_phy_intf_1);

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7.2.1.0", 24, AF_INET, NULL, test_phy_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    nas_rt_lnx_ip_addr_cfg(0, "7.2.1.1", 24, test_phy_intf_1);
    nas_ut_os_rt_cfg (0, "7.2.1.0", 24, AF_INET, NULL, NULL);

    /* configure new ip address in same subnet and then add connected route */
    nas_rt_lnx_ip_addr_cfg(1, "7.2.1.2", 24, test_phy_intf_1);
    /* simulate connected route add from RTM */
    nas_ut_os_rt_cfg (1, "7.2.1.0", 24, AF_INET, NULL, test_phy_intf_1);

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7.2.1.0", 24, AF_INET, NULL, test_phy_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    nas_rt_lnx_ip_addr_cfg(0, "7.2.1.2", 24, test_phy_intf_1);
    /* simulate connected route delete from RTM */
    nas_ut_os_rt_cfg (0, "7.2.1.0", 24, AF_INET, NULL, NULL);

    /* wait for few secs after config delete, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7.2.1.0", 24, AF_INET, NULL, test_phy_intf_1, false);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

    /* test clean-up */
    nas_rt_lnx_intf_admin_cfg (0, test_phy_intf_1);
}

//validate connected route after admin down event
TEST(std_nas_route_test, nas_os_rt_cfg_ut_3) {
    cps_api_return_code_t rc;

    if (run_test_mode) return;

    /* config test pre-requisite */
    nas_rt_lnx_intf_admin_cfg (1, test_phy_intf_1);

    /* configure ip address and connected route */
    nas_rt_lnx_ip_addr_cfg(1, "7.3.1.1", 24, test_phy_intf_1);
    nas_ut_os_rt_cfg (1, "7.3.1.0", 24, AF_INET, NULL, test_phy_intf_1);

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7.3.1.0", 24, AF_INET, NULL, test_phy_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    /* set admin down */
    nas_rt_lnx_intf_admin_cfg (0, test_phy_intf_1);
    /* simulate connected route delete from RTM */
    nas_ut_os_rt_cfg (0, "7.3.1.0", 24, AF_INET, NULL, NULL);

    /* don't validate it for now, as we need to simulate
     * admin down/up in quick succession and see check on the netlink events
     */
/*
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7.3.1.0", 24, AF_INET, NULL, test_phy_intf_1, false);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);
*/

    /* set admin up */
    nas_rt_lnx_intf_admin_cfg (1, test_phy_intf_1);
    /* simulate connected route add from RTM */
    nas_ut_os_rt_cfg (1, "7.3.1.0", 24, AF_INET, NULL, test_phy_intf_1);

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7.3.1.0", 24, AF_INET, NULL, test_phy_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    nas_rt_lnx_ip_addr_cfg(0, "7.3.1.1", 24, test_phy_intf_1);
    nas_ut_os_rt_cfg (0, "7.3.1.0", 24, AF_INET, NULL, NULL);

    /* wait for few secs after config delete, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7.3.1.0", 24, AF_INET, NULL, test_phy_intf_1, false);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

    /* test clean-up */
    nas_rt_lnx_intf_admin_cfg (0, test_phy_intf_1);
}


//validate connected route after oper down event
TEST(std_nas_route_test, nas_os_rt_cfg_ut_4) {
    cps_api_return_code_t rc;

    if (run_test_mode) return;

    /* config test pre-requisite */
    nas_rt_lnx_vlan_intf_cfg (1, test_vlan_intf_1, test_vlan_id_1, test_vlan_intf_mem_port_1);
    nas_rt_lnx_intf_admin_cfg (1, test_vlan_intf_1);

    /* configure ip address and connected route */
    nas_rt_lnx_ip_addr_cfg(1, "7.4.1.1", 24, test_vlan_intf_1);
    nas_ut_os_rt_cfg (1, "7.4.1.0", 24, AF_INET, NULL, test_vlan_intf_1);

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7.4.1.0", 24, AF_INET, NULL, test_vlan_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    /* set admin down of vlan member port */
    nas_rt_lnx_intf_admin_cfg (0, test_vlan_intf_mem_port_1);
    /* simulate connected route delete from RTM */
    nas_ut_os_rt_cfg (0, "7.4.1.0", 24, AF_INET, NULL, NULL);

    sleep (3);
    rc = nas_ut_validate_nas_rt_cfg ("7.4.1.0", 24, AF_INET, NULL, test_vlan_intf_1, false);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

    /* set admin up of vlan member port */
    nas_rt_lnx_intf_admin_cfg (1, test_vlan_intf_mem_port_1);
    /* simulate connected route add from RTM */
    nas_ut_os_rt_cfg (1, "7.4.1.0", 24, AF_INET, NULL, test_vlan_intf_1);

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7.4.1.0", 24, AF_INET, NULL, test_vlan_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    nas_rt_lnx_ip_addr_cfg(0, "7.4.1.1", 24, test_vlan_intf_1);
    nas_ut_os_rt_cfg (0, "7.4.1.0", 24, AF_INET, NULL, NULL);

    /* wait for few secs after config delete, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7.4.1.0", 24, AF_INET, NULL, test_vlan_intf_1, false);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

    /* test clean-up */
    nas_rt_lnx_intf_admin_cfg (0, test_vlan_intf_1);
    nas_rt_lnx_vlan_intf_cfg (0, test_vlan_intf_1, test_vlan_id_1, test_vlan_intf_mem_port_1);
}

//validate connected route del & route add for other routes (like static route/protocol route)
TEST(std_nas_route_test, nas_os_rt_cfg_ut_5) {
    cps_api_return_code_t rc;

    if (run_test_mode) return;

    /* config test pre-requisite */
    nas_rt_lnx_intf_admin_cfg (1, test_phy_intf_1);

    /* configure ip address and connected route */
    nas_rt_lnx_ip_addr_cfg(1, "7.5.1.1", 24, test_phy_intf_1);
    /* simulate connected route add from RTM */
    nas_ut_os_rt_cfg (1, "7.5.1.0", 24, AF_INET, NULL, test_phy_intf_1);

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7.5.1.0", 24, AF_INET, NULL, test_phy_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    nas_rt_lnx_ip_addr_cfg(0, "7.5.1.1", 24, test_phy_intf_1);
    /* simulate connected route delete from RTM */
    nas_ut_os_rt_cfg (0, "7.5.1.0", 24, AF_INET, NULL, NULL);
    /* simulate protocol direct route add from RTM */
    nas_ut_os_rt_cfg (1, "7.5.1.0", 24, AF_INET, NULL, test_phy_intf_1);

    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7.5.1.0", 24, AF_INET, NULL, test_phy_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    /* simulate protocol route delete from RTM */
    nas_ut_os_rt_cfg (0, "7.5.1.0", 24, AF_INET, NULL, NULL);

    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7.5.1.0", 24, AF_INET, NULL, test_phy_intf_1, false);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

    /* test clean-up */
    nas_rt_lnx_intf_admin_cfg (0, test_phy_intf_1);
}

//validate connected route del & route add for other routes (like static route/protocol route)
//followed by ip address change, route add for connected route.
TEST(std_nas_route_test, nas_os_rt_cfg_ut_6) {
    cps_api_return_code_t rc;

    if (run_test_mode) return;

    /* config test pre-requisite */
    nas_rt_lnx_intf_admin_cfg (1, test_phy_intf_1);

    /* configure ip address and connected route */
    nas_rt_lnx_ip_addr_cfg(1, "7.6.1.1", 24, test_phy_intf_1);
    /* simulate connected route add from RTM */
    nas_ut_os_rt_cfg (1, "7.6.1.0", 24, AF_INET, NULL, test_phy_intf_1);

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7.6.1.0", 24, AF_INET, NULL, test_phy_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    nas_rt_lnx_ip_addr_cfg(0, "7.6.1.1", 24, test_phy_intf_1);
    /* simulate connected route delete from RTM */
    nas_ut_os_rt_cfg (0, "7.6.1.0", 24, AF_INET, NULL, NULL);
    sleep (2);
    /* simulate protocol direct route add from RTM */
    nas_ut_os_rt_cfg (1, "7.6.1.0", 24, AF_INET, NULL, test_phy_intf_1);
    sleep (2);
    /* ip address change */
    nas_rt_lnx_ip_addr_cfg(1, "7.6.1.2", 24, test_phy_intf_1);
    sleep (2);
    /* simulate protocol direct route del from RTM */
    nas_ut_os_rt_cfg (0, "7.6.1.0", 24, AF_INET, NULL, NULL);
    /* simulate connected route add from RTM */
    nas_ut_os_rt_cfg (1, "7.6.1.0", 24, AF_INET, NULL, test_phy_intf_1);

    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7.6.1.0", 24, AF_INET, NULL, test_phy_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    /* ip address del */
    nas_rt_lnx_ip_addr_cfg(0, "7.6.1.2", 24, test_phy_intf_1);
    /* simulate connected route delete from RTM */
    nas_ut_os_rt_cfg (0, "7.6.1.0", 24, AF_INET, NULL, NULL);

    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7.6.1.0", 24, AF_INET, NULL, test_phy_intf_1, false);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

    /* test clean-up */
    nas_rt_lnx_intf_admin_cfg (0, test_phy_intf_1);
}


//validate connected route add & delete
TEST(std_nas_route_test, nas_os_v6_rt_cfg_ut_1) {
    cps_api_return_code_t rc;

    /* config test pre-requisite */
    nas_rt_lnx_intf_admin_cfg (1, test_phy_intf_1);

    /* configure ip address and connected route */
    nas_rt_lnx_ip_addr_cfg(1, "7:1:1::1", 64, test_phy_intf_1);
    /* simulate connected route add from RTM */
    nas_ut_os_rt_cfg (1, "7:1:1::", 64, AF_INET6, NULL, test_phy_intf_1);

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7:1:1::", 64, AF_INET6, NULL, test_phy_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    nas_rt_lnx_ip_addr_cfg(0, "7:1:1::1", 64, test_phy_intf_1);
    /* simulate connected route delete from RTM */
    nas_ut_os_rt_cfg (0, "7:1:1::", 64, AF_INET6, NULL, NULL);

    /* wait for few secs after config delete, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7:1:1::", 64, AF_INET6, NULL, test_phy_intf_1, false);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

    /* test clean-up */
    nas_rt_lnx_intf_admin_cfg (0, test_phy_intf_1);
}

//validate connected route after IP address change
TEST(std_nas_route_test, nas_os_v6_rt_cfg_ut_2) {
    cps_api_return_code_t rc;

    if (run_test_mode) return;

    /* config test pre-requisite */
    nas_rt_lnx_intf_admin_cfg (1, test_phy_intf_1);

    /* configure ip address and connected route */
    nas_rt_lnx_ip_addr_cfg(1, "7:2:1::1", 64, test_phy_intf_1);
    nas_ut_os_rt_cfg (1, "7:2:1::", 64, AF_INET6, NULL, test_phy_intf_1);

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7:2:1::", 64, AF_INET6, NULL, test_phy_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    nas_rt_lnx_ip_addr_cfg(0, "7:2:1::1", 64, test_phy_intf_1);
    nas_ut_os_rt_cfg (0, "7:2:1::", 64, AF_INET6, NULL, NULL);

    /* configure new ip address in same subnet and then add connected route */
    nas_rt_lnx_ip_addr_cfg(1, "7:2:1::2", 64, test_phy_intf_1);
    /* simulate connected route add from RTM */
    nas_ut_os_rt_cfg (1, "7:2:1::", 64, AF_INET6, NULL, test_phy_intf_1);

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7:2:1::", 64, AF_INET6, NULL, test_phy_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    nas_rt_lnx_ip_addr_cfg(0, "7:2:1::2", 64, test_phy_intf_1);
    /* simulate connected route delete from RTM */
    nas_ut_os_rt_cfg (0, "7:2:1::", 64, AF_INET6, NULL, NULL);

    /* wait for few secs after config delete, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7:2:1::", 64, AF_INET6, NULL, test_phy_intf_1, false);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

    /* test clean-up */
    nas_rt_lnx_intf_admin_cfg (0, test_phy_intf_1);
}

//validate connected route after admin down event
TEST(std_nas_route_test, nas_os_v6_rt_cfg_ut_3) {
    cps_api_return_code_t rc;

    if (run_test_mode) return;

    /* config test pre-requisite */
    nas_rt_lnx_intf_admin_cfg (1, test_phy_intf_1);

    /* configure ip address and connected route */
    nas_rt_lnx_ip_addr_cfg(1, "7:3:1::1", 64, test_phy_intf_1);
    nas_ut_os_rt_cfg (1, "7:3:1::", 64, AF_INET6, NULL, test_phy_intf_1);

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7:3:1::", 64, AF_INET6, NULL, test_phy_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    /* set admin down */
    nas_rt_lnx_intf_admin_cfg (0, test_phy_intf_1);
    /* simulate connected route delete from RTM */
    nas_ut_os_rt_cfg (0, "7:3:1::", 64, AF_INET6, NULL, NULL);

    /* don't validate it for now, as we need to simulate
     * admin down/up in quick succession and see check on the netlink events
     */
/*
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7:3:1::", 64, AF_INET6, NULL, test_phy_intf_1, false);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);
*/

    /* set admin up */
    nas_rt_lnx_intf_admin_cfg (1, test_phy_intf_1);
    /* simulate connected route add from RTM */
    nas_ut_os_rt_cfg (1, "7:3:1::", 64, AF_INET6, NULL, test_phy_intf_1);

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7:3:1::", 64, AF_INET6, NULL, test_phy_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    nas_rt_lnx_ip_addr_cfg(0, "7:3:1::1", 64, test_phy_intf_1);
    nas_ut_os_rt_cfg (0, "7:3:1::", 64, AF_INET6, NULL, NULL);

    /* wait for few secs after config delete, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7:3:1::", 64, AF_INET6, NULL, test_phy_intf_1, false);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

    /* test clean-up */
    nas_rt_lnx_intf_admin_cfg (0, test_phy_intf_1);
}

//validate connected route after oper down event
TEST(std_nas_route_test, nas_os_v6_rt_cfg_ut_4) {
    cps_api_return_code_t rc;

    if (run_test_mode) return;

    /* config test pre-requisite */
    nas_rt_lnx_vlan_intf_cfg (1, test_vlan_intf_1, test_vlan_id_1, test_vlan_intf_mem_port_1);
    nas_rt_lnx_intf_admin_cfg (1, test_vlan_intf_1);

    /* configure ip address and connected route */
    nas_rt_lnx_ip_addr_cfg(1, "7:4:1::1", 64, test_vlan_intf_1);
    nas_ut_os_rt_cfg (1, "7:4:1::", 64, AF_INET6, NULL, test_vlan_intf_1);

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7:4:1::", 64, AF_INET6, NULL, test_vlan_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    /* set admin down of vlan member port */
    nas_rt_lnx_intf_admin_cfg (0, test_vlan_intf_mem_port_1);
    /* simulate connected route delete from RTM */
    nas_ut_os_rt_cfg (0, "7:4:1::", 64, AF_INET6, NULL, NULL);

    sleep (3);
    rc = nas_ut_validate_nas_rt_cfg ("7:4:1::", 64, AF_INET6, NULL, test_vlan_intf_1, false);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

    /* set admin up of vlan member port */
    nas_rt_lnx_intf_admin_cfg (1, test_vlan_intf_mem_port_1);
    /* simulate connected route add from RTM */
    nas_ut_os_rt_cfg (1, "7:4:1::", 64, AF_INET6, NULL, test_vlan_intf_1);

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7:4:1::", 64, AF_INET6, NULL, test_vlan_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    nas_rt_lnx_ip_addr_cfg(0, "7:4:1::1", 64, test_vlan_intf_1);
    nas_ut_os_rt_cfg (0, "7:4:1::", 64, AF_INET6, NULL, NULL);

    /* wait for few secs after config delete, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7:4:1::", 64, AF_INET6, NULL, test_vlan_intf_1, false);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

    /* test clean-up */
    nas_rt_lnx_intf_admin_cfg (0, test_vlan_intf_1);
    nas_rt_lnx_vlan_intf_cfg (0, test_vlan_intf_1, test_vlan_id_1, test_vlan_intf_mem_port_1);
}

//validate connected route del & route add for other routes (like static route/protocol route)
TEST(std_nas_route_test, nas_os_v6_rt_cfg_ut_5) {
    cps_api_return_code_t rc;

    if (run_test_mode) return;

    /* config test pre-requisite */
    nas_rt_lnx_intf_admin_cfg (1, test_phy_intf_1);

    /* configure ip address and connected route */
    nas_rt_lnx_ip_addr_cfg(1, "7:5:1::1", 64, test_phy_intf_1);
    /* simulate connected route add from RTM */
    nas_ut_os_rt_cfg (1, "7:5:1::", 64, AF_INET6, NULL, test_phy_intf_1);

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7:5:1::", 64, AF_INET6, NULL, test_phy_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    nas_rt_lnx_ip_addr_cfg(0, "7:5:1::1", 64, test_phy_intf_1);
    sleep (1);
    /* simulate connected route delete from RTM */
    nas_ut_os_rt_cfg (0, "7:5:1::", 64, AF_INET6, NULL, NULL);
    /* simulate protocol direct route add from RTM */
    nas_ut_os_rt_cfg (1, "7:5:1::", 64, AF_INET6, NULL, test_phy_intf_1);

    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7:5:1::", 64, AF_INET6, NULL, test_phy_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    /* simulate protocol route delete from RTM */
    nas_ut_os_rt_cfg (0, "7:5:1::", 64, AF_INET6, NULL, NULL);

    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7:5:1::", 64, AF_INET6, NULL, test_phy_intf_1, false);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

    /* test clean-up */
    nas_rt_lnx_intf_admin_cfg (0, test_phy_intf_1);
}

//validate connected route del & route add for other routes (like static route/protocol route)
//followed by ip address change, route add for connected route.
TEST(std_nas_route_test, nas_os_v6_rt_cfg_ut_6) {
    cps_api_return_code_t rc;

    if (run_test_mode) return;

    /* config test pre-requisite */
    nas_rt_lnx_intf_admin_cfg (1, test_phy_intf_1);

    /* configure ip address and connected route */
    nas_rt_lnx_ip_addr_cfg(1, "7:6:1::1", 64, test_phy_intf_1);
    /* simulate connected route add from RTM */
    nas_ut_os_rt_cfg (1, "7:6:1::", 64, AF_INET6, NULL, test_phy_intf_1);

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7:6:1::", 64, AF_INET6, NULL, test_phy_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    nas_rt_lnx_ip_addr_cfg(0, "7:6:1::1", 64, test_phy_intf_1);
    sleep (1);
    /* simulate connected route delete from RTM */
    nas_ut_os_rt_cfg (0, "7:6:1::", 64, AF_INET6, NULL, NULL);
    /* simulate protocol direct route add from RTM */
    nas_ut_os_rt_cfg (1, "7:6:1::", 64, AF_INET6, NULL, test_phy_intf_1);
    sleep (2);
    /* ip address change */
    nas_rt_lnx_ip_addr_cfg(1, "7:6:1::2", 64, test_phy_intf_1);
    sleep (2);
    /* simulate protocol direct route del from RTM */
    nas_ut_os_rt_cfg (0, "7:6:1::", 64, AF_INET6, NULL, NULL);
    /* simulate connected route add from RTM */
    nas_ut_os_rt_cfg (1, "7:6:1::", 64, AF_INET6, NULL, test_phy_intf_1);

    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7:6:1::", 64, AF_INET6, NULL, test_phy_intf_1, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    /* ip address del */
    nas_rt_lnx_ip_addr_cfg(0, "7:6:1::2", 64, test_phy_intf_1);
    /* simulate connected route delete from RTM */
    nas_ut_os_rt_cfg (0, "7:6:1::", 64, AF_INET6, NULL, NULL);

    sleep (5);
    rc = nas_ut_validate_nas_rt_cfg ("7:6:1::", 64, AF_INET6, NULL, test_phy_intf_1, false);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

    /* test clean-up */
    nas_rt_lnx_intf_admin_cfg (0, test_phy_intf_1);
}

static cps_api_return_code_t nas_os_vrf_cfg (const char *vrf_name, bool is_add)
{
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    NI_NETWORK_INSTANCES_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_attr_add(obj,NI_NETWORK_INSTANCES_NETWORK_INSTANCE_NAME, vrf_name,
                            strlen(vrf_name)+1);
    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    cps_api_transaction_init(&tr);

    if (is_add)
        cps_api_create(&tr,obj);
    else
        cps_api_delete(&tr,obj);

    rc = cps_api_commit(&tr);
    cps_api_transaction_close(&tr);

    return rc;
}

TEST(std_nas_route_test, nas_os_verify_lla) {
    int ret = system("opx-show-version | grep \"OS_NAME.*Enterprise\"");
    if (ret == 0) {
        FILE *fp;

        fp = fopen("/tmp/test_pre_req","w");
        fprintf(fp, "configure terminal\n");
        fprintf(fp, "interface range vlan 200-350\n");
        fprintf(fp, "exit\n");
        fflush(fp);
        system("sudo -u admin clish --b /tmp/test_pre_req");
        sleep(2);
        /* Check if LLAs are created for all VLANs */
        ret = system("ip -6 route show | grep -c fe80 > /tmp/result");
        FILE * result = fopen("/tmp/result","r");
        int val = 0;
        fscanf(result, "%d", &val);
        fclose(result);

        printf("\r\n LLA count:%d\r\n", val);
        ASSERT_TRUE(val >=150);
        fclose(fp);

        fp = fopen("/tmp/test_pre_req","w");
        fprintf(fp, "configure terminal\n");
        fprintf(fp, "no interface range vlan 200-350\n");
        fprintf(fp, "exit\n");
        fflush(fp);
        system("sudo -u admin clish --b /tmp/test_pre_req");
        fclose(fp);
    }
}

static cps_api_return_code_t nas_ut_proxy_arp_cfg (const char *vrf_name, const char* if_name, bool is_add)
{
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PROXY_ARP_CONFIG_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_attr_add(obj,BASE_ROUTE_PROXY_ARP_CONFIG_VRF_NAME, vrf_name,
                            strlen(vrf_name)+1);
    cps_api_object_attr_add(obj,BASE_ROUTE_PROXY_ARP_CONFIG_IFNAME, if_name,
                            strlen(if_name)+1);
    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    cps_api_transaction_init(&tr);

    if (is_add)
        cps_api_create(&tr,obj);
    else
        cps_api_delete(&tr,obj);

    rc = cps_api_commit(&tr);
    cps_api_transaction_close(&tr);

    return rc;
}

TEST(std_nas_route_test, nas_os_vrf_cfg) {
    cps_api_return_code_t rc;
    system("mkdir /etc/netns/red");
    rc = nas_os_vrf_cfg("red", true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    system("rmdir /etc/netns/red");
    rc = nas_os_vrf_cfg("red", false);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
}

TEST(std_nas_route_test, nas_os_verify_proxy_arp) {
    int val = 0;
    FILE * result = NULL;
    nas_ut_proxy_arp_cfg("default", "br1", true);
    result = fopen("/proc/sys/net/ipv4/conf/br1/proxy_arp","r");
    ASSERT_TRUE(result != NULL);
    fscanf(result, "%d", &val);
    fclose(result);
    ASSERT_TRUE(val == 1);
    nas_ut_proxy_arp_cfg("default", "br1", false);
    result = fopen("/proc/sys/net/ipv4/conf/br1/proxy_arp","r");
    ASSERT_TRUE(result != NULL);
    fscanf(result, "%d", &val);
    fclose(result);
    ASSERT_TRUE(val == 0);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);


  printf("\r\n Executing: args:%d %s %s \r\n", argc, argv[0], argv[1]);

  if ((argc > 1) && (strncmp(argv[1], "run-test",8) == 0)){
      /* run_test mode enable */
      run_test_mode = true;
  }


  /* configure the test pre-requisites */
  printf("___________________________________________\n");
  printf("Test pre-requisite\n");
  printf("Configure following modes for the test ports and make oper UP\n");
  printf("Port:%-15s Mode:%-20s\n", test_phy_intf_1, "no switchport");
  printf("Port:%-15s Mode:%-20s\n", "e101-008-0", "no switchport");
  printf("Port:%-15s Mode:%-20s\n", test_vlan_intf_mem_port_1, "switchport mode access");
  printf("___________________________________________\n\n");

  return RUN_ALL_TESTS();
}
