#!/usr/bin/python
# Copyright (c) 2018 Dell Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
# LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
# FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
#
# See the Apache Version 2.0 License for specific language governing
# permissions and limitations under the License.


import subprocess
import cps
import cps_utils
import cps_object
import threading
import time
import nas_os_if_utils as nas_if



BASE_CMN_INTERFACE_TYPE_L3_PORT = 1
BASE_CMN_INTERFACE_TYPE_L2_PORT = 2
BASE_CMN_INTERFACE_TYPE_LOOPBACK = 3
BASE_CMN_INTERFACE_TYPE_NULL = 4
BASE_CMN_INTERFACE_TYPE_TUNNEL = 5
BASE_CMN_INTERFACE_TYPE_SVI = 6
BASE_CMN_INTERFACE_TYPE_CPU = 7
BASE_CMN_INTERFACE_TYPE_MANAGEMENT = 8
BASE_CMN_INTERFACE_TYPE_ETHERNET = 9
BASE_CMN_INTERFACE_TYPE_VLAN = 10
BASE_CMN_INTERFACE_TYPE_LAG = 11
BASE_CMN_INTERFACE_TYPE_VRF = 12
BASE_CMN_INTERFACE_TYPE_MACVLAN = 13
BASE_CMN_INTERFACE_TYPE_VXLAN = 14
BASE_CMN_INTERFACE_TYPE_BRIDGE = 15
BASE_CMN_INTERFACE_TYPE_VLAN_SUBINTF = 16
BASE_CMN_INTERFACE_TYPE_MIN=1
BASE_CMN_INTERFACE_TYPE_MAX=16

dell_type_to_str = {
BASE_CMN_INTERFACE_TYPE_L3_PORT : 'Physical',
BASE_CMN_INTERFACE_TYPE_L2_PORT : 'L2_Port',
BASE_CMN_INTERFACE_TYPE_LOOPBACK : 'Loopback',
BASE_CMN_INTERFACE_TYPE_NULL : 'null',
BASE_CMN_INTERFACE_TYPE_TUNNEL : 'tunnel',
BASE_CMN_INTERFACE_TYPE_SVI : 'svi',
BASE_CMN_INTERFACE_TYPE_CPU : 'cpu',
BASE_CMN_INTERFACE_TYPE_MANAGEMENT : 'mgmt',
BASE_CMN_INTERFACE_TYPE_ETHERNET : 'ethernet',
BASE_CMN_INTERFACE_TYPE_VLAN : 'vlan',
BASE_CMN_INTERFACE_TYPE_LAG : 'Lag',
BASE_CMN_INTERFACE_TYPE_VRF : 'VRF',
BASE_CMN_INTERFACE_TYPE_MACVLAN : 'macvlan',
BASE_CMN_INTERFACE_TYPE_VXLAN : 'vxlan',
BASE_CMN_INTERFACE_TYPE_BRIDGE : 'Bridge',
BASE_CMN_INTERFACE_TYPE_VLAN_SUBINTF : 'Vlan Sub interface',
}


cps_ev_hdl = None               # CPS API event service handle
br_list = {}
debug = True

# Print in Bold
def dbg_print(obj):
    global debug
    if debug == True:
        # print in Bold
        print '\033[1m'
        print(obj)
        print '\033[0m'

def cps_attr_data_get(obj, attr):
    d = obj['data']
    if attr not in d:
        return None
    return cps_utils.cps_attr_types_map.from_data(attr, d[attr])


def nas_os_event_handler(ev_obj):

    global g_intf_list
    operation, if_name, untagged_if_name, tagged_if_name = None, None, None, None

    if 'operation' in ev_obj:
        operation = ev_obj['operation']
    else:
        return
    intf_obj = cps_object.CPSObject(obj=ev_obj)
    dbg_print(" Operation:  %s " % (operation))

    if_name = nas_if.get_cps_attr(intf_obj, 'if/interfaces/interface/name')
    if if_name is None:
        dbg_print("Exception in reading name")
    if_type = nas_if.get_cps_attr(intf_obj, 'base-if-linux/if/interfaces/interface/dell-type')
    if operation == 'create':

        if if_name in g_intf_list:
            dbg_print(" Interface %s already present" %(if_name))
        if BASE_CMN_INTERFACE_TYPE_L2_PORT == 2 and if_name in g_intf_list:
            # Member Addition in a bridge
            # Check for untagged member
            ut_mem = nas_if.get_cps_attr(intf_obj, 'dell-if/if/interfaces/interface/untagged-ports')
            t_mem = nas_if.get_cps_attr(intf_obj, 'dell-if/if/interfaces/interface/tagged-ports')
            if ut_mem is not None:
                g_intf_list[if_name].add_attr('dell-if/if/interfaces/interface/untagged-ports', ut_mem)
                dbg_print(" New untagged Member %s addition to the bridge %s" %(ut_mem, if_name))
            # Check for tagged member
            if t_mem is not None:
                g_intf_list[if_name].add_attr('dell-if/if/interfaces/interface/tagged-ports', t_mem)
                dbg_print(" New tagged Member %s addition to the bridge %s" %(t_mem, if_name))
        else:
            g_intf_list[if_name] = intf_obj
            dbg_print(" Create Interface %s  type %s create event" % (if_name, dell_type_to_str[if_type]))
    elif operation == 'delete':
        if if_name not in g_intf_list:
            dbg_print(" delete interface or member event received but intf %s not present" % (if_name))
        else:
            if if_type == 2:
                # member delete event
                ut_mem = nas_if.get_cps_attr(intf_obj, 'dell-if/if/interfaces/interface/untagged-ports')
                t_mem = nas_if.get_cps_attr(intf_obj, 'dell-if/if/interfaces/interface/tagged-ports')
                if ut_mem is not None:
                    g_intf_list[if_name].del_attr('dell-if/if/interfaces/interface/untagged-ports')
                    dbg_print(" Untagged Member %s deletion to the bridge %s" %(ut_mem, if_name))
                if t_mem is not None:
                    g_intf_list[if_name].del_attr('dell-if/if/interfaces/interface/tagged-ports')
                    dbg_print(" tagged Member %s deletion to the bridge %s" %(t_mem, if_name))
            else:
                # Delete Interface event
                dbg_print(" Delete Interface %s event received" % (if_name))
                del g_intf_list[if_name]

    elif operation == 'set':
        dbg_print(" set Interface event received ")
        if if_name not in g_intf_list:
            dbg_print(" set event received but intf not present")
    cps_utils.print_obj(ev_obj)


## Handle the NAS OS events corresponding to the interfaces and bridge netlink events.
## This will store the interface and bridges alongwith its CPS object on create and delete the entry
## upon delete event.
##
def process_events():
    while True:
        obj = cps.event_wait(cps_ev_hdl)
        nas_os_event_handler(obj)

def main():
    while True:
        process_events() # Process events as they occur
        time.sleep(5)    # Pause and retry

class processEventThread(threading.Thread):
    def __init__(self, threadID, name):
        threading.Thread.__init__(self)
        self.__init__threadId = threadID
        self.__init__name = name
    def run(self):
        main()
    def __str__(self):
        return ' %s %d ' %(self.name, self.threadID)

# Connect to CPS API event service
def init_events():
    global cps_ev_hdl
    cps_ev_hdl = cps.event_connect()
    cps.event_register(cps_ev_hdl, cps.key_from_name('observed', 'base-if-linux/if/interfaces/interface'))

def prRed(prt): print("\033[91m {}\033[00m".format(prt))

def exec_shell(cmd):
    print(cmd)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    return out

g_intf_list = {}
def vlan_sub_interface_create_test():
    global g_intf_list
    exec_shell("ip link del e101-001-0.600")
    # test
    exec_shell("ip link add link e101-001-0 name e101-001-0.600 type vlan id 600")

    # Check
    while 'e101-001-0.600' not in g_intf_list:
        time.sleep(1)

    assert 'e101-001-0.600' in g_intf_list
    intf_obj = g_intf_list['e101-001-0.600']
    #cps_utils.print_obj(intf_obj.get())
    dbg_print("********Interface e101-001-0.600 creation is successful*****")


def vlan_sub_interface_delete_test():
    global g_intf_list
    exec_shell("ip link del e101-001-0.600")
    # test
    while  True:
        if 'e101-001-0.600' not in g_intf_list:
            break

    assert 'e101-001-0.600' not in g_intf_list
    dbg_print("********Interface e101-001-0.600 deletion is successful*****")

def bridge_create_test():
    global g_intf_list
    exec_shell("brctl delbr br600")

    # test
    exec_shell("brctl addbr br600")
    while 'br600' not in g_intf_list:
        time.sleep(1)

    dbg_print("********Bridge br600 creation is successful*****")
    # create a sub interface
    exec_shell("ip link add link e101-001-0 name e101-001-0.600 type vlan id 600")
    while 'e101-001-0.600' not in g_intf_list:
        time.sleep(1)
    # Add the sub interface to the bridge
    exec_shell("brctl addif br600 e101-001-0.600")
    t_mem = nas_if.get_cps_attr(g_intf_list['br600'], 'dell-if/if/interfaces/interface/tagged-ports')
    while t_mem is None:
        t_mem = nas_if.get_cps_attr(g_intf_list['br600'], 'dell-if/if/interfaces/interface/tagged-ports')
    if 'e101-001-0.600' in t_mem:
        dbg_print("********Member e101-001-0.600 addition is successful*****")

    # delete member from the bridge
    exec_shell("brctl delif br600 e101-001-0.600")
    t_mem = nas_if.get_cps_attr(g_intf_list['br600'], 'dell-if/if/interfaces/interface/tagged-ports')
    if t_mem is None:
        dbg_print("********Member e101-001-0.600 from bridge deletion is successful*****")



def bridge_delete_test():
    global g_intf_list
    exec_shell("brctl delbr br600")

    # test
    while 'br600' in g_intf_list:
        time.sleep(1)

def lag_create_test():
    global g_intf_list
    exec_shell("ip link del bond100")
    # test
    exec_shell("ip link add bond100 type bond mode 1 miimon 100")

    # Check
    while 'bond100' not in g_intf_list:
        time.sleep(1)

    assert 'bond100' in g_intf_list
    dbg_print("********Interface bond100 creation is successful*****")


def lag_delete_test():
    global g_intf_list
    exec_shell("ip link del bond100")
    # test
    while  True:
        if 'bond100' not in g_intf_list:
            break

    assert 'bond100' not in g_intf_list
    dbg_print("********Interface bond100 deletion is successful*****")

def vxlan_create_test():
    global g_intf_list
    exec_shell("ip link del vtep500")
    # test
    exec_shell("ip link add vtep500 type vxlan id 500 local 10.11.1.2 dstport 4789")

    # Check
    while 'vtep500' not in g_intf_list:
        time.sleep(1)

    assert 'vtep500' in g_intf_list
    dbg_print("********Interface vtep500 creation is successful*****")


def vxlan_delete_test():
    global g_intf_list
    exec_shell("ip link del vtep500")
    # test
    while  True:
        if 'vtep500' not in g_intf_list:
            break

    assert 'vtep500' not in g_intf_list
    dbg_print("********Interface vtep500 deletion is successful*****")

def bridge_1d_configure_test():
    bridge_create_test()
    vxlan_create_test()
    vlan_sub_interface_create_test()
    lag_create_test()

    # Add Lag, VXLAN and VLans sub interfaces to the bridge

    # Add VXLAN to the bridge
    exec_shell("brctl addif br600 vtep500")
    t_mem = nas_if.get_cps_attr(g_intf_list['br600'], 'dell-if/if/interfaces/interface/tagged-ports')
    while t_mem is None or 'vtep500' not in t_mem:
        t_mem = nas_if.get_cps_attr(g_intf_list['br600'], 'dell-if/if/interfaces/interface/tagged-ports')

    dbg_print("********Interface Vtep500 added in the bridge br600**************************")

    # Add Vlan sub interface  to the bridge
    exec_shell("brctl addif br600 e101-001-0.600")
    t_mem = nas_if.get_cps_attr(g_intf_list['br600'], 'dell-if/if/interfaces/interface/tagged-ports')
    while 'e101-001-0.600' not in t_mem:
        t_mem = nas_if.get_cps_attr(g_intf_list['br600'], 'dell-if/if/interfaces/interface/tagged-ports')
    dbg_print("********Interface e101-001-0.600 added in the bridge br600**************************")

    # Add Bond interface  to the bridge
    exec_shell("brctl addif br600 bond100")
    ut_mem = nas_if.get_cps_attr(g_intf_list['br600'], 'dell-if/if/interfaces/interface/untagged-ports')
    while ut_mem is None or 'bond100' not in ut_mem:
        ut_mem = nas_if.get_cps_attr(g_intf_list['br600'], 'dell-if/if/interfaces/interface/untagged-ports')
    dbg_print("********Interface bond100 added in the bridge br600**************************")


    exec_shell("brctl delif br600 vtep500")
    exec_shell("brctl delif br600 bond100")
    exec_shell("brctl delif br600 e101-001-0.600")
    exec_shell("brctl delbr br600")
    exec_shell("ip link del vtep500")
    exec_shell("ip link del bond100")
    exec_shell("ip link del e101-001-0.600")


tests = {
    1: vlan_sub_interface_create_test,
    2: vlan_sub_interface_delete_test,
    3: bridge_create_test,
    4: bridge_delete_test,
    5: lag_create_test,
    6: lag_delete_test,
    7: vxlan_create_test,
    8: vxlan_delete_test,
    9: bridge_1d_configure_test

}

#Test Prep
def register_for_event():
    init_events()
    process_event_thread = processEventThread(1, "Event Processing Thread")
    process_event_thread.daemon = True
    process_event_thread.start()

if __name__ == '__main__':
    register_for_event()
    idx = 1
    while(idx <= len(tests)):
        tests[idx]()
        raw_input("Press Enter to continue... \n")
        idx += 1
