#
# Copyright (c) 2019 Dell Inc.
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
#


import os
import subprocess
import cps
import cps_utils
import cps_object
import threading
import time
import bytearray_utils as ba

cps_ev_hdl = None               # CPS API event service handle
br_list = {}
debug = False

def dbg_print(obj):
    global debug
    if debug == True:
        print(obj)

def cps_get(qualifier, obj, attrs={}):
    resp = []
    if cps.get([cps_object.CPSObject(obj, qual=qualifier, data=attrs).get()], resp):
        return resp

def cps_attr_data_get(obj, attr):
    d = obj['data']
    if attr not in d:
        return None
    return cps_utils.cps_attr_types_map.from_data(attr, d[attr])

def print_attrs(operation, br_name, untagged_if_name, tagged_if_name):
    if operation is not None:
        dbg_print("operation: " + operation)
    if br_name is not None:
        dbg_print("br_name: " + br_name)
    if untagged_if_name is not None:
        dbg_print("untagged_if_name: " + str(untagged_if_name))
    if tagged_if_name is not None:
        dbg_print("tagged_if_name: " + str(tagged_if_name))

def event_handler(obj):

    global br_list

    operation, br_name, untagged_if_name, tagged_if_name = None, None, None, None
    try:
        operation = obj['operation']
    except:
        dbg_print("Exception in reading operation")

    try:
        br_name = cps_attr_data_get(obj, 'if/interfaces/interface/name')
    except:
        dbg_print("Exception in reading name")

    try:
        untagged_if_name = obj['data'].get('dell-if/if/interfaces/interface/untagged-ports')
        untagged_if_name = ba.ba_to_value('string', untagged_if_name[0])
    except:
        dbg_print("Exception in reading untagged Port name")

    try:
        tagged_if_name = obj['data'].get('dell-if/if/interfaces/interface/tagged-ports')
        tagged_if_name = ba.ba_to_value('string', tagged_if_name[0])
    except:
        dbg_print("Exception in reading tagged port name")

    if operation is not None and br_name is not None and tagged_if_name is not None:
        #Bridge tagged member add
        if operation == 'create':
            dbg_print("\nAdd Tagged Member")
            print_attrs(operation, br_name, untagged_if_name, tagged_if_name)
            if br_name in br_list:
                br_list[br_name].append(tagged_if_name)
        #Bridge tagged member delete
        if operation == 'delete':
            dbg_print("\nRemove Tagged Member")
            print_attrs(operation, br_name, untagged_if_name, tagged_if_name)
            if br_name in br_list:
                br_list[br_name].remove(tagged_if_name)

    elif operation is not None and br_name is not None and untagged_if_name is not None:
        #Bridge untagged member add
        if operation == 'create':
            dbg_print("\nAdd Unagged Member")
            print_attrs(operation, br_name, untagged_if_name, tagged_if_name)
            if br_name in br_list:
                br_list[br_name].append(untagged_if_name)
        #Bridge untagged member delete
        if operation == 'delete':
            dbg_print("\nRemove Unagged Member")
            print_attrs(operation, br_name, untagged_if_name, tagged_if_name)
            if br_name in br_list:
                br_list[br_name].remove(untagged_if_name)

    elif operation is not None or br_name is not None:
        #Bridge create
        if operation == 'create':
            dbg_print("\nCreate Bridge")
            print_attrs(operation, br_name, untagged_if_name, tagged_if_name)
            if br_name not in br_list:
                br_list[br_name] = []
        #Bridge delete
        if operation == 'delete':
            dbg_print("\nDelete Bridge")
            print_attrs(operation, br_name, untagged_if_name, tagged_if_name)
            if br_name in br_list:
                del br_list[br_name]
    return


def process_events():
    while True:
        obj = cps.event_wait(cps_ev_hdl)
        event_handler(obj)

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
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    return out


def test_1():
    #Test Prep
    register_for_event()
    global br_list
    exec_shell("brctl delbr br666")

    #Test Exec
    prRed("Test Description: Create br600")
    exec_shell("brctl addbr br666")

    #Test Check
    while 'br666' not in br_list:
        True

    assert 'br666' in br_list
    resp = cps_get('target', 'bridge-domain/bridge', {'bridge-domain/bridge/name': 'br666'})
    assert resp[0] is not None

def test_2():
    #Test Prep
    global br_list

    #Test Exec
    prRed("Test Description: Add e101-011-0.100 to br666")
    exec_shell("opx-config-vxlan.py delete vlanSubIntf --parent e101-011-0 --vlanId 100")
    exec_shell("opx-config-vxlan.py create vlanSubIntf --parent e101-011-0 --vlanId 100")
    exec_shell("brctl addif br666 e101-011-0.100")

    #Test Check
    while True:
        if 'e101-011-0.100' in br_list['br666']:
            break
    assert "e101-011-0.100" in br_list['br666']
    resp = cps_get('target', 'bridge-domain/bridge', {'bridge-domain/bridge/name': 'br666'})
    assert resp[0] is not None

def _test_3():
    #Test Prep
    global br_list

    #Test Exec
    prRed("Test Description: Remove e101-011-0.100 from br666")
    exec_shell("brctl delif br666 e101-011-0.100")
    exec_shell("opx-config-vxlan.py delete vlanSubIntf --parent e101-011-0 --vlanId 100")

    #Test Check
    while True:
        if 'e101-011-0' not in br_list['br666']:
            break
    assert "e101-011-0" not in br_list['br666']
    resp = cps_get('target', 'bridge-domain/bridge', {'bridge-domain/bridge/name': 'br666'})
    assert resp[0] is not None


def _test_4():
    #Test Prep
    global br_list

    #Test Exec
    prRed("Test Description: Add VTEP 100 to br666")
    exec_shell("ip link del vtep100")
    exec_shell("ip link add vtep100 type vxlan id 100 local 10.11.1.2 dstport 4789")
    exec_shell("brctl addif br666 vtep100")

    #Test Check
    while True:
        if 'vtep100' in br_list['br666']:
            break
    assert "vtep100" in br_list['br666']


def _test_5():
    #Test Prep
    global br_list

    #Test Exec
    prRed("Test Description: Remove vtep100 from br666")
    exec_shell("brctl delif br666 vtep100")

    #Test Check
    while True:
        if 'vtep100' not in br_list['br666']:
            break
    assert "vtep100" not in br_list['br666']
    resp = cps_get('target', 'bridge-domain/bridge', {'bridge-domain/bridge/name': 'br666'})
    assert resp[0] is not None


def test_3():
    #Test Prep
    global br_list

    #Test Exec
    prRed("Test Description: Delete br666")
    exec_shell("brctl delbr br666")

    #Test Check
    while True:
        if 'br666' not in br_list:
            break
    assert 'br666' not in br_list
    resp = cps_get('target', 'bridge-domain/bridge', {'bridge-domain/bridge/name': 'br666'})
    assert resp is None

tests = {
    1: test_1,
    2: test_2,
    3: test_3,
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
