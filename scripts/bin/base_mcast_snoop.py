#!/usr/bin/python
# Copyright (c) 2017 Dell Inc.
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

import signal
import cps
import cps_utils
import cps_object
import systemd.daemon
import dn_base_mcast_snoop_utils as mcast_utils
import dn_base_mcast_snoop as mcast_snoop
import time
import event_log as ev
import logging
import os as mcast_os
import threading

key_prefix = 'igmp-mld-snooping/rt/routing-state/control-plane-protocols/'
ip_types = {'igmp-snooping': 'ipv4', 'mld-snooping': 'ipv6'}

snoop_state_keys = {key_prefix + x + '/' + 'vlans/vlan': (
        cps.key_from_name('observed', key_prefix + x + '/' + 'vlans/vlan'), ip_types[x]) \
    for x in ip_types}

_igmp_keys = {
               "igmp-mld-snooping/rt/routing/control-plane-protocols/igmp-snooping/global":
               cps.key_from_name("target", "igmp-mld-snooping/rt/routing/control-plane-protocols/igmp-snooping/global"),
               "igmp-mld-snooping/rt/routing/control-plane-protocols/mld-snooping/global":
               cps.key_from_name("target", "igmp-mld-snooping/rt/routing/control-plane-protocols/mld-snooping/global"),
               "igmp-mld-snooping/rt/routing/control-plane-protocols/igmp-snooping/vlans/vlan":
               cps.key_from_name("target", "igmp-mld-snooping/rt/routing/control-plane-protocols/igmp-snooping/vlans/vlan"),
               "igmp-mld-snooping/rt/routing/control-plane-protocols/mld-snooping/vlans/vlan":
               cps.key_from_name("target", "igmp-mld-snooping/rt/routing/control-plane-protocols/mld-snooping/vlans/vlan"),
                "igmp-mld-snooping/rt/routing-state/control-plane-protocols/igmp-snooping/vlans/vlan":
                cps.key_from_name("observed", "igmp-mld-snooping/rt/routing-state/control-plane-protocols/igmp-snooping/vlans/vlan"),
                 "igmp-mld-snooping/rt/routing-state/control-plane-protocols/igmp-snooping/vlans":
                 cps.key_from_name("observed", "igmp-mld-snooping/rt/routing-state/control-plane-protocols/igmp-snooping/vlans")
             }
_igmp_keys.update({x: snoop_state_keys[x][0] for x in snoop_state_keys})

snoop_cfg_file = '/etc/opx/base_no_mcast_snooping'
kernel_snooping_needed = True

def _is_ip_link_snoop_cmd_supported():
    #For now, all snoop updates are based on file
    return False

def get_cb(methods, params):
    iplink_get_state = _is_ip_link_snoop_cmd_supported()
    obj = cps_object.CPSObject(obj = params['filter'])
    resp = params['list']
    ret_val = False
    for key_str, (key, ip_type) in snoop_state_keys.items():
        if obj.get_key() == key:
            try:
                vlan_id = obj.get_attr_data('vlan-id')
            except ValueError:
                vlan_id = None

            try:
                ret_val = mcast_utils.get_igmp_snooping(resp, key_str, ip_type,
                                                iplink_get_state, vlan_id)
            except Exception as ex:
                return False
            break
    return ret_val

def trans_cb(methods, params):
    try:
        if kernel_snooping_needed is True:
            ret = _is_ip_link_snoop_cmd_supported()
            if ret:
                return mcast_utils.handle_configs(params)
            else:
                return mcast_utils.handle_configs_fs(params)
        else:
            #Some snooping application is present and it will update
            #snoop status,mrouter port and routes.No update to kernel.
            return mcast_snoop.handle_snoop_updates(params)
    except Exception as ex:
        logging.exception(ex)
        return False

def sigterm_hdlr(signum, frame):
    global shutdown
    shutdown = True

def _mcast_set_attr_type():
    cps_utils.add_attr_type("igmp-mld-snooping/rt/routing/control-plane-protocols/igmp-snooping/vlans/vlan/static-l2-multicast-group/source-addr", "string")
    cps_utils.add_attr_type("igmp-mld-snooping/rt/routing/control-plane-protocols/mld-snooping/vlans/vlan/static-l2-multicast-group/source-addr", "string")

if __name__ == '__main__':

    shutdown = False

    # Install signal handlers.
    signal.signal(signal.SIGTERM, sigterm_hdlr)

    # Notify systemd: Daemon is ready
    systemd.daemon.notify("READY=1")

    #if file exists means kernel snooping is not needed and some snooping
    #application might be running
    if mcast_os.path.isfile(snoop_cfg_file) is True:
        ev.logging("BASE_MCAST_SNOOP",ev.DEBUG,"MCAST_SVC","","",0,"Kernel IGMP/MLD snooping not needed")
        kernel_snooping_needed = False

    # Wait for interface service being ready
    interface_key = cps.key_from_name('target', 'dell-base-if-cmn/if/interfaces/interface')

    ev.logging("BASE_MCAST_SNOOP",ev.DEBUG,"MCAST_SVC","","",0,"Wait for interface object to be ready")
    while cps.enabled(interface_key) == False:
        time.sleep(1)

    ev.logging("BASE_MCAST_SNOOP",ev.DEBUG,"MCAST_SVC","","",0,"Interface object ready")

    # Few IP address attributes are in binaries, these ip address are treated as string type.
    _mcast_set_attr_type()

    handle = cps.obj_init()
    d = {}

    d['transaction'] = trans_cb

    #get is supported only for kernel snooping
    if kernel_snooping_needed is True:
        d['get'] = get_cb
        for i in _igmp_keys.keys():
            if i.find('igmp-mld-snooping') == -1:
                continue
            cps.obj_register(handle, _igmp_keys[i], d)

        # Start thread for multicast groups polling
        mcast_utils.polling_thread.start()
    else:
        #Start VLAN monitor thread to disable snooping in kernel.
        monitor = threading.Thread(target=mcast_snoop.monitor_VLAN_interface_event, name="Snoop_VLAN_Monitor")
        monitor.setDaemon(True)
        monitor.start()

        #if kernel snooping is not used, then only few sets are supported
        # and no gets.
        #TODO: till application code gets commited, relax that part, otherwise it might fail
        d['get'] = mcast_snoop.snoop_get_cb

        for i in _igmp_keys.keys():
            if i.find('igmp-mld-snooping') == -1:
                continue
            cps.obj_register(handle, _igmp_keys[i], d)


    # wait until a signal is received
    while False == shutdown:
        signal.pause()

    systemd.daemon.notify("STOPPING=1")
    # cleanup code here
    # No need to specifically call sys.exit(0).
    # That's the default behavior in Python.

