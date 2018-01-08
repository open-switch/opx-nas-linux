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
import platform
import cps
import cps_object
import systemd.daemon
import dn_base_mcast_snoop_utils as mcast_utils
import time
import event_log as ev
import logging

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

_jessie_kernel_version = "3.16"
_stretch_kernel_version = "4.9"

def _is_ip_link_snoop_cmd_supported():
    ret = False
    version = platform.uname()[2]  # The third element of uname information is version
    if _jessie_kernel_version in version:
        ret = False
    elif _stretch_kernel_version in version:
       ret = True
    return ret

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
        ret = _is_ip_link_snoop_cmd_supported()
        if ret:
            return mcast_utils.handle_configs(params)
        else:
            return mcast_utils.handle_configs_fs(params)
    except Exception as ex:
        logging.exception(ex)
        return False

def sigterm_hdlr(signum, frame):
    global shutdown
    shutdown = True

if __name__ == '__main__':

    shutdown = False

    # Install signal handlers.
    signal.signal(signal.SIGTERM, sigterm_hdlr)

    # Notify systemd: Daemon is ready
    systemd.daemon.notify("READY=1")

    # Wait for interface service being ready
    interface_key = cps.key_from_name('target', 'dell-base-if-cmn/if/interfaces/interface')

    ev.logging("BASE_MCAST_SNOOP",ev.DEBUG,"MCAST_SVC","","",0,"Wait for interface object to be ready")
    while cps.enabled(interface_key) == False:
        time.sleep(1)

    ev.logging("BASE_MCAST_SNOOP",ev.DEBUG,"MCAST_SVC","","",0,"Interface object ready")
    handle = cps.obj_init()
    d = {}
    d['get'] = get_cb
    d['transaction'] = trans_cb

    for i in _igmp_keys.keys():
        if i.find('igmp-mld-snooping') == -1:
            continue
        cps.obj_register(handle, _igmp_keys[i], d)

    # Start thread for multicast groups polling
    mcast_utils.polling_thread.start()

    # wait until a signal is received
    while False == shutdown:
        signal.pause()

    systemd.daemon.notify("STOPPING=1")
    # cleanup code here
    # No need to specifically call sys.exit(0).
    # That's the default behavior in Python.

