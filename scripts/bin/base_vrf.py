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

import cps
import cps_object
import socket
import binascii

import dn_base_vrf_tool
import systemd.daemon
import event_log as ev

_mgmt_vrf_name = 'management'
_vrf_key = cps.key_from_name('target', 'vrf-mgmt/ni/network-instances/network-instance')
_vrf_intf_key = cps.key_from_name('target', 'vrf-mgmt/ni/if/interfaces/interface')
_vrf_incoming_svc_config_key = cps.key_from_name('target', 'vrf-firewall/ns-incoming-service')
_vrf_outgoing_svc_config_key = cps.key_from_name('target', 'vrf-firewall/ns-outgoing-service')

_protocol = {
    1: 'tcp',
    2: 'udp',
    3: 'icmp',
};
_action = {
    1: 'ACCEPT',
    2: 'DROP',
}
_af = {
    2 : 'ipv4',
    10 : 'ipv6',
}

def incoming_ip_svcs_attr(t):
    return 'vrf-firewall/ns-incoming-service/' + t
def outgoing_ip_svcs_attr(t):
    return 'vrf-firewall/ns-outgoing-service/' + t

def log_err(msg):
    ev.logging("BASE_VRF",ev.ERR,"VRF-CONFIG","","",0,msg)

def log_info(msg):
    ev.logging("BASE_VRF",ev.INFO,"VRF-CONFIG","","",0,msg)

def ip_ni_attr(t):
    return 'ni/network-instances/network-instance/' + t

def set_vrf_cb(methods, params):
    obj = cps_object.CPSObject(obj=params['change'])
    vrf_name = None

    vrf_name = ip_ni_attr('name')
    try:
        vrf_name = obj.get_attr_data(vrf_name)
    except ValueError as e:
        log_msg = 'Missing mandatory attribute ' + e.args[0]
        log_err(log_msg)
        return False

    if vrf_name != _mgmt_vrf_name:
        log_err('Configuration failed, only Management VRF is supported!')
        return False

    try:
        if params['operation'] == 'set':
            return False
        elif params['operation'] == 'create':
            log_msg = 'VRF config create - VRF Name:' + vrf_name
            log_info(log_msg)
            # When we support regular VRF, add the handler accordingly.
            if dn_base_vrf_tool.process_mgmt_vrf_config(True, vrf_name):
                return True
            log_msg = 'VRF config create failed - VRF Name:' + vrf_name
            log_err(log_msg)
        elif params['operation'] == 'delete':
            log_msg = 'VRF config delete - VRF Name:' + vrf_name
            log_info(log_msg)
            if dn_base_vrf_tool.process_mgmt_vrf_config(False, vrf_name):
                return True
            log_msg = 'VRF config delete failed - VRF Name:' + vrf_name
            log_err(log_msg)
    except Exception as e:
        log_msg = 'Faild to commit operation.' + e + 'params' + params
        log_err(log_msg)

    return False

def set_vrf_intf_cb(methods, params):
    obj = cps_object.CPSObject(obj=params['change'])
    if_name = None
    vrf_name = None

    if_name = 'if/interfaces/interface/name'
    vrf_name = 'ni/if/interfaces/interface/bind-ni-name'
    try:
        if_name = obj.get_attr_data(if_name)
        vrf_name = obj.get_attr_data(vrf_name)
    except ValueError as e:
        log_msg = 'Missing mandatory attribute ' + e.args[0]
        log_err(log_msg)
        return False
    if vrf_name != _mgmt_vrf_name:
        log_err('Configuration failed, only Management VRF is supported!')
        return False

    try:
        if params['operation'] == 'set':
            return False
        elif params['operation'] == 'create':
            log_msg = 'VRF ' + vrf_name + 'intf ' + if_name + ' add request'
            log_info(log_msg)
            # When we support regular VRF, add the handler accordingly.
            if dn_base_vrf_tool.process_mgmt_vrf_intf_config(True, if_name, vrf_name):
                return True
            log_msg = 'Failed to execute VRF ' + vrf_name + 'intf ' + if_name + ' add request'
            log_err(log_msg)
        elif params['operation'] == 'delete':
            log_msg = 'VRF ' + vrf_name + 'intf ' + if_name + ' del request'
            log_info(log_msg)
            if dn_base_vrf_tool.process_mgmt_vrf_intf_config(False, if_name, vrf_name):
                return True
            log_msg = 'Failed to execute VRF ' + vrf_name + 'intf ' + if_name + ' delete request'
            log_err(log_msg)
    except Exception as e:
        log_msg = 'Faild to commit operation.' + e + params
        log_err(log_msg)

    return False

def config_incoming_ip_svcs_cb(methods, params):
    obj = cps_object.CPSObject(obj=params['change'])

    vrf_name = incoming_ip_svcs_attr('ni-name')
    af = incoming_ip_svcs_attr('af')
    protocol = incoming_ip_svcs_attr('protocol')
    dst_port = incoming_ip_svcs_attr('dst-port')
    action = incoming_ip_svcs_attr('action')
    try:
        af = obj.get_attr_data(af)
        vrf_name = obj.get_attr_data(vrf_name)
        protocol = obj.get_attr_data(protocol)
        dst_port = obj.get_attr_data(dst_port)
        action = obj.get_attr_data(action)
    except ValueError as e:
        log_msg = 'Missing mandatory attribute ' + e.args[0]
        log_err(log_msg)
        return False

    operation = params['operation']

    try:
        if operation == 'set':
            return False
        elif operation == 'create':
            if dn_base_vrf_tool.process_incoming_ip_svcs_config(True,_af[af], _protocol[protocol],\
                                                       str(dst_port), _action[action], vrf_name):
                return True
        elif operation == 'delete':
            if dn_base_vrf_tool.process_incoming_ip_svcs_config(False,_af[af], _protocol[protocol],\
                                                       str(dst_port), _action[action], vrf_name):
                return True
    except Exception as e:
        log_msg = 'Faild to commit operation.' + e + params
        log_err(log_msg)
        return False

    log_msg = 'Failed for Operation:' + operation + ' VRF:' + vrf_name + ' family:'\
              + _af[af] + ' protocol:' + _protocol[protocol] + ' dst-port:'\
              + str(dst_port) + ' action:' + _action[action]
    log_err(log_msg)
    return False

def _create_ip_from_attr(addr, iptype):
    addr = binascii.unhexlify(addr)
    af = socket.AF_INET
    if _af[iptype] == 'ipv6':
        af = socket.AF_INET6
    addr = socket.inet_ntop(af, addr)
    return addr

def config_outgoing_ip_svcs_cb(methods, params):
    obj = cps_object.CPSObject(obj=params['change'])

    vrf_name = outgoing_ip_svcs_attr('ni-name')
    af = outgoing_ip_svcs_attr('af')
    public_ip = outgoing_ip_svcs_attr('public-ip')
    protocol = outgoing_ip_svcs_attr('protocol')
    public_port = outgoing_ip_svcs_attr('public-port')
    try:
        af = obj.get_attr_data(af)
        vrf_name = obj.get_attr_data(vrf_name)
        public_ip_data = obj.get_attr_data(public_ip)
        public_ip = _create_ip_from_attr(public_ip_data,af)
        protocol = obj.get_attr_data(protocol)
        public_port = obj.get_attr_data(public_port)

    except ValueError as e:
        log_msg = 'Missing mandatory attribute ' + e.args[0]
        log_err(log_msg)
        return False

    if vrf_name != _mgmt_vrf_name:
        log_err('Configuration failed, only Management VRF is supported!')
        return False

    operation = params['operation']

    log_msg = 'Operation:' + operation + ' VRF:' + vrf_name + ' family:'\
              + _af[af] + ' public-ip' + public_ip + ' protocol:' + _protocol[protocol] + ' public-port:'\
              + str(public_port)
    log_info(log_msg)
    try:
        if operation == 'set':
            return False
        elif operation == 'create':
            ret_val, private_port = dn_base_vrf_tool.process_outgoing_ip_svcs_config(True,\
                                    _af[af], public_ip, _protocol[protocol],\
                                    str(public_port), vrf_name)
            veth_mgmt_ip = None
            family = socket.AF_INET
            if _af[af] == 'ipv4':
                veth_mgmt_ip = dn_base_vrf_tool.veth_management_intf_ip
            else:
                veth_mgmt_ip = dn_base_vrf_tool.veth_management_intf_ip6
                family = socket.AF_INET6
            if ret_val is True:
                veth_mgmt_ip = binascii.hexlify(socket.inet_pton(family, veth_mgmt_ip))
                cps_obj = cps_object.CPSObject(module='vrf-firewall/ns-outgoing-service', qual='target',
                                           data={outgoing_ip_svcs_attr('ni-name'):vrf_name,
                                           outgoing_ip_svcs_attr('af'):af,
                                           outgoing_ip_svcs_attr('public-ip'):public_ip_data,
                                           outgoing_ip_svcs_attr('protocol'):protocol,
                                           outgoing_ip_svcs_attr('public-port'):public_port,
                                           outgoing_ip_svcs_attr('private-ip'):veth_mgmt_ip,
                                           outgoing_ip_svcs_attr('private-port'):private_port
                                           })
                params['change'] = cps_obj.get()
                return True
        elif operation == 'delete':
            ret_val, private_port = dn_base_vrf_tool.process_outgoing_ip_svcs_config(False,\
                                    _af[af], public_ip, _protocol[protocol],\
                                    str(public_port), vrf_name)
            if ret_val is True:
                return True
    except Exception as e:
        log_msg = 'Faild to commit operation.' + e + params
        log_err(log_msg)
        return False

    log_msg = 'Operation:' + operation + ' VRF:' + vrf_name + ' family:'\
              + _af[af] + ' public-ip' + public_ip + ' protocol:' + _protocol[protocol] + ' public-port:'\
              + str(public_port)
    log_err(log_msg)
    return False


def sigterm_hdlr(signum, frame):
    global shutdown
    shutdown = True

if __name__ == '__main__':

    shutdown = False

    # Install signal handlers.
    import signal
    signal.signal(signal.SIGTERM, sigterm_hdlr)

    handle = cps.obj_init()

    d = {}
    d['transaction'] = set_vrf_cb
    cps.obj_register(handle, _vrf_key, d)

    d = {}
    d['transaction'] = set_vrf_intf_cb
    cps.obj_register(handle, _vrf_intf_key, d)

    d = {}
    d['transaction'] = config_incoming_ip_svcs_cb
    cps.obj_register(handle, _vrf_incoming_svc_config_key, d)

    d = {}
    d['transaction'] = config_outgoing_ip_svcs_cb
    cps.obj_register(handle, _vrf_outgoing_svc_config_key, d)

    log_msg = 'CPS IP VRF registration done'
    log_info(log_msg)

    # Notify systemd: Daemon is ready
    systemd.daemon.notify("READY=1")

    # wait until a signal is received
    while False == shutdown:
        signal.pause()

    systemd.daemon.notify("STOPPING=1")
    # cleanup code here
    # No need to specifically call sys.exit(0).
    # That's the default behavior in Python.
