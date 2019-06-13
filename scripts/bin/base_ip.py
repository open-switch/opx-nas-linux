#!/usr/bin/python
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

import cps
import subprocess
import sys
import cps_object
import cps_utils
import socket
import binascii
import ifindex_utils

import dn_base_ip_tool
import systemd.daemon
import dn_base_ip_tbl_tool
import dn_base_ipsec_utils
import threading
from dn_base_ip_tool import log_err, log_info

iplink_cmd = '/sbin/ip'

_keys = {
    'base-ip/ipv4': cps.key_from_name('target', 'base-ip/ipv4'),
    'base-ip/ipv6': cps.key_from_name('target', 'base-ip/ipv6'),
    cps.key_from_name('target', 'base-ip/ipv4'): 'base-ip/ipv4',
    cps.key_from_name('target', 'base-ip/ipv6'): 'base-ip/ipv6',
}

_ip_unreach_key = cps.key_from_name('target', 'os-icmp-cfg/ip-unreachables-config')
_proxy_arp_key = cps.key_from_name('target', 'base-route/proxy-arp-config')
_ip_af = {
    2 : 'ipv4',
    10 : 'ipv6',
}

_ip_neigh_flush_key = cps.key_from_name('target', 'base-neighbor/flush')
_ipv6_enable_status = {}

def get_next_index(d):
    count = 0
    while True:
        if str(count) not in d:
            return count
        count += 1

def _get_af_from_name(name):
    type = 'ipv4'
    if name.find(type) == -1:
        type = 'ipv6'
    return type


def _get_obj_name(obj):
    return _keys[obj.get_key()]


def _get_af_from_obj(obj):
    return _get_af_from_name(_get_obj_name(obj))


def _get_proc_fwd_entry(dev, iptype):
    return ['proc', 'sys', 'net', iptype, 'conf', dev, 'forwarding']

def _get_proc_disable_ipv6_entry(dev):
    return ['proc', 'sys', 'net', 'ipv6', 'conf', dev, 'disable_ipv6']

def _get_proc_ipv6_autoconf_entry(dev):
    return ['proc', 'sys', 'net', 'ipv6', 'conf', dev, 'autoconf']

def _get_proc_ipv6_accept_dad_entry(dev):
    return ['proc', 'sys', 'net', 'ipv6', 'conf', dev, 'accept_dad']

def _get_proc_ipv4_arp_accept_entry(dev):
    return ['proc', 'sys', 'net', 'ipv4', 'conf', dev, 'arp_accept']

def _get_proc_variable(path):
    try:
        path = '/'.join(path)
        with open('/' + path, 'r') as f:
            data = f.read()
        return int(data)
    except:
        print "Error reading ", path
        return -1


def _set_proc_variable(path, value):
    try:
        path = '/'.join(path)
        with open('/' + path, 'w') as f:
            f.write(str(value))
    except:
        print "Error writing ", path
        return -1


def create_obj_from_line(obj_type, ifix, ifname, vrfname):

    af = _get_af_from_name(obj_type)

    o = cps_object.CPSObject(obj_type, data={'base-ip/' + af + '/vrf-id': 0,
                                             'base-ip/' + af + '/ifindex': ifix,
                                             'base-ip/' + af + '/name': ifname,
                                             'base-ip/' + af + '/vrf-name': vrfname,
                                             })
    return o


def _get_key_from_obj(obj):
    af = _get_af_from_obj(obj)

    str_index = 'base-ip/' + af + '/ifindex'
    str_name = 'base-ip/' + af + '/name'

    name = None

    try:
        index = obj.get_attr_data(str_index)
        name = ifindex_utils.if_indextoname(index)
    except:
        pass
    if name is None:
        try:
            name = obj.get_attr_data(str_name)
        except:
            pass
    return name


def _ip_line_type_valid(af, ip):

    if af == 'ipv4' and ip[0] == 'inet':
        return True
    if af == 'ipv6' and ip[0] == 'inet6':
        return True
    return False


def process_ip_line(af, d, ip):
    search_str = None

    _srch = {'ipv4': 'inet', 'ipv6': 'inet6'}
    _af = {'ipv4': socket.AF_INET, 'ipv6': socket.AF_INET6}

    if af not in _srch:
        return

    if ip[0] == _srch[af]:
        try:
            addr = ip[1]
            prefix = ip[2]

            addr = binascii.hexlify(socket.inet_pton(_af[af], addr))
            prefix = int(prefix)

            d['base-ip/' + af + '/address/ip'] = cps_object.types.to_data(
                'base-ip/' + af + '/address/ip', addr)
            d['base-ip/' + af + '/address/prefix-length'] = cps_object.types.to_data(
                'base-ip/' + af + '/address/prefix-length', prefix)

        except:
            print "Unable to convert address ", header
            pass


def add_ip_info(af, o, ip):
    if af is None:
        return

    if 'base-ip/' + af + '/address' not in o.get()['data']:
        o.get()['data']['base-ip/' + af + '/address'] = {}

    _v = o.get()['data']['base-ip/' + af + '/address']

    d = {}
    next_index = get_next_index(_v)
    process_ip_line(af, d, ip)
    if (len(d)) > 0:
        _v[str(next_index)] = d


def _get_ip_objs(filt, resp):
    af = _get_af_from_obj(filt)
    name = _get_key_from_obj(filt)

    vrf_name = None
    try:
        vrf_name = filt.get_attr_data('base-ip/' + af + '/vrf-name')
    except:
        # VRF-name is optional attribute.
        pass
    if (vrf_name is None) and (name is not None):
        vrf_name = 'default'

    lst = dn_base_ip_tool.get_if_details(vrf_name, name)

    for _if in lst:
        o = create_obj_from_line('base-ip/' + af, _if.ifix, _if.ifname, _if.vrf_name)

        name = o.get_attr_data('base-ip/' + af + '/name')
        if not filt.key_compare(
            {'base-ip/' + af + '/name': name,
                               'base-ip/' + af + '/ifindex': o.get_attr_data('base-ip/' + af + '/ifindex')}):
            continue

        fwd = _get_proc_variable(
            _get_proc_fwd_entry(o.get_attr_data('base-ip/' + af + '/name'), af))
        if fwd == -1:
            fwd = 0
        o.add_attr('base-ip/' + af + '/forwarding', fwd)

        if af == 'ipv6':
            enabled = _ipv6_enable_status.get(name, None)
            log_msg = 'IPv6 intf-name:' + name + ' enabled status in DB:' + str(enabled)
            log_info(log_msg)
            if enabled is None:
                enabled = 1
                disable_ipv6 = _get_proc_variable(_get_proc_disable_ipv6_entry(name))
                if disable_ipv6 == -1 or disable_ipv6 == 1:
                    enabled = 0
            o.add_attr('base-ip/' + af + '/enabled', enabled)
            autoconf = _get_proc_variable(_get_proc_ipv6_autoconf_entry(name))
            if autoconf == -1 or autoconf == 0:
                autoconf = 0
            o.add_attr('base-ip/' + af + '/autoconf', autoconf)
            accept_dad = _get_proc_variable(_get_proc_ipv6_accept_dad_entry(name))
            if accept_dad != 1 and accept_dad != -1:
                o.add_attr('base-ip/' + af + '/accept-dad', accept_dad + 1)

            log_msg = 'IPv6 intf-name:' + name + ' fwd status:' + str(fwd) + ' ipv6 status:' \
                       + str(enabled) + 'auto conf:' + str(autoconf) + 'accept_dad:' + str(accept_dad)
            log_info(log_msg)
        else:
            log_msg = 'IPv4 intf-name:' + name + ' fwd status:' + str(fwd)
            log_info(log_msg)

        for _ip in _if.ip:
            add_ip_info(af, o, _ip)
        resp.append(o.get())

    return True



def get_cb(methods, params):
    obj = cps_object.CPSObject(obj=params['filter'])
    resp = params['list']

    if obj.get_key() == _keys['base-ip/ipv4'] or obj.get_key() == _keys['base-ip/ipv6']:
        return _get_ip_objs(obj, resp)
    return False


def trans_cb(methods, params):
    obj = cps_object.CPSObject(obj=params['change'])
    af = _get_af_from_obj(obj)

    name = _get_key_from_obj(obj)
    if name is None:
        print "Missing keys for request ", obj
        return False

    vrf_name = 'default'
    try:
       vrf_name = obj.get_attr_data('base-ip/' + af + '/vrf-name')
    except:
       # VRF-name is optional attribute.
       pass

    addr = ""

    try:
        if params['operation'] == 'set' and obj.get_key() == _keys['base-ip/' + af]:
            if af == 'ipv6':
                try:
                    enabled = obj.get_attr_data('base-ip/' + af + '/enabled')
                    if enabled == 1:
                        disable_ipv6 = 0
                    else:
                        disable_ipv6 = 1
                    _ipv6_enable_status[name] = enabled
                    if vrf_name == 'default':
                        ret_val = _set_proc_variable(_get_proc_disable_ipv6_entry(name),\
                                                     str(disable_ipv6))
                    else:
                        ret_val = dn_base_ip_tool.disable_ipv6_config(name, str(disable_ipv6), vrf_name)

                    log_msg = 'CPS set for VRF:' + vrf_name + 'intf-name:' + name + ' ipv6 status:' +\
                               str(enabled) + 'ret_val:' + str(ret_val)
                    log_info(log_msg)
                    if ret_val == -1:
                        return False
                except:
                    pass
                try:
                    autoconf = obj.get_attr_data('base-ip/' + af + '/autoconf')
                    if vrf_name == 'default':
                        ret_val = _set_proc_variable(_get_proc_ipv6_autoconf_entry(name), str(autoconf))
                    else:
                        ret_val = dn_base_ip_tool.ipv6_autoconf_config(name, autoconf, vrf_name)
                    log_msg = 'CPS set for VRF:' + vrf_name + 'intf-name:' + name + ' ipv6 auto conf status:'\
                              + str(autoconf) + 'ret_val:' + str(ret_val)
                    log_info(log_msg)
                    if ret_val == -1:
                        return False
                except:
                    pass
                try:
                    accept_dad = obj.get_attr_data('base-ip/' + af + '/accept-dad')
                    # Check the valid enum values
                    if accept_dad not in [1,2,3]:
                        return False
                    # CPS enum starts from 1 but kernel enum starts from 0
                    accept_dad = accept_dad - 1
                    if vrf_name == 'default':
                        ret_val = _set_proc_variable(_get_proc_ipv6_accept_dad_entry(name), str(accept_dad))
                    else:
                        ret_val = dn_base_ip_tool.ipv6_accept_dad_config(name, str(accept_dad), vrf_name)
                    log_msg = 'CPS set for VRF:' + vrf_name + 'intf-name:' + name + ' ipv6 accept DAD status:'\
                              + str(accept_dad) + 'ret_val:' + str(ret_val)
                    log_info(log_msg)
                    if ret_val == -1:
                        return False
                except:
                    pass
            elif af == 'ipv4':
                try:
                    arp_accept = obj.get_attr_data('base-ip/' + af + '/arp-accept')
                    if arp_accept == 1:
                        arp_accept = 0
                    else:
                        arp_accept = 1

                    if vrf_name == 'default':
                        ret_val = _set_proc_variable(_get_proc_ipv4_arp_accept_entry(name), str(arp_accept))
                    else:
                        ret_val = dn_base_ip_tool.ipv4_arp_accept_config(name, str(arp_accept), vrf_name)
                    log_msg = 'CPS set for VRF:' + vrf_name + 'intf-name:' + name + ' ipv4 arp accept status:'\
                              + str(arp_accept) + 'ret_val:' + str(ret_val)
                    log_info(log_msg)
                    if ret_val == -1:
                        return False
                except:
                    pass

            try:
                fwd = obj.get_attr_data('base-ip/' + af + '/forwarding')
                if vrf_name == 'default':
                    ret_val = _set_proc_variable(_get_proc_fwd_entry(name, af), str(fwd))
                else:
                    ret_val = dn_base_ip_tool.ip_forwarding_config(af, name, str(fwd), vrf_name)
                log_msg = 'CPS set for VRF:' + vrf_name + 'intf-name:' + name + ' fwd status:' + str(fwd)\
                          + 'ret_val:' + str(ret_val)
                log_info(log_msg)
                if ret_val == -1:
                    return False
            except:
                pass
            return True

    except Exception as e:
        log_err("Faild to commit operation exception:%s params:%s"% (e, params))

    return False

def ip_unreach_attr(t):
    return 'os-icmp-cfg/ip-unreachables-config/input/' + t

def set_ip_unreach_cb(methods, params):
    obj = cps_object.CPSObject(obj=params['change'])

    if params['operation'] != 'rpc':
        log_err('oper is not RPC')
        return False

    operation = ip_unreach_attr('operation')
    enable = ip_unreach_attr('enable')
    af = ip_unreach_attr('af')
    ifname = ip_unreach_attr('ifname')
    vrf_name = ip_unreach_attr('vrf-name')

    dev = None
    vrf = None

    try:
        operation = obj.get_attr_data(operation)
        af = obj.get_attr_data(af)
        enable = obj.get_attr_data(enable)
    except ValueError as e:
        log_msg = 'Missing mandatory attribute ' + e.args[0]
        log_err(log_msg)
        return False
    try:
        vrf = obj.get_attr_data(vrf_name)
    except:
        pass
        vrf = 'default'

    # Operation types
    #BASE_CMN_OPERATION_TYPE_CREATE=1
    #BASE_CMN_OPERATION_TYPE_DELETE=2
    #BASE_CMN_OPERATION_TYPE_UPDATE=3
    is_add = True;
    if operation == 3:
        log_msg = 'Update operation is not supported!'
        log_err(log_msg)
        return False
    elif operation == 2:
       is_add = False;

    if af != socket.AF_INET and af != socket.AF_INET6:
        log_msg = 'Invalid address family' + str(af)
        log_err(log_msg)
        return False

    try:
        dev = obj.get_attr_data(ifname)
    except:
        pass
        log_info('Ifname is not present in the object')

    if dn_base_ip_tbl_tool.ip_tables_unreach_rule(vrf, is_add, enable, af, dev):
        return True
    log_msg = 'Failed to execute IP unreachable request ' + str(is_add) + str(af) \
              + 'enable' + str(enable) + 'ifname' + ifname
    log_err(log_msg)

    return False

def ip_neigh_flush_attr(t):
    return 'base-neighbor/flush/input/' + t

def _create_neigh_flush_ip_and_prefix_from_attr(ip_addr, prefix_len, af):
    addr = binascii.unhexlify(ip_addr)
    addr = socket.inet_ntop(af, addr)
    if prefix_len is not None:
        addr = addr + '/' + str(prefix_len)
    return addr

def _nbr_flush_handle(vrf_name, af, if_name):
    obj = cps_object.CPSObject(module='base-route/nbr-flush')
    obj.add_attr("base-route/nbr-flush/input/vrf-name", str(vrf_name))
    obj.add_attr("base-route/nbr-flush/input/af", af)
    # Incase of leaked VRF neigh flush, this 'dev' wont be present
    # in the leaked VRF and hence flush_ip_neigh is expected to fail.
    if if_name is not None:
        obj.add_attr("base-route/nbr-flush/input/ifname", if_name)
    l = []
    tr_obj = {'change': obj.get(), 'operation': 'rpc'}
    l.append(tr_obj)
    return cps.transaction(l)

def flush_ip_neigh_cb(methods, params):
    obj = cps_object.CPSObject(obj=params['change'])

    if params['operation'] != 'rpc':
        log_err('oper is not RPC')
        return False

    vrf_name = ip_neigh_flush_attr('vrf-name')
    af = ip_neigh_flush_attr('af')
    ifname = ip_neigh_flush_attr('ifname')
    ip_addr = ip_neigh_flush_attr('ip')
    prefix_len = ip_neigh_flush_attr('prefix-len')

    dev = None

    try:
        vrf_name = obj.get_attr_data(vrf_name)
    except ValueError as e:
        log_msg = 'Missing mandatory attribute ' + e.args[0]
        log_err(log_msg)
        return False

    try:
        af = obj.get_attr_data(af)
    except:
        pass
        af = socket.AF_INET
        log_info('Address family is not present in the object')

    if af != socket.AF_INET and af != socket.AF_INET6:
        log_msg = 'Invalid address family' + str(af)
        log_err(log_msg)
        return False

    try:
        dev = obj.get_attr_data(ifname)
    except:
        pass
        dev = None
        log_info('Ifname is not present in the object')

    try:
        ip_addr = obj.get_attr_data(ip_addr)
    except:
        pass
        ip_addr = None

    try:
        prefix_len = obj.get_attr_data(prefix_len)
    except:
        pass
        prefix_len = None

    addr = None
    if ip_addr is not None:
        addr = _create_neigh_flush_ip_and_prefix_from_attr(ip_addr, prefix_len, af)

    log_msg = 'IP neigh flush request vrf-name:' + str(vrf_name)\
              + ' af:' + str(af) + ' ifname:' + str(dev)\
              + ' to addr:' + str(addr)
    log_info(log_msg)
    if dev is not None:
        for ifname in dev:
            if dn_base_ip_tool.is_intf_exist_in_vrf(str(vrf_name), ifname):
                val = dn_base_ip_tool.flush_ip_neigh(_ip_af[af], ifname, addr, str(vrf_name))
            else:
                val = _nbr_flush_handle(str(vrf_name), af, ifname)
    else:
        val = dn_base_ip_tool.flush_ip_neigh(_ip_af[af], dev, addr, str(vrf_name))
        if val is False:
            log_err("IP neigh flush on VRF:%s af:%s addr:%s failed"% (str(vrf_name),\
                                                                      str(af), str(addr)))
        val = _nbr_flush_handle(str(vrf_name), af, dev)
    return val

def proxy_arp_attr(t):
    return 'base-route/proxy-arp-config/' + t

def set_proxy_arp_cb(methods, params):
    obj = cps_object.CPSObject(obj=params['change'])

    vrf_name = proxy_arp_attr('vrf-name')
    ifname = proxy_arp_attr('ifname')

    vrf = None
    dev = None

    try:
        vrf = obj.get_attr_data(vrf_name)
        dev = obj.get_attr_data(ifname)
    except ValueError as e:
        log_msg = 'Missing mandatory attribute ' + e.args[0]
        log_err(log_msg)
        return False

    log_info("Proxy ARP configuration on VRF:%s intf:%s operation:%s"% (vrf, dev, params['operation']))
    try:
        if params['operation'] == 'create':
            if dn_base_ip_tool.proxy_arp_config(dev, 1, vrf):
                return True
        if params['operation'] == 'delete':
            if dn_base_ip_tool.proxy_arp_config(dev, 0, vrf):
                return True
    except Exception as e:
        log_err("Faild to commit operation exception:%s params:%s"% (e, params))

    log_err("Proxy ARP configuration failed on VRF:%s intf:%s operation:%s"% (vrf, dev, params['operation']))
    return False


def sigterm_hdlr(signum, frame):
    global shutdown
    shutdown = True

if __name__ == '__main__':
    shutdown = False

    # Install signal handlers.
    import signal
    signal.signal(signal.SIGTERM, sigterm_hdlr)

    if len(sys.argv) > 1:
        l = []
        _get_ip_objs(cps_object.CPSObject('base-ip/ipv4'), l)
        for i in l:
            cps_utils.print_obj(i)
        sys.exit(1)

    handle = cps.obj_init()
    d = {}
    d['get'] = get_cb
    d['transaction'] = trans_cb

    for i in _keys.keys():
        if i.find('base-ip') == -1:
            continue
        cps.obj_register(handle, _keys[i], d)

    # IPSec Object registration
    dn_base_ipsec_utils.obj_reg()

    # Set IPSec Authentication and Encryption keys type as string
    dn_base_ipsec_utils.add_attr_type()

    d = {}
    d['transaction'] = set_ip_unreach_cb
    cps.obj_register(handle, _ip_unreach_key, d)

    log_msg = 'CPS IP unreachable registration done'
    log_info(log_msg)

    d = {}
    d['transaction'] = flush_ip_neigh_cb
    cps.obj_register(handle, _ip_neigh_flush_key, d)

    log_msg = 'CPS IP neighbor flush registration done'
    log_info(log_msg)

    d = {}
    d['transaction'] = set_proxy_arp_cb
    cps.obj_register(handle, _proxy_arp_key, d)

    log_msg = 'CPS Proxy ARP registration done'
    log_info(log_msg)

    #Start interface event handle thread to program LLA into the kernel.
    lla_cfg_thread = threading.Thread(target=dn_base_ip_tool.handle_interface_event_for_lla_cfg,\
                                      name="IPv6_Intf_LLA_Cfg")
    lla_cfg_thread.setDaemon(True)
    lla_cfg_thread.start()

    #Start ipv6 address event handle thread to handle the DAD failures
    lla_cfg_thread = threading.Thread(target=dn_base_ip_tool.handle_addr_event,\
                                      name="IPv6_Addr_Dad_Handle")
    lla_cfg_thread.setDaemon(True)
    lla_cfg_thread.start()


    # Notify systemd: Daemon is ready
    systemd.daemon.notify("READY=1")

    # wait until a signal is received
    while False == shutdown:
        signal.pause()

    systemd.daemon.notify("STOPPING=1")
    # cleanup code here
    # No need to specifically call sys.exit(0).
    # That's the default behavior in Python.
