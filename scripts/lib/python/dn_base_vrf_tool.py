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

"""This module provides a OPX base python API constructed
   around the ip utility"""

import subprocess
import os
import socket
import event_log as ev
from shutil import rmtree
import nas_mac_addr_utils as ma

_default_vrf_name = 'default'
_mgmt_vrf_name = 'management'
iplink_cmd = '/sbin/ip'
# 127.<100+x>.100.1 -> x gets next available id for connectivity to default VRF
veth_default_intf_ip_prefix = '127.'
veth_default_intf_ip_suffix = '.100.1'
veth_default_intf_ip_pref_len = '24'

# 127.<100+x>.100.2 -> x gets next available id for connectivity to non-default VRF
veth_non_default_intf_ip_prefix = '127.'
veth_non_default_intf_ip_suffix = '.100.2'
veth_non_default_intf_ip_pref_len = '24'

# fda5:74c8:b79e:4:<100+x>::1 -> x gets next available id for connectivity to default VRF
veth_default_intf_ip6_prefix = 'fda5:74c8:b79e:4:'
veth_default_intf_ip6_suffix = '::1'
veth_default_intf_ip6_pref_len = '64'
rej_rule_mark_value = 255

# fda5:74c8:b79e:4:<100+x>::2 -> x gets next available id for connectivity to non=default VRF
veth_non_default_intf_ip6_prefix = 'fda5:74c8:b79e:4:'
veth_non_default_intf_ip6_suffix = '::2'
veth_non_default_intf_ip6_pref_len = '64'

_outgoing_ip_svcs_map = {}
# Use the private port range for internal NAT translations to handle the remote requests (e.g. SSH)
# coming via non-default VRF in the default VRF.
_start_private_port = 62000
_end_private_port = 65000

_vrf_sub_net_map = {}
_vrf_name_to_id = {}
_start_vrf_sub_net_val = 100
_end_vrf_sub_net_val = 200

def log_err(msg):
    ev.logging("BASE_VRF",ev.ERR,"VRF-CONFIG","","",0,msg)

def log_info(msg):
    ev.logging("BASE_VRF",ev.INFO,"VRF-CONFIG","","",0,msg)

def run_command(cmd, response, log_fail = True):
    """Method to run a command in shell"""

    if len(response) > 0:
        del response[:]

    p = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    output = p.communicate()[0]
    for line in output.splitlines():
        # If dump was interrupted during kernel info. dump, ignore it,
        # App has to do get again for the latest information.
        if 'Dump was interrupted and may be inconsistent.' in line:
            continue
        response.append(line.rstrip())
    if log_fail and p.returncode != 0:
        log_err('Failed CMD: %s' % ' '.join(cmd))
        for msg in response:
            log_err('* ' + msg)

    return p.returncode

def process_vrf_ip_nat_config(is_add, vrf_name, if_name, iptables):
    res = []
    operation = None
    if is_add:
        operation = '-A'
    else:
        operation = '-D'

    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptables, '-t', 'nat', operation, 'POSTROUTING',\
          '-o', if_name, '-j', 'MASQUERADE']
    if run_command(cmd, res) != 0:
        return False

    return True

def process_veth_config(is_add, vrf_name, def_ip, def_ip_pref_len, non_def_ip, non_def_ip_pref_len,\
                        def_ip6, def_ip6_pref_len, non_def_ip6, non_def_ip6_pref_len):
    # Create vEth pair for comunication between default and
    # non-default (e.g management) namespaces
    res = []
    vrf_id = None
    vrf_id = _vrf_name_to_id.get(vrf_name, None)
    if vrf_id is None:
        return False

    if is_add is False:
        cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'ip', 'link',\
              'delete', 'dev', 'veth-nsid'+str(vrf_id)]
        if run_command(cmd, res) != 0:
            return False
        return True

    cmd = [iplink_cmd, 'link', 'add', 'name', 'vdef-nsid' + str(vrf_id), 'type',\
          'veth', 'peer', 'name', 'veth-nsid' + str(vrf_id)]
    if run_command(cmd, res) != 0:
        return False

    cmd = ['sysctl', '-w', 'net.ipv4.conf.vdef-nsid'+str(vrf_id)+'.route_localnet=1']
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'link', 'set', 'vdef-nsid'+str(vrf_id), 'up']
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'link', 'set', 'dev', 'veth-nsid'+str(vrf_id), 'netns', vrf_name]
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'ip', 'link', 'set', 'veth-nsid'+str(vrf_id), 'up']
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'address', 'add', def_ip + '/' + \
          def_ip_pref_len, 'dev', 'vdef-nsid'+str(vrf_id)]
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'ip', 'address', 'add',\
          non_def_ip + '/' + non_def_ip_pref_len,\
          'dev', 'veth-nsid' + str(vrf_id)]
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'address', 'add', def_ip6 + '/' + \
          def_ip6_pref_len, 'dev', 'vdef-nsid'+str(vrf_id)]
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'ip', 'address', 'add',\
          non_def_ip6 + '/' + non_def_ip6_pref_len,\
          'dev', 'veth-nsid' + str(vrf_id)]
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'sysctl', '-w',\
          'net.ipv4.conf.veth-nsid'+str(vrf_id)+'.route_localnet=1']
    if run_command(cmd, res) != 0:
        return False

    return True


def process_pkt_reject_rule(is_add, vrf_name):
    ipt_action = '-I' if is_add else '-D'
    chain_list = ['INPUT']
    if vrf_name == 'default':
        cmd_prefix = []
    else:
        cmd_prefix = [iplink_cmd, 'netns', 'exec', vrf_name]
        if vrf_name == 'management':
            chain_list.append('FORWARD')
    for iptable in ['iptables', 'ip6tables']:
        for chain in chain_list:
            res = []
            cmd = cmd_prefix + [iptable, ipt_action, chain, '-m', 'mark', '--mark',
                   str(rej_rule_mark_value), '-j', 'REJECT']
            if run_command(cmd, res) != 0:
                log_err('Error running: %s' % ' '.join(cmd))
                return False
    return True

def process_vrf_config(is_add, vrf_name, vrf_id):
    res = []
    # Network namespace deletion
    ip_svcs_folder = '/etc/netns/'+vrf_name
    if is_add is False:
        try:
            # If this is the last VRF to delete, remove the default soft link
            if len(_vrf_name_to_id) == 1:
                os.unlink('/var/run/netns/default')
            rmtree(ip_svcs_folder, ignore_errors=False, onerror=None)
        except:
            pass

        sub_net_val = None
        sub_net_val = _vrf_sub_net_map.get(vrf_name, None)
        if sub_net_val is not None:
            ret_val, sub_net_val = ip_svcs_subnet_setup(False, vrf_name)
            if ret_val is False:
                return False

        vrf_id = None
        vrf_id = _vrf_name_to_id.get(vrf_name, None)
        if vrf_id is None:
            return False
        vrf_id = _vrf_name_to_id.pop(vrf_name, None)
        if vrf_id is None:
            return False
        process_pkt_reject_rule(False, vrf_name)
        cmd = [iplink_cmd, 'netns', 'delete', vrf_name]
        if run_command(cmd, res) != 0:
            return False
        return True

    # Network namespace addition and vEth pair creation
    # between default and mgmt namespaces.
    cmd = [iplink_cmd, 'netns', 'add', vrf_name]
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'set', vrf_name, str(vrf_id)]
    if run_command(cmd, res) != 0:
        return False

    # Create the default namespace soft link
    # ln -s /proc/1/ns/net /var/run/netns/default
    _vrf_name_to_id[vrf_name] = vrf_id
    try:
        if len(_vrf_name_to_id) == 1:
            os.symlink('/proc/1/ns/net', '/var/run/netns/default')
        os.makedirs(ip_svcs_folder, 0755)
    except:
        pass
    # Enable IPv6 forwarding on all interface for the ip6tables to work.
    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'sysctl', '-w',\
          'net.ipv6.conf.all.forwarding=1']
    if run_command(cmd, res) != 0:
        return False
    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'ip', 'link', 'set', 'lo', 'up']
    if run_command(cmd, res) != 0:
        return False

    cmd = ['ifconfig', 'lo', '127.0.0.1/16']
    run_command(cmd, res)

    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'ifconfig', 'lo', '127.0.0.1/16']
    run_command(cmd, res)

    ip_tables = { 'iptables', 'ip6tables' }
    for iptable in ip_tables:
        cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptable, '-t', 'nat', '-N', 'VRF']
        if run_command(cmd, res) != 0:
            return False

    if not process_pkt_reject_rule(True, vrf_name):
        return False

    return True

def process_vrf_intf_config(is_add, if_name, vrf_name):
    res = []
    if_index = 0
    v_mac_str = None
    # Remove VRF association from L3 intf
    if is_add is False:
        # For intf removal from default VRF case, no action required
        # since there is no dedicated router interface (MAC-VLAN interface).
        if vrf_name == _default_vrf_name:
            return (True,if_name,if_index, v_mac_str)

        if vrf_name != _mgmt_vrf_name:
            # Delete the MAC-VLAN interface and also, delete the associated IP table rules.
            if_name = 'v-'+if_name
            cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'ip', 'link', 'delete', if_name]
            if run_command(cmd, res) != 0:
                return (False,if_name,if_index, v_mac_str)
            process_vrf_ip_nat_config(is_add, vrf_name, if_name, 'iptables')
            process_vrf_ip_nat_config(is_add, vrf_name, if_name, 'ip6tables')
        else:
            cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'ip', 'link', 'set', if_name, 'netns', '1']
            if run_command(cmd, res) != 0:
                return (False,if_name,if_index, v_mac_str)
            # Disable local network (127/8) routing.
            cmd = ['sysctl', '-w', 'net.ipv4.conf.'+if_name+'.route_localnet=0']
            if run_command(cmd, res) != 0:
                return (False,if_name,if_index, v_mac_str)
            process_vrf_ip_nat_config(is_add, vrf_name, if_name, 'iptables')
            process_vrf_ip_nat_config(is_add, vrf_name, if_name, 'ip6tables')
        return (True,if_name,if_index, v_mac_str)

    # For default VRF, use the interface MAC
    # For non-default VRF, use the base MAC as router interface MAC,
    # if there is a need for a seperate MAC, will have to allocate
    # and use it on the router interface.

    # For default VRF case, just return the if-index and MAC address from
    # the interface present in the default VRF.
    if vrf_name == _default_vrf_name:
        # L3 intf with default VRF binding
        cmd = [iplink_cmd, 'link', 'show', 'dev', if_name]
        res = []
        if run_command(cmd, res) != 0:
            return (False,if_name,if_index, v_mac_str)
        if_index = int(res[0].split(':')[0])
        # In the ip link interface output, 2nd line and 5th field
        # is always MAC address.
        v_mac_str = str(res[1].split(' ')[5])
        return (True,if_name,if_index,v_mac_str)

    if vrf_name == _mgmt_vrf_name:
        # @@TODO Migrate this to MAC-VLAN approach - L3 intf with management VRF binding
        cmd = [iplink_cmd, 'link', 'set', 'dev', if_name, 'netns', vrf_name]
        if run_command(cmd, res) != 0:
            return (False,if_name,if_index, v_mac_str)
    else:
        # L3 intf with non-default VRF binding
        intf_up = None
        v_mac_str = ma.get_offset_mac_addr(ma.get_base_mac_addr(), 0)
        # Create MAC-VLAN interface on L3 interface
        res = []
        cmd = [iplink_cmd, 'link', 'show', 'dev', if_name]
        if run_command(cmd, res) != 0:
            return (False,if_name,if_index, v_mac_str)
        # Check whether the lower layer interface is admin up, if admin up,
        # update on the router interface (MAC-VLAN) interface as well.
        try:
            # 2nd field <BROADCAST,MULTICAST,UP,LOWER_UP> is admin up/down in the interface show
            if 'UP' in (res[0].split(' ')[2]):
                intf_up = 'UP'
        except:
            pass
        # For loopback interface, dont assign the MAC, kernel assigned random is fine,
        # there seems to be no use of this loopback MAC in the L3 packets.
        # @@TODO Double check if there is a real use-case for loopback MAC.
        if if_name[0:2] == 'lo':
            cmd = [iplink_cmd, 'link', 'add', 'link', if_name, 'v-'+if_name, 'type', 'macvlan',\
                  'mode', 'bridge']
        else:
            cmd = [iplink_cmd, 'link', 'add', 'link', if_name, 'v-'+if_name, 'address', v_mac_str, 'type', 'macvlan',\
                  'mode', 'bridge']
        if run_command(cmd, res) != 0:
            return (False,if_name,if_index, v_mac_str)

        # L3 intf with VRF bind
        cmd = [iplink_cmd, 'link', 'set', 'dev', 'v-'+if_name, 'netns', vrf_name]
        if run_command(cmd, res) != 0:
            return (False,if_name,if_index, v_mac_str)

        if_name = 'v-'+if_name

        # Get the if-index from MAC-VLAN interface
        # Enable local network (127/8) routing.
        if intf_up == 'UP':
            cmd = [iplink_cmd, '-n', vrf_name, 'link', 'set', 'dev', if_name, 'up']
            if run_command(cmd, res) != 0:
                return (False,if_name,if_index, v_mac_str)

        cmd = [iplink_cmd, '-n', vrf_name, 'link', 'show', 'dev', if_name]
        res = []
        if run_command(cmd, res) != 0:
            return (False,if_name,if_index, v_mac_str)
        # In the ip link show interface output, always the first field is interface index.
        if_index = int(res[0].split(':')[0])

    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'sysctl', '-w',\
          'net.ipv4.conf.'+if_name+'.route_localnet=1']
    if run_command(cmd, res) != 0:
        return (False,if_name,if_index, v_mac_str)
    # DROP if local network packets are going out of eth0
    # iptables -I OUTPUT -o eth0 -d loopback/8 -j DROP
    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'iptables', '-I', 'OUTPUT',\
          '-o', if_name, '-d', 'loopback/8', '-j', 'DROP']
    if run_command(cmd, res) != 0:
        return (False,if_name,if_index, v_mac_str)
    # @@TODO Put the similar rule for IPv6 reserved address also.
    # Once the default NAT rules are created, it will be there until the management
    # net_ns is deleted
    process_vrf_ip_nat_config(is_add, vrf_name, if_name, 'iptables')
    process_vrf_ip_nat_config(is_add, vrf_name, if_name, 'ip6tables')

    return (True,if_name,if_index, v_mac_str)

def ip_svcs_subnet_setup(is_add, vrf_name):
    res = []
    ip_tables = { 'iptables', 'ip6tables' }
    ip_proto = { 'tcp', 'udp' }
    sub_net_val = None
    vrf_id = None
    vrf_id = _vrf_name_to_id.get(vrf_name, None)
    if vrf_id is None:
        return (False, sub_net_val)

    _src_port_range = str(_start_private_port)+'-'+str(_end_private_port)
    if is_add is False:
        if process_veth_config(is_add, vrf_name,0,0,0,0,0,0,0,0) != True:
            return (False, sub_net_val)

        sub_net_val = None
        sub_net_val = _vrf_sub_net_map.get(vrf_name, None)
        if sub_net_val is None:
            return (False, sub_net_val)
        sub_net_val = _vrf_sub_net_map.pop(vrf_name, None)
        if sub_net_val is None:
            return (False, sub_net_val)

        veth_non_default_ip = None
        for iptable in ip_tables:
            if iptable == 'iptables':
                veth_non_default_ip = veth_non_default_intf_ip_prefix + str(sub_net_val) + veth_non_default_intf_ip_suffix
            else:
                veth_non_default_ip = veth_non_default_intf_ip6_prefix + str(sub_net_val) + veth_non_default_intf_ip6_suffix

            for proto in ip_proto:
                _ip = veth_non_default_ip
                if iptable == 'ip6tables':
                    _ip = '['+veth_non_default_ip+']'

                cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptable, '-t', 'nat', '-D', 'POSTROUTING',\
                      '-o', 'veth-nsid'+str(vrf_id), '-p', proto, '-j', 'SNAT', '--to-source',\
                      _ip+':'+str(_src_port_range)]
                if run_command(cmd, res) != 0:
                    return (False, sub_net_val)
            cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptable, '-t', 'nat', '-D', 'POSTROUTING',\
                  '-o', 'veth-nsid'+str(vrf_id), '-j', 'SNAT', '--to-source', veth_non_default_ip]
            if run_command(cmd, res) != 0:
                return (False, sub_net_val)

            cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptable, '-t', 'nat', '-F']
            ret_val = run_command(cmd, res)
            if ret_val != 0:
                cmd = 'IP rules deletion failed in the table:' + iptable
                log_err(cmd)

            cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptable, '-t', 'nat', '-X', 'VRF']
            ret_val = run_command(cmd, res)
            if ret_val != 0:
                cmd = 'IP VRF chain deletion failed in the table:' + iptable
                log_err(cmd)
        return (True, sub_net_val)

    # Setup the veth pairs with default VRF to make use of the services (SSH..) running in default VRF
    sub_net_val = _vrf_sub_net_map.get(vrf_name, None)
    if sub_net_val is not None:
        return (True, sub_net_val)
    for val in range (_start_vrf_sub_net_val, _end_vrf_sub_net_val):
        if val not in _vrf_sub_net_map.values():
            _vrf_sub_net_map[vrf_name] = val
            sub_net_val = val
            break
    if sub_net_val is None:
        return (False, sub_net_val)
    def_private_ip = veth_default_intf_ip_prefix + str(sub_net_val) + veth_default_intf_ip_suffix
    non_def_private_ip = veth_non_default_intf_ip_prefix + str(sub_net_val) + veth_non_default_intf_ip_suffix
    def_private_ip6 = veth_default_intf_ip6_prefix + str(sub_net_val) + veth_default_intf_ip6_suffix
    non_def_private_ip6 = veth_non_default_intf_ip6_prefix + str(sub_net_val) + veth_non_default_intf_ip6_suffix
    if process_veth_config(is_add, vrf_name, def_private_ip, veth_default_intf_ip_pref_len,\
                           non_def_private_ip, veth_non_default_intf_ip_pref_len,\
                           def_private_ip6, veth_default_intf_ip6_pref_len,\
                           non_def_private_ip6, veth_non_default_intf_ip6_pref_len) != True:
        return (False, sub_net_val)
    veth_non_default_ip = None
    for iptable in ip_tables:
        cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptable, '-t', 'nat', '-A', 'PREROUTING',\
              '-j', 'VRF']
        if run_command(cmd, res) != 0:
            return False
        if iptable == 'iptables':
            veth_non_default_ip = veth_non_default_intf_ip_prefix + str(sub_net_val) + veth_non_default_intf_ip_suffix
        else:
            veth_non_default_ip = veth_non_default_intf_ip6_prefix + str(sub_net_val) + veth_non_default_intf_ip6_suffix
        for proto in ip_proto:
            _ip = veth_non_default_ip
            if iptable == 'ip6tables':
                _ip = '['+veth_non_default_ip+']'
            cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptable, '-t', 'nat', '-A', 'POSTROUTING',\
                  '-o', 'veth-nsid'+str(vrf_id), '-p', proto, '-j', 'SNAT', '--to-source',\
                  _ip+':'+str(_src_port_range)]
            if run_command(cmd, res) != 0:
                return (False, sub_net_val)
        cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptable, '-t', 'nat', '-A', 'POSTROUTING',\
              '-o', 'veth-nsid'+str(vrf_id), '-j', 'SNAT', '--to-source', veth_non_default_ip]
        if run_command(cmd, res) != 0:
            return (False, sub_net_val)

    return (True, sub_net_val)

def get_veth_ip(af, vrf_name='default'):

    sub_net_val = None
    sub_net_val = _vrf_sub_net_map.get(vrf_name, None)
    if sub_net_val is None:
        ret_val, sub_net_val = ip_svcs_subnet_setup(True, vrf_name)
        if ret_val is False:
            return None

    veth_ip = None
    if af == socket.AF_INET:
        veth_intf_ip = veth_default_intf_ip_prefix + str(sub_net_val) + veth_default_intf_ip_suffix
        veth_ip = socket.inet_pton(af, veth_intf_ip)
    elif af == socket.AF_INET6:
        veth_intf_ip6 = veth_default_intf_ip6_prefix + str(sub_net_val) + veth_default_intf_ip6_suffix
        veth_ip = socket.inet_pton(af, veth_intf_ip6)
    return veth_ip

def process_outgoing_ip_svcs_config(is_add, af, public_ip, protocol, public_port, vrf_name='default'):
    res = []

    sub_net_val = None
    sub_net_val = _vrf_sub_net_map.get(vrf_name, None)
    if sub_net_val is None:
        ret_val, sub_net_val = ip_svcs_subnet_setup(True, vrf_name)
        if ret_val is False:
            return (False, 0, None)

    _outgoing_private_port = None
    alias = (vrf_name,af,public_ip,protocol,public_port)
    if is_add is False:
        _outgoing_private_port = _outgoing_ip_svcs_map.pop(alias, None)
    else:
        # Add case
        dup_check = _outgoing_ip_svcs_map.get(alias, None)
        if dup_check is not None:
            return (False, 0, None)
        for private_port in range (_start_private_port, _end_private_port):
            if private_port not in _outgoing_ip_svcs_map.values():
                _outgoing_ip_svcs_map[alias] = private_port
                _outgoing_private_port = private_port
                break

    if _outgoing_private_port is None:
        return (False, 0, None)

    iptable = None
    operation = None
    private_ip = None
    if is_add:
        operation = '-A'
    else:
        operation = '-D'

    if af == 'ipv4':
        iptable = 'iptables'
        private_ip = veth_non_default_intf_ip_prefix + str(sub_net_val) + veth_non_default_intf_ip_suffix
    elif af == 'ipv6':
        private_ip = veth_non_default_intf_ip6_prefix + str(sub_net_val) + veth_non_default_intf_ip6_suffix
        iptable = 'ip6tables'

    vrf_id = None
    vrf_id = _vrf_name_to_id.get(vrf_name, None)
    if vrf_id is None:
        return False

    # For outgoing IP services (SNMP Traps, RSYSLOG, RADIUS...etc) in the mgmt namespace, add the DNAT rule to
    # modify the packets with the actual public IP address and public port
    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptable, '-t', 'nat', operation, 'PREROUTING',\
          '-i', 'veth-nsid'+str(vrf_id), '-p', protocol, '--dport', str(_outgoing_private_port), '-j', 'DNAT',\
          '--to-destination', public_ip + ':' + public_port]
    if run_command(cmd, res) != 0:
        return (False, 0, None)
    return (True, _outgoing_private_port, private_ip)

