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
import base_vrf


iplink_cmd = '/sbin/ip'
veth_default_intf_ip = '127.100.100.1'
veth_default_intf_ip_pref_len = '24'
veth_management_intf_ip = '127.100.100.2'
veth_management_intf_ip_pref_len = '24'

veth_default_intf_ip6 = 'fda5:74c8:b79e:4::1'
veth_default_intf_ip6_pref_len = '64'
veth_management_intf_ip6 = 'fda5:74c8:b79e:4::2'
veth_management_intf_ip6_pref_len = '64'

_outgoing_ip_svcs_map = {}
_outgoing_start_private_port = 62000
_outgoing_end_private_port = 63000

def run_command(cmd, respose):

    """Method to run a command in shell"""

    prt = subprocess.Popen(
        cmd,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    for line in prt.stdout.readlines():
        respose.append(line.rstrip())
    retval = prt.wait()
    return retval


def process_vrf_ip_nat_config(is_add, vrf_name, if_name, iptables, veth_management_ip):
    res = []
    operation = None
    if is_add:
        operation = '-A'
    else:
        operation = '-D'

    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptables, '-t', 'nat', operation, 'PREROUTING',\
          '-i', if_name, '-j', 'VRF']
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptables, '-t', 'nat', operation, 'POSTROUTING',\
          '-o', if_name, '-j', 'MASQUERADE']
    if run_command(cmd, res) != 0:
        return False

    return True

def process_veth_config(is_add, vrf_name):
    # Create vEth pair for comunication between default and
    # non-default (e.g management) namespaces
    res = []
    if is_add is False:
        cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'ip', 'link',\
              'delete', 'dev', 'veth-'+vrf_name]
        if run_command(cmd, res) != 0:
            return False
        return True

    cmd = [iplink_cmd, 'link', 'add', 'name', 'veth-default', 'type',\
          'veth', 'peer', 'name', 'veth-' + vrf_name]
    if run_command(cmd, res) != 0:
        return False

    cmd = ['sysctl', '-w', 'net.ipv4.conf.veth-default.route_localnet=1']
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'link', 'set', 'veth-default', 'up']
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'link', 'set', 'dev', 'veth-'+vrf_name, 'netns', vrf_name]
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'ip', 'link', 'set', 'veth-'+vrf_name, 'up']
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'address', 'add', veth_default_intf_ip + '/' + \
          veth_default_intf_ip_pref_len, 'dev', 'veth-default']
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'ip', 'address', 'add',\
          veth_management_intf_ip + '/' + veth_management_intf_ip_pref_len,\
          'dev', 'veth-' + vrf_name]
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'address', 'add', veth_default_intf_ip6 + '/' + \
          veth_default_intf_ip6_pref_len, 'dev', 'veth-default']
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'ip', 'address', 'add',\
          veth_management_intf_ip6 + '/' + veth_management_intf_ip6_pref_len,\
          'dev', 'veth-' + vrf_name]
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'sysctl', '-w',\
          'net.ipv4.conf.veth-'+vrf_name+'.route_localnet=1']
    if run_command(cmd, res) != 0:
        return False

    return True


def process_mgmt_vrf_config(is_add, vrf_name):
    res = []
    # Network namespace deletion
    ip_tables = { 'iptables', 'ip6tables' }
    if is_add is False:
        try:
            os.unlink('/var/run/netns/default')
        except:
            pass
        if process_veth_config(is_add, vrf_name) != True:
            return False
        veth_management_ip = None
        for iptable in ip_tables:
            if iptable == 'iptables':
                veth_management_ip = veth_management_intf_ip
            else:
                veth_management_ip = veth_management_intf_ip6

            cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptable, '-t', 'nat', '-D', 'POSTROUTING',\
                  '-o', 'veth-'+vrf_name, '-j', 'SNAT', '--to-source', veth_management_ip]
            if run_command(cmd, res) != 0:
                return False
            cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptable, '-t', 'nat', '-F']
            ret_val = run_command(cmd, res)
            cmd = 'IP rules deletion failed in the table:' + iptable
            if ret_val != 0:
                base_vrf.log_err(cmd)

            cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptable, '-t', 'nat', '-X', 'VRF']
            ret_val = run_command(cmd, res)
            cmd = 'IP VRF chain deletion failed in the table:' + iptable
            if ret_val != 0:
                base_vrf.log_err(cmd)

        cmd = [iplink_cmd, 'netns', 'delete', vrf_name]
        if run_command(cmd, res) != 0:
            return False

        return True

    # Network namespace addition and vEth pair creation
    # between default and mgmt namespaces.
    cmd = [iplink_cmd, 'netns', 'add', vrf_name]
    if run_command(cmd, res) != 0:
        return False

    # Create the default namespace soft link
    # ln -s /proc/1/ns/net /var/run/netns/default
    try:
        os.symlink('/proc/1/ns/net', '/var/run/netns/default')
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

    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'ifconfig', 'lo', 'inet6', 'add', '::1/128']
    run_command(cmd, res)

    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'iptables', '-t', 'nat', '-N', 'VRF']
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'ip6tables', '-t', 'nat', '-N', 'VRF']
    if run_command(cmd, res) != 0:
        return False

    if process_veth_config(is_add, vrf_name) != True:
        return False
    veth_management_ip = None
    for iptable in ip_tables:
        if iptable == 'iptables':
            veth_management_ip = veth_management_intf_ip
        else:
            veth_management_ip = veth_management_intf_ip6
        cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptable, '-t', 'nat', '-A', 'POSTROUTING',\
              '-o', 'veth-'+vrf_name, '-j', 'SNAT', '--to-source', veth_management_ip]
        if run_command(cmd, res) != 0:
            return False
    return True

def process_mgmt_vrf_intf_config(is_add, if_name, vrf_name):
    res = []
    # Remove VRF association from L3 intf
    if is_add is False:
        cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'ip', 'link', 'set', if_name, 'netns', '1']
        if run_command(cmd, res) != 0:
            return False
        # Disable local network (127/8) routing.
        cmd = ['sysctl', '-w', 'net.ipv4.conf.'+if_name+'.route_localnet=0']
        if run_command(cmd, res) != 0:
            return False
        process_vrf_ip_nat_config(is_add, vrf_name, if_name, 'iptables', veth_management_intf_ip)
        process_vrf_ip_nat_config(is_add, vrf_name, if_name, 'ip6tables', veth_management_intf_ip6)
        return True

    # L3 intf with VRF bind
    cmd = [iplink_cmd, 'link', 'set', 'dev', if_name, 'netns', vrf_name]
    if run_command(cmd, res) != 0:
        return False

    # Enable local network (127/8) routing.
    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'sysctl', '-w',\
          'net.ipv4.conf.'+if_name+'.route_localnet=1']
    if run_command(cmd, res) != 0:
        return False
    # DROP if local network packets are going out of eth0
    # iptables -I OUTPUT -o eth0 -d loopback/8 -j DROP
    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'iptables', '-I', 'OUTPUT',\
          '-o', if_name, '-d', 'loopback/8', '-j', 'DROP']
    if run_command(cmd, res) != 0:
        return False
    # @@TODO Put the similar rule for IPv6 reserved address also.
    # Once the default NAT rules are created, it will be there until the management
    # net_ns is deleted
    process_vrf_ip_nat_config(is_add, vrf_name, if_name, 'iptables', veth_management_intf_ip)
    process_vrf_ip_nat_config(is_add, vrf_name, if_name, 'ip6tables', veth_management_intf_ip6)

    return True

def process_incoming_ip_svcs_config(is_add, af, protocol, dst_port, action, vrf_name='default'):
    res = []
    iptable = None
    veth_ip = None
    operation = None
    if af == 'ipv4':
        iptable = 'iptables'
        veth_ip = veth_default_intf_ip
    elif af == 'ipv6':
        iptable = 'ip6tables'
        veth_ip = veth_default_intf_ip6

    if is_add:
        operation = '-A'
    else:
        operation = '-D'
    # Pinning SSH service to mgmt namespace i.e SSH will be allowed only
    # from mgmt interface not from front panel interface.
    #iptables -A INPUT -p tcp --dport 22 ! -i veth-default -j DROP
    if vrf_name == 'default':
        # By default, IP Services are allowed on default, no need for explicit ACCEPT.
        if action == 'ACCEPT':
            return False

        cmd = ['/sbin/'+iptable, operation, 'INPUT', '-p', protocol, '--dport', dst_port,\
              '!', '-i', 'veth-default', '-j', action]
        if run_command(cmd, res) != 0:
            return False
        return True

    # For incoming IP services (SSH, TFTP...etc) in the mgmt namespace, add the DNAT rule to
    # redirect to default namespace for processing.
    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptable, '-t', 'nat', operation, 'VRF',\
          '-p', protocol, '--dport', dst_port, '-j', 'DNAT', '--to-destination', veth_ip]
    if run_command(cmd, res) != 0:
        return False
    return True

def process_outgoing_ip_svcs_config(is_add, af, public_ip, protocol, public_port, vrf_name='default'):
    res = []
    _outgoing_private_port = None
    alias = (vrf_name,af,public_ip,protocol,public_port)
    if is_add is False:
        _outgoing_private_port = _outgoing_ip_svcs_map.pop(alias, None)
    else:
        # Add case
        dup_check = _outgoing_ip_svcs_map.get(alias, None)
        if dup_check is not None:
            return (False, 0)
        for private_port in range (_outgoing_start_private_port, _outgoing_end_private_port):
            if private_port not in _outgoing_ip_svcs_map.values():
                _outgoing_ip_svcs_map[alias] = private_port
                _outgoing_private_port = private_port
                break

    if _outgoing_private_port is None:
        return (False, 0)

    iptable = None
    operation = None
    if is_add:
        operation = '-A'
    else:
        operation = '-D'

    if af == 'ipv4':
        iptable = 'iptables'
    elif af == 'ipv6':
        iptable = 'ip6tables'

    # For outgoing IP services (SNMP Traps, RSYSLOG, RADIUS...etc) in the mgmt namespace, add the DNAT rule to
    # modify the packets with the actual public IP address and public port
    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptable, '-t', 'nat', operation, 'PREROUTING',\
          '-i', 'veth-management', '-p', protocol, '--dport', str(_outgoing_private_port), '-j', 'DNAT',\
          '--to-destination', public_ip + ':' + public_port]
    if run_command(cmd, res) != 0:
        return (False, 0)
    return (True, _outgoing_private_port)


