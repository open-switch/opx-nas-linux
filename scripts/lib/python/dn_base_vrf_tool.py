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
import cps
import cps_object
import socket
import binascii
import dn_base_ip_tool
import event_log as ev
from shutil import rmtree
import nas_mac_addr_utils as ma

# For IP services/Routing based on leaked route to work across VRFs,
# the veth pair is required between two VRFs (source and destination VRFs).
# For example, if the veth needs to be created between management (nsid- 1024)
# and default (nsid - 0) VRFs to support IP services, the interface is created
# from mgmt VRF to default VRF, the veth interface in mgmt VRF would be 'vdst-nsid0'
# to indicate the veth destination (nsid - 0) which is default VRF, similarly in default,
# vdst-nsid1024 is created.
# vEth IP assigment:
# Whichever VRF needs the veth (in this case, mgmt VRF) for any IP services/leaked routing,
# that VRF's veth interface will have the IP address 127.<100+x>.100.1 and on the other veth end
# in different VRF (in this case, default VRF) will have 127.<100_x>/100.2 IP address.
#
#_vrf_sub_net_map = {} - This stores the subnet value second byte
#                        in case of IPv4 address and 4 octet incase of IPv6 for
#                        a given source and destination VRF or vice-versa mapping.
#_vrf_name_to_id = {} -> This stores the VRF name to nsid mapping to make use of
#                        the single netlink socket to receive netlink from various
#                        namespaces with nsid.
# _vrf_src_ip_map -> This stores [VRF, AF, IP] to apply on the veth interface
#                    in order for the traffic originated from leaked VRF and exit via parent VRF
#                    to use that as the source-IP in the packet.

_default_vrf_name = 'default'
_mgmt_vrf_name = 'management'
iplink_cmd = '/sbin/ip'
# 127.<100+x>.100.1 -> x gets next available id for connectivity across VRFs
veth_intf_ip_prefix = '127.'
veth_intf_src_ip_suffix = '.100.1'
veth_intf_dst_ip_suffix = '.100.2'
veth_intf_ip_pref_len = '24'


# fda5:74c8:b79e:4:<100+x>::1/2 -> x gets next available id for connectivity across VRFs
veth_intf_ip6_prefix = 'fda5:74c8:b79e:4:'
veth_intf_src_ip6_suffix = '::1'
veth_intf_dst_ip6_suffix = '::2'
veth_intf_ip6_pref_len = '80'

rej_rule_mark_value = 255

veth_internal_ip_prefix = '127.0.0.0'
veth_internal_ip_pref_len = 8
veth_internal_ip6_prefix = 'fda5:74c8:b79e:4::'
veth_internal_ip6_pref_len = veth_intf_ip6_pref_len

_outgoing_ip_svcs_map = {}
# Use the private port range for internal NAT translations to handle the remote requests (e.g. SSH)
# coming via non-default VRF in the default VRF.
_start_private_port = 62000
_end_private_port = 65000

_vrf_sub_net_map = {}
_vrf_src_ip_map = {}
_vrf_name_to_id = {}
_start_vrf_sub_net_val = 100
_end_vrf_sub_net_val = 200
vrf_chain_name = 'VRF'
_DEFAULT_VRF_ID = 0

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

def get_ip_str(af, ip_bin):
    if af is None:
        af_list = [socket.AF_INET, socket.AF_INET6]
    else:
        af_list = [af]
    for af in af_list:
        try:
            ip_str = socket.inet_ntop(af, ip_bin)
            return ip_str
        except ValueError:
            continue
    return '-'

def process_vrf_ip_nat_config(is_add, vrf_name, if_name, iptables):
    res = []
    operation = None
    if is_add:
        operation = '-A'
    else:
        operation = '-D'

    vrf_id = None
    vrf_id = _vrf_name_to_id.get(vrf_name, None)
    if vrf_id is None:
        return False

    private_ip_src = None
    if iptables == 'iptables':
        private_ip_src = get_veth_ip_prefix(socket.AF_INET)
    else:
        private_ip_src = get_veth_ip_prefix(socket.AF_INET6)

    # ip netns exec management iptables -t nat -A POSTROUTING -s loopback -o eth0 -j MASQUERADE

    #@@@TODO - revisit and move this MASQUERADE rule to outgoing services config to maintain the rule order
    #all user configure SNAT rule's should be actually added only after any interface MASQUERADE rule.
    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptables, '-t', 'nat', operation, 'POSTROUTING',\
          '-s', private_ip_src, '-o', if_name, '-j', 'MASQUERADE']
    if run_command(cmd, res) != 0:
        return False

    return True

def process_veth_config(is_add, src_vrf_name, dst_vrf_name, src_ip, dst_ip, ip_pref_len,\
                        src_ip6, dst_ip6, ip6_pref_len):
    # Create vEth pair for comunication between default and
    # non-default (e.g management) namespaces
    res = []
    src_vrf_id = None
    src_vrf_id = _vrf_name_to_id.get(src_vrf_name, None)
    if src_vrf_id is None:
        return False
    dst_vrf_id = None
    dst_vrf_id = _vrf_name_to_id.get(dst_vrf_name, None)
    if dst_vrf_id is None:
        return False

    if is_add is False:
        cmd = [iplink_cmd, 'netns', 'exec', src_vrf_name, 'ip', 'link',\
              'delete', 'dev', 'vdst-nsid'+str(dst_vrf_id)]
        if run_command(cmd, res) != 0:
            cmd = [iplink_cmd, 'netns', 'exec', src_vrf_name, 'ip', 'link',\
                  'delete', 'dev', 'vdst-nsid'+str(src_vrf_id)]
            if run_command(cmd, res) != 0:
                return False
        return True

    cmd = [iplink_cmd, 'netns', 'exec', src_vrf_name, 'ip', 'link', 'add', 'name',\
          'vdst-nsid' + str(dst_vrf_id), 'type', 'veth', 'peer', 'name', 'vdst-nsid'\
          + str(src_vrf_id)]
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'exec', src_vrf_name, 'ip', 'link', 'set',\
          'vdst-nsid'+str(dst_vrf_id), 'up']
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'exec', src_vrf_name, 'ip', 'link', 'set', 'dev',\
          'vdst-nsid'+str(src_vrf_id), 'netns', dst_vrf_name]
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'exec', dst_vrf_name, 'ip', 'link', 'set', 'vdst-nsid'+str(src_vrf_id), 'up']
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'exec', src_vrf_name, 'ip', 'address', 'add',\
          src_ip + '/' + ip_pref_len,\
          'dev', 'vdst-nsid' + str(dst_vrf_id)]
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'exec', dst_vrf_name, 'ip', 'address', 'add', dst_ip + '/' + \
          ip_pref_len, 'dev', 'vdst-nsid'+str(src_vrf_id)]
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'exec', src_vrf_name, 'ip', 'address', 'add',\
          src_ip6 + '/' + ip6_pref_len,\
          'dev', 'vdst-nsid' + str(dst_vrf_id)]
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'exec', dst_vrf_name, 'ip', 'address', 'add', dst_ip6 + '/' + \
          ip6_pref_len, 'dev', 'vdst-nsid'+str(src_vrf_id)]
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'exec', src_vrf_name, 'sysctl', '-w',\
          'net.ipv4.conf.vdst-nsid'+str(dst_vrf_id)+'.route_localnet=1']
    if run_command(cmd, res) != 0:
        return False

    cmd = [iplink_cmd, 'netns', 'exec', dst_vrf_name, 'sysctl', '-w',\
          'net.ipv4.conf.vdst-nsid'+str(src_vrf_id)+'.route_localnet=1']
    if run_command(cmd, res) != 0:
        return False

    return True

def process_default_vrf_chain(is_add):
    ipt_action = '-N' if is_add else '-X'
    for iptable in ['iptables', 'ip6tables']:
        cmd = [iptable, '-t', 'raw', ipt_action, vrf_chain_name]
        res = []
        if run_command(cmd, res) != 0:
            log_err('Error running: %s' % ' '.join(cmd))
            return False
    return True

def process_vrf_top_chain_rule(is_add, vrf_name):
    if is_add and vrf_name == 'default':
        # Create VRF chain on default ns here
        if not process_default_vrf_chain(True):
            log_err('Failed to create VRF chain')
            return False

    ipt_action = '-A' if is_add else '-D'
    rej_chain_list = ['INPUT']
    if vrf_name == 'default':
        cmd_prefix = []
    else:
        cmd_prefix = [iplink_cmd, 'netns', 'exec', vrf_name]
        if vrf_name == 'management':
            rej_chain_list.append('FORWARD')
    for iptable in ['iptables', 'ip6tables']:
        cmd = cmd_prefix + [iptable, '-t', 'raw', ipt_action, 'PREROUTING', '!', '-i', 'lo', '-j', vrf_chain_name]
        res = []
        if run_command(cmd, res) != 0:
            log_err('Error running: %s' % ' '.join(cmd))
            return False
        for chain in rej_chain_list:
            res = []
            cmd = cmd_prefix + [iptable, ipt_action, chain, '-m', 'mark', '--mark',
                   str(rej_rule_mark_value), '-j', 'REJECT']
            if run_command(cmd, res) != 0:
                log_err('Error running: %s' % ' '.join(cmd))
                return False

    # Delete VRF chain from default ns
    if not is_add and vrf_name == 'default':
        if not process_default_vrf_chain(False):
            log_err('Failed to delete VRF chain')

    return True

def process_vrf_config(is_add, vrf_name, vrf_id):
    res = []
    ip_tables = { 'iptables', 'ip6tables' }
    for key in _vrf_sub_net_map:
        log_info('VRF:%s op:%d vrf_subnet key:%s val:%d' % (vrf_name, is_add, key, _vrf_sub_net_map[key]))
    # Network namespace deletion
    ip_svcs_folder = '/etc/netns/'+vrf_name
    if is_add is False:
        process_vrf_top_chain_rule(False, vrf_name)

        for key in _vrf_sub_net_map.keys():
            if '*'+vrf_name+'*' not in key:
                continue
            log_info('VRF subnet deletion for key:%s' % key)
            ret_val, sub_net_val = ip_svcs_subnet_setup(False, key.split("*")[1], key.split("*")[2])
            if ret_val is False:
                log_err('VRF deletion failed while deleting the key:%s' % key)
                return False

        vrf_id = None
        vrf_id = _vrf_name_to_id.get(vrf_name, None)
        if vrf_id is None:
            return False
        vrf_id = _vrf_name_to_id.pop(vrf_name, None)
        if vrf_id is None:
            return False

        try:
            # If this is the last VRF to delete, remove the default soft link
            if len(_vrf_name_to_id) == 1:
                os.unlink('/var/run/netns/default')
                vrf_id = _vrf_name_to_id.pop('default', None)
                if vrf_id is None:
                    return False
            rmtree(ip_svcs_folder, ignore_errors=False, onerror=None)
        except Exception as ex:
            log_info('Error cleanup default netns folder')

        for iptable in ip_tables:
            for table_name in ['nat', 'raw']:
                cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptable, '-t', table_name, '-F', vrf_chain_name]
                ret_val = run_command(cmd, res)
                if ret_val != 0:
                    log_err('%s IP rules deletion failed for table %s, ret=%d' %
                            (iptable, table_name, ret_val))
                cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptable, '-t', table_name, '-X', vrf_chain_name]
                ret_val = run_command(cmd, res)
                if ret_val != 0:
                    log_err('%s VRF chain deletion failed for table %s, ret=%d' %
                            (iptable, table_name, ret_val))

        cmd = [iplink_cmd, 'netns', 'delete', vrf_name]
        if run_command(cmd, res) != 0:
            return False
        log_info('VRF %s deleted successfully!' % (vrf_name))
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
            _vrf_name_to_id['default'] = 0
        os.makedirs(ip_svcs_folder, 0755)
    except:
        pass
    # Enable IPv6 forwarding on all interface for the ip6tables to work.
    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'sysctl', '-w',\
          'net.ipv6.conf.all.forwarding=1']
    if run_command(cmd, res) != 0:
        return False

    # Update the multicast values for scalability on data VRF
    igmp_max_memberships = 0
    igmp_max_msf = 0
    try:
        with open('/etc/sysctl.d/dn-igmp.conf', "r") as fd:
            lines = fd.readlines()
            for line in lines:
                if "net.ipv4.igmp_max_memberships" in line:
                    igmp_max_memberships = line.split()[2]
                if "net.ipv4.igmp_max_msf" in line:
                    igmp_max_msf = line.split()[2]
        if igmp_max_memberships:
            cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'sysctl', '-w',\
                  'net.ipv4.igmp_max_memberships='+str(igmp_max_memberships)]
            if run_command(cmd, res) != 0:
                return False
        if igmp_max_msf:
            cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'sysctl', '-w',\
                   'net.ipv4.igmp_max_msf='+str(igmp_max_msf)]
            if run_command(cmd, res) != 0:
                return False
    except:
        pass

    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'ip', 'link', 'set', 'lo', 'up']
    if run_command(cmd, res) != 0:
        return False

    cmd = ['ifconfig', 'lo', '127.0.0.1/16']
    run_command(cmd, res)

    cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'ifconfig', 'lo', '127.0.0.1/16']
    run_command(cmd, res)

    for iptable in ip_tables:
        for table_name in ['nat', 'raw']:
            cmd = [iplink_cmd, 'netns', 'exec', vrf_name, iptable, '-t', table_name, '-N', vrf_chain_name]
            ret_val = run_command(cmd, res)
            if ret_val != 0:
                log_err('%s VRF chain creation failed for table %s, ret=%d' %
                        (iptable, table_name, ret_val))
                return False

    if not process_vrf_top_chain_rule(True, vrf_name):
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
            if run_command(['sysctl', '-w', 'net.ipv6.conf.'+if_name+'.disable_ipv6=0'], res) != 0:
                return (False,if_name,if_index, v_mac_str)
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
            return (False,if_name,0,None)
        if_index = int(res[0].split(':')[0])
        # In the ip link interface output, 2nd line and 5th field
        # is always MAC address.
        v_mac_str = str(res[1].split(' ')[5])
        return (True,if_name,if_index,v_mac_str)

    v_mac_str = ma.get_offset_mac_addr(ma.get_base_mac_addr(), 0)
    if vrf_name == _mgmt_vrf_name:
        # @@TODO Migrate this to MAC-VLAN approach - L3 intf with management VRF binding
        cmd = [iplink_cmd, 'link', 'set', 'dev', if_name, 'netns', vrf_name]
        if run_command(cmd, res) != 0:
            return (False,if_name,if_index, v_mac_str)
        cmd = [iplink_cmd, '-n', vrf_name, 'link', 'show', 'dev', if_name]
        res = []
        if run_command(cmd, res) != 0:
            return (False,if_name,if_index, v_mac_str)
        # In the ip link show interface output, always the first field is interface index.
        if_index = int(res[0].split(':')[0])
    else:
        # L3 intf with non-default VRF binding
        intf_up = None
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

        if run_command(['sysctl', '-w', 'net.ipv6.conf.'+if_name+'.disable_ipv6=1'], res) != 0:
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

""" Return the veth IP, if is_peer_ip is set, return the veth peer end IP
    if not, return the local veth IP
"""
def _veth_ip_get(src_vrf_name, dst_vrf_name='default', is_peer_ip=False):
    veth_ip_suffix = None
    veth_ip6_suffix = None
    sub_net_val = None
    nexthop_ip = None
    nexthop_ip6 = None
    if src_vrf_name == 'default' and dst_vrf_name == 'default':
        return (False, nexthop_ip, nexthop_ip6)

    if is_peer_ip:
        veth_ip_suffix = veth_intf_dst_ip_suffix
        veth_ip6_suffix = veth_intf_dst_ip6_suffix
    else:
        veth_ip_suffix = veth_intf_src_ip_suffix
        veth_ip6_suffix = veth_intf_src_ip6_suffix

    vrf_name = '*'+src_vrf_name+'*'+dst_vrf_name+'*'
    sub_net_val = _vrf_sub_net_map.get(vrf_name, None)
    if sub_net_val is None:
        vrf_name = '*'+dst_vrf_name+'*'+src_vrf_name+'*'
        sub_net_val = _vrf_sub_net_map.get(vrf_name, None)
        if sub_net_val is not None:
            if is_peer_ip:
                veth_ip_suffix = veth_intf_src_ip_suffix
                veth_ip6_suffix = veth_intf_src_ip6_suffix
            else:
                veth_ip_suffix = veth_intf_dst_ip_suffix
                veth_ip6_suffix = veth_intf_dst_ip6_suffix
        else:
            ret_val, sub_net_val = ip_svcs_subnet_setup(True, src_vrf_name, dst_vrf_name)
            if ret_val is False:
                return (False, nexthop_ip, nexthop_ip6)

    nexthop_ip = veth_intf_ip_prefix + str(sub_net_val) + veth_ip_suffix
    nexthop_ip6 = veth_intf_ip6_prefix + str(sub_net_val) + veth_ip6_suffix
    return (True, nexthop_ip, nexthop_ip6)

""" Setup the veth interface for IP services and leaked VRF to work across VRFs.
"""
def ip_svcs_subnet_setup(is_add, src_vrf_name, dst_vrf_name='default'):
    res = []
    ip_tables = { 'iptables', 'ip6tables' }
    ip_proto = { 'tcp', 'udp' }
    sub_net_val = None
    vrf_id = None
    vrf_id = _vrf_name_to_id.get(src_vrf_name, None)
    if vrf_id is None:
        return (False, sub_net_val)

    log_info('ip svcs subnet setup is_add:%d src-vrf:%s dst-vrf-name:%s' % (is_add, src_vrf_name, dst_vrf_name))
    _src_port_range = str(_start_private_port)+'-'+str(_end_private_port)
    if is_add is False:
        sub_net_val = None
        vrf_name_key = None

        vrf_name_key = '*'+src_vrf_name+'*'+dst_vrf_name+'*'
        sub_net_val = _vrf_sub_net_map.get(vrf_name_key, None)
        if sub_net_val is None:
            return (False, sub_net_val)
        if process_veth_config(is_add, src_vrf_name, dst_vrf_name, 0,0,0,0,0,0) != True:
            return (False, sub_net_val)

        sub_net_val = _vrf_sub_net_map.pop(vrf_name_key, None)
        if sub_net_val is None:
            return (False, sub_net_val)
        log_info('vrf_name_key:%s val:%d deleted successfully' % (vrf_name_key, sub_net_val))

        if src_vrf_name != 'default' and dst_vrf_name != 'default':
            return (True, sub_net_val)

        if src_vrf_name == 'default':
            return (True, sub_net_val)

        private_src_ip = None
        private_dst_ip = None
        for iptable in ip_tables:
            if iptable == 'iptables':
                private_src_ip = veth_intf_ip_prefix + str(sub_net_val) + veth_intf_src_ip_suffix
                private_dst_ip = veth_intf_ip_prefix + str(sub_net_val) + veth_intf_dst_ip_suffix
            else:
                private_src_ip = veth_intf_ip6_prefix + str(sub_net_val) + veth_intf_src_ip6_suffix
                private_dst_ip = veth_intf_ip6_prefix + str(sub_net_val) + veth_intf_dst_ip6_suffix

            _src_ip = private_src_ip
            if iptable == 'ip6tables':
                _src_ip = '['+private_src_ip+']'

            for proto in ip_proto:
                cmd = [iplink_cmd, 'netns', 'exec', src_vrf_name, iptable, '-t', 'nat', '-D', 'POSTROUTING',\
                      '-o', 'vdst-nsid0', '-d', private_dst_ip, '-p', proto, '-j', 'SNAT', '--to-source',\
                      _src_ip+':'+str(_src_port_range)]
                if run_command(cmd, res) != 0:
                    return (False, sub_net_val)
            cmd = [iplink_cmd, 'netns', 'exec', src_vrf_name, iptable, '-t', 'nat', '-D', 'POSTROUTING',\
                  '-o', 'vdst-nsid0', '-d', private_dst_ip, '-j', 'SNAT', '--to-source',\
                  _src_ip]
            if run_command(cmd, res) != 0:
                return (False, sub_net_val)

            #@@@TODO - revisit and remove any IPtable flush configuration. trigger only explicit rule delete.
            cmd = [iplink_cmd, 'netns', 'exec', src_vrf_name, iptable, '-t', 'nat', '-F']
            ret_val = run_command(cmd, res)
            if ret_val != 0:
                cmd = 'IP rules deletion failed in the table:' + iptable
                log_err(cmd)

            cmd = [iplink_cmd, 'netns', 'exec', src_vrf_name, iptable, '-t', 'nat', '-X', 'VRF']
            ret_val = run_command(cmd, res)
            if ret_val != 0:
                cmd = 'IP VRF chain deletion failed in the table:' + iptable
                log_err(cmd)
        return (True, sub_net_val)

    # Setup the veth pairs across VRFs to make use of the services (SSH..) running
    # in default VRF and route leaking cases
    vrf_name_key1 = '*'+src_vrf_name+'*'+dst_vrf_name+'*'
    sub_net_val = _vrf_sub_net_map.get(vrf_name_key1, None)
    if sub_net_val is not None:
        return (True, sub_net_val)

    src_private_ip = None
    src_private_ip6 = None
    dst_private_ip = None
    dst_private_ip6 = None
    if sub_net_val is None:
        for val in range (_start_vrf_sub_net_val, _end_vrf_sub_net_val):
            if val not in _vrf_sub_net_map.values():
                _vrf_sub_net_map[vrf_name_key1] = val
                sub_net_val = val
                break
        if sub_net_val is None:
            return (False, sub_net_val)

        src_private_ip = veth_intf_ip_prefix + str(sub_net_val) + veth_intf_src_ip_suffix
        dst_private_ip = veth_intf_ip_prefix + str(sub_net_val) + veth_intf_dst_ip_suffix
        src_private_ip6 = veth_intf_ip6_prefix + str(sub_net_val) + veth_intf_src_ip6_suffix
        dst_private_ip6 = veth_intf_ip6_prefix + str(sub_net_val) + veth_intf_dst_ip6_suffix
        if process_veth_config(is_add, src_vrf_name, dst_vrf_name,\
                               src_private_ip, dst_private_ip, veth_intf_ip_pref_len,\
                               src_private_ip6, dst_private_ip6, veth_intf_ip6_pref_len) != True:
            return (False, sub_net_val)

    for key in _vrf_src_ip_map.keys():
        if '*'+src_vrf_name+'*' not in key:
            continue
        vrf_id = None
        vrf_id = _vrf_name_to_id.get(dst_vrf_name, None)
        if vrf_id is None:
            continue
        intf_name = 'vdst-nsid'+str(vrf_id)
        dn_base_ip_tool.add_ip_addr(key.split("*")[3], intf_name, key.split("*")[2], key.split("*")[1])
    for key in _vrf_src_ip_map.keys():
        if '*'+dst_vrf_name+'*' not in key:
            continue
        vrf_id = None
        vrf_id = _vrf_name_to_id.get(src_vrf_name, None)
        if vrf_id is None:
            continue
        intf_name = 'vdst-nsid'+str(vrf_id)
        dn_base_ip_tool.add_ip_addr(key.split("*")[3], intf_name, key.split("*")[1], key.split("*")[2])

    if src_vrf_name != 'default' and dst_vrf_name != 'default':
        return (True, sub_net_val)

    if src_vrf_name == 'default':
        return (True, sub_net_val)

    for iptable in ip_tables:
        _src_ip = src_private_ip
        _dst_ip = dst_private_ip
        if iptable == 'ip6tables':
            _src_ip = '['+src_private_ip6+']'
            _dst_ip = dst_private_ip6
        cmd = [iplink_cmd, 'netns', 'exec', src_vrf_name, iptable, '-t', 'nat', '-A', 'PREROUTING',\
              '-j', 'VRF']
        if run_command(cmd, res) != 0:
            return False

        for proto in ip_proto:
            cmd = [iplink_cmd, 'netns', 'exec', src_vrf_name, iptable, '-t', 'nat', '-A', 'POSTROUTING',\
                  '-o', ('vdst-nsid%d' % _DEFAULT_VRF_ID), '-d', _dst_ip, '-p', proto, '-j', 'SNAT', '--to-source',\
                  _src_ip+':'+str(_src_port_range)]
            if run_command(cmd, res) != 0:
                return (False, sub_net_val)
        cmd = [iplink_cmd, 'netns', 'exec', src_vrf_name, iptable, '-t', 'nat', '-A', 'POSTROUTING',\
              '-o', ('vdst-nsid%d' % _DEFAULT_VRF_ID), '-d', _dst_ip, '-j', 'SNAT', '--to-source',\
              _src_ip]
        if run_command(cmd, res) != 0:
            return (False, sub_net_val)

    return (True, sub_net_val)

def get_veth_ip_subnet(src_vrf_name, dst_vrf_name='default'):
    vrf_name_key1 = '*'+src_vrf_name+'*'+dst_vrf_name+'*'
    vrf_name_key2 = '*'+dst_vrf_name+'*'+src_vrf_name+'*'
    sub_net_val = None
    sub_net_val = _vrf_sub_net_map.get(vrf_name_key1, None)
    if sub_net_val is None:
        sub_net_val = _vrf_sub_net_map.get(vrf_name_key2, None)
    return sub_net_val

def get_veth_ip_prefix(af):
    veth_ip_prefix = None

    if af == socket.AF_INET:
        veth_ip_prefix = veth_internal_ip_prefix+'/'+str(veth_internal_ip_pref_len)
    elif af == socket.AF_INET6:
        veth_ip_prefix = veth_internal_ip6_prefix+'/'+str(veth_internal_ip6_pref_len)

    return veth_ip_prefix


def get_veth_ip(af, vrf_name='default', is_peer_ip=True):
    veth_ip = None
    ret_val, nexthop_ip, nexthop_ip6 = _veth_ip_get(vrf_name, 'default', is_peer_ip)
    if ret_val is False:
       return veth_ip

    if af == socket.AF_INET:
       veth_ip = socket.inet_pton(af, nexthop_ip)
    elif af == socket.AF_INET6:
       veth_ip = socket.inet_pton(af, nexthop_ip6)
    return veth_ip

def get_veth_ip_str(af, vrf_name='default', is_peer_ip=True):
    veth_ip = None
    ret_val, nexthop_ip, nexthop_ip6 = _veth_ip_get(vrf_name, 'default', is_peer_ip)
    if ret_val is False:
       return veth_ip

    if af == socket.AF_INET:
       veth_ip = nexthop_ip
    elif af == socket.AF_INET6:
       veth_ip = nexthop_ip6
    return veth_ip

""" This method provides the private IP, port for given
    public IP, port required for the binding outgoing IP services.
"""
def process_outgoing_ip_svcs_sub_net_config(is_add, vrf_name, af, protocol, public_ip, public_port):
    ret_val, nexthop_ip, nexthop_ip6 = _veth_ip_get(vrf_name, 'default', False)
    if ret_val is False:
        return (False, None, 0)

    _outgoing_private_port = None
    alias = (vrf_name,af,public_ip,protocol,public_port)
    if is_add is False:
        _outgoing_private_port = _outgoing_ip_svcs_map.pop(alias, None)
    else:
        # Add case
        dup_check = _outgoing_ip_svcs_map.get(alias, None)
        if dup_check is not None:
            return (False, None, 0)
        for private_port in range (_start_private_port, _end_private_port):
            if private_port not in _outgoing_ip_svcs_map.values():
                _outgoing_ip_svcs_map[alias] = private_port
                _outgoing_private_port = private_port
                break

    if _outgoing_private_port is None:
        return (False, None, 0)

    private_ip = None
    if af == socket.AF_INET:
        private_ip = (socket.inet_pton(af, nexthop_ip))
    elif af == socket.AF_INET6:
        private_ip = (socket.inet_pton(af, nexthop_ip6))

    return (True, private_ip, _outgoing_private_port)

""" Return the peer veth interface name from a given source and destination VRF names.
"""
def get_vrf_intf_to_dst_vrf(src_vrf_name, dst_vrf_name):

    vrf_name_key = '*'+src_vrf_name+'*'+dst_vrf_name+'*'
    sub_net_val = _vrf_sub_net_map.get(vrf_name_key, None)
    if sub_net_val is None:
        vrf_name_key = '*'+dst_vrf_name+'*'+src_vrf_name+'*'
        sub_net_val = _vrf_sub_net_map.get(vrf_name_key, None)
        if sub_net_val is None:
            return (False, None)

    vrf_id = None
    vrf_id = _vrf_name_to_id.get(dst_vrf_name, None)
    if vrf_id is None:
        return (False, None)
    return (True, 'vdst-nsid'+str(vrf_id))

""" Handle the source IP configuration for a leaked VRF to apply on the veth interface
    in order to use it as the source IP for the packets originated from leaked VRF.
"""
def process_src_ip_config(vrf, is_add, af, ip):

    prefix_len = '32'
    if af == 'ipv6':
        prefix_len = '128'
    ip_addr = ip+'/'+prefix_len
    src_ip_key = '*'+vrf+'*'+str(af)+'*'+ip_addr+'*'
    val = _vrf_src_ip_map.get(src_ip_key, None)
    if is_add is False and val is None:
        return True
    if is_add and val is not None:
        return True

    if (is_add):
        _vrf_src_ip_map[src_ip_key] = 1
    else:
        val = _vrf_src_ip_map.pop(src_ip_key, None)
        if val is None:
            return False

    # Loop all veth interfaces available in the VRF
    dst_vrf = None
    for key in _vrf_sub_net_map.keys():
        if '*'+vrf+'*' not in key:
            continue
        if key.split("*")[1] == vrf:
            dst_vrf = key.split("*")[2]
        if key.split("*")[2] == vrf:
            dst_vrf = key.split("*")[1]

        vrf_id = None
        vrf_id = _vrf_name_to_id.get(dst_vrf, None)
        if vrf_id is None:
            continue
        intf_name = 'vdst-nsid'+str(vrf_id)
        if is_add:
            dn_base_ip_tool.add_ip_addr(ip_addr, intf_name, af, vrf)
        else:
            dn_base_ip_tool.del_ip_addr(ip_addr, intf_name, vrf)
    return True

def process_leaked_rt_config(op, af, dst_vrf_name, prefix, prefix_len, nexthop_ip):
        tbl_op = '-A'
        if op == 'del':
            tbl_op = '-D'
        res = []
        cmd = [iplink_cmd, 'netns', 'exec', dst_vrf_name, 'ip', 'route', op, prefix+'/'+str(prefix_len), 'via', str(nexthop_ip)]
        if run_command(cmd, res) != 0:
            return False
        if af == socket.AF_INET:
            cmd = [iplink_cmd, 'netns', 'exec', dst_vrf_name, 'iptables', '-t', 'mangle', tbl_op, 'POSTROUTING', \
                  '-d', prefix+'/'+str(prefix_len), '-j', 'TTL', '--ttl-inc', '1']
        elif af == socket.AF_INET6:
            cmd = [iplink_cmd, 'netns', 'exec', dst_vrf_name, 'ip6tables', '-t', 'mangle', tbl_op, 'POSTROUTING', \
                  '-d', prefix+'/'+str(prefix_len), '-j', 'HL', '--hl-inc', '1']

        if run_command(cmd, res) != 0:
            return False
        return True

