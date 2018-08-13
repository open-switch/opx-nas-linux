# Copyright (c) 2015 Dell Inc.
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
import netaddr
import re
import os
import cps
import cps_object
import event_log as ev

iplink_cmd = '/sbin/ip'
VXLAN_PORT = '4789'

_mgmt_vrf_name = 'management'

def log_err(msg):
    ev.logging("BASE_IP",ev.ERR,"IP-CONFIG","","",0,msg)

def log_info(msg):
    ev.logging("BASE_IP",ev.INFO,"IP-CONFIG","","",0,msg)

def get_ip_line_type(lines):
    header = lines[0].strip().split()
    return header[0]


def find_first_non_ws(str):
    _str = str.lstrip()
    return len(str) - len(_str)


def _group_lines_based_on_position(scope, lines):
    data = []
    resp = []
    for line in lines:
        if find_first_non_ws(line) == scope:
            if len(data) > 0:
                resp.append(data)
            data = []

        data.append(line)

    if len(data) > 0:
        resp.append(data)
    return resp

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


def _get_ip_addr(vrf_name, dev=None):
    output = []
    result = []
    if vrf_name == 'default':
        cmd = [iplink_cmd, 'addr', 'show']
    else:
        cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'ip', 'addr', 'show']
    if dev is not None:
        cmd.append('dev')
        cmd.append(dev)

    if run_command(cmd, output) != 0:
        return result
    return output


def _find_field(pattern, key, line):
    res = None
    m = re.search(pattern, line)
    if m is None:
        return None
    m = m.groupdict()
    if key in m:
        return m[key]
    return None


class InterfaceObject:

    def process_ip_line(self, lines):
        _af_type = _find_field(
            r'\s+(?P<af_type>\S+)\s+(?P<addr>\S+)/(?P<prefix>\S+)',
            'af_type',
            lines[0])
        _addr = _find_field(
            r'\s+(?P<af_type>\S+)\s+(?P<addr>\S+)/(?P<prefix>\S+)',
            'addr',
            lines[0])
        _prefix = _find_field(
            r'\s+(?P<af_type>\S+)\s+(?P<addr>\S+)/(?P<prefix>\S+)',
            'prefix',
            lines[0])
        return (_af_type, _addr, _prefix)

    def process_ether_line(self, lines):
        _ether = _find_field(
            r'\s+link/ether\s+(?P<addr>\S+)\s+',
            'addr',
            lines[0])
        if _ether is not None:
            _ether = ''.join(filter(lambda x: x != ':', _ether))
        return _ether

    def _create_type(self):
        self.type = 8  # ethernet

        if self.ifname.find('lo:') == 0 or self.ifname == 'lo':
            self.type = 2
        elif os.path.exists('/sys/class/net/' + self.ifname + '/uevent'):
            with open('/sys/class/net/' + self.ifname + '/uevent', 'r') as f:
                while True:
                    l = f.readline().strip()
                    if len(l) == 0:
                        break
                    data = l.split('=', 1)
                    if len(data) < 2:
                        continue
                    if data[0] == 'DEVTYPE':
                        if data[1] == 'vlan':
                            self.type = 9
                        if data[1] == 'bond':
                            self.type = 10

    def __init__(self, lines, vrf_name):
        self.vrf_name = str(vrf_name)
        self.ifix = _find_field(
            r'(?P<ifindex>\d+):\s+(?P<ifname>\S+):\s+<(?P<flags>\S+)>',
            'ifindex',
            lines[0])
        self.ifix = int(self.ifix)
        self.ifname = _find_field(
            r'(?P<ifindex>\d+):\s+(?P<ifname>\S+):\s+<(?P<flags>\S+)>',
            'ifname',
            lines[0])

        if self.ifname.find('@') != -1:
            self.ifname = self.ifname.split('@', 1)[0]

        self.flags = _find_field(
            r'(?P<ifindex>\d+):\s+(?P<ifname>\S+):\s+<(?P<flags>\S+)>',
            'flags',
            lines[0])
        self.state = 2 # Admin down
        for i in self.flags.split(','):
            if i.lower() == 'up':
                self.state = 1  # admin up

        self.mtu = _find_field('(\s+mtu (?P<mtu>\S+))', 'mtu', lines[0])
        op_state = _find_field('(\s+state (?P<oper>\S+))', 'oper', lines[0])
        self.oper_state = 2  # oper down
        if op_state.lower() == 'up':
            self.oper_state = 1  # oper up

        self._create_type()
        self.mac = None

        # first line after header - contains IP - therefore group all lines
        # based on this spacing
        self.ips = lines[1:]
        scope = find_first_non_ws(self.ips[0])
        self.ips = _group_lines_based_on_position(scope, self.ips)
        self.ip = []

        for i in self.ips:
            if i[0].find('link/ether') != -1:
                self.mac = self.process_ether_line(i)
                continue

            _af, _addr, _prefix = self.process_ip_line(i)

            if _af == 'inet' or _af == 'inet6':
                self.ip.append((_af, _addr, _prefix))

def get_if_details_per_vrf(resp, vrf_name, dev=None):
    l = []
    l = _get_ip_addr(vrf_name, dev)
    l = _group_lines_based_on_position(0, l)
    for i in l:
        resp.append(InterfaceObject(i, vrf_name))
    return True

def get_if_details(vrf_name=None, dev=None):
    resp = []
    if vrf_name is None:
        cmd = ['/sbin/ip','netns','list']
        res = []
        if run_command(cmd, res) != 0:
            return resp
        if len(res) == 0:
            get_if_details_per_vrf(resp, 'default', dev)
        else:
            for vrf in res:
                vrf_name = vrf.split(' ')[0]
                get_if_details_per_vrf(resp, vrf_name, dev)
    else:
        get_if_details_per_vrf(resp, vrf_name, dev)

    return resp


def add_ip_addr(addr_and_prefix, dev, af, vrf_name='default'):
    bcast_addr = None
    if af == "ipv4":
        try:
            ip = netaddr.IPNetwork(addr_and_prefix)
            bcast_addr = ip.broadcast
        except Exception as e:
            return False

    cmds = {
               'bcast_flag': { 'default': [iplink_cmd, 'addr', 'add', addr_and_prefix, 'broadcast', str(bcast_addr), 'dev', dev],
                               'vrf_name': [iplink_cmd, 'netns', 'exec', vrf_name, 'ip', 'addr', 'add',
                                            addr_and_prefix, 'broadcast', str(bcast_addr), 'dev', dev] },
               'no_bcast_flag': { 'default': [iplink_cmd, 'addr', 'add', addr_and_prefix, 'dev', dev],
                                  'vrf_name': [iplink_cmd, 'netns', 'exec', vrf_name, 'ip', 'addr', 'add',
                                              addr_and_prefix, 'dev', dev]}
          }

    res = []
    if bcast_addr is None:
       if vrf_name == 'default':
           cmd = cmds['no_bcast_flag']['default']
       else:
            cmd = cmds['no_bcast_flag']['vrf_name']
    else:
        if vrf_name == 'default':
           cmd = cmds['bcast_flag']['default']
        else:
            cmd = cmds['bcast_flag']['vrf_name']

    if run_command(cmd, res) == 0:
        return True

    return False


def del_ip_addr(addr_and_prefix, dev, vrf_name='default'):
    res = []
    if vrf_name == 'default':
        if run_command([iplink_cmd, 'addr', 'del', addr_and_prefix, 'dev', dev], res) == 0:
            return True
        return False

    if run_command([iplink_cmd, 'netns', 'exec', vrf_name, 'ip', 'addr', 'del',\
                   addr_and_prefix, 'dev', dev], res) == 0:
        return True
    return False


def create_vxlan_if(name, vn_id, tunnel_source_ip, addr_family):

    """Method to create a VxLAN Interface
    Args:
        bname (str): Name of the VxLAN Interface
        vn_id (str): VNI ID
        tunnel_source_ip (str): Tunnel Source IP Address
        addr_family (int): Address family of the IP address
    Returns:
        bool: The return value. True for success, False otherwise
    """

    res = []
    cmd = [iplink_cmd,
           'link', 'add',
           'name', name,
           'type', 'vxlan',
           'id', vn_id,
           'local', tunnel_source_ip,
           'dstport', VXLAN_PORT
           ]

    if run_command(cmd, res) == 0:
        return True
    return False


def create_loopback_if(name, mtu=None, mac=None):
    res = []
    cmd = [iplink_cmd,
           'link', 'add',
           'name', name,
           ]
    if mtu is not None:
        cmd.append('mtu')
        cmd.append(mtu)

    if mac is not None:
        cmd.append('address')
        cmd.append(mac)
    cmd.append('type')
    cmd.append('dummy')

    if run_command(cmd, res) == 0:
        return True
    return False


def create_macvlan_if(name, parent_if, mac):
    res = []
    cmd = [iplink_cmd,
           'link', 'add',
           'link', parent_if, name,
           'address', mac,
           'type', 'macvlan'
           ]

    if run_command(cmd, res) == 0:
        return True
    return False


def delete_if(name):
    res = []
    if run_command([iplink_cmd, 'link', 'delete', 'dev', name], res) == 0:
        return True
    return False


def configure_vlan_tag(name, vlan_id):

    """Method to configure a VLAN tag Interface
    Args:
        name (str): Name of the Interface
        vlan_id (str): VLAN ID
    Returns:
        bool: The return value. True for success, False otherwise
    """

    res = []
    cmd = [iplink_cmd,
           'link', 'add',
           'link', name,
           'name', str(name) + '.' + str(vlan_id),
           'type', 'vlan',
           'id', str(vlan_id)
           ]
    if run_command(cmd, res) == 0:
        return True
    return False


def set_if_mtu(name, mtu):
    res = []
    if run_command([iplink_cmd, 'link', 'set', name, 'mtu', str(mtu)], res) == 0:
        return True
    return False


def set_if_mac(name, mac):
    res = []
    if run_command([iplink_cmd, 'link', 'set', 'dev', name, 'address', mac], res) == 0:
        return True
    return False


def set_if_state(name, state):
    res = []
    if int(state) == 1:
        state = 'up'
    else:
        state = 'down'
    if run_command([iplink_cmd, 'link', 'set', 'dev', name, state], res) == 0:
        return True
    return False

def ip_forwarding_config(ip_type, if_name, fwd, vrf_name='default'):
    res = []
    if run_command([iplink_cmd, 'netns', 'exec', vrf_name, 'sysctl', '-w',\
                   'net.'+ip_type+'.conf.'+if_name+'.forwarding='+fwd], res) == 0:
        return True
    return False

def disable_ipv6_config(if_name, disable_ipv6, vrf_name='default'):
    res = []
    if run_command([iplink_cmd, 'netns', 'exec', vrf_name, 'sysctl', '-w',\
                   'net.ipv6.conf.'+if_name+'.disable_ipv6='+disable_ipv6], res) == 0:
        return True
    return False

def ipv6_autoconf_config(if_name, autoconf, vrf_name='default'):
    res = []
    if vrf_name == _mgmt_vrf_name:
        # 2 - Overrule forwarding behaviour. Accept Router Advertisements
        #     even if forwarding is enabled on the mgmt. interface
        #     since forwarding is enabled for iptables to work.
        accept_ra = 1
        if autoconf:
            accept_ra = 2
        cmd = [iplink_cmd, 'netns', 'exec', vrf_name, 'sysctl', '-w',\
              'net.ipv6.conf.'+if_name+'.accept_ra='+str(accept_ra)]
        if run_command(cmd, res) != 0:
            return False

    if run_command([iplink_cmd, 'netns', 'exec', vrf_name, 'sysctl', '-w',\
                   'net.ipv6.conf.'+if_name+'.autoconf='+str(autoconf)], res) == 0:
        return True
    return False

def ipv6_accept_dad_config(if_name, accept_dad, vrf_name='default'):
    res = []
    if run_command([iplink_cmd, 'netns', 'exec', vrf_name, 'sysctl', '-w',\
                   'net.ipv6.conf.'+if_name+'.accept_dad='+accept_dad], res) == 0:
        return True
    return False

def flush_ip_neigh(af, dev, addr=None, vrf_name='default'):
    res = []
    neigh_af = '-4'
    if af == 'ipv6':
        neigh_af = '-6'

    if vrf_name == 'default':
        if addr is not None and dev is not None:
            # When an address is set, it has to be on the particular interface.
            if len(dev) != 1:
                return False
            if run_command([iplink_cmd, neigh_af, 'neigh', 'flush', 'to', str(addr), 'dev', dev[0]], res) == 0:
                return True
        elif dev is not None:
            for ifname in dev:
                if run_command([iplink_cmd, neigh_af, 'neigh', 'flush', 'dev', ifname], res) != 0:
                    return False
            return True
        elif addr is not None:
            if run_command([iplink_cmd, neigh_af, 'neigh', 'flush', 'to', str(addr)], res) == 0:
                return True
        else:
            if run_command([iplink_cmd, neigh_af, 'neigh', 'flush', 'all'], res) == 0:
                return True

        return False

    # Flush the neighbors present in the non-default VRF
    if addr is not None and dev is not None:
        # When an address is set, it has to be on the particular interface.
        if len(dev) != 1:
            return False
        if run_command([iplink_cmd, 'netns', 'exec', vrf_name, 'ip', neigh_af,\
                   'neigh', 'flush', 'to', str(addr), 'dev', dev[0]], res) == 0:
            return True
    elif dev is not None:
        for ifname in dev:
            if run_command([iplink_cmd, 'netns', 'exec', vrf_name, 'ip', neigh_af,\
                   'neigh', 'flush', 'dev', ifname], res) != 0:
                return False
        return True
    elif addr is not None:
        if run_command([iplink_cmd, 'netns', 'exec', vrf_name, 'ip', neigh_af,\
                   'neigh', 'flush', 'to', str(addr)], res) == 0:
            return True
    else:
        if run_command([iplink_cmd, 'netns', 'exec', vrf_name, 'ip', neigh_af,\
                   'neigh', 'flush', 'all'], res) == 0:
            return True
    return False

def proxy_arp_config(if_name, proxy_arp_val, vrf_name='default'):
    res = []
    if vrf_name == 'default':
        if run_command(['sysctl', '-w', 'net.ipv4.conf.'+if_name+'.proxy_arp='+str(proxy_arp_val)], res) == 0:
            return True
        return False

    if run_command([iplink_cmd, 'netns', 'exec', vrf_name, 'sysctl', '-w',\
                   'net.ipv4.conf.'+if_name+'.proxy_arp='+str(proxy_arp_val)], res) == 0:
        return True
    return False

_linux_intf_key = cps.key_from_name('observed', 'base-if-linux/if/interfaces/interface')
def handle_interface_event_for_lla_cfg():
    _intf_evt_handle = cps.event_connect()
    cps.event_register(_intf_evt_handle, _linux_intf_key)

    while True:
        intf_evt = cps.event_wait(_intf_evt_handle)
        obj = cps_object.CPSObject(obj=intf_evt)
        if obj is None:
            continue

        if not 'operation' in intf_evt.keys():
            continue
        if (intf_evt['operation'] != 'create'):
            continue

        vrf_name = None
        intf_name = None
        intf_mac = None
        intf_admin_status = 0

        try:
            vrf_name = obj.get_attr_data('ni/if/interfaces/interface/bind-ni-name')
            intf_name = obj.get_attr_data('if/interfaces/interface/name')
            intf_mac = obj.get_attr_data('dell-if/if/interfaces/interface/phys-address')
            intf_admin_status = obj.get_attr_data('if/interfaces/interface/enabled')
            # if admin status is not enabled, ignore the interface event
            if intf_admin_status != 1:
                continue
        except ValueError as e:
            continue

        mac_list= intf_mac.split(':')
        # Create the LLA
        lla_addr = 'fe80::'+hex(int(mac_list[0],16)^2)[2:]+mac_list[1]+':'+mac_list[2]+\
                   'ff:fe'+mac_list[3]+':'+mac_list[4]+mac_list[5]
        lla_addr_with_prefix_len = lla_addr + '/64'
        # Configuring the LLA on the L2 intf will lead to error, pass the exception
        try:
            add_ip_addr(lla_addr_with_prefix_len, intf_name,"ipv6",vrf_name)
        except:
            pass


