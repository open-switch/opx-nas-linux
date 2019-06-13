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

"""This module provides a OPX base python API constructed
   around the ip[6]tables utility"""

import subprocess
import socket

iplink_cmd = '/sbin/ip'
ipv4_tables_cmd = '/sbin/iptables'
ipv6_tables_cmd = '/sbin/ip6tables'

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


def ip_tables_unreach_rule(vrf, is_add, enable, family, dev):
    res = []
    ip_table = None
    proto = None
    proto_type = None
    operation = None

    if family == socket.AF_INET:
        ip_table = ipv4_tables_cmd
        proto = 'icmp'
        proto_type = '--icmp-type'
    else:
        ip_table = ipv6_tables_cmd
        proto = 'icmpv6'
        proto_type = '--icmpv6-type'

    if is_add == 1:
        operation = '-I'
    else:
        operation = '-D'

    if enable == 1:
        action = 'ACCEPT'
    else:
        action = 'DROP'

    cmd = None
    if dev != None:
        if vrf == 'default':
            cmd = [ip_table, operation, 'OUTPUT', '-o', dev, '-p', proto, proto_type, 'destination-unreachable', '-j', action]
        else:
            cmd = [iplink_cmd, 'netns', 'exec', vrf, ip_table, operation, 'OUTPUT', '-o', dev,\
                  '-p', proto, proto_type, 'destination-unreachable', '-j', action]
    else:
        if vrf == 'default':
            cmd = [ip_table, operation, 'OUTPUT', '-p', proto, proto_type, 'destination-unreachable', '-j', action]
        else:
            cmd = [iplink_cmd, 'netns', 'exec', vrf, ip_table, operation, 'OUTPUT', '-p',\
                  proto, proto_type, 'destination-unreachable', '-j', action]
    if run_command(cmd, res) == 0:
        return True

    return False

