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

"""
This module provides support for caching VRF incoming & outgoing IP rules, as well as rule
configuration through iptables
"""

from dn_base_vrf_tool import iplink_cmd, run_command, log_info, log_err, get_ip_str,\
                             rej_rule_mark_value, vrf_chain_name, _vrf_name_to_id
from dn_base_vrf_tool import process_outgoing_ip_svcs_sub_net_config, get_veth_ip_str
from dn_base_id_tool import IdGenerator
import cps_object
import socket
import bisect
import threading
import logging
import copy
import binascii
from StringIO import StringIO
from enum import IntEnum
import re
import netaddr
import ipaddress

DEFAULT_VRF_ID = 0
MGMT_VRF_ID = 1024

""" Object to define VRF services rule definitions like
    Type, Action, Protocol, Group Priority.
"""
class VrfSvcsRuleType(IntEnum):
    RULE_TYPE_IP = 1
    RULE_TYPE_ACL = 2
    RULE_TYPE_OUT_IP = 3
    RULE_TYPE_SNAT = 4

class VrfSvcsRuleAction(IntEnum):
    """ actions defined in model,
        insert new action values per model before internal actions.
    """
    RULE_ACTION_ALLOW = 1
    RULE_ACTION_DENY = 2
    """ internal actions defined for kernel programming """
    RULE_ACTION_DNAT = 3
    RULE_ACTION_REJECT = 4
    RULE_ACTION_SNAT = 5

class VrfSvcsRuleProto(IntEnum):
    RULE_PROTO_TCP = 1
    RULE_PROTO_UDP = 2
    RULE_PROTO_ICMP = 3
    RULE_PROTO_ALL = 4
    RULE_PROTO_ICMPV6 = 5

class VrfSvcsRuleGroupPrio(IntEnum):
    HIGH_GRP_PRIO = 1
    DEFAULT_GRP_PRIO = 10

""" Object to define one VRF incoming IP service rule """
class VrfIncomingSvcsRule(object):

    KEY_ATTRS = ['rule_type', 'vrf_name', 'af', 'src_ip', 'src_prefix_len',
                 'protocol', 'dst_port', 'low_dst_port', 'high_dst_port',
                 'action', 'in_intf', 'dst_ip', 'dst_prefix_len']

    @classmethod
    def is_rule_equal(cls, r1, r2):
        if r1 is None or r2 is None:
            if r1 is None and r2 is None:
                return True
            else:
                return False
        r1_attrs = vars(r1)
        r2_attrs = vars(r2)
        for key_attr in cls.KEY_ATTRS:
            if key_attr in r1_attrs and key_attr in r2_attrs:
                if r1_attrs[key_attr] != r2_attrs[key_attr]:
                    return False
            else:
                if key_attr not in r1_attrs and key_attr not in r2_attrs:
                    continue
                return False
        return True

    def normalize_ip_prefix(self, ip_attr, prefix_attr):
        if ip_attr not in vars(self) or prefix_attr not in vars(self):
            return
        ip = vars(self)[ip_attr]
        prefix_len = vars(self)[prefix_attr]
        if ip is not None and prefix_len is not None:
            ip_net = netaddr.IPNetwork('%s/%d' % (socket.inet_ntop(self.af, ip),
                                                  prefix_len))
            ip = ip_net.cidr.ip.packed
        # anywhere IP address
        elif ip is None or ip == '\x00' * len(ip):
            prefix_len = 0
            if ip is None:
                ip_str = '0.0.0.0' if self.af == socket.AF_INET else '::'
                ip = socket.inet_pton(self.af, ip_str)
        else:
            return
        self.__setattr__(ip_attr, ip)
        self.__setattr__(prefix_attr, prefix_len)


    def __init__(self, rule_type, vrf_name, action, af, src_ip = None, src_prefix_len = None,
                 protocol = None, dst_port = None, dst_ip = None, dst_prefix_len = None, low_dst_port = None,
                 high_dst_port = None, seq_num = 0, rule_id = None, high_prio = False,
                 in_intf = None):
        """
        Constructor to create a ACL rule object
        @rule_type - either IP or ACL rule
        @vrf_name - namespace
        @action - 1: accept 2: drop 3: dnat
        @af - address family, either IPv4 or IPv6, it could be direct number or string
        @src_ip - matched source IP address
        @src_prefix_len - prefix length to specify source subnet
        @protocol - IP protocol: 1: tcp, 2: udp, 3: icmp, 4: all
        @dst_port - L4 destination port
        @low_dst_port - lower L4 destination port (inclusive)
        @high_dst_port - upper L4 destination port (inclusive)
        @dst_ip - specify destination IP address
        @dst_prefix_len - prefix length to specify destination subnet
        @seq_num - sequence number of the rule
        @rule_id - rule ID. it is optional
        @high_prio - if it is high priority rule
        @in_intf - interface where packets coming from
        """
        self.rule_type = rule_type
        self.vrf_name = vrf_name
        self.af = af
        self.src_ip = src_ip
        self.src_prefix_len = src_prefix_len
        self.protocol = protocol
        self.dst_port = dst_port
        self.low_dst_port = low_dst_port
        self.high_dst_port = high_dst_port
        self.dst_ip = dst_ip
        self.dst_prefix_len = dst_prefix_len
        self.seq_num = seq_num
        self.action = action
        self.grp_priority = high_prio
        self.packet_count = None
        self.byte_count = None
        if self.action == VrfSvcsRuleAction.RULE_ACTION_DNAT and self.dst_ip is None:
            log_err('Destination IP is mandatory for DNAT action')
            raise ValueError
        if self.action == VrfSvcsRuleAction.RULE_ACTION_DENY and self.rule_type == VrfSvcsRuleType.RULE_TYPE_ACL:
            # For ACL rule, use REJECT action instead of DROP
            self.action = VrfSvcsRuleAction.RULE_ACTION_REJECT
        self.rule_id = rule_id
        self.in_intf = in_intf
        self.normalize_ip_prefix('src_ip', 'src_prefix_len')
        self.normalize_ip_prefix('dst_ip', 'dst_prefix_len')

    def __setattr__(self, key, val):
        if key == 'grp_priority' and val is not None:
            if val:
                val = VrfSvcsRuleGroupPrio.HIGH_GRP_PRIO
            else:
                val = VrfSvcsRuleGroupPrio.DEFAULT_GRP_PRIO
        elif key == 'in_intf' and val is not None:
            if len(val) > 0 and val[0] == '!':
                val = val[1:]
                super(VrfIncomingSvcsRule, self).__setattr__('negative', True)
            else:
                super(VrfIncomingSvcsRule, self).__setattr__('negative', False)
        super(VrfIncomingSvcsRule, self).__setattr__(key, val)
        if key == 'rule_type' and self.get_rule_type_name() is None:
            log_err('Invalid rule type %s' % str(self.rule_type))
            raise ValueError
        elif key == 'af' and self.get_af_name() is None:
            log_err('Invalid address family number %s' % str(self.af))
            raise ValueError
        elif key == 'action' and self.get_action_name() is None:
            log_err('Invalid action ID %s' % str(self.action))
            raise ValueError

        if val is not None:
            if key == 'protocol' and self.get_proto_name() is None:
                log_err('Invalid protocol number %s' % str(self.protocol))
                raise ValueError

    def __eq__(self, other):
        return VrfIncomingSvcsRule.is_rule_equal(self, other)

    def __ne__(self, other):
        return not VrfIncomingSvcsRule.is_rule_equal(self, other)

    def __hash__(self):
        hash_val = 0
        attrs = vars(self)
        for key_attr in self.KEY_ATTRS:
            if key_attr in attrs and attrs[key_attr] is not None:
                hash_val ^= hash(attrs[key_attr])
        return hash_val

    def get_rule_type_name(self):
        type_name_map = {VrfSvcsRuleType.RULE_TYPE_IP: 'IP',
                         VrfSvcsRuleType.RULE_TYPE_ACL: 'ACL'}
        if self.rule_type in type_name_map:
            return type_name_map[self.rule_type]
        else:
            return None

    def get_af_name(self):
        af_name_map = {socket.AF_INET: 'IPv4', socket.AF_INET6: 'IPv6'}
        if self.af in af_name_map:
            return af_name_map[self.af]
        else:
            return None

    def get_action_name(self, for_ipt_target = False):
        action_name_map = {VrfSvcsRuleAction.RULE_ACTION_ALLOW: ('allow', 'accept'),
                           VrfSvcsRuleAction.RULE_ACTION_DENY: ('deny', 'drop'),
                           VrfSvcsRuleAction.RULE_ACTION_DNAT: 'dnat',
                           VrfSvcsRuleAction.RULE_ACTION_REJECT: ('reject', 'mark')}
        if self.action in action_name_map:
            action_name = action_name_map[self.action]
            if type(action_name) is tuple:
                return action_name[1] if for_ipt_target else action_name[0]
            else:
                return action_name
        else:
            return None

    def get_proto_name(self):
        proto_name_map = {VrfSvcsRuleProto.RULE_PROTO_TCP: 'tcp',
                          VrfSvcsRuleProto.RULE_PROTO_UDP: 'udp',
                          VrfSvcsRuleProto.RULE_PROTO_ICMP: 'icmp',
                          VrfSvcsRuleProto.RULE_PROTO_ICMPV6: 'icmpv6',
                          VrfSvcsRuleProto.RULE_PROTO_ALL: 'ip'}
        if self.protocol in proto_name_map:
            return proto_name_map[self.protocol]
        else:
            return None

    def __str__(self):
        # <type> <id> VRF <vrf> SEQ <prio>-<seq> RULE <action> AF <af> [src_ip/pfx][dst_ip/pfx][proto][port][port_range][iif]
        ret_str =  ('%-5s %-8sVRF %-10s SEQ %5d-%-4d RULE %-10s AF %s %s%s%s%s%s%s' %
                        (self.get_rule_type_name(),
                         ('-' if self.rule_id is None else ('%d' % self.rule_id)),
                         self.vrf_name, self.grp_priority, self.seq_num,
                         ('%s' % self.get_action_name() if self.action is not None else ''),
                         self.get_af_name(),
                         (' SIP %s/%d' % (socket.inet_ntop(self.af, self.src_ip), self.src_prefix_len) \
                            if self.src_ip is not None and self.src_prefix_len is not None else ''),
                         (' DIP %s/%d' % (socket.inet_ntop(self.af, self.dst_ip), self.dst_prefix_len) \
                            if self.dst_ip is not None and self.dst_prefix_len is not None else ''),
                         (' %s' % self.get_proto_name() if self.protocol is not None else ''),
                         (' DST_PORT %d' % self.dst_port if self.dst_port is not None else ''),
                         (' DST_PORT RANGE %d-%d' % (self.low_dst_port, self.high_dst_port) \
                            if self.low_dst_port is not None else ''),
                         (' IIF %s%s' % (('not ' if self.negative else ''), self.in_intf) if self.in_intf is not None else '')))
        return ret_str

    def to_cps_obj(self):
        cps_attr_map = {
            'vrf_name': 'ni-name',
            'af': 'af',
            'src_ip': 'src-ip',
            'src_prefix_len': 'src-prefix-len',
            'dst_ip': 'dst-ip',
            'dst_prefix_len': 'dst-prefix-len',
            'protocol': 'protocol',
            'dst_port': 'dst-port',
            'low_dst_port': 'lower-dst-port',
            'high_dst_port': 'upper-dst-port',
            'action': 'action',
            'seq_num': 'seq-num',
            'in_intf': 'ifname',
            'rule_id': 'id',
            'packet_count': 'matched-packets',
            'byte_count': 'matched-bytes'}
        obj = cps_object.CPSObject('vrf-firewall/ns-incoming-service')
        for attr_name, attr_val in vars(self).items():
            if attr_name in cps_attr_map and attr_val is not None:
                if attr_name == 'action':
                    if attr_val == VrfSvcsRuleAction.RULE_ACTION_DNAT:
                        # Always use allow action for DNAT
                        attr_val = VrfSvcsRuleAction.RULE_ACTION_ALLOW
                    elif attr_val == VrfSvcsRuleAction.RULE_ACTION_REJECT:
                        # Use deny action for cps get output
                        attr_val = VrfSvcsRuleAction.RULE_ACTION_DENY
                if attr_name == 'src_ip':
                    attr_val = binascii.hexlify(attr_val)
                if attr_name == 'in_intf' and self.negative is True:
                    attr_val = '!'+ attr_val
                if (attr_name == 'dst_ip' or attr_name == 'dst_prefix_len') and \
                        self.rule_type == VrfSvcsRuleType.RULE_TYPE_IP:
                    # Only show dst_ip for ACL rule
                    continue
                if attr_name == 'dst_ip':
                    attr_val = binascii.hexlify(attr_val)
                if attr_name == 'packet_count' and attr_val is None:
                    continue
                if attr_name == 'byte_count' and attr_val is None:
                    continue
                obj.add_attr(cps_attr_map[attr_name], attr_val)
        return obj

    def match(self, **params):
        attrs = vars(self)
        for key, val in params.items():
            if key not in attrs:
                return False
            if val is not None and val != attrs[key]:
                return False
        return True

class VrfIncomingSvcsRuleList(list):
    def __init__(self):
        super(VrfIncomingSvcsRuleList, self).__init__()
        # sorted list of all seq num
        self.seq_num_list = []
        # map: rule_id => rule position in list
        self.rule_id_map = {}

    def __str__(self):
        str_buf = StringIO()
        for rule in self:
            str_buf.write('%s\n' % rule)
        out_str = str_buf.getvalue()
        str_buf.close()
        return out_str

    def __eq__(self, other):
        return super(VrfIncomingSvcsRuleList, self).__eq__(other)

    def __ne__(self, other):
        return super(VrfIncomingSvcsRuleList, self).__ne__(other)

    def update_rule_id_map(self, start_idx):
        for idx in range(start_idx, len(self)):
            self.rule_id_map[self[idx].rule_id] = idx

    # insert rule to list, update seq_num list and rule_id map
    def insert(self, rule):
        if rule.rule_id is None or rule.rule_id in self.rule_id_map:
            # rule ID should be assigned and not used by another rule
            log_err('Rule ID is not assigned' if rule.rule_id is None
                    else ('Rule ID %d is used' % rule.rule_id))
            return None
        try:
            idx = self.index(rule)
        except ValueError:
            idx = None
        if idx is not None:
            # same rule already in list
            log_err('Rule to be inserted is already in list')
            return None
        idx = bisect.bisect_right(self.seq_num_list, (rule.grp_priority, rule.seq_num))
        super(VrfIncomingSvcsRuleList, self).insert(idx, rule)
        self.seq_num_list.insert(idx, (rule.grp_priority, rule.seq_num))
        self.update_rule_id_map(idx)
        return idx

    def remove(self, rule):
        if rule.rule_id is not None and rule.rule_id in self.rule_id_map:
            idx = self.rule_id_map[rule.rule_id]
            rule_id = rule.rule_id
        else:
            try:
                idx = self.index(rule)
            except ValueError:
                # rule not found
                log_err('Rule not found for delete')
                return None
            rule_id = self[idx].rule_id
        orig_rule = self[idx]
        del self[idx]
        del self.seq_num_list[idx]
        del self.rule_id_map[rule_id]
        self.update_rule_id_map(idx)
        return (orig_rule, idx)

    def remove_by_id(self, rule_id):
        if rule_id not in self.rule_id_map:
            return None
        idx = self.rule_id_map[rule_id]
        orig_rule = self[idx]
        del self[idx]
        del self.seq_num_list[idx]
        del self.rule_id_map[rule_id]
        self.update_rule_id_map(idx)
        return orig_rule

    def clear(self):
        del self[:]
        del self.seq_num_list[:]
        self.rule_id_map.clear()

#IP tables handler for both incoming & outgoing service configurations
class IptablesHandler:
    PKT_CNT_TK_ID = 0
    BYTE_CNT_TK_ID = 1
    TARGET_TK_ID = 2
    PROTO_TK_ID = 3
    IN_IF_TK_ID = 4
    OUT_IF_TK_ID = 5
    SRC_IP_TK_ID = 6
    DST_IP_TK_ID = 7
    OPT_TK_ID = 8
    MIN_TK_NUM = 9

    @classmethod
    def is_vrf_valid(cls, vrf_name):
        cmd = [iplink_cmd, 'netns', 'show']
        res = []
        if run_command(cmd, res) != 0:
            log_err('Failed to run command: %s' % ' '.join(cmd))
            return False
        for token in res:
            m = re.search('(.*)\s+\(id:\s+(\S+)\)', token)
            if m is not None:
                vrf, _ = m.groups()
            else:
                vrf = token
            if vrf == vrf_name:
                return True
        return False

    @classmethod
    def get_chain_name(cls, vrf_name, rule_type):
        if rule_type == VrfSvcsRuleType.RULE_TYPE_IP:
            chain_name = 'INPUT' if vrf_name == 'default' else vrf_chain_name
        elif rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP:
            chain_name = 'PREROUTING'
        elif rule_type == VrfSvcsRuleType.RULE_TYPE_SNAT:
            chain_name = 'POSTROUTING'
        else:
            chain_name = vrf_chain_name
        return chain_name

    @classmethod
    def get_ipt_cmd_prefix(cls, rule_type, af, vrf_name):
        iptables = 'iptables' if af == socket.AF_INET else 'ip6tables'
        if vrf_name == 'default':
            ipt_prefix = ['/sbin/%s' % iptables]
            #tbl_name = (None if rule_type == VrfSvcsRuleType.RULE_TYPE_IP else 'raw')
            if rule_type == VrfSvcsRuleType.RULE_TYPE_IP:
                tbl_name = None
            elif rule_type == VrfSvcsRuleType.RULE_TYPE_SNAT:
                tbl_name = 'nat'
            else :
                tbl_name = 'raw'
        else:
            ipt_prefix = [iplink_cmd, 'netns', 'exec', vrf_name, iptables]
            #tbl_name = ('nat' if rule_type == VrfSvcsRuleType.RULE_TYPE_IP else 'raw')
            if rule_type == VrfSvcsRuleType.RULE_TYPE_IP or\
                rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP or\
                rule_type == VrfSvcsRuleType.RULE_TYPE_SNAT:
                tbl_name = 'nat'
            else :
                tbl_name = 'raw'
        if tbl_name is not None:
            ipt_prefix += ['-t', tbl_name]
        return ipt_prefix

    @classmethod
    def find_stats_info(cls, pattern, line):
        """Method to parse regex matching return value"""
        match = re.match(pattern, line)
        if match is None:
            return (None, None)
        match = match.group()
        stats_pattern = re.compile(r'\d+')
        stats_list = stats_pattern.findall(match)
        #number at first position is packet count and the one at second position is byte count.
        return (stats_list[0], stats_list[1])

    @classmethod
    def parse_rule_stats(cls, result):
        packets, bytes = cls.find_stats_info(r'\s+\d+\s+\d+\s+', result)
        return (packets, bytes)

    @classmethod
    def proc_rule(cls, op, rule, idx = None):
        if (op.lower() == 'delete' and rule.vrf_name != 'default' and
            not cls.is_vrf_valid(rule.vrf_name)):
            log_info('VRF %s is not opened, bypass iptables setting.' % rule.vrf_name)
            return True

        if (op.lower() == 'get' and rule.vrf_name != 'default' and
            not IptablesHandler.is_vrf_valid(rule.vrf_name)):
            log_info('VRF %s is not opened, bypass iptables get.' % rule.vrf_name)
            return True

        """ outgoing IP services rules are not allowed in default VRF """
        if rule.vrf_name == 'default' and rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP:
            log_info('Invalid Rule. rule type %s not supported in VRF:%s.' % (rule.rule_type, rule.vrf_name))
            return False

        if op == 'replace' and idx is None:
            log_err('Missing rule index for replace operation')
            return False

        ipt_prefix = cls.get_ipt_cmd_prefix(rule.rule_type, rule.af, rule.vrf_name)

        # Set protocol related filtering options
        flt_args = []
        if rule.src_ip is not None:
            flt_args += ['-s', '%s%s' % (socket.inet_ntop(rule.af, rule.src_ip),
                                        ('/%d' % rule.src_prefix_len if rule.src_prefix_len is not None else ''))]
        if rule.protocol is not None:
            flt_args += ['-p', rule.get_proto_name()]

        if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP:
            flt_args += ['--dport', str(rule.private_port)]
        elif rule.dst_port is not None:
            flt_args += ['--dport', str(rule.dst_port)]

        if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_ACL and rule.low_dst_port is not None:
            flt_args += ['--match', 'multiport', '--dports',
                         '%s:%s' % (str(rule.low_dst_port), str(rule.high_dst_port))]

        if (rule.rule_type == VrfSvcsRuleType.RULE_TYPE_SNAT or\
            rule.rule_type == VrfSvcsRuleType.RULE_TYPE_ACL or \
            (rule.vrf_name == 'default' and \
             rule.rule_type == VrfSvcsRuleType.RULE_TYPE_IP)) and rule.dst_ip is not None:
            flt_args += ['-d', '%s%s' % (socket.inet_ntop(rule.af, rule.dst_ip),
                                        ('/%d' % rule.dst_prefix_len if rule.dst_prefix_len is not None else ''))]

        # Set interface filtering options
        if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_IP:
            # Allow the IP services only from mgmt and data VRFs if configured, any IP services received
            # in front panel ports will be ignored.
            if rule.vrf_name == 'default':
                if rule.in_intf is not None:
                    flt_args += ['-i', rule.in_intf]
                else:
                    flt_args += ['!', '-i', 'vdst-nsid+']
        elif rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP:
            vrf_id = None
            vrf_id = _vrf_name_to_id.get(rule.vrf_name, None)
            if vrf_id is not None:
                flt_args += ['-i', 'vdst-nsid%d'%DEFAULT_VRF_ID]
                # Do the DNAT operation for IP services destined to interval veth IP,
                # all the other traffic forwarding via veth should not affect this DNAT rule.
                flt_args += ['-d', '%s' % (get_veth_ip_str(rule.af, rule.vrf_name, False))]
        elif rule.rule_type == VrfSvcsRuleType.RULE_TYPE_SNAT:
            #in management/data vrf, apply SNAT rules on interfaces other than internal veth interfaces.
            if rule.vrf_name != 'default':
                flt_args += ['!', '-o', 'vdst-nsid%d'%DEFAULT_VRF_ID]
        else:
            if rule.in_intf is not None:
                if rule.negative:
                    flt_args.append('!')
                flt_args += ['-i', rule.in_intf]

        # Set rule action
        flt_args += ['-j', rule.get_action_name(True).upper()]
        if rule.action == VrfSvcsRuleAction.RULE_ACTION_DNAT:
            if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP:
                if rule.af == socket.AF_INET:
                    flt_args += ['--to-destination',
                             '%s:%s' % (socket.inet_ntop(rule.af, rule.dst_ip),str(rule.dst_port))]
                else:
                    flt_args += ['--to-destination',
                             '[%s]:%s' % (socket.inet_ntop(rule.af, rule.dst_ip),str(rule.dst_port))]
            else:
                flt_args += ['--to-destination', '%s' % (socket.inet_ntop(rule.af, rule.dst_ip))]
        elif rule.action == VrfSvcsRuleAction.RULE_ACTION_REJECT:
            flt_args += ['--set-mark', str(rej_rule_mark_value)]
        elif rule.action == VrfSvcsRuleAction.RULE_ACTION_SNAT:
            flt_args += ['--to-source', '%s' % (socket.inet_ntop(rule.af, rule.out_src_ip))]

        # Chain configuration
        chain_name = cls.get_chain_name(rule.vrf_name, rule.rule_type)
        if op.lower() == 'insert':
            if idx is None:
                chain_args = ['-A', chain_name]
            else:
                chain_args = ['-I', chain_name, '%d' % (idx + 1)]
            cmd = ipt_prefix + chain_args + flt_args
        elif op.lower() == 'delete':
            chain_args = ['-D', chain_name]
            if idx is not None:
                chain_args.append('%d' % (idx + 1))
            cmd = ipt_prefix + chain_args
            if idx is None:
                cmd += flt_args
        elif op.lower() == 'replace':
            chain_args = ['-R', chain_name]
            chain_args.append('%d' % (idx + 1))
            cmd = ipt_prefix + chain_args + flt_args
        elif op.lower() == 'check':
            chain_args = ['-C', chain_name]
            cmd = ipt_prefix + chain_args + flt_args
        elif op.lower() == 'get':
            if idx is None:
                log_err('Invalid idx for operation %s' % op)
                return False
            chain_args = ['-xvL', chain_name, '%d' % (idx + 1)]
            cmd = ipt_prefix + chain_args

            log_info('GET CMD: %s' % ' '.join(cmd))
            res = []
            if run_command(cmd, res, op.lower() != 'check') != 0:
                log_err('Invalid idx for operation:%s, error:%s' % (op, res))
                return False
            else:
                if res[0] is not None:
                    rule.packet_count, rule.byte_count = cls.parse_rule_stats(res[0])
                log_info('Rule stats, packet_count:%s, byte_count:%s' %(rule.packet_count, rule.byte_count))
                return True
        else:
            log_err('Invalid operation %s' % op)
            return False

        log_info('CMD: %s' % ' '.join(cmd))
        res = []
        return run_command(cmd, res, op.lower() != 'check') == 0

    @classmethod
    def get_l4_port_num(cls, port_str):
        if port_str.isdigit():
            port_num = int(port_str)
        else:
            try:
                port_num = socket.getservbyname(port_str)
            except socket.error:
                return None
        return port_num

    @classmethod
    def get_ip_prefix(cls, af, ip_str):
        if ip_str == 'anywhere':
            return (None, None)
        else:
            try:
                ip_mask = ip_str.split('/')
                ip_addr = socket.inet_pton(af, ip_mask[0])
                if len(ip_mask) > 1:
                    prefix_len = int(ip_mask[1])
                else:
                    prefix_len = ipaddress.IPV4LENGTH if af == socket.AF_INET else ipaddress.IPV6LENGTH
            except ValueError, socket.error:
                return (None, None)
        return (ip_addr, prefix_len)

    @classmethod
    def ipt_tokens_to_rule(cls, rule_type, af, vrf_name, tokens):
        if len(tokens) < cls.MIN_TK_NUM:
            return None
        log_info('TOKENS: %s' % tokens)
        dst_ip = None
        dst_prefix_len = None
        dst_port = None
        low_port = high_port = None
        if tokens[cls.TARGET_TK_ID] == 'ACCEPT':
            action = VrfSvcsRuleAction.RULE_ACTION_ALLOW
        elif tokens[cls.TARGET_TK_ID] == 'DROP':
            action = VrfSvcsRuleAction.RULE_ACTION_DENY
        elif tokens[cls.TARGET_TK_ID] == 'MARK':
            mo = re.search('MARK\s+set\s+(\S+)', tokens[cls.OPT_TK_ID])
            if mo is None or len(mo.groups()) < 1:
                return None
            try:
                mark_num = int(mo.groups()[0], 16)
            except ValueError:
                return None
            if mark_num != rej_rule_mark_value:
                return None
            action = VrfSvcsRuleAction.RULE_ACTION_REJECT
        elif tokens[cls.TARGET_TK_ID] == 'DNAT':
            mo = re.search('to:(\S+)', tokens[cls.OPT_TK_ID])
            if mo is None or len(mo.groups()) < 1:
                return None
            try:
                dst_ip = socket.inet_pton(af, mo.groups()[0])
            except socket.error:
                return None
            action = VrfSvcsRuleAction.RULE_ACTION_DNAT
        else:
            log_err('Invalid target %s' % tokens[cls.TARGET_TK_ID])
            return None
        protocol = None
        proto_type_map = {'tcp': VrfSvcsRuleProto.RULE_PROTO_TCP,
                          'udp': VrfSvcsRuleProto.RULE_PROTO_UDP,
                          'icmp': VrfSvcsRuleProto.RULE_PROTO_ICMP,
                          'icmpv6': VrfSvcsRuleProto.RULE_PROTO_ICMPV6}
        if tokens[cls.PROTO_TK_ID] in proto_type_map:
            protocol = proto_type_map[tokens[cls.PROTO_TK_ID]]
        if tokens[cls.IN_IF_TK_ID] == 'any':
            in_intf = None
        else:
            in_intf = tokens[cls.IN_IF_TK_ID]
        if (rule_type == VrfSvcsRuleType.RULE_TYPE_IP and vrf_name == 'default' and
            in_intf == '!vdst-nsid+'):
            in_intf = None
        src_ip, src_prefix_len = cls.get_ip_prefix(af, tokens[cls.SRC_IP_TK_ID])
        if rule_type == VrfSvcsRuleType.RULE_TYPE_ACL:
            dst_ip, dst_prefix_len = cls.get_ip_prefix(af, tokens[cls.DST_IP_TK_ID])
        mo = re.search('dpt:(\S+)', tokens[cls.OPT_TK_ID])
        if mo is not None and mo.groups() > 0:
            dst_port = cls.get_l4_port_num(mo.groups()[0])
            if dst_port is None:
                log_err('Failed to get L4 destination port from token %s' % tokens[cls.OPT_TK_ID])
                return None
        mo = re.search('multiport\s+dports\s+(\S+):(\S+)', tokens[cls.OPT_TK_ID])
        if mo is not None and mo.groups() >= 2:
            low_port = cls.get_l4_port_num(mo.groups()[0])
            high_port = cls.get_l4_port_num(mo.groups()[1])
            if low_port is None or high_port is None:
                log_err('Failed to get L4 destination port range from token %s' % tokens[cls.OPT_TK_ID])
                return None
        rule = VrfIncomingSvcsRule(rule_type, vrf_name, action, af, src_ip = src_ip, src_prefix_len = src_prefix_len,
                                   protocol = protocol, dst_port = dst_port,
                                   dst_ip = dst_ip, dst_prefix_len = dst_prefix_len, in_intf = in_intf,
                                   low_dst_port = low_port, high_dst_port = high_port)
        log_info('RULE: %s' % rule)
        return rule

    @classmethod
    def get_rule_from_ipt(cls, rule_type, af, vrf_name, rule_list):
        cmd = cls.get_ipt_cmd_prefix(rule_type, af, vrf_name)
        cmd += ['-L', cls.get_chain_name(vrf_name, rule_type), '-v']
        log_info('GET_CMD: %s' % ' '.join(cmd))
        res = []
        if run_command(cmd, res) != 0:
            log_err('Failed to read iptables rules')
            return False
        start = False
        for line in res:
            if start:
                max_split = cls.MIN_TK_NUM if af == socket.AF_INET else cls.MIN_TK_NUM - 1
                tokens = line.split(None, max_split)
                if len(tokens) < cls.MIN_TK_NUM - 1:
                    log_err('Invalid number of tokens in line: %s' % tokens)
                    continue
                if af == socket.AF_INET:
                    # OPT field
                    del tokens[4]
                if len(tokens) < cls.MIN_TK_NUM:
                    # add empty optional field
                    tokens.append('')
                rule = cls.ipt_tokens_to_rule(rule_type, af, vrf_name, tokens)
                if rule is None:
                    log_err('Failed to get ACL rule from tokens: %s' % tokens)
                    continue
                rule_list.append(rule)
            else:
                ret_val = re.match('pkts\s+bytes\s+target\s+prot\s+opt\s+in\s+out\s+source\s+destination',
                                   line.lstrip())
                if ret_val is not None:
                    start = True

        return True

class VrfIncomingSvcsRuleCache:
    # map: af, vrf_name => rule_list
    acl_rules = {socket.AF_INET: {}, socket.AF_INET6: {}}
    ip_rules = {socket.AF_INET: {}, socket.AF_INET6: {}}
    mutex = threading.RLock()
    id_generator = IdGenerator()

    @classmethod
    def insert_rule(cls, rule):
        log_info('Handling add rule: %s' % rule)
        cls.mutex.acquire()
        rule_list = cls.ip_rules[rule.af] if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_IP else cls.acl_rules[rule.af]
        if rule.vrf_name not in rule_list:
            rule_list[rule.vrf_name] = VrfIncomingSvcsRuleList()
        if rule.rule_id is None:
            rule.rule_id = cls.id_generator.get_new_id()
            if rule.rule_id is None:
                log_err('Could not generate new rule ID')
                log_info(str(cls.id_generator))
                cls.mutex.release()
                return False
        else:
            if cls.id_generator.is_id_used(rule.rule_id):
                log_err('Given rule ID %d is used' % rule.rule_id)
                log_info(str(cls.id_generator))
                cls.mutex.release()
                return False
            if not cls.id_generator.reserve_id(rule.rule_id):
                log_err('Failed to reserve rule ID %d' % rule.rule_id)
                log_info(str(cls.id_generator))
                cls.mutex.release()
                return False
        ret_val = True
        idx = rule_list[rule.vrf_name].insert(rule)
        if idx is not None:
            if not IptablesHandler.proc_rule('insert', rule, idx):
                log_err('Failed to call iptables to insert ACL rule')
                # rollback
                rule_list[rule.vrf_name].remove(rule)
                ret_val = False
        else:
            log_err('Failed to insert rule to cache')
            cls.id_generator.release_id(rule.rule_id)
            ret_val = False
        cls.mutex.release()
        if ret_val:
            log_info('Rule added, ID=%d' % rule.rule_id)
        return ret_val

    @classmethod
    def delete_rule(cls, rule):
        log_info('Handling delete rule: %s' % rule)
        cls.mutex.acquire()
        rule_list = cls.ip_rules[rule.af] if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_IP else cls.acl_rules[rule.af]
        if rule.vrf_name not in rule_list:
            log_err('VRF name %s not found in cache' % rule.vrf_name)
            cls.mutex.release()
            return False
        ret_val = rule_list[rule.vrf_name].remove(rule)
        if ret_val is None:
            log_err('Failed to delete rule from cache')
            cls.mutex.release()
            return False
        del_rule, idx = ret_val
        ret_val = True
        if not IptablesHandler.proc_rule('delete', del_rule, idx):
            log_err('Failed to call iptables to delete ACL rule')
            # rollback
            rule_list[del_rule.vrf_name].insert(del_rule)
            ret_val = False
        if len(rule_list[rule.vrf_name]) == 0:
            del rule_list[rule.vrf_name]
        cls.mutex.release()
        if ret_val:
            if not cls.id_generator.release_id(del_rule.rule_id):
                log_err('Failed to release rule ID %d' % del_rule.rule_id)
                log_info(str(cls.id_generator))
            log_info('Rule deleted')
        return ret_val

    @classmethod
    def find_rule_by_id(cls, rule_id):
        ret_val = None
        cls.mutex.acquire()
        for af in [socket.AF_INET, socket.AF_INET6]:
            for vrf_name, rule_list in cls.ip_rules[af].items():
                if rule_id in rule_list.rule_id_map:
                    idx = rule_list.rule_id_map[rule_id]
                    ret_val = (rule_list[idx], idx)
                    IptablesHandler.proc_rule('get', rule_list[idx], idx)
                    break
            if ret_val is not None:
                break
            for vrf_name, rule_list in cls.acl_rules[af].items():
                if rule_id in rule_list.rule_id_map:
                    idx = rule_list.rule_id_map[rule_id]
                    ret_val = (rule_list[idx], idx)
                    IptablesHandler.proc_rule('get', rule_list[idx], idx)
                    break
            if ret_val is not None:
                break
        cls.mutex.release()
        return ret_val

    @classmethod
    def find_rule_by_match(cls, rule):
        cls.mutex.acquire()
        rule_list = cls.ip_rules[rule.af] if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_IP else cls.acl_rules[rule.af]
        if rule.vrf_name not in rule_list:
            cls.mutex.release()
            return None
        try:
            idx = rule_list[rule.vrf_name].index(rule)
        except ValueError:
            cls.mutex.release()
            return None
        cls.mutex.release()
        return rule_list[rule.vrf_name][idx]

    @classmethod
    def delete_rule_by_id(cls, rule_id):
        log_info('Handling delete rule by ID: %d' % rule_id)
        cls.mutex.acquire()
        ret_val = True
        found_rule = cls.find_rule_by_id(rule_id)
        if found_rule is not None:
            del_rule, idx = found_rule
            rule_list = cls.ip_rules[del_rule.af] \
                if del_rule.rule_type == VrfSvcsRuleType.RULE_TYPE_IP else cls.acl_rules[del_rule.af]
            if rule_list[del_rule.vrf_name].remove_by_id(rule_id) is None:
                log_err('Failed to remove rule with ID %d' % rule_id)
                cls.mutex.release()
                return False
            if not IptablesHandler.proc_rule('delete', del_rule, idx):
                log_err('Failed to call iptables to delete ACL rule')
                # rollback
                rule_list = cls.ip_rules[del_rule.af] \
                    if del_rule.rule_type == VrfSvcsRuleType.RULE_TYPE_IP else cls.acl_rules[del_rule.af]
                rule_list[del_rule.vrf_name].insert(del_rule)
                ret_val = False
            if len(rule_list[del_rule.vrf_name]) == 0:
                del rule_list[del_rule.vrf_name]
        else:
            log_err('Rule ID %d not found for delete' % rule_id)
            ret_val = False
        cls.mutex.release()
        if ret_val:
            if not cls.id_generator.release_id(rule_id):
                log_err('Failed to release rule ID %d' % rule_id)
                log_info(str(cls.id_generator))
            log_info('Rule deleted')
        return ret_val

    @classmethod
    def replace_rule(cls, rule_id, new_rule):
        log_info('Handling replace rule with ID %d' % rule_id)
        cls.mutex.acquire()
        ret_val = True
        found_rule = cls.find_rule_by_id(rule_id)
        if found_rule is not None:
            old_rule, idx = found_rule
            rule_list = cls.ip_rules[old_rule.af] \
                if old_rule.rule_type == VrfSvcsRuleType.RULE_TYPE_IP else cls.acl_rules[old_rule.af]
            if not IptablesHandler.proc_rule('replace', new_rule, idx):
                log_err('Failed to call iptables to replace ACL rule')
                ret_val = False
            else:
                rule_list[old_rule.vrf_name][idx] = new_rule
        else:
            log_err('Rule ID %d not found for replace' % rule_id)
            ret_val = False
        cls.mutex.release()
        if ret_val:
            log_info('Rule replaced')
        return ret_val

    @classmethod
    def update_rule(cls, rule_id, **params):
        log_info('Handling update rule: ID %d param %s' % (rule_id, params))
        cls.mutex.acquire()
        found_rule = cls.find_rule_by_id(rule_id)
        if found_rule is None:
            log_err('Rule ID %d not found for update' % rule_id)
            cls.mutex.release()
            return False
        old_rule, _ = found_rule
        upd_rule = copy.deepcopy(old_rule)
        changed_attrs = set()

        def check_and_set(rule, key, val):
            try:
                orig_val = getattr(rule, key)
            except AttributeError:
                orig_val = None
            if val != orig_val:
                if val is not None:
                    setattr(rule, key, val)
                else:
                    delattr(rule, key)
                changed_attrs.add(key)

        for key, val in params.items():
            if val is not None:
                check_and_set(upd_rule, key, val)
        if len(changed_attrs) == 0:
            log_info('There is no change to be updated, just return')
            cls.mutex.release()
            return True

        log_info('old_rule: %s' % old_rule)
        log_info('new_rule: %s' % upd_rule)

        match_rule = cls.find_rule_by_match(upd_rule)
        if match_rule is not None and match_rule.rule_id != old_rule.rule_id:
            log_err('The updating rule already exists')
            cls.mutex.release()
            return False

        repl_attrs = {'src_ip', 'src_prefix_len', 'dst_ip', 'dst_prefix_len', 'protocol', 'dst_port',
                      'low_dst_port', 'high_dst_port', 'action', 'in_intf'}
        no_repl_attrs = changed_attrs.difference(repl_attrs)
        if len(no_repl_attrs) > 0:
            log_info('Non-replacable attributes %s changed, delete and add rule' % no_repl_attrs)
            if not cls.delete_rule_by_id(rule_id):
                log_err('Failed to delete existing rule by ID')
                cls.mutex.release()
                return False

            ret_val = cls.insert_rule(upd_rule)
            if not ret_val:
                log_err('Failed to insert updated rule')
                cls.insert_rule(old_rule)
        else:
            log_info('Only replacable attributes changed, just replace rule')
            ret_val = cls.replace_rule(rule_id, upd_rule)
            if not ret_val:
                log_err('Failed to replace rule')
        cls.mutex.release()
        if ret_val:
            log_info('Rule updated')
        return ret_val

    @classmethod
    def clear_all_rules(cls, flt_vrf = None, flt_af = None):
        log_info('Handling clear all rules for VRF %s and AF %s' % (
                    flt_vrf if flt_vrf is not None else '-',
                    str(flt_af) if flt_af is not None else '-'))
        cls.mutex.acquire()
        for af in [socket.AF_INET, socket.AF_INET6]:
            if flt_af is not None and flt_af != af:
                continue
            for vrf_name, rule_list in cls.ip_rules[af].items():
                if flt_vrf is not None and flt_vrf != vrf_name:
                    continue
                for rule in rule_list:
                    IptablesHandler.proc_rule('delete', rule)
                    cls.id_generator.release_id(rule.rule_id)
                rule_list.clear()
                del cls.ip_rules[af][vrf_name]
            for vrf_name, rule_list in cls.acl_rules[af].items():
                if flt_vrf is not None and flt_vrf != vrf_name:
                    continue
                for rule in rule_list:
                    IptablesHandler.proc_rule('delete', rule)
                    cls.id_generator.release_id(rule.rule_id)
                rule_list.clear()
                del cls.acl_rules[af][vrf_name]
        cls.mutex.release()

    @classmethod
    def dump_rules(cls):
        cls.mutex.acquire()
        for af in [socket.AF_INET, socket.AF_INET6]:
            for vrf_name, rule_list in cls.ip_rules[af].items():
                log_info('-------------------------------------')
                log_info(' %s IP Rules of VRF %s' % ('IPv4' if af == socket.AF_INET else 'IPv6', vrf_name))
                log_info('-------------------------------------')
                log_info('\n%s\n' % rule_list)
            for vrf_name, rule_list in cls.acl_rules[af].items():
                log_info('-------------------------------------')
                log_info(' %s ACL Rules of VRF %s' % ('IPv4' if af == socket.AF_INET else 'IPv6', vrf_name))
                log_info('-------------------------------------')
                log_info('\n%s\n' % rule_list)
        cls.mutex.release()

    @classmethod
    def get_all_rules(cls, rule_type = None, vrf_name = None, **params):
        log_info('Handling get rules for vrf %s' % (vrf_name if vrf_name is not None else 'ALL'))
        cls.mutex.acquire()
        ret_list = []
        for af in [socket.AF_INET, socket.AF_INET6]:
            if rule_type is None or rule_type == VrfSvcsRuleType.RULE_TYPE_IP:
                for vrf, rule_list in cls.ip_rules[af].items():
                    if vrf_name is not None and vrf != vrf_name:
                        continue
                    for rule in rule_list:
                        if not rule.match(**params):
                            continue
                        if rule.rule_id is not None and rule.rule_id in rule_list.rule_id_map:
                            idx = rule_list.rule_id_map[rule.rule_id]
                            IptablesHandler.proc_rule('get', rule, idx)
                        ret_list.append(copy.deepcopy(rule))
            if rule_type is None or rule_type == VrfSvcsRuleType.RULE_TYPE_ACL:
                for vrf, rule_list in cls.acl_rules[af].items():
                    if vrf_name is not None and vrf != vrf_name:
                        continue
                    for rule in rule_list:
                        if not rule.match(**params):
                            continue
                        if rule.rule_id is not None and rule.rule_id in rule_list.rule_id_map:
                            idx = rule_list.rule_id_map[rule.rule_id]
                            IptablesHandler.proc_rule('get', rule, idx)
                        ret_list.append(copy.deepcopy(rule))
        cls.mutex.release()
        return ret_list

    @classmethod
    def check_ipt_rules(cls, rule_type, af, vrf_name):
        log_info('Checking if rules in cache are in sync with system')
        cls.mutex.acquire()
        if rule_type == VrfSvcsRuleType.RULE_TYPE_IP and vrf_name in cls.ip_rules[af]:
            rule_list = cls.ip_rules[af][vrf_name]
        elif rule_type == VrfSvcsRuleType.RULE_TYPE_ACL and vrf_name in cls.acl_rules[af]:
            rule_list = cls.acl_rules[af][vrf_name]
        else:
            rule_list = []
        ipt_rule_list = []
        if not IptablesHandler.get_rule_from_ipt(rule_type, af, vrf_name, ipt_rule_list):
            log_err('Failed to get iptables rule for rule_type %d af %d vrf %s' %
                    (rule_type, af, vrf_name))
            cls.mutex.release()
            return False
        is_sync = (rule_list == ipt_rule_list)
        if not is_sync:
            log_err('Rules of cache is not sync with those in system: TYPE %d AF %d VRF %s' %
                     (rule_type, af, vrf_name))
            log_info('-------------------------------')
            log_info('%d rules in cache' % len(rule_list))
            log_info('-------------------------------')
            for idx in range(len(rule_list)):
                log_info('%3d: %s' % (idx, rule_list[idx]))
            log_info('-------------------------------')
            log_info('%d rules in system' % len(ipt_rule_list))
            log_info('-------------------------------')
            for idx in range(len(ipt_rule_list)):
                log_info('%3d: %s' % (idx, ipt_rule_list[idx]))
        cls.mutex.release()
        return is_sync

def process_vrf_svcs_rule_add(rule_type, vrf_name, action, af, **params):
    try:
        rule = VrfIncomingSvcsRule(rule_type, vrf_name, action, af, **params)
        if not VrfIncomingSvcsRuleCache.insert_rule(rule):
            return None
    except ValueError:
        log_err('Failed to initiate rule object')
        return None
    except Exception as ex:
        logging.exception(ex)
        return None
    return rule.rule_id

def process_vrf_svcs_rule_set(rule_id, **params):
    try:
        if not VrfIncomingSvcsRuleCache.update_rule(rule_id, **params):
            return False
    except ValueError:
        log_err('Failed to update rule with params: %s' % params)
        return False
    except Exception as ex:
        logging.exception(ex)
        return False
    return True

def process_vrf_svcs_rule_del(rule_type, vrf_name, action, af, **params):
    try:
        rule = VrfIncomingSvcsRule(rule_type, vrf_name, action, af, **params)
        if not VrfIncomingSvcsRuleCache.delete_rule(rule):
            return False
    except ValueError:
        log_err('Failed to initiate rule object')
        return False
    except Exception as ex:
        logging.exception(ex)
        return False
    return True

def process_vrf_svcs_rule_del_by_id(rule_id):
    try:
        if not VrfIncomingSvcsRuleCache.delete_rule_by_id(rule_id):
            return False
    except Exception as ex:
        logging.exception(ex)
        return False
    return True

def process_vrf_svcs_rule_get(resp, rule_id = None, rule_type = None, vrf_name = None, **params):
    try:
        if rule_id is not None:
            found_rule = VrfIncomingSvcsRuleCache.find_rule_by_id(rule_id)
            if found_rule is not None:
                resp.append(found_rule[0].to_cps_obj().get())
        else:
            rule_list = VrfIncomingSvcsRuleCache.get_all_rules(rule_type, vrf_name, **params)
            for rule in rule_list:
                resp.append(rule.to_cps_obj().get())
    except Exception as ex:
        logging.exception(ex)
        return False
    return True

def process_vrf_svcs_clear_rules(vrf_name = None):
    try:
        VrfIncomingSvcsRuleCache.clear_all_rules(vrf_name)
    except Exception as ex:
        logging.exception(ex)
        return False
    return True


""" Object to define one VRF outgoing IP service rule """
class VrfOutgoingSvcsRule(object):

    KEY_ATTRS = ['rule_type', 'vrf_name', 'af', 'dst_ip',
                 'protocol', 'dst_port', 'out_src_ip']

    @classmethod
    def is_rule_equal(cls, r1, r2):
        r1_attrs = vars(r1)
        r2_attrs = vars(r2)
        for key_attr in cls.KEY_ATTRS:
            if key_attr in r1_attrs and key_attr in r2_attrs:
                if r1_attrs[key_attr] != r2_attrs[key_attr]:
                    return False
            else:
                return False
        return True

    def __init__(self, rule_type, vrf_name, action, af, dst_ip = None, protocol = None,
                 dst_port = None, out_src_ip = None, private_ip = None, private_port = None,
                 seq_num = 0, rule_id = None, high_prio = False):
        """
        Constructor to create a outgoing service IP rule object
        @rule_type - either IP or SNAT rule
        @vrf_name - namespace
        @action - 1: dnat 2: snat
        @af - address family, either IPv4 or IPv6, it could be direct number or string
        @dst_ip - matched destination IP address
        @protocol - IP protocol: 1: tcp, 2: udp, 3: icmp
        @dst_port - L4 destination port
        @out_src_ip - outgoing source IP when action is SNAT
        @private_ip - private IP for outgoing IP services. it is optional
        @private_port - private PORT for outgoing IP services. it is optional
        @seq_num - sequence number of the rule. it is optional
        @rule_id - rule ID. it is optional
        @high_prio - if it is high priority rule
        """
        self.rule_type = rule_type
        self.vrf_name = vrf_name
        self.af = af
        self.dst_ip = dst_ip
        self.dst_prefix_len = None  # For compatibility purpose
        self.protocol = protocol
        self.dst_port = dst_port
        self.out_src_ip = out_src_ip
        self.action = action
        self.seq_num = seq_num
        self.grp_priority = high_prio
        self.packet_count = None
        self.byte_count = None

        self.private_ip = private_ip
        self.private_port = private_port

        # following attributes are added to outgoing service rule,
        # just to keep the rule common b/w incoming & outgoing service rule.
        self.src_ip = None
        if self.rule_type == VrfSvcsRuleType.RULE_TYPE_SNAT:
            if self.action != VrfSvcsRuleAction.RULE_ACTION_SNAT:
                log_err('for SNAT rule, action should be SNAT')
                raise ValueError
            if self.out_src_ip is None:
                log_err('Outgoing Source IP is mandatory for SNAT action')
                raise ValueError
        self.rule_id = rule_id

    def __setattr__(self, key, val):
        if key == 'grp_priority' and val is not None:
            if val:
                val = VrfSvcsRuleGroupPrio.HIGH_GRP_PRIO
            else:
                val = VrfSvcsRuleGroupPrio.DEFAULT_GRP_PRIO
        super(VrfOutgoingSvcsRule, self).__setattr__(key, val)
        if key == 'rule_type' and self.get_rule_type_name() is None:
            log_err('Invalid rule type %s' % str(self.rule_type))
            raise ValueError
        elif key == 'af' and self.get_af_name() is None:
            log_err('Invalid address family number %s' % str(self.af))
            raise ValueError
        elif key == 'action' and self.get_action_name() is None:
            log_err('Invalid action ID %s' % str(self.action))
            raise ValueError

        if val is not None:
            if key == 'protocol' and self.get_proto_name() is None:
                log_err('Invalid protocol number %s' % str(self.protocol))
                raise ValueError

    def __eq__(self, other):
        return VrfOutgoingSvcsRule.is_rule_equal(self, other)

    def __ne__(self, other):
        return not VrfOutgoingSvcsRule.is_rule_equal(self, other)

    def __hash__(self):
        hash_val = 0
        attrs = vars(self)
        for key_attr in self.KEY_ATTRS:
            if key_attr in attrs and attrs[key_attr] is not None:
                hash_val ^= hash(attrs[key_attr])
        return hash_val

    def get_rule_type_name(self):
        type_name_map = {VrfSvcsRuleType.RULE_TYPE_OUT_IP: 'IP',
                         VrfSvcsRuleType.RULE_TYPE_SNAT: 'SNAT'}
        if self.rule_type in type_name_map:
            return type_name_map[self.rule_type]
        else:
            return None

    def get_af_name(self):
        af_name_map = {socket.AF_INET: 'IPv4', socket.AF_INET6: 'IPv6'}
        if self.af in af_name_map:
            return af_name_map[self.af]
        else:
            return None

    def get_action_name(self, for_ipt_target = False):
        action_name_map = {VrfSvcsRuleAction.RULE_ACTION_DNAT: 'dnat',
                           VrfSvcsRuleAction.RULE_ACTION_SNAT: 'snat'}
        if self.action in action_name_map:
            action_name = action_name_map[self.action]
            if type(action_name) is tuple:
                return action_name[1] if for_ipt_target else action_name[0]
            else:
                return action_name
        else:
            return None

    def get_proto_name(self):
        proto_name_map = {VrfSvcsRuleProto.RULE_PROTO_TCP: 'tcp',
                          VrfSvcsRuleProto.RULE_PROTO_UDP: 'udp',
                          VrfSvcsRuleProto.RULE_PROTO_ICMP: 'icmp',
                          VrfSvcsRuleProto.RULE_PROTO_ICMPV6: 'icmpv6'}
        if self.protocol in proto_name_map:
            return proto_name_map[self.protocol]
        else:
            return None

    def __str__(self):
        ret_str =  ('%-5s %-8sVRF: %-10s SEQ: %5d-%-4d RULE: %-10s %s%s%s%s' %
                        (self.get_rule_type_name(),
                         ('-' if self.rule_id is None else ('%d' % self.rule_id)),
                         self.vrf_name, self.grp_priority, self.seq_num,
                         ('%s' % self.get_action_name() if self.action is not None else ''),
                         self.get_af_name(),
                         ('dst_ip %s' % (socket.inet_ntop(self.af, self.dst_ip))\
                            if self.dst_ip is not None else ''),
                         (' %s' % self.get_proto_name() if self.protocol is not None else ''),
                         (' dst_port %d' % self.dst_port if self.dst_port is not None else '')))
        if self.action == VrfSvcsRuleAction.RULE_ACTION_SNAT:
            ret_str += ('%s' %
                        ('outgoing source IP %s' % (socket.inet_ntop(self.af, self.out_src_ip) \
                          if self.af is not None and self.out_src_ip is not None else '')))
        if self.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP:
            ret_str += ('%s%s' %
                        (('private-ip %s' % (socket.inet_ntop(self.af, self.private_ip) \
                          if self.af is not None and self.private_ip is not None else '')),
                        ('private-port %s' % (str(self.private_port) if self.private_port is not None else ''))))
        return ret_str

    def to_cps_obj(self):
        cps_attr_map = {
            'vrf_name': 'ni-name',
            'af': 'af',
            'dst_ip': 'public-ip',
            'protocol': 'protocol',
            'dst_port': 'public-port',
            'out_src_ip': 'outgoing-source-ip',
            'private_ip': 'private-ip',
            'private_port': 'private-port',
            'rule_id': 'id'}
        obj = cps_object.CPSObject('vrf-firewall/ns-outgoing-service')
        for attr_name, attr_val in vars(self).items():
            if attr_name in cps_attr_map and attr_val is not None:
                if attr_name == 'dst_ip' or attr_name == 'out_src_ip' or attr_name == 'private_ip':
                    attr_val = binascii.hexlify(attr_val)
                obj.add_attr(cps_attr_map[attr_name], attr_val)
        return obj

    def match(self, **params):
        attrs = vars(self)
        for key, val in params.items():
            if key not in attrs:
                return False
            if val is not None and val != attrs[key]:
                return False
        return True

class VrfOutgoingSvcsRuleList(list):
    def __init__(self):
        super(VrfOutgoingSvcsRuleList, self).__init__()
        # sorted list of all seq num
        self.seq_num_list = []
        # map: rule_id => rule position in list
        self.rule_id_map = {}

    def __str__(self):
        str_buf = StringIO()
        for rule in self:
            str_buf.write('%s\n' % rule)
        out_str = str_buf.getvalue()
        str_buf.close()
        return out_str

    def __eq__(self, other):
        return super(VrfOutgoingSvcsRuleList, self).__eq__(other)

    def __ne__(self, other):
        return super(VrfOutgoingSvcsRuleList, self).__ne__(other)

    def update_rule_id_map(self, start_idx):
        for idx in range(start_idx, len(self)):
            self.rule_id_map[self[idx].rule_id] = idx

    # insert rule to list, update seq_num list and rule_id map
    def insert(self, rule):
        if rule.rule_id is None or rule.rule_id in self.rule_id_map:
            # rule ID should be assigned and not used by another rule
            log_err('Rule ID is not assigned' if rule.rule_id is None
                    else ('Rule ID %d is used' % rule.rule_id))
            return None
        try:
            idx = self.index(rule)
        except ValueError:
            idx = None
        if idx is not None:
            # same rule already in list
            log_err('Rule to be inserted is already in list')
            return None
        idx = bisect.bisect_right(self.seq_num_list, (rule.grp_priority, rule.seq_num))
        super(VrfOutgoingSvcsRuleList, self).insert(idx, rule)
        self.seq_num_list.insert(idx, (rule.grp_priority, rule.seq_num))
        self.update_rule_id_map(idx)
        return idx

    def remove(self, rule):
        if rule.rule_id is not None and rule.rule_id in self.rule_id_map:
            idx = self.rule_id_map[rule.rule_id]
            rule_id = rule.rule_id
        else:
            try:
                idx = self.index(rule)
            except ValueError:
                # rule not found
                log_err('Rule not found for delete')
                return None
            if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP:
                if rule.private_ip is not None and \
                    (self[idx].private_ip is None or \
                     rule.private_ip != self[idx].private_ip):
                    # rule not found
                    log_err('Rule (private-ip) not found for delete.')
                    return None
                if rule.private_port is not None and \
                    (self[idx].private_port is None or \
                     rule.private_port != self[idx].private_port):
                    # rule not found
                    log_err('Rule (private-port) not found for delete.')
                    return None

            rule_id = self[idx].rule_id
        orig_rule = self[idx]
        del self[idx]
        del self.seq_num_list[idx]
        del self.rule_id_map[rule_id]
        self.update_rule_id_map(idx)
        return (orig_rule, idx)

    def remove_by_id(self, rule_id):
        if rule_id not in self.rule_id_map:
            return None
        idx = self.rule_id_map[rule_id]
        orig_rule = self[idx]
        del self[idx]
        del self.seq_num_list[idx]
        del self.rule_id_map[rule_id]
        self.update_rule_id_map(idx)
        return orig_rule

    def clear(self):
        del self[:]
        del self.seq_num_list[:]
        self.rule_id_map.clear()


class VrfOutgoingSvcsRuleCache:
    # map: af, vrf_name => rule_list
    snat_rules = {socket.AF_INET: {}, socket.AF_INET6: {}}
    ip_rules = {socket.AF_INET: {}, socket.AF_INET6: {}}
    mutex = threading.RLock()
    id_generator = IdGenerator()

    @classmethod
    def outgoing_ip_svcs_rule_sub_net_config(cls, op, rule):
        if rule.rule_type != VrfSvcsRuleType.RULE_TYPE_OUT_IP:
            log_err('Cannot update private IP/Port for rule that is not of outgoing service binding config')
            return False

        #During rule add, retrieve new private IP & port information.
        if (op.lower() == 'insert'):
            ret, private_ip, private_port = process_outgoing_ip_svcs_sub_net_config(True,\
                                    rule.vrf_name, rule.af, rule.protocol, rule.dst_ip, rule.dst_port)
            if ret is False:
                log_err('Failed to allocate private IP, port for outgoing service binding config.'
                        ' VRF %s %s%s%s%s%s' % (
                        rule.vrf_name,
                        ('AF %d' % rule.af if rule.af is not None else ' '),
                        (' PROTO %d' % rule.protocol if rule.protocol is not None else ''),
                        (' DST IP %s' % get_ip_str(rule.af, rule.dst_ip) if rule.dst_ip is not None else ''),
                        (' PORT %d' % rule.dst_port if rule.dst_port is not None else ''),
                        (' ID %d' % rule.rule_id if rule.rule_id is not None else '')))
            else:
                #update the allocated private IP and port to the rule cache.
                rule.private_ip = private_ip
                rule.private_port = private_port
            return ret
        elif (op.lower() == 'delete'):
            #During rule delete, release private IP & port information.
            ret, private_ip, private_port = process_outgoing_ip_svcs_sub_net_config(False,\
                                    rule.vrf_name, rule.af, rule.protocol, rule.dst_ip, rule.dst_port)

            if ret is False:
                log_err('Failed to release private IP, port for outgoing service binding config.'
                        ' VRF %s %s%s%s%s%s' % (
                        rule.vrf_name,
                        ('AF %d' % rule.af if rule.af is not None else ' '),
                        (' PROTO %d' % rule.protocol if rule.protocol is not None else ''),
                        (' DST IP %s' % get_ip_str(rule.af, rule.dst_ip) if rule.dst_ip is not None else ''),
                        (' PORT %d' % rule.dst_port if rule.dst_port is not None else ''),
                        (' ID %d' % rule.rule_id if rule.rule_id is not None else '')))
            return ret
        return False

    @classmethod
    def insert_rule(cls, rule):
        log_info('Handling add rule: %s' % rule)
        cls.mutex.acquire()
        rule_list = cls.ip_rules[rule.af]\
            if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP else cls.snat_rules[rule.af]
        if rule.vrf_name not in rule_list:
            rule_list[rule.vrf_name] = VrfOutgoingSvcsRuleList()
        if rule.rule_id is None:
            rule.rule_id = cls.id_generator.get_new_id()
            if rule.rule_id is None:
                log_err('Could not generate new rule ID')
                log_info(str(cls.id_generator))
                cls.mutex.release()
                return False
        else:
            if cls.id_generator.is_id_used(rule.rule_id):
                log_err('Given rule ID %d is used' % rule.rule_id)
                log_info(str(cls.id_generator))
                cls.mutex.release()
                return False
            if not cls.id_generator.reserve_id(rule.rule_id):
                log_err('Failed to reserve rule ID %d' % rule.rule_id)
                log_info(str(cls.id_generator))
                cls.mutex.release()
                return False
        ret_val = True

        #allocate private IP and port for outgoing service binding config
        if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP and \
          not cls.outgoing_ip_svcs_rule_sub_net_config('insert', rule):
            log_err('Failed to retrieve private IP, port for outgoing service binding config')
            cls.id_generator.release_id(rule.rule_id)
            cls.mutex.release()
            return False

        idx = rule_list[rule.vrf_name].insert(rule)
        if idx is not None:
            if not IptablesHandler.proc_rule('insert', rule, idx):
                log_err('Failed to call iptables to insert rule')
                cls.id_generator.release_id(rule.rule_id)
                # rollback
                rule_list[rule.vrf_name].remove(rule)
                ret_val = False
                #on failure, release private IP and port for outgoing service binding config
                if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP:
                    cls.outgoing_ip_svcs_rule_sub_net_config('delete', rule)
        else:
            log_err('Failed to insert rule to cache')
            #on failure, release private IP and port for outgoing service binding config
            if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP:
                cls.outgoing_ip_svcs_rule_sub_net_config('delete', rule)
            cls.id_generator.release_id(rule.rule_id)
            ret_val = False
        cls.mutex.release()
        if ret_val:
            log_info('Rule added, ID=%d' % rule.rule_id)
        return ret_val

    @classmethod
    def delete_rule(cls, rule):
        log_info('Handling delete rule: %s' % rule)
        cls.mutex.acquire()
        rule_list = cls.ip_rules[rule.af]\
            if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP else cls.snat_rules[rule.af]
        if rule.vrf_name not in rule_list:
            log_err('VRF name %s not found in cache' % rule.vrf_name)
            cls.mutex.release()
            return False

        ret_val = rule_list[rule.vrf_name].remove(rule)
        if ret_val is None:
            log_err('Failed to delete rule from cache')
            cls.mutex.release()
            return False
        del_rule, idx = ret_val
        ret_val = True
        if not IptablesHandler.proc_rule('delete', del_rule, idx):
            log_err('Failed to call iptables to delete rule')
            # rollback
            rule_list[del_rule.vrf_name].insert(del_rule)
            ret_val = False
        #release private IP and port for outgoing service binding config
        if ret_val is True and del_rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP:
            cls.outgoing_ip_svcs_rule_sub_net_config('delete', del_rule)
        if len(rule_list[rule.vrf_name]) == 0:
            del rule_list[rule.vrf_name]
        cls.mutex.release()
        if ret_val:
            if not cls.id_generator.release_id(del_rule.rule_id):
                log_err('Failed to release rule ID %d' % del_rule.rule_id)
                log_info(str(cls.id_generator))
            log_info('Rule deleted')
        return ret_val

    @classmethod
    def find_rule_by_id(cls, rule_id):
        ret_val = None
        cls.mutex.acquire()
        for af in [socket.AF_INET, socket.AF_INET6]:
            for vrf_name, rule_list in cls.ip_rules[af].items():
                if rule_id in rule_list.rule_id_map:
                    idx = rule_list.rule_id_map[rule_id]
                    ret_val = (rule_list[idx], idx)
                    break
            if ret_val is not None:
                break
            for vrf_name, rule_list in cls.snat_rules[af].items():
                if rule_id in rule_list.rule_id_map:
                    idx = rule_list.rule_id_map[rule_id]
                    ret_val = (rule_list[idx], idx)
                    break
            if ret_val is not None:
                break
        cls.mutex.release()
        return ret_val

    @classmethod
    def find_rule_by_match(cls, rule):
        cls.mutex.acquire()
        rule_list = cls.ip_rules[rule.af] if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP else cls.snat_rules[rule.af]
        if rule.vrf_name not in rule_list:
            cls.mutex.release()
            return None
        try:
            idx = rule_list[rule.vrf_name].index(rule)
        except ValueError:
            cls.mutex.release()
            return None
        cls.mutex.release()
        return rule_list[rule.vrf_name][idx]

    @classmethod
    def delete_rule_by_id(cls, rule_id):
        log_info('Handling delete rule by ID: %d' % rule_id)
        cls.mutex.acquire()
        ret_val = True
        found_rule = cls.find_rule_by_id(rule_id)
        if found_rule is not None:
            del_rule, idx = found_rule
            rule_list = cls.ip_rules[del_rule.af] \
                if del_rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP \
                else cls.snat_rules[del_rule.af]
            if rule_list[del_rule.vrf_name].remove_by_id(rule_id) is None:
                log_err('Failed to remove rule with ID %d' % rule_id)
                cls.mutex.release()
                return False

            if not IptablesHandler.proc_rule('delete', del_rule, idx):
                log_err('Failed to call iptables to delete rule')
                # rollback
                rule_list = cls.ip_rules[del_rule.af] \
                    if del_rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP \
                    else cls.snat_rules[del_rule.af]
                rule_list[del_rule.vrf_name].insert(del_rule)
                ret_val = False

            #release private IP and port for outgoing service binding config
            if ret_val is True and del_rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP:
                cls.outgoing_ip_svcs_rule_sub_net_config('delete', del_rule)
            if len(rule_list[del_rule.vrf_name]) == 0:
                del rule_list[del_rule.vrf_name]
        else:
            log_err('Rule ID %d not found for delete' % rule_id)
            ret_val = False
        cls.mutex.release()
        if ret_val:
            if not cls.id_generator.release_id(rule_id):
                log_err('Failed to release rule ID %d' % rule_id)
                log_info(str(cls.id_generator))
            log_info('Rule deleted')
        return ret_val

    @classmethod
    def replace_rule(cls, rule_id, new_rule):
        log_info('Handling replace rule with ID %d' % rule_id)
        cls.mutex.acquire()
        ret_val = True
        found_rule = cls.find_rule_by_id(rule_id)
        if found_rule is not None:
            old_rule, idx = found_rule
            rule_list = cls.ip_rules[old_rule.af] \
                if old_rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP else cls.snat_rules[old_rule.af]
            if not IptablesHandler.proc_rule('replace', new_rule, idx):
                log_err('Failed to call iptables to replace rule')
                ret_val = False
            else:
                rule_list[old_rule.vrf_name][idx] = new_rule
        else:
            log_err('Rule ID %d not found for replace' % rule_id)
            ret_val = False
        cls.mutex.release()
        if ret_val:
            log_info('Rule replaced')
        return ret_val

    @classmethod
    def update_rule(cls, rule_id, **params):
        log_info('Handling update rule: ID %d param %s' % (rule_id, params))
        cls.mutex.acquire()
        found_rule = cls.find_rule_by_id(rule_id)
        if found_rule is None:
            log_err('Rule ID %d not found for update' % rule_id)
            cls.mutex.release()
            return False
        old_rule, _ = found_rule
        upd_rule = copy.deepcopy(old_rule)
        changed_attrs = set()

        def check_and_set(rule, key, val):
            try:
                orig_val = getattr(rule, key)
            except AttributeError:
                orig_val = None
            if val != orig_val:
                if val is not None:
                    setattr(rule, key, val)
                else:
                    delattr(rule, key)
                changed_attrs.add(key)

        for key, val in params.items():
            if val is not None:
                check_and_set(upd_rule, key, val)
        if len(changed_attrs) == 0:
            log_info('There is no change to be updated, just return')
            cls.mutex.release()
            return True

        log_info('old_rule: %s' % old_rule)
        log_info('new_rule: %s' % upd_rule)

        match_rule = cls.find_rule_by_match(upd_rule)
        if match_rule is not None and match_rule.rule_id != old_rule.rule_id:
            log_err('The updating rule already exists')
            cls.mutex.release()
            return False

        repl_attrs = {'dst_ip', 'dst_port', 'out_src_ip', 'action'}
        no_repl_attrs = changed_attrs.difference(repl_attrs)
        if len(no_repl_attrs) > 0:
            log_info('Non-replacable attributes %s changed, delete and add rule' % no_repl_attrs)
            if not cls.delete_rule_by_id(rule_id):
                log_err('Failed to delete existing rule by ID')
                cls.mutex.release()
                return False

            ret_val = cls.insert_rule(upd_rule)
            if not ret_val:
                log_err('Failed to insert updated rule')
                cls.insert_rule(old_rule)
        else:
            log_info('Only replacable attributes changed, just replace rule')
            ret_val = cls.replace_rule(rule_id, upd_rule)
            if not ret_val:
                log_err('Failed to replace rule')
        cls.mutex.release()
        if ret_val:
            log_info('Rule updated')
        return ret_val

    @classmethod
    def clear_all_rules(cls, flt_vrf = None, flt_af = None):
        log_info('Handling clear all rules for VRF %s and AF %s' % (
                    flt_vrf if flt_vrf is not None else '-',
                    str(flt_af) if flt_af is not None else '-'))
        cls.mutex.acquire()
        for af in [socket.AF_INET, socket.AF_INET6]:
            if flt_af is not None and flt_af != af:
                continue
            for vrf_name, rule_list in cls.ip_rules[af].items():
                if flt_vrf is not None and flt_vrf != vrf_name:
                    continue
                for rule in rule_list:
                    IptablesHandler.proc_rule('delete', rule)
                    cls.outgoing_ip_svcs_rule_sub_net_config('delete', rule)
                    cls.id_generator.release_id(rule.rule_id)
                rule_list.clear()
                del cls.ip_rules[af][vrf_name]
            for vrf_name, rule_list in cls.snat_rules[af].items():
                if flt_vrf is not None and flt_vrf != vrf_name:
                    continue
                for rule in rule_list:
                    IptablesHandler.proc_rule('delete', rule)
                    cls.id_generator.release_id(rule.rule_id)
                rule_list.clear()
                del cls.snat_rules[af][vrf_name]
        cls.mutex.release()

    @classmethod
    def dump_rules(cls):
        cls.mutex.acquire()
        for af in [socket.AF_INET, socket.AF_INET6]:
            for vrf_name, rule_list in cls.ip_rules[af].items():
                log_info('-------------------------------------')
                log_info(' %s IP Rules of VRF %s' % ('IPv4' if af == socket.AF_INET else 'IPv6', vrf_name))
                log_info('-------------------------------------')
                log_info('\n%s\n' % rule_list)
            for vrf_name, rule_list in cls.snat_rules[af].items():
                log_info('-------------------------------------')
                log_info(' %s SNAT Rules of VRF %s' % ('IPv4' if af == socket.AF_INET else 'IPv6', vrf_name))
                log_info('--------------------------------------')
                log_info('\n%s\n' % rule_list)
        cls.mutex.release()

    @classmethod
    def get_all_rules(cls, rule_type = None, vrf_name = None, **params):
        log_info('Handling get rules for vrf %s' % (vrf_name if vrf_name is not None else 'ALL'))
        cls.mutex.acquire()
        ret_list = []
        for af in [socket.AF_INET, socket.AF_INET6]:
            if rule_type is None or rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP:
                for vrf, rule_list in cls.ip_rules[af].items():
                    if vrf_name is not None and vrf != vrf_name:
                        continue
                    for rule in rule_list:
                        if not rule.match(**params):
                            continue
                        ret_list.append(copy.deepcopy(rule))
            if rule_type is None or rule_type == VrfSvcsRuleType.RULE_TYPE_SNAT:
                for vrf, rule_list in cls.snat_rules[af].items():
                    if vrf_name is not None and vrf != vrf_name:
                        continue
                    for rule in rule_list:
                        if not rule.match(**params):
                            continue
                        ret_list.append(copy.deepcopy(rule))
        cls.mutex.release()
        return ret_list


def process_vrf_outgoing_svcs_rule_add(rule_type, vrf_name, action, af, **params):
    try:
        rule = VrfOutgoingSvcsRule(rule_type, vrf_name, action, af, **params)
        if not VrfOutgoingSvcsRuleCache.insert_rule(rule):
            return (None, None, None)
    except ValueError:
        log_err('Failed to initiate rule object')
        return (None, None, None)
    except Exception as ex:
        logging.exception(ex)
        return (None, None, None)
    return (rule.rule_id, rule.private_ip, rule.private_port)

def process_vrf_outgoing_svcs_rule_set(rule_id, **params):
    try:
        if not VrfOutgoingSvcsRuleCache.update_rule(rule_id, **params):
            return False
    except ValueError:
        log_err('Failed to update rule with params: %s' % params)
        return False
    except Exception as ex:
        logging.exception(ex)
        return False
    return True

def process_vrf_outgoing_svcs_rule_del(rule_type, vrf_name, action, af, **params):
    try:
        rule = VrfOutgoingSvcsRule(rule_type, vrf_name, action, af, **params)
        if not VrfOutgoingSvcsRuleCache.delete_rule(rule):
            return None
    except ValueError:
        log_err('Failed to initiate rule object')
        return False
    except Exception as ex:
        logging.exception(ex)
        return False
    return True

def process_vrf_outgoing_svcs_rule_del_by_id(rule_id):
    try:
        if not VrfOutgoingSvcsRuleCache.delete_rule_by_id(rule_id):
            return False
    except Exception as ex:
        logging.exception(ex)
        return False
    return True

def process_vrf_outgoing_svcs_rule_get(resp, rule_id = None, rule_type = None, vrf_name = None, **params):
    try:
        if rule_id is not None:
            found_rule = VrfOutgoingSvcsRuleCache.find_rule_by_id(rule_id)
            if found_rule is not None:
                resp.append(found_rule[0].to_cps_obj().get())
        else:
            rule_list = VrfOutgoingSvcsRuleCache.get_all_rules(rule_type, vrf_name, **params)
            for rule in rule_list:
                resp.append(rule.to_cps_obj().get())
    except Exception as ex:
        logging.exception(ex)
        return False
    return True

def process_vrf_outgoing_svcs_clear_rules(vrf_name = None):
    try:
        VrfOutgoingSvcsRuleCache.clear_all_rules(vrf_name)
    except Exception as ex:
        logging.exception(ex)
        return False
    return True

