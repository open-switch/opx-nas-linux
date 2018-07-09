# Copyright (c) 2018 Dell Inc.
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

from dn_base_vrf_tool import iplink_cmd, run_command, log_info, log_err, rej_rule_mark_value, _vrf_name_to_id
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

class VrfSvcsRuleGroupPrio(IntEnum):
    HIGH_GRP_PRIO = 1
    DEFAULT_GRP_PRIO = 10


""" Object to define one VRF incoming IP service rule """
class VrfIncomingSvcsRule(object):

    KEY_ATTRS = ['rule_type', 'vrf_name', 'af', 'src_ip', 'prefix_len',
                 'protocol', 'dst_port', 'low_dst_port', 'high_dst_port',
                 'action', 'in_intf']

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

    def __init__(self, rule_type, vrf_name, action, af, src_ip = None, prefix_len = None,
                 protocol = None, dst_port = None, dst_ip = None, low_dst_port = None,
                 high_dst_port = None, seq_num = 0, rule_id = None, high_prio = False,
                 in_intf = None):
        """
        Constructor to create a ACL rule object
        @rule_type - either IP or ACL rule
        @vrf_name - namespace
        @action - 1: accept 2: drop 3: dnat
        @af - address family, either IPv4 or IPv6, it could be direct number or string
        @src_ip - matched source IP address
        @prefix_len - prefix length to specify subnet
        @protocol - IP protocol: 1: tcp, 2: udp, 3: icmp, 4: all
        @dst_port - L4 destination port
        @low_dst_port - lower L4 destination port (inclusive)
        @high_dst_port - upper L4 destination port (inclusive)
        @dst_ip - specify destination IP when action is DNAT
        @seq_num - sequence number of the rule
        @rule_id - rule ID. it is optional
        @high_prio - if it is high priority rule
        @in_intf - interface where packets coming from
        """
        self.rule_type = rule_type
        self.vrf_name = vrf_name
        self.af = af
        self.src_ip = src_ip
        self.prefix_len = prefix_len
        self.protocol = protocol
        self.dst_port = dst_port
        self.low_dst_port = low_dst_port
        self.high_dst_port = high_dst_port
        self.dst_ip = dst_ip
        self.seq_num = seq_num
        self.action = action
        self.grp_priority = high_prio
        if self.action == VrfSvcsRuleAction.RULE_ACTION_DNAT and self.dst_ip is None:
            log_err('Destination IP is mandatory for DNAT action')
            raise ValueError
        if self.action == VrfSvcsRuleAction.RULE_ACTION_DENY and self.rule_type == VrfSvcsRuleType.RULE_TYPE_ACL:
            # For ACL rule, use REJECT action instead of DROP
            self.action = VrfSvcsRuleAction.RULE_ACTION_REJECT
        self.rule_id = rule_id
        self.in_intf = in_intf

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
                          VrfSvcsRuleProto.RULE_PROTO_ALL: 'ip'}
        if self.protocol in proto_name_map:
            return proto_name_map[self.protocol]
        else:
            return None

    def __str__(self):
        ret_str =  ('%-5s %-8sVRF: %-10s SEQ: %5d-%-4d RULE: %-10s %s%s%s%s%s%s' %
                        (self.get_rule_type_name(),
                         ('-' if self.rule_id is None else ('%d' % self.rule_id)),
                         self.vrf_name, self.grp_priority, self.seq_num,
                         ('%s' % self.get_action_name() if self.action is not None else ''),
                         self.get_af_name(),
                         (' %s/%d' % (socket.inet_ntop(self.af, self.src_ip), self.prefix_len) \
                            if self.src_ip is not None and self.prefix_len is not None else ''),
                         (' %s' % self.get_proto_name() if self.protocol is not None else ''),
                         (' dst_port %d' % self.dst_port if self.dst_port is not None else ''),
                         (' dst_port range %d-%d' % (self.low_dst_port, self.high_dst_port) \
                            if self.low_dst_port is not None else ''),
                         (' iif %s' % self.in_intf if self.in_intf is not None else '')))
        if self.action == VrfSvcsRuleAction.RULE_ACTION_DNAT:
            ret_str += (' to %s' % socket.inet_ntop(self.af, self.dst_ip))
        return ret_str

    def to_cps_obj(self):
        cps_attr_map = {
            'vrf_name': 'ni-name',
            'af': 'af',
            'src_ip': 'src-ip',
            'prefix_len': 'src-prefix-len',
            'protocol': 'protocol',
            'dst_port': 'dst-port',
            'low_dst_port': 'lower-dst-port',
            'high_dst_port': 'upper-dst-port',
            'action': 'action',
            'seq_num': 'seq-num',
            'in_intf': 'ifname',
            'rule_id': 'id'}
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
    @staticmethod
    def is_vrf_valid(vrf_name):
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

    @staticmethod
    def proc_rule(op, rule, idx = None):
        if (op.lower() == 'delete' and rule.vrf_name != 'default' and
            not IptablesHandler.is_vrf_valid(rule.vrf_name)):
            log_info('VRF %s is not opened, bypass iptables setting.' % rule.vrf_name)
            return True

        #@@@TODO - check if this below check is really needed
        """ outgoing IP services rules are not allowed in default VRF """
        if rule.vrf_name == 'default' and rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP:
            log_info('Invalid Rule. rule type %s not supported in VRF:%s.' % (rule.rule_type, rule.vrf_name))
            return False

        if op == 'replace' and idx is None:
            log_err('Missing rule index for replace operation')
            return False
        iptables = 'iptables' if rule.af == socket.AF_INET else 'ip6tables'

        if rule.vrf_name == 'default':
            ipt_prefix = ['/sbin/%s' % iptables]
            #tbl_name = (None if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_IP else 'raw')
            if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_IP:
                tbl_name = None
            elif rule.rule_type == VrfSvcsRuleType.RULE_TYPE_SNAT:
                tbl_name = 'nat'
            else :
                tbl_name = 'raw'
        else:
            ipt_prefix = [iplink_cmd, 'netns', 'exec', rule.vrf_name, iptables]
            #tbl_name = ('nat' if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_IP else 'raw')
            if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_IP or\
                rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP or\
                rule.rule_type == VrfSvcsRuleType.RULE_TYPE_SNAT:
                tbl_name = 'nat'
            else :
                tbl_name = 'raw'
        if tbl_name is not None:
            ipt_prefix += ['-t', tbl_name]

        flt_args = []
        if rule.src_ip is not None:
            flt_args += ['-s', '%s%s' % (socket.inet_ntop(rule.af, rule.src_ip),
                                        ('/%d' % rule.prefix_len if rule.prefix_len is not None else ''))]
        if rule.protocol is not None:
            flt_args += ['-p', rule.get_proto_name()]

        if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP:
            flt_args += ['--dport', str(rule.private_port)]
        elif rule.dst_port is not None:
            flt_args += ['--dport', str(rule.dst_port)]

        if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_ACL and rule.low_dst_port is not None:
            flt_args += ['--match', 'multiport', '--dports',
                         '%s:%s' % (str(rule.low_dst_port), str(rule.high_dst_port))]

        if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_IP:
            if rule.vrf_name == 'default':
                flt_args += ['!', '-i', 'vdef-nsid%d' % MGMT_VRF_ID]
                chain_name = 'INPUT'
            else:
                chain_name = 'VRF'
        elif rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP:
            vrf_id = None
            vrf_id = _vrf_name_to_id.get(rule.vrf_name, None)
            if vrf_id is not None:
                flt_args += ['-i', 'veth-nsid%d'%vrf_id]
            chain_name = 'PREROUTING'
        elif rule.rule_type == VrfSvcsRuleType.RULE_TYPE_SNAT:
            if rule.dst_ip is not None:
                flt_args += ['--destination', '%s' % (socket.inet_ntop(rule.af, rule.dst_ip))]
            #in management vrf, apply SNAT rules on interfaces other than internal veth interfaces.
            #@@TODO - check how to handle for data vrf
            if rule.vrf_name == 'management':
                flt_args += ['!', '-o', 'veth-nsid%d' % MGMT_VRF_ID]
            chain_name = 'POSTROUTING'
        else:
            chain_name = 'PREROUTING'
            if rule.in_intf is not None:
                if rule.negative:
                    flt_args.append('!')
                flt_args += ['-i', rule.in_intf]
        flt_args += ['-j', rule.get_action_name(True).upper()]

        if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_OUT_IP:
            flt_args += ['--to-destination',
                         '%s:%s' % (socket.inet_ntop(rule.af, rule.dst_ip),str(rule.dst_port))]
        elif rule.action == VrfSvcsRuleAction.RULE_ACTION_DNAT:
            flt_args += ['--to-destination', '%s' % (socket.inet_ntop(rule.af, rule.dst_ip))]
        elif rule.action == VrfSvcsRuleAction.RULE_ACTION_REJECT:
            flt_args += ['--set-mark', str(rej_rule_mark_value)]
        elif rule.rule_type == VrfSvcsRuleType.RULE_TYPE_SNAT:
            flt_args += ['--to-source', '%s' % (socket.inet_ntop(rule.af, rule.out_src_ip))]

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
        else:
            log_err('Invalid operation %s' % op)
            return False

        log_info('CMD: %s' % ' '.join(cmd))
        res = []
        return run_command(cmd, res, op.lower() != 'check') == 0


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
                    break
            if ret_val is not None:
                break
            for vrf_name, rule_list in cls.acl_rules[af].items():
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
        rule_list = cls.ip_rules[rule.af] if rule.rule_type == VrfSvcsRuleType.RULE_TYPE_IP else cls.acl_rules[rule.af]
        if rule.vrf_name not in rule_list:
            cls.mutex.release()
            return None
        try:
            idx = rule_list[rule.vrf_name].index(rule)
        except ValueError:
            cls.mutex.release()
            return None
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
                ret_val = False;
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
                ret_val = False;
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

        repl_attrs = {'src_ip', 'prefix_len', 'protocol', 'dst_port', 'low_dst_port', 'high_dst_port', 'action', 'in_intf'}
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
                        ret_list.append(copy.deepcopy(rule))
            if rule_type is None or rule_type == VrfSvcsRuleType.RULE_TYPE_ACL:
                for vrf, rule_list in cls.acl_rules[af].items():
                    if vrf_name is not None and vrf != vrf_name:
                        continue
                    for rule in rule_list:
                        if not rule.match(**params):
                            continue
                        ret_list.append(copy.deepcopy(rule))
        cls.mutex.release()
        return ret_list

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
        self.protocol = protocol
        self.dst_port = dst_port
        self.out_src_ip = out_src_ip
        self.action = action
        self.seq_num = seq_num
        self.grp_priority = high_prio

        # @@TODO - generate private_ip & private_port for IP rule
        self.private_ip = private_ip
        self.private_port = private_port

        # @@TODO - following attributes are added to outgoing service rule,
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
                          VrfSvcsRuleProto.RULE_PROTO_ICMP: 'icmp'}
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
        idx = rule_list[rule.vrf_name].insert(rule)
        if idx is not None:
            if not IptablesHandler.proc_rule('insert', rule, idx):
                log_err('Failed to call iptables to insert rule')
                cls.id_generator.release_id(rule.rule_id)
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
                ret_val = False;
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
                ret_val = False;
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
    #@@TODO - when clearing outgoing service binding rules, release the private port mapping
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
            return None
    except ValueError:
        log_err('Failed to initiate rule object')
        return None
    except Exception as ex:
        logging.exception(ex)
        return None
    return rule.rule_id

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


