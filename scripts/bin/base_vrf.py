#!/usr/bin/python
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

import cps
import cps_object
import socket
import binascii
import ipaddress
import netaddr
import logging

import dn_base_vrf_tool
import systemd.daemon
import os
import threading
from shutil import rmtree
from dn_base_vrf_tool import log_err, log_info, get_ip_str, process_vrf_top_chain_rule, get_vrf_intf_to_dst_vrf,\
                             _veth_ip_get
from dn_base_vrf_svcs_config import VrfSvcsRuleType,\
                                    VrfSvcsRuleAction,\
                                    VrfSvcsRuleProto,\
                                    process_vrf_svcs_rule_add,\
                                    process_vrf_svcs_rule_set,\
                                    process_vrf_svcs_rule_del,\
                                    process_vrf_svcs_rule_del_by_id,\
                                    process_vrf_svcs_rule_get, \
                                    process_vrf_svcs_clear_rules, \
                                    process_vrf_outgoing_svcs_rule_add,\
                                    process_vrf_outgoing_svcs_rule_del,\
                                    process_vrf_outgoing_svcs_rule_del_by_id,\
                                    process_vrf_outgoing_svcs_rule_get

_vrf_key = cps.key_from_name('target', 'vrf-mgmt/ni/network-instances/network-instance')
_vrf_intf_key = cps.key_from_name('target', 'vrf-mgmt/ni/if/interfaces/interface')
_vrf_incoming_svc_config_key = cps.key_from_name('target', 'vrf-firewall/ns-incoming-service')
_vrf_outgoing_svc_config_key = cps.key_from_name('target', 'vrf-firewall/ns-outgoing-service')
_vrf_get_intf_key = cps.key_from_name('target', 'vrf-mgmt/get-vrf-internal-binding')
_vrf_intf_ip_key = cps.key_from_name('target', 'vrf-mgmt/src-ip-config')

_protocol = {
    1: 'tcp',
    2: 'udp',
    3: 'icmp',
};
_action = {
    1: 'ACCEPT',
    2: 'DROP',
    3: 'DNAT',
    4: 'REJECT',
    5: 'SNAT',
}
_af = {
    2 : 'ipv4',
    10 : 'ipv6',
}

_vrf_default_rule = {}
_vrf_mutex = 0

def incoming_ip_svcs_attr(t):
    return 'vrf-firewall/ns-incoming-service/' + t
def outgoing_ip_svcs_attr(t):
    return 'vrf-firewall/ns-outgoing-service/' + t
def ni_intf_attr(t):
    return 'ni/if/interfaces/interface/' + t
def vrf_mgmt_intf_attr(t):
    return 'vrf-mgmt/ni/if/interfaces/interface/' + t
def intf_attr(t):
    return 'if/interfaces/interface/' + t
def vrf_mgmt_ni_attr(t):
    return 'vrf-mgmt/ni/network-instances/network-instance/' + t

def ip_ni_attr(t):
    return 'ni/network-instances/network-instance/' + t

def create_default_lo_pkts_rule():
    loopback_ip_str = '127.0.0.1'
    loopback_intf = 'lo'

    rule_id = process_vrf_svcs_rule_add(VrfSvcsRuleType.RULE_TYPE_IP, 'default',
                                        VrfSvcsRuleAction.RULE_ACTION_ALLOW, socket.AF_INET,
                                        src_ip = socket.inet_pton(socket.AF_INET, loopback_ip_str), src_prefix_len = 32,
                                        dst_ip = socket.inet_pton(socket.AF_INET, loopback_ip_str), dst_prefix_len = 32,
                                        high_prio = True, in_intf = loopback_intf)
    if rule_id is None:
        log_err('Failed to create default rule to accept pkts on lo')
        return (False, rule_id)
    return (True, rule_id)

def create_vrf_default_rules(vrf_name, rule_id_list = None):
    for af in [socket.AF_INET, socket.AF_INET6]:
        any_ip_str = '0.0.0.0' if af == socket.AF_INET else '::'
        intf = 'vdst-nsid+'
        rule_id = process_vrf_svcs_rule_add(VrfSvcsRuleType.RULE_TYPE_ACL, vrf_name,
                                            VrfSvcsRuleAction.RULE_ACTION_ALLOW, af,
                                            src_ip = socket.inet_pton(af, any_ip_str), src_prefix_len = 0,
                                            high_prio = True, in_intf = intf)
        if rule_id is None:
            log_err('Failed to create default ACL rules: VRF %s af %d intf %s' % (vrf_name, af, intf))
            return False
        if rule_id_list is not None:
            log_info('Default rule created: VRF %s af %d intf %s ID %d' % (vrf_name, af, intf, rule_id))
            rule_id_list.append(rule_id)
    return True

def set_vrf_cb(methods, params):
    global _vrf_mutex
    _vrf_mutex.acquire()
    ret_val = set_vrf_cb_int(methods, params)
    _vrf_mutex.release()
    return ret_val

def set_vrf_cb_int(methods, params):
    obj = cps_object.CPSObject(obj=params['change'])
    vrf_name = None

    vrf_name = ip_ni_attr('name')
    vrf_id = vrf_mgmt_ni_attr('vrf-id')
    try:
        vrf_name = obj.get_attr_data(vrf_name)
        vrf_id = obj.get_attr_data(vrf_id)
    except ValueError as e:
        log_msg = 'Missing mandatory attribute ' + e.args[0]
        log_err(log_msg)
        return False

    global _vrf_default_rule

    try:
        if params['operation'] == 'set':
            return False
        elif params['operation'] == 'create':
            log_msg = 'VRF config create - VRF Name:' + vrf_name + str(vrf_id)
            log_info(log_msg)
            # cache cleanup before create new VRF
            if not process_vrf_svcs_clear_rules(vrf_name):
                log_err('Failed to delete all rules for VRF %s' % vrf_name)
            # When we support regular VRF, add the handler accordingly.
            if dn_base_vrf_tool.process_vrf_config(True, vrf_name, vrf_id):
                # Create default rules for VRF
                _vrf_default_rule[vrf_name] = []
                if not create_vrf_default_rules(vrf_name, _vrf_default_rule[vrf_name]):
                    log_err('Failed to create default ACL rules for VRF %s to VRF ns' % vrf_name)
                if not create_vrf_default_rules('default', _vrf_default_rule[vrf_name]):
                    log_err('Failed to create default ACL rules for VRF %s to default ns' % vrf_name)
                return True
            log_msg = 'VRF config create failed - VRF Name:' + vrf_name
            log_err(log_msg)
        elif params['operation'] == 'delete':
            log_msg = 'VRF config delete - VRF Name:' + vrf_name
            log_info(log_msg)
            if vrf_name in _vrf_default_rule:
                for rule_id in _vrf_default_rule[vrf_name]:
                    log_info('Delete default ACl rule %d' % rule_id)
                    process_vrf_svcs_rule_del_by_id(rule_id)
                del _vrf_default_rule[vrf_name]
            if dn_base_vrf_tool.process_vrf_config(False, vrf_name, vrf_id):
                return True
            log_msg = 'VRF config delete failed - VRF Name:' + vrf_name
            log_err(log_msg)
    except Exception as e:
        logging.exception(e)
        log_msg = 'Faild to commit operation.' + str(e) + 'params' + params
        log_err(log_msg)

    return False

def set_vrf_intf_cb(methods, params):
    global _vrf_mutex
    _vrf_mutex.acquire()
    ret_val = set_vrf_intf_cb_int(methods, params)
    _vrf_mutex.release()
    return ret_val

def set_vrf_intf_cb_int(methods, params):
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

    operation = params['operation']
    try:
        if operation == 'set':
            return False
        else:
            op = True
            if operation == 'delete':
                op = False

            log_msg = 'VRF ' + vrf_name + ' intf ' + if_name + ' request ' + operation
            log_info(log_msg)
            ret_val, v_if_name, v_if_index, v_mac_str = dn_base_vrf_tool.process_vrf_intf_config(op, if_name, vrf_name)
            if ret_val is True:
                if op:
                    cps_obj = cps_object.CPSObject(module='vrf-mgmt/ni/if/interfaces/interface', qual='target',
                                           data={intf_attr('name'):if_name,
                                           ni_intf_attr('bind-ni-name'):vrf_name,
                                           vrf_mgmt_intf_attr('ifname'):v_if_name,
                                           vrf_mgmt_intf_attr('ifindex'):v_if_index,
                                           vrf_mgmt_intf_attr('mac-addr'):v_mac_str,
                                           })
                    params['change'] = cps_obj.get()
                return True

            log_msg = 'Failed to execute VRF ' + vrf_name + ' intf ' + if_name + ' request ' + operation
            log_err(log_msg)
    except Exception as e:
        logging.exception(e)
        log_msg = 'Faild to commit operation.' + str(e) + params
        log_err(log_msg)

    return False

def normalize_ip_with_prefix(af, ip, pfx_len = None):
    if af is None:
        chk_af_list = [socket.AF_INET, socket.AF_INET6]
    else:
        chk_af_list = [af]

    ip_str = None
    for af in chk_af_list:
        # if input is hexlified string, convert it to regular string
        try:
            ip = binascii.unhexlify(ip)
        except TypeError:
            # if ip is not hexlified string, keep it as is
            pass

        # test if input is binary
        try:
            ip_str = socket.inet_ntop(af, ip)
            break
        except (ValueError, socket.error):
            pass

    if ip_str is None:
        log_err('Invalid AF or IP: %s %s' % (str(af), str(ip)))
        return None

    if pfx_len is None:
        pfx_len = ipaddress.IPV4LENGTH if af == socket.AF_INET else ipaddress.IPV6LENGTH
    try:
        ip_net = netaddr.IPNetwork('%s/%d' % (ip_str, pfx_len))
    except netaddr.AddrFormatError:
        log_err('Invalid IP or prefix length: %s %d' % (ip_str, pfx_len))
        return None
    ip = ip_net.cidr.ip.packed

    return (af, ip, pfx_len)

def check_attr_list(attr_list, in_param_list, missed_list = None):
    ret_val = True
    for attr in attr_list:
        if attr not in in_param_list or in_param_list[attr] is None:
            ret_val = False
            if missed_list is not None:
                missed_list.append(attr)
    return ret_val

def config_incoming_ip_svcs_int(methods, params):
    obj = cps_object.CPSObject(obj=params['change'])
    in_param_list = {}

    log_info('Callback for incoming IP service configuration')
    def get_svcs_attr_val(attr_name, dft_val = None):
        attr_id = incoming_ip_svcs_attr(attr_name)
        try:
            attr_val = obj.get_attr_data(attr_id)
        except ValueError:
            attr_val = None
        if attr_val is None:
            attr_val = dft_val
        in_param_list[attr_name] = attr_val
        return attr_val

    operation = params['operation']

    af = get_svcs_attr_val('af')
    vrf_name = get_svcs_attr_val('ni-name')
    protocol = get_svcs_attr_val('protocol')
    dst_port = get_svcs_attr_val('dst-port')
    low_dst_port = get_svcs_attr_val('lower-dst-port')
    high_dst_port = get_svcs_attr_val('upper-dst-port')
    action = get_svcs_attr_val('action')
    src_ip = get_svcs_attr_val('src-ip')
    src_prefix_len = get_svcs_attr_val('src-prefix-len')
    dst_ip = get_svcs_attr_val('dst-ip')
    dst_prefix_len = get_svcs_attr_val('dst-prefix-len')
    in_intf = get_svcs_attr_val('ifname')
    if operation == 'create':
        # set default seq number to 0 for create
        seq_num = get_svcs_attr_val('seq-num', 0)
    else:
        seq_num = get_svcs_attr_val('seq-num')
    rule_id = get_svcs_attr_val('id')

    # check source and destination IP
    if src_ip is not None:
        ip_tuple = normalize_ip_with_prefix(af, src_ip, src_prefix_len)
        if ip_tuple is None:
            log_err('Failed to normalize source IP with prefix')
            return False
        orig_af = af
        af, src_ip, src_prefix_len = ip_tuple
        if orig_af is None:
            log_info('Address family %d is deduced from input source IP %s' %
                     (af, src_ip))
        in_param_list['af'] = af
        in_param_list['src-ip'] = src_ip
        in_param_list['src-prefix-len'] = src_prefix_len
    if dst_ip is not None:
        ip_tuple = normalize_ip_with_prefix(af, dst_ip, dst_prefix_len)
        if ip_tuple is None:
            log_err('Failed to normalize destination IP with prefix')
            return False
        orig_af = af
        af, dst_ip, dst_prefix_len = ip_tuple
        if orig_af is None:
            log_info('Address family %d is deduced from input destination IP %s' %
                     (af, dst_ip))
        in_param_list['af'] = af
        in_param_list['dst-ip'] = dst_ip
        in_param_list['dst-prefix-len'] = dst_prefix_len

    # check lower & upper destination ports
    if low_dst_port is not None and high_dst_port is None:
        log_err('Missing upper-dst-port for VTY ACL rule configuration')
        return False
    if low_dst_port is None and high_dst_port is not None:
        log_err('Missing lower-dst-port for VTY ACL rule configuration')
        return False
    if (low_dst_port is not None or high_dst_port is not None) and dst_port is not None:
        log_err('Invalid VTY ACL rule configuration, \
                 dst port attribute cannot be configured along with dst port range attributes')
        return False

    """
    The input object stands for VTY ACL configuration request if:
    1. Destination L4 port attribute is not given or given value is 0,
    2. Or Source IP address attribute is given,
    3. Or lower & upper destination L4 port attributes are given.

    For all other cases, input object stands for VRF incoming IP service
    request.
    """
    def is_vty_acl_config():
        if dst_port is None or dst_port == 0:
            return True
        if src_ip is not None:
            return True
        if low_dst_port is not None and high_dst_port is not None:
            return True
        return False

    log_info('Input parameters:')
    for name, val in in_param_list.items():
        if val is not None:
            if name == 'src-ip' or name == 'dst-ip':
                log_info('  %-10s - %s' % (name, binascii.hexlify(val)))
            else:
                log_info('  %-10s - %s' % (name, str(val)))

    if is_vty_acl_config():
        log_info('Handle VTY ACL configuration, operation: %s' % operation)
        rule_type = VrfSvcsRuleType.RULE_TYPE_ACL
        reqd_input = ['ni-name', 'af', 'src-ip', 'src-prefix-len', 'action']
    else:
        log_info('Handle incoming IP configuration, operation: %s' % operation)
        rule_type = VrfSvcsRuleType.RULE_TYPE_IP
        reqd_input = ['af', 'ni-name', 'protocol', 'dst-port']
        if vrf_name == 'default':
            reqd_input.append('action')

    def check_rule_input(missed_attr_list = None):
        """ The keys to identify a rule """
        if operation == 'delete':
            """
            For delete operation, either rule ID or rule keys need to be given to find
            rule to be deleted
            """
            if rule_id is not None:
                return True
            else:
                if check_attr_list(reqd_input, in_param_list, missed_attr_list):
                    return True
        elif operation == 'set':
            """
            For set operation, rule ID is the only required input to find the rule to be
            updated. And the attributes of the rule will be changed to attribute value
            given by input
            """
            if rule_id is not None:
                return True
            else:
                if missed_attr_list is not None:
                    missed_attr_list.append('id')
        elif operation == 'create':
            """
            For create operation, all key attributes plus sequence number need to be given
            by input
            """
            if check_attr_list(reqd_input + ['seq-num'], in_param_list, missed_attr_list):
                return True

        return False

    not_found_list = []
    if not check_rule_input(not_found_list):
        log_err('Mandatory attributes %s not found for operation %s' %
                (str(not_found_list), operation))
        return False

    if operation == 'create':
        if rule_type == VrfSvcsRuleType.RULE_TYPE_IP and vrf_name != 'default':
            """
            If it is IP forwarding rule and the name space is not default, we set its action
            type as DNAT
            """
            dst_ip = dn_base_vrf_tool.get_veth_ip(af, vrf_name)
            action = VrfSvcsRuleAction.RULE_ACTION_DNAT
        else:
            if (dst_port is not None and
                protocol != VrfSvcsRuleProto.RULE_PROTO_TCP and
                protocol != VrfSvcsRuleProto.RULE_PROTO_UDP):
                log_err('L4 destination port filter must with protocol type TCP or UDP')
                return False
            if (low_dst_port is not None and
                protocol != VrfSvcsRuleProto.RULE_PROTO_TCP and
                protocol != VrfSvcsRuleProto.RULE_PROTO_UDP):
                log_err('L4 destination port range filter must with protocol type TCP or UDP')
                return False
        ret_val = process_vrf_svcs_rule_add(rule_type, vrf_name, action, af,
                                            src_ip = src_ip, src_prefix_len = src_prefix_len,
                                            dst_ip = dst_ip, dst_prefix_len = dst_prefix_len,
                                            seq_num = seq_num, protocol = protocol, dst_port = dst_port,
                                            low_dst_port = low_dst_port, high_dst_port = high_dst_port,
                                            in_intf = in_intf, rule_id = rule_id)
        if ret_val is None:
            log_err('Failed to add incoming IP rule: VRF %s AF %s%s%s%s%s%s%s%s%s%s%s' % (
                        vrf_name, _af[af],
                        (' IIF %s' % in_intf if in_intf is not None else ' '),
                        (' SRC %s/%d' % (get_ip_str(af, src_ip), src_prefix_len) if src_ip is not None and src_prefix_len is not None else ''),
                        (' DST %s/%d' % (get_ip_str(af, dst_ip), dst_prefix_len) if dst_ip is not None and dst_prefix_len is not None else ''),
                        (' PROTO %s' % _protocol[protocol] if protocol is not None else ''),
                        (' PORT %d' % dst_port if dst_port is not None else ''),
                        (' PORT RANGE %d-%d' % (low_dst_port, high_dst_port) if low_dst_port is not None else ''),
                        (' SEQ %d' % seq_num if seq_num is not None else ''),
                        (' ACTION %s' % _action[action] if action is not None else ''),
                        (' DST %s' % get_ip_str(af, dst_ip) if dst_ip is not None else ''),
                        (' ID %d' % rule_id if rule_id is not None else '')))
            return False
        if rule_id is not None and ret_val != rule_id:
            log_err('Given rule id %d is not equal to actually used id %d' % (rule_id, ret_val))
        obj.add_attr(incoming_ip_svcs_attr('id'), ret_val)
        params['change'] = obj.get()
    elif operation == 'set':
        ret_val = process_vrf_svcs_rule_set(rule_id, src_ip = src_ip,
                                            src_prefix_len = src_prefix_len, protocol = protocol,
                                            dst_ip = dst_ip, dst_prefix_len = dst_prefix_len,
                                            dst_port = dst_port, action = action,
                                            low_dst_port = low_dst_port, high_dst_port = high_dst_port,
                                            seq_num = seq_num, in_intf = in_intf)
        if not ret_val:
            log_err('Failed to update rule with ID %d' % rule_id)
            return False
    elif operation == 'delete':
        if rule_id is None:
            if rule_type == VrfSvcsRuleType.RULE_TYPE_IP and vrf_name != 'default':
                """
                If it is IP forwarding rule and the name space is not default, we set its action
                type as DNAT
                """
                dst_ip = dn_base_vrf_tool.get_veth_ip(af, vrf_name)
                action = VrfSvcsRuleAction.RULE_ACTION_DNAT
            ret_val = process_vrf_svcs_rule_del(rule_type, vrf_name, action, af,
                                                src_ip = src_ip, src_prefix_len = src_prefix_len,
                                                dst_ip = dst_ip, dst_prefix_len = dst_prefix_len,
                                                protocol = protocol, dst_port = dst_port,
                                                low_dst_port = low_dst_port, high_dst_port = high_dst_port,
                                                in_intf = in_intf)
        else:
            ret_val = process_vrf_svcs_rule_del_by_id(rule_id)
        if not ret_val:
            log_err('Failed to delete rule')
            return False
    else:
        log_err('Invalid operation type %s' % operation)
        return False

    return True

def config_incoming_ip_svcs_cb(methods, params):
    global _vrf_mutex
    _vrf_mutex.acquire()
    ret_val = False
    try:
        ret_val = config_incoming_ip_svcs_int(methods, params)
    except Exception as ex:
        logging.exception(ex)
        ret_val = False
    _vrf_mutex.release()
    return ret_val

def config_outgoing_ip_svcs_int(methods, params):
    obj = cps_object.CPSObject(obj=params['change'])
    in_param_list = {}

    log_info('Callback for outgoing IP service configuration')
    def get_svcs_attr_val(attr_name, dft_val = None):
        attr_id = outgoing_ip_svcs_attr(attr_name)
        try:
            attr_val = obj.get_attr_data(attr_id)
        except ValueError:
            attr_val = None
        if attr_val is None:
            attr_val = dft_val
        in_param_list[attr_name] = attr_val
        return attr_val

    operation = params['operation']

    vrf_name = get_svcs_attr_val('ni-name')
    af = get_svcs_attr_val('af')
    public_ip_attr = get_svcs_attr_val('public-ip')
    outgoing_source_ip_attr = get_svcs_attr_val('outgoing-source-ip')
    protocol = get_svcs_attr_val('protocol')
    public_port = get_svcs_attr_val('public-port')
    private_ip_attr = get_svcs_attr_val('private-ip')
    private_port = get_svcs_attr_val('private-port')

    rule_id = get_svcs_attr_val('id')

    orig_af = af
    public_ip = None
    # check public IP
    if public_ip_attr is not None:
        af_ip = normalize_ip_with_prefix(orig_af, public_ip_attr)
        if af_ip is None:
            log_err('Invalid public IP %s for rule configuration' % public_ip_attr)
            return False
        af, public_ip, _ = af_ip
        if orig_af is None:
            log_info('Address family %d is deducted from input public IP %s' %
                     (af, public_ip_attr))
            in_param_list['af'] = af
        in_param_list['public-ip'] = public_ip

    orig_af = af
    outgoing_source_ip = None
    # check outgoing source IP
    if outgoing_source_ip_attr is not None:
        af_ip = normalize_ip_with_prefix(orig_af, outgoing_source_ip_attr)
        if af_ip is None:
            log_err('Invalid outgoing source IP %s for rule configuration' % outgoing_source_ip_attr)
            return False
        af, outgoing_source_ip, _ = af_ip
        if orig_af is None:
            log_info('Address family %d is deducted from input source IP %s' %
                     (af, outgoing_source_ip_attr))
            in_param_list['af'] = af
        in_param_list['outgoing-source-ip'] = outgoing_source_ip

    orig_af = af
    private_ip = None
    # check private IP
    if private_ip_attr is not None:
        af_ip = normalize_ip_with_prefix(orig_af, private_ip_attr)
        if af_ip is None:
            log_err('Invalid private IP %s for rule configuration' % private_ip_attr)
            return False
        af, private_ip, _ = af_ip
        if orig_af is None:
            log_info('Address family %d is deducted from input private IP %s' %
                     (af, private_ip_attr))
            in_param_list['af'] = af
        in_param_list['private-ip'] = private_ip

    """
    The input object stands for Source IP configuration request if:
    1. Outgoing source IP attribute is given

    For all other cases, input object stands for VRF outgoing IP service
    binding request.
    """
    def is_egress_source_ip_config():
        if outgoing_source_ip is not None:
            return True
        return False

    log_info('Input parameters:')
    for name, val in in_param_list.items():
        if val is not None:
            if name == 'public-ip' or name == 'outgoing-source-ip' or name == 'private-ip':
                log_info('  %-10s - %s' % (name, binascii.hexlify(val)))
            else:
                log_info('  %-10s - %s' % (name, str(val)))

    if is_egress_source_ip_config():
        log_info('Handle Outgoing Source IP configuration, operation: %s' % operation)
        rule_type = VrfSvcsRuleType.RULE_TYPE_SNAT
        action    = VrfSvcsRuleAction.RULE_ACTION_SNAT
        reqd_input = ['ni-name', 'af', 'public-ip', 'protocol', 'public-port', 'outgoing-source-ip']
    else:
        log_info('Handle Outgoing IP service binding configuration, operation: %s' % operation)
        rule_type = VrfSvcsRuleType.RULE_TYPE_OUT_IP
        action    = VrfSvcsRuleAction.RULE_ACTION_DNAT
        reqd_input = ['ni-name', 'af', 'public-ip', 'protocol', 'public-port']

    def check_rule_input(missed_attr_list = None):
        """ The keys to identify a rule """
        if operation == 'delete':
            """
            For delete operation, either rule ID or rule keys need to be given to find
            rule to be deleted
            """
            if rule_id is not None:
                return True
            else:
                if check_attr_list(reqd_input, in_param_list, missed_attr_list):
                    return True
        elif operation == 'set':
            """
            set operation, not supported on outgoing IP service configuration
            """
            return False
        elif operation == 'create':
            """
            For create operation, all key attributes need to be given
            """
            if check_attr_list(reqd_input, in_param_list, missed_attr_list):
                return True
        return False

    not_found_list = []
    if not check_rule_input(not_found_list):
        log_err('Operation not support or Mandatory attributes %s not found for operation %s' %
                (str(not_found_list), operation))
        return False

    log_info('Outgoing IP service rule: Operation %s VRF %s AF %s%s%s%s%s%s' % (
              operation, vrf_name,
              (_af[af] if af is not None else ' '),
              (' public-ip %s' % (get_ip_str(af, public_ip)) if public_ip is not None else ''),
              (' protocol %s' % _protocol[protocol] if protocol is not None else ''),
              (' public-port %d' % public_port if public_port is not None else ''),
              (' outgoing-source-ip %s' %
                  (get_ip_str(af, outgoing_source_ip)) if outgoing_source_ip is not None else ''),
              (' ID %d' % rule_id if rule_id is not None else '')))
    try:
        if operation == 'set':
            return False
        elif operation == 'create':
            ret_val, private_ip, private_port  = process_vrf_outgoing_svcs_rule_add(rule_type, vrf_name, action, af,
                                                dst_ip = public_ip, protocol = protocol,
                                                dst_port = public_port,
                                                out_src_ip = outgoing_source_ip,
                                                private_ip = private_ip,
                                                private_port = private_port,
                                                rule_id = rule_id)

            log_info('%s in adding outgoing %s: VRF %s AF %s%s%s%s%s%s%s%s%s' % (
                    ('Success' if ret_val is not None else 'Failure'),
                    ('%s rule' % 'SNAT' if rule_type == VrfSvcsRuleType.RULE_TYPE_SNAT else 'IP'),
                    vrf_name,
                    (_af[af] if af is not None else ' '),
                    (' PROTO %s' % _protocol[protocol] if protocol is not None else ''),
                    (' DST IP %s' % get_ip_str(af, public_ip) if public_ip is not None else ''),
                    (' PORT %d' % public_port if public_port is not None else ''),
                    (' ACTION %s' % _action[action] if action is not None else ''),
                    (' SRC IP %s' %
                        get_ip_str(af, outgoing_source_ip) if outgoing_source_ip is not None else ''),
                    (' PRIVATE IP %s' % get_ip_str(af, private_ip) if private_ip is not None else ''),
                    (' PRIVATE PORT %d' % private_port if private_port is not None else ''),
                    (' ID %d' % ret_val if ret_val is not None else '')))

            if ret_val is not None:
                if rule_type == VrfSvcsRuleType.RULE_TYPE_SNAT:
                    #SNAT flow
                    obj.add_attr(outgoing_ip_svcs_attr('id'), ret_val)
                    params['change'] = obj.get()
                else:
                    #DNAT - service binding flow
                    private_ip = binascii.hexlify(private_ip)
                    cps_obj = cps_object.CPSObject(module='vrf-firewall/ns-outgoing-service', qual='target',
                                               data={
                                               outgoing_ip_svcs_attr('id'):ret_val,
                                               outgoing_ip_svcs_attr('ni-name'):vrf_name,
                                               outgoing_ip_svcs_attr('af'):af,
                                               outgoing_ip_svcs_attr('public-ip'):public_ip_attr,
                                               outgoing_ip_svcs_attr('protocol'):protocol,
                                               outgoing_ip_svcs_attr('public-port'):public_port,
                                               outgoing_ip_svcs_attr('private-ip'):private_ip,
                                               outgoing_ip_svcs_attr('private-port'):private_port
                                               })
                    params['change'] = cps_obj.get()
                return True
        elif operation == 'delete':
            if rule_id is None:
                ret_val = process_vrf_outgoing_svcs_rule_del(rule_type, vrf_name, action, af,
                                                    dst_ip = public_ip, protocol = protocol, dst_port = public_port,
                                                    out_src_ip = outgoing_source_ip, private_ip = private_ip,
                                                    private_port = private_port)
            else:
                ret_val = process_vrf_outgoing_svcs_rule_del_by_id(rule_id)

            if ret_val is True:
                #deleted successfully
                return True
    except Exception as e:
        log_msg = ('%s %s %s' %('Failed to commit operation.',e,params))
        log_err(log_msg)
        return False

    log_err('Outgoing IP service rule: Operation %s Failed VRF %s AF %s%s%s%s%s%s' % (
               operation, vrf_name,
               (_af[af] if af is not None else ' '),
               (' public-ip %s' % (get_ip_str(af, public_ip)) if public_ip is not None else ''),
               (' protocol %s' % _protocol[protocol] if protocol is not None else ''),
               (' public-port %d' % public_port if public_port is not None else ''),
               (' outgoing-source-ip %s' %
                  (get_ip_str(af, outgoing_source_ip)) if outgoing_source_ip is not None else ''),
               (' ID %d' % rule_id if rule_id is not None else '')))
    return False

def config_outgoing_ip_svcs_cb(methods, params):
    global _vrf_mutex
    _vrf_mutex.acquire()
    ret_val = False
    try:
        ret_val = config_outgoing_ip_svcs_int(methods, params)
    except Exception as ex:
        logging.exception(ex)
        ret_val = False
    _vrf_mutex.release()
    return ret_val

def sigterm_hdlr(signum, frame):
    global shutdown
    shutdown = True

def get_incoming_ip_svcs_int(methods, params):
    log_info('Callback for incoming IP service reading')
    obj_attr_map = {
        'ni-name': 'vrf_name',
        'af': 'af',
        'src-ip': 'src_ip',
        'src-prefix-len': 'src_prefix_len',
        'dst-ip': 'dst_ip',
        'dst-prefix-len': 'dst_prefix_len',
        'protocol': 'protocol',
        'dst-port': 'dst_port',
        'lower-dst-port': 'low_dst_port',
        'upper-dst-port': 'high_dst_port',
        'action': 'action',
        'seq-num': 'seq_num',
        'ifname': 'in_intf',
        'id': 'rule_id'}
    obj = cps_object.CPSObject(obj = params['filter'])
    resp = params['list']
    args = {}
    for key, val in obj_attr_map.items():
        attr_name = incoming_ip_svcs_attr(key)
        try:
            attr_val = obj.get_attr_data(attr_name)
        except ValueError:
            attr_val = None
        if attr_val is not None:
            args[val] = attr_val

    # check af
    if 'af' in args and args['af'] is not None:
        af = args['af']
        if af != socket.AF_INET and af != socket.AF_INET6:
            log_err('Invalid address family number %d' % af)
            return False

    # check source and destination IP
    if 'src_ip' in args and args['src_ip'] is not None:
        af = args['af'] if 'af' in args else None
        pfx_len = args['src_prefix_len'] if 'src_prefix_len' in args else None
        ip_tuple = normalize_ip_with_prefix(af, args['src_ip'], pfx_len)
        if ip_tuple is None:
            log_err('Invalid source IP %s for rule reading' % args['src_ip'])
            return False
        args['af'], args['src_ip'], args['src_prefix_len'] = ip_tuple
    if 'dst_ip' in args and args['dst_ip'] is not None:
        af = args['af'] if 'af' in args else None
        pfx_len = args['dst_prefix_len'] if 'dst_prefix_len' in args else None
        ip_tuple = normalize_ip_with_prefix(af, args['dst_ip'], pfx_len)
        if ip_tuple is None:
            log_err('Invalid destination IP %s for rule reading' % args['dst_ip'])
            return False
        args['af'], args['dst_ip'], args['dst_prefix_len'] = ip_tuple

    log_info('Input parameters:')
    for name, val in args.items():
        if val is not None:
            log_info('  %-10s : %s' % (name, str(val)))

    return process_vrf_svcs_rule_get(resp, **args)

def get_incoming_ip_svcs_cb(methods, params):
    global _vrf_mutex
    _vrf_mutex.acquire()
    ret_val = False
    try:
        ret_val = get_incoming_ip_svcs_int(methods, params)
    except Exception as ex:
        logging.exception(ex)
        ret_val = False
    _vrf_mutex.release()
    return ret_val

def get_outgoing_ip_svcs_int(methods, params):
    log_info('Callback for outgoing IP service reading')
    obj_attr_map = {
        'ni-name': 'vrf_name',
        'af': 'af',
        'public-ip': 'dst_ip',
        'protocol': 'protocol',
        'public-port': 'dst_port',
        'private-ip': 'private_ip',
        'private-port': 'private_port',
        'outgoing-source-ip': 'out_src_ip',
        'id': 'rule_id'}
    obj = cps_object.CPSObject(obj = params['filter'])
    resp = params['list']
    args = {}
    for key, val in obj_attr_map.items():
        attr_name = outgoing_ip_svcs_attr(key)
        try:
            attr_val = obj.get_attr_data(attr_name)
        except ValueError:
            attr_val = None
        if attr_val is not None:
            args[val] = attr_val

    # check af
    if 'af' in args and args['af'] is not None:
        af = args['af']
        if af != socket.AF_INET and af != socket.AF_INET6:
            log_err('Invalid address family number %d' % af)
            return False

    # check public IP
    if 'dst_ip' in args and args['dst_ip'] is not None:
        af = args['af'] if 'af' in args else None
        af_ip = normalize_ip_with_prefix(af, args['dst_ip'])
        if af_ip is None:
            log_err('Invalid public IP %s for rule reading' % args['dst_ip'])
            return False
        args['af'], args['dst_ip'], _ = af_ip

    # check source IP
    if 'out_src_ip' in args and args['out_src_ip'] is not None:
        af = args['af'] if 'af' in args else None
        af_ip = normalize_ip_with_prefix(af, args['out_src_ip'])
        if af_ip is None:
            log_err('Invalid outgoing source IP %s for rule reading' % args['out_src_ip'])
            return False
        args['af'], args['out_src_ip'], _ = af_ip

    # check private IP
    if 'private_ip' in args and args['private_ip'] is not None:
        af = args['af'] if 'af' in args else None
        af_ip = normalize_ip_with_prefix(af, args['private_ip'])
        if af_ip is None:
            log_err('Invalid private IP %s for rule reading' % args['private_ip'])
            return False
        args['af'], args['private_ip'], _ = af_ip

    log_info('Input parameters:')
    for name, val in args.items():
        if val is not None:
            if name == 'dst_ip' or name == 'out_src_ip':
                log_info('  %-10s - %s' % (name, binascii.hexlify(val)))
            else:
                log_info('  %-10s : %s' % (name, str(val)))

    return process_vrf_outgoing_svcs_rule_get(resp, **args)


def get_outgoing_ip_svcs_cb(methods, params):
    global _vrf_mutex
    _vrf_mutex.acquire()
    ret_val = False
    try:
        ret_val = get_outgoing_ip_svcs_int (methods, params)
    except Exception as ex:
        logging.exception(ex)
        ret_val = False
    _vrf_mutex.release()
    return ret_val

def get_vrf_intf_cb(methods, params):
    global _vrf_mutex
    _vrf_mutex.acquire()
    ret_val = get_vrf_intf_cb_int(methods, params)
    _vrf_mutex.release()
    return ret_val

def get_vrf_intf_cb_int(methods, params):
    obj = cps_object.CPSObject(obj=params['filter'])
    resp = params['list']

    src_vrf_name = None
    dst_vrf_name = None
    try:
        src_vrf_name = obj.get_attr_data('vrf-mgmt/get-vrf-internal-binding/input/ni-name')
        dst_vrf_name = obj.get_attr_data('vrf-mgmt/get-vrf-internal-binding/input/dst-ni-name')
    except ValueError as e:
        log_msg = 'Missing mandatory attribute ' + e.args[0]
        log_err(log_msg)
        return False

    ret_val, veth_intf = get_vrf_intf_to_dst_vrf(src_vrf_name, dst_vrf_name)
    if ret_val == False:
        return False

    cps_obj = cps_object.CPSObject(module='vrf-mgmt/get-vrf-internal-binding', qual='target',
                                   data={'vrf-mgmt/get-vrf-internal-binding/output/ifname':veth_intf})
    resp.append(cps_obj.get())
    return True

def set_vrf_intf_ip_cb(methods, params):
    global _vrf_mutex
    _vrf_mutex.acquire()
    ret_val = set_vrf_intf_ip_cb_int(methods, params)
    _vrf_mutex.release()
    return ret_val

def set_vrf_intf_ip_cb_int(methods, params):
    obj = cps_object.CPSObject(obj=params['change'])

    if params['operation'] != 'rpc':
        log_err('oper is not RPC')
        return False

    operation = 1
    vrf_name = None
    af = None
    ip = None

    try:
        operation = obj.get_attr_data('vrf-mgmt/src-ip-config/input/operation')
        vrf_name = obj.get_attr_data('vrf-mgmt/src-ip-config/input/ni-name')
        af = obj.get_attr_data('vrf-mgmt/src-ip-config/input/af')
        ip = obj.get_attr_data('vrf-mgmt/src-ip-config/input/src-ip')
    except ValueError as e:
        log_msg = 'Missing mandatory attribute ' + e.args[0]
        log_err(log_msg)
        return False

    # Operation types
    #BASE_CMN_OPERATION_TYPE_CREATE=1
    #BASE_CMN_OPERATION_TYPE_DELETE=2
    #BASE_CMN_OPERATION_TYPE_UPDATE=3
    is_add = True
    if operation == 3:
        log_msg = 'Update operation is not supported!'
        log_err(log_msg)
        return False
    elif operation == 2:
        is_add = False

    if af != socket.AF_INET and af != socket.AF_INET6:
        log_msg = 'Invalid address family' + str(af)
        log_err(log_msg)
        return False

    ip = binascii.unhexlify(ip)
    ip = socket.inet_ntop(af, ip)
    family = 'ipv4'
    if af == socket.AF_INET6:
        family = 'ipv6'

    if dn_base_vrf_tool.process_src_ip_config(vrf_name, is_add, family, ip):
        return True

    return False

""" Handle the leaked VRF configuration to add the route in the VRF with
    veth end IP (in the parent VRF) as the next-hop.
"""
_leaked_rt_key = cps.key_from_name('observed', 'os-re/os-leak-route-config')
def handle_leaked_rt_event():
    _leaked_rt_evt_handle = cps.event_connect()
    cps.event_register(_leaked_rt_evt_handle, _leaked_rt_key)

    while True:
        leaked_rt_evt = cps.event_wait(_leaked_rt_evt_handle)
        obj = cps_object.CPSObject(obj=leaked_rt_evt)
        if obj is None:
            continue

        if not 'operation' in leaked_rt_evt.keys():
            continue

        op = None
        if leaked_rt_evt['operation'] == 'create':
            op = 'add'
        if leaked_rt_evt['operation'] == 'delete':
            op = 'del'

        src_vrf_name = None
        af = None
        prefix = None
        prefix_len = 0
        dst_vrf_name = None
        try:
            dst_vrf_name = obj.get_attr_data('os-re/os-leak-route-config/vrf-name')
            af = obj.get_attr_data('os-re/os-leak-route-config/af')
            prefix = obj.get_attr_data('os-re/os-leak-route-config/route-prefix')
            prefix = binascii.unhexlify(prefix)
            prefix = get_ip_str(af, prefix)
            prefix_len = obj.get_attr_data('os-re/os-leak-route-config/prefix-len')
            src_vrf_name = obj.get_attr_data('os-re/os-leak-route-config/src-vrf-name')
        except ValueError as e:
            log_err('Error - Mandatatory object attributes are not present for route leak configuration!')
            continue

        global _vrf_mutex
        _vrf_mutex.acquire()
        ret_val, nexthop_ip, nexthop_ip6 = _veth_ip_get(dst_vrf_name, src_vrf_name, True)
        _vrf_mutex.release()
        if ret_val is False:
            log_err('veth info. not found while handling src-vrf:%s af:%s prefix:%s/%s dst-vrd:%s'\
                    % (src_vrf_name, str(af), prefix, str(prefix_len), dst_vrf_name))
            continue
        if af == socket.AF_INET6:
            nexthop_ip = nexthop_ip6
        if dn_base_vrf_tool.process_leaked_rt_config(op, af, dst_vrf_name, prefix,\
                                                     prefix_len, nexthop_ip) != True:
            log_err('VRF route leaking configuration failed op:%s src-vrf:%s af:%s prefix:%s/%s dst-vrd:%s'\
                    % (op, src_vrf_name, str(af), prefix, str(prefix_len), dst_vrf_name))
            continue

if __name__ == '__main__':

    shutdown = False

    # Install signal handlers.
    import signal
    signal.signal(signal.SIGTERM, sigterm_hdlr)
    # Clean-up the IP services folders in the /etc/netns/
    try:
        net_ns_ip_svcs_folder = '/etc/netns'
        for dirs in os.listdir(net_ns_ip_svcs_folder):
            rmtree(net_ns_ip_svcs_folder+'/'+dirs)
    except:
        pass

    handle = cps.obj_init()

    _vrf_mutex = threading.Lock()

    d = {}
    d['transaction'] = set_vrf_cb
    cps.obj_register(handle, _vrf_key, d)

    d = {}
    d['transaction'] = set_vrf_intf_cb
    cps.obj_register(handle, _vrf_intf_key, d)

    d = {}
    d['get'] = get_incoming_ip_svcs_cb
    d['transaction'] = config_incoming_ip_svcs_cb
    cps.obj_register(handle, _vrf_incoming_svc_config_key, d)

    d = {}
    d['get'] = get_outgoing_ip_svcs_cb
    d['transaction'] = config_outgoing_ip_svcs_cb
    cps.obj_register(handle, _vrf_outgoing_svc_config_key, d)

    d = {}
    d['get'] = get_vrf_intf_cb
    cps.obj_register(handle, _vrf_get_intf_key, d)

    d = {}
    d['transaction'] = set_vrf_intf_ip_cb
    cps.obj_register(handle, _vrf_intf_ip_key, d)

    log_msg = 'CPS IP VRF registration done'
    log_info(log_msg)

    process_vrf_top_chain_rule(True, 'default')
    # Create the rule to accept the loopback pkts by default i.e snmpwalk destined
    # to loopback IP (127.0.0.1) when pinning is on to accept mgmt pkts only from mgmt VRF.
    lo_pkts_ret_val, rule_id = create_default_lo_pkts_rule()
    #Start leaked route event handle thread to program leaked routes into the OS.
    leaked_rt_cfg_thread = threading.Thread(target=handle_leaked_rt_event,\
                                      name="VRF_Leaked_Rt_Cfg")
    leaked_rt_cfg_thread.setDaemon(True)
    leaked_rt_cfg_thread.start()

    # Notify systemd: Daemon is ready
    systemd.daemon.notify("READY=1")

    # wait until a signal is received
    while False == shutdown:
        signal.pause()

    systemd.daemon.notify("STOPPING=1")
    if lo_pkts_ret_val:
        process_vrf_svcs_rule_del_by_id(rule_id)

    # cleanup code here
    # No need to specifically call sys.exit(0).
    # That's the default behavior in Python.
    process_vrf_top_chain_rule(False, 'default')
