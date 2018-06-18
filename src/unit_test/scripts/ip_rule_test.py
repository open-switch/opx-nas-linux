from dn_base_id_tool import IdGenerator
import dn_base_vrf_svcs_config as cfg

import socket
import pytest
import random
import copy
import re

vrf_name_list = ['default', 'management', 'vrf_test']
test_rule_count = 20

def local_log_err(msg):
    print 'ERROR: %s' % msg

def local_log_info(msg):
    print 'INFO: %s' % msg

orig_run_command = cfg.run_command

def local_run_command(cmd, resp, log_fail = True):
    global orig_run_command
    print 'CMD: %s' % ' '.join(cmd)
    if cmd[0] == '/sbin/ip' and cmd[1] == 'netns' and cmd[2] == 'exec':
        cmd[3] = vrf_prefix + cmd[3]
    elif cmd[0] == '/sbin/iptables' or cmd[0] == '/sbin/ip6tables':
        cmd = ['/sbin/ip', 'netns', 'exec', vrf_prefix + 'default'] + cmd
    else:
        return 0
    ret_val = orig_run_command(cmd, resp)
    if log_fail and ret_val != 0:
        print '*** Command execution failed ***'
        print ' '.join(cmd)
        for r in resp:
            print r
        return ret_val
    return 0

cfg.log_err = local_log_err
#cfg.log_info = local_log_info
cfg.run_command = local_run_command

vrf_prefix = 'test_'

# Initiate namespace for testing
def test_init_netns():
    print '*** Initiate network namespace ***'
    for vrf_name in vrf_name_list:
        ni_name = vrf_prefix + vrf_name
        resp = []
        assert orig_run_command(['/sbin/ip', 'netns', 'add', ni_name], resp) == 0
        for ipt in ['iptables', 'ip6tables']:
            resp = []
            assert orig_run_command(['/sbin/ip', 'netns', 'exec', ni_name, ipt, '-t', 'nat', '-N', 'VRF'], resp) == 0

def get_rand_list_item(lst, remove = False):
    if len(lst) == 0:
        return None
    if not remove:
        return random.choice(lst)
    idx = random.randint(0, len(lst) - 1)
    ret_val = lst[idx]
    del lst[idx]
    return ret_val

def test_id_generator():
    min_id = 10
    max_id = 20
    id_gen = IdGenerator(min_id, max_id)
    test_id = 5
    assert not id_gen.reserve_id(test_id)
    test_id = 25
    assert not id_gen.reserve_id(test_id)
    test_id = 15
    assert not id_gen.is_id_used(test_id)
    assert id_gen.reserve_id(test_id)
    assert id_gen.is_id_used(test_id)
    assert id_gen.release_id(test_id)
    assert not id_gen.release_id(test_id)
    assert not id_gen.is_id_used(test_id)
    for idx in range(min_id, max_id + 1):
        new_id = id_gen.get_new_id()
        assert idx == new_id
    print 'ID generator where all IDs were assigned:'
    print str(id_gen)
    assert id_gen.get_new_id() is None
    assert not id_gen.reserve_id(test_id)
    for idx in range(min_id, max_id + 1):
        assert id_gen.release_id(idx)
    print 'ID generator where all IDs were released:'
    print str(id_gen)
    assert id_gen.reserve_id(min_id)
    assert id_gen.release_id(min_id)

def test_id_alloc_resv():
    id_gen = IdGenerator()
    max_id = 100
    alloc_id_set = set()
    for exp_id in range(1, max_id + 1):
        alloc_id = id_gen.get_new_id()
        assert exp_id == alloc_id
        assert alloc_id not in alloc_id_set
        assert id_gen.is_id_used(alloc_id)
        assert id_gen.max_resved_id == alloc_id
        alloc_id_set.add(alloc_id)
    for exp_id in range(max_id + 1, max_id * 2 + 1):
        assert id_gen.reserve_id(exp_id)
        assert id_gen.is_id_used(exp_id)
        # reserve used ID will fail
        assert not id_gen.reserve_id(exp_id)
        assert id_gen.max_resved_id == exp_id
    id_list = list(alloc_id_set)
    rel_id_set = set()
    for idx in range(max_id / 2):
        test_id = get_rand_list_item(id_list, True)
        assert id_gen.release_id(test_id)
        # release non-existent ID will fail
        assert not id_gen.release_id(test_id)
        assert not id_gen.is_id_used(test_id)
        rel_id_set.add(test_id)
    sorted_list = sorted(rel_id_set)
    for exp_id in sorted_list:
        alloc_id = id_gen.get_new_id()
        # test if ID allocation is always from the lowest available one
        assert exp_id == alloc_id
    assert id_gen.max_resved_id == max_id * 2
    for test_id in range(1, max_id * 2 + 1):
        assert id_gen.release_id(test_id)
    assert len(id_gen.resved_ids) == 0
    assert id_gen.avail_id == 1
    assert id_gen.max_resved_id is None

def test_rule_obj():
    af = socket.AF_INET
    rule1 = cfg.VrfIncomingSvcsRule(cfg.VrfIncomingSvcsRule.RULE_TYPE_ACL, 'test_vrf',
                                cfg.VrfIncomingSvcsRule.RULE_ACTION_ALLOW, af,
                                src_ip = socket.inet_pton(af, '1.1.1.0'), prefix_len = 24,
                                protocol = cfg.VrfIncomingSvcsRule.RULE_PROTO_TCP,
                                dst_port = 8080, seq_num = 100,
                                rule_id = 1)
    rule2 = cfg.VrfIncomingSvcsRule(cfg.VrfIncomingSvcsRule.RULE_TYPE_ACL, 'test_vrf',
                                cfg.VrfIncomingSvcsRule.RULE_ACTION_DENY, af,
                                src_ip = socket.inet_pton(af, '1.1.2.0'), prefix_len = 24,
                                protocol = cfg.VrfIncomingSvcsRule.RULE_PROTO_UDP,
                                dst_port = 1000, seq_num = 110,
                                rule_id = 2)
    assert rule1.get_rule_type_name() == 'ACL'
    assert rule1.get_af_name() == 'IPv4'
    assert rule1.get_action_name() == 'allow'
    assert rule1.get_proto_name() == 'tcp'
    print 'IPv4 rule created:'
    print str(rule1)
    print str(rule2)
    assert rule1 == rule1
    assert not rule1 == rule2
    assert rule1.match(src_ip = socket.inet_pton(af, '1.1.1.0'), prefix_len = 24)
    assert not rule2.match(src_ip = socket.inet_pton(af, '1.1.1.0'), prefix_len = 24)

    af = socket.AF_INET6
    rule1 = cfg.VrfIncomingSvcsRule(cfg.VrfIncomingSvcsRule.RULE_TYPE_IP, 'test_vrf',
                                cfg.VrfIncomingSvcsRule.RULE_ACTION_DNAT, af,
                                src_ip = socket.inet_pton(af, '1::1'), prefix_len = 128,
                                dst_ip = socket.inet_pton(af, '2::1'),
                                protocol = cfg.VrfIncomingSvcsRule.RULE_PROTO_ICMP)
    rule2 = cfg.VrfIncomingSvcsRule(cfg.VrfIncomingSvcsRule.RULE_TYPE_IP, 'test_vrf',
                                cfg.VrfIncomingSvcsRule.RULE_ACTION_DNAT, af,
                                src_ip = socket.inet_pton(af, '1::2'), prefix_len = 128,
                                dst_ip = socket.inet_pton(af, '2::1'),
                                seq_num = 20)
    print 'IPv6 rule created:'
    print str(rule1)
    print str(rule2)
    assert rule1 == rule1
    assert not rule1 == rule2
    assert rule1.match(src_ip = socket.inet_pton(af, '1::1'))
    assert not rule2.match(src_ip = socket.inet_pton(af, '1::1'))
    with pytest.raises(ValueError):
        rule = cfg.VrfIncomingSvcsRule(100, 'vrf', 1, socket.AF_INET6)
    with pytest.raises(ValueError):
        rule = cfg.VrfIncomingSvcsRule(cfg.VrfIncomingSvcsRule.RULE_TYPE_ACL, 'vrf', 1, 50)
    with pytest.raises(ValueError):
        rule = cfg.VrfIncomingSvcsRule(cfg.VrfIncomingSvcsRule.RULE_TYPE_ACL, 'vrf', 1, socket.AF_INET,
                                   protocol = 6)
    with pytest.raises(ValueError):
        rule = cfg.VrfIncomingSvcsRule(cfg.VrfIncomingSvcsRule.RULE_TYPE_ACL, 'vrf', 6, socket.AF_INET)

# check if seq_num is sorted and rule_id_map
def check_rule_list(rule_list):
    last_seq_num = None
    for idx in range(len(rule_list)):
        rule = rule_list[idx]
        if last_seq_num is not None:
            assert rule.seq_num >= last_seq_num
        last_seq_num = rule.seq_num
        assert rule.rule_id in rule_list.rule_id_map
        assert rule_list.rule_id_map[rule.rule_id] == idx

def test_rule_list():
    id_gen = IdGenerator()
    prefix_len_list = [8, 16, 24, 32]
    action_list = [cfg.VrfIncomingSvcsRule.RULE_ACTION_ALLOW, cfg.VrfIncomingSvcsRule.RULE_ACTION_DENY]
    src_ip_list = []
    for idx in range(1, 250):
        src_ip_list.append('2.2.2.' + str(idx))
    rule_list = cfg.VrfIncomingSvcsRuleList()

    af = socket.AF_INET
    rule1 = cfg.VrfIncomingSvcsRule(cfg.VrfIncomingSvcsRule.RULE_TYPE_ACL, 'test_vrf',
                                cfg.VrfIncomingSvcsRule.RULE_ACTION_ALLOW, af,
                                src_ip = socket.inet_pton(af, '1.1.1.0'), prefix_len = 24,
                                protocol = cfg.VrfIncomingSvcsRule.RULE_PROTO_TCP,
                                dst_port = 8080, seq_num = 100)

    assert rule_list.insert(rule1) is None
    rule1.rule_id = 5
    assert rule_list.insert(rule1) == 0
    assert len(rule_list) == 1
    new_rule = copy.deepcopy(rule1)
    # duplicate insert is not allowed
    assert rule_list.insert(new_rule) is None
    new_rule.rule_id = None
    # delete rule by rule attribute match
    assert rule_list.remove(new_rule) is not None
    assert len(rule_list) == 0
    rule1.rule_id = 10
    assert rule_list.insert(rule1) == 0
    assert rule_list.remove_by_id(10) is not None
    assert len(rule_list) == 0
    assert len(rule_list.seq_num_list) == 0
    assert len(rule_list.rule_id_map) == 0

    test_rule_num = 20
    rule_id_list = []
    while test_rule_num > 0:
        src_ip = get_rand_list_item(src_ip_list, True)
        if src_ip is None:
            break
        prefix_len = get_rand_list_item(prefix_len_list)
        action = get_rand_list_item(action_list)
        rule = cfg.VrfIncomingSvcsRule(cfg.VrfIncomingSvcsRule.RULE_TYPE_ACL, "test_vrf", action, af,
                                   src_ip = socket.inet_pton(socket.AF_INET, src_ip),
                                   prefix_len = prefix_len, seq_num = random.randint(1, 1000),
                                   rule_id = id_gen.get_new_id())
        print 'Add rule to list: %s' % rule
        idx = rule_list.insert(rule)
        assert idx is not None
        check_rule_list(rule_list)
        rule_id_list.append(rule.rule_id)
        test_rule_num -= 1
    assert len(rule_list) == 20
    assert len(rule_id_list) == 20
    print 'Rule IDs: %s' % rule_id_list
    # clone rule list
    new_list = copy.deepcopy(rule_list)
    assert len(new_list) == 20

    # delete all rules
    while len(rule_id_list) > 0:
        rule_id = get_rand_list_item(rule_id_list, True)
        print 'Delete rule ID %d' % rule_id
        assert rule_list.remove_by_id(rule_id) is not None
        check_rule_list(rule_list)
    assert len(rule_list) == 0
    assert len(rule_list.seq_num_list) == 0
    assert len(rule_list.rule_id_map) == 0
    print 'All rules were deleted'

    new_list.clear()
    assert len(new_list) == 0
    assert len(new_list.seq_num_list) == 0
    assert len(new_list.rule_id_map) == 0

def generate_random_rules(max_rule_num):
    src_ip_list = ['10.1.1.%d' % x for x in range(1, 255)]
    src_ip6_list = ['1000::%d' % x for x in range(101, 300)]
    dst_port_list = range(20, 200)
    dst_ip4 = '192.168.0.1'
    dst_ip6 = '1::1'
    rule_type_list = [cfg.VrfIncomingSvcsRule.RULE_TYPE_ACL, cfg.VrfIncomingSvcsRule.RULE_TYPE_IP]
    af_list = [socket.AF_INET, socket.AF_INET6]
    proto_list = [cfg.VrfIncomingSvcsRule.RULE_PROTO_TCP, cfg.VrfIncomingSvcsRule.RULE_PROTO_UDP]
    action_list = [cfg.VrfIncomingSvcsRule.RULE_ACTION_DENY, cfg.VrfIncomingSvcsRule.RULE_ACTION_ALLOW]
    prefix_list = [8, 16, 24, 32]
    prefix6_list = [8, 16, 24, 32, 64, 128]
    bool_list = [True, False]
    rule_id_list = range(10000, 10200)
    intf_list = [None, 'vdef-nsid1024', 'lo']
    rules = []
    for idx in xrange(max_rule_num):
        vrf_name = get_rand_list_item(vrf_name_list)
        af = get_rand_list_item(af_list)
        action = get_rand_list_item(action_list)
        rule_type = get_rand_list_item(rule_type_list)
        seq_num = random.randint(1, 1000)
        if get_rand_list_item(bool_list):
            rule_id = get_rand_list_item(rule_id_list, True)
        else:
            rule_id = None
        high_prio = get_rand_list_item(bool_list)
        if rule_type == cfg.VrfIncomingSvcsRule.RULE_TYPE_ACL:
            if af == socket.AF_INET:
                src_ip = get_rand_list_item(src_ip_list, True)
                prefix_len = get_rand_list_item(prefix_list)
            else:
                src_ip = get_rand_list_item(src_ip6_list, True)
                prefix_len = get_rand_list_item(prefix6_list)
            if src_ip is None:
                break
            in_intf = get_rand_list_item(intf_list)
            rule = cfg.VrfIncomingSvcsRule(rule_type, vrf_name, action, af,
                                           src_ip = socket.inet_pton(af, src_ip), prefix_len = prefix_len,
                                           seq_num = seq_num, rule_id = rule_id,
                                           high_prio = high_prio, in_intf = in_intf)
        else:
            proto = get_rand_list_item(proto_list)
            dst_port = get_rand_list_item(dst_port_list, True)
            if dst_port is None:
                break
            if vrf_name != 'default':
                action = cfg.VrfIncomingSvcsRule.RULE_ACTION_DNAT
                if af == socket.AF_INET:
                    dst_ip = dst_ip4
                else:
                    dst_ip = dst_ip6
            else:
                dst_ip = None
            rule = cfg.VrfIncomingSvcsRule(rule_type, vrf_name, action, af, protocol = proto,
                                           dst_port = dst_port, dst_ip = (None if dst_ip is None else socket.inet_pton(af, dst_ip)),
                                           seq_num = seq_num, rule_id = rule_id, high_prio = high_prio)
        rules.append(rule)
    return rules

def get_rule_count(rule_list):
    count_acl = {socket.AF_INET: {}, socket.AF_INET6: {}}
    count_ip = {socket.AF_INET: {}, socket.AF_INET6: {}}
    for rule in rule_list:
        if rule.rule_type == cfg.VrfIncomingSvcsRule.RULE_TYPE_IP:
            count_map = count_ip
        else:
            count_map = count_acl
        if rule.vrf_name not in count_map[rule.af]:
            count_map[rule.af][rule.vrf_name] = 1
        else:
            count_map[rule.af][rule.vrf_name] += 1
    return (count_acl, count_ip)

def test_ipt_handler():
    rule_list = generate_random_rules(test_rule_count)
    bool_list = [True, False]
    rule = copy.deepcopy(rule_list[0])
    assert cfg.IptablesHandler.proc_rule('insert', rule)
    assert cfg.IptablesHandler.proc_rule('replace', rule, idx = 0)
    assert cfg.IptablesHandler.proc_rule('check', rule)
    assert cfg.IptablesHandler.proc_rule('delete', rule, idx = 0)

    print 'Test iptables handler with %d rules' % len(rule_list)
    for idx in xrange(len(rule_list)):
        print 'Insert rule %d: %s' % (idx, rule_list[idx])
        if get_rand_list_item(bool_list):
            rule_idx = 0
        else:
            rule_idx = None
        assert cfg.IptablesHandler.proc_rule('insert', rule_list[idx], idx = rule_idx)
    for rule in rule_list:
        print 'Check rule: %s' % rule
        assert cfg.IptablesHandler.proc_rule('check', rule)
    for rule in rule_list:
        print 'Delete rule: %s' % rule
        assert cfg.IptablesHandler.proc_rule('delete', rule)

def test_rule_cache():
    bool_list = [True, False]
    action_list = [cfg.VrfIncomingSvcsRule.RULE_ACTION_DENY, cfg.VrfIncomingSvcsRule.RULE_ACTION_ALLOW]
    rule_list = generate_random_rules(test_rule_count)
    acl_count, ip_count = get_rule_count(rule_list)
    print 'Test rule cache insert/delete_by_id with %d rules' % len(rule_list)
    rule_id_list = set()
    exp_rule_id = 1
    for rule in rule_list:
        orig_rule_id = rule.rule_id
        print 'INSERT: %s' % rule
        assert cfg.VrfIncomingSvcsRuleCache.insert_rule(rule)
        if orig_rule_id is None:
            assert exp_rule_id == rule.rule_id
            exp_rule_id += 1
        assert rule.rule_id not in rule_id_list
        rule_id_list.add(rule.rule_id)
    max_prio_rule_idx = {}
    min_reg_rule_idx = {}
    rule_key_count = {}
    for rule_id in rule_id_list:
        ret_val = cfg.VrfIncomingSvcsRuleCache.find_rule_by_id(rule_id)
        assert ret_val is not None
        rule, idx = ret_val
        if rule.grp_priority == cfg.VrfIncomingSvcsRule.HIGH_GRP_PRIO:
            if ((rule.rule_type, rule.vrf_name, rule.af) not in max_prio_rule_idx or
                idx > max_prio_rule_idx[(rule.rule_type, rule.vrf_name, rule.af)]):
                max_prio_rule_idx[(rule.rule_type, rule.vrf_name, rule.af)] = idx
        elif rule.grp_priority == cfg.VrfIncomingSvcsRule.DEFAULT_GRP_PRIO:
            if ((rule.rule_type, rule.vrf_name, rule.af) not in min_reg_rule_idx or
                idx < min_reg_rule_idx[(rule.rule_type, rule.vrf_name, rule.af)]):
                min_reg_rule_idx[(rule.rule_type, rule.vrf_name, rule.af)] = idx
        else:
            assert False
        if (rule.rule_type, rule.vrf_name, rule.af) not in rule_key_count:
            rule_key_count[(rule.rule_type, rule.vrf_name, rule.af)] = 0
        else:
            rule_key_count[(rule.rule_type, rule.vrf_name, rule.af)] += 1
    for key, val in rule_key_count.items():
        if key not in max_prio_rule_idx:
            print 'There is no high priority rule for type %d vrf %s af %d' % key
        elif key not in min_reg_rule_idx:
            print 'There is no regular priority rule for type %d vrf %s af %d' % key
        else:
            print 'Check priority rule index for type %d vrf %s af %d (%d rules)' % (key + (val, ))
            assert max_prio_rule_idx[key] < min_reg_rule_idx[key]
    for af in [socket.AF_INET, socket.AF_INET6]:
        for vrf_name, count in acl_count[af].items():
            assert vrf_name in cfg.VrfIncomingSvcsRuleCache.acl_rules[af]
            assert len(cfg.VrfIncomingSvcsRuleCache.acl_rules[af][vrf_name]) == count
        for vrf_name, count in ip_count[af].items():
            assert vrf_name in cfg.VrfIncomingSvcsRuleCache.ip_rules[af]
            assert len(cfg.VrfIncomingSvcsRuleCache.ip_rules[af][vrf_name]) == count
    assert cfg.VrfIncomingSvcsRuleCache.find_rule_by_id(exp_rule_id) is None
    rule_id = random.choice(list(rule_id_list))
    ret_val = cfg.VrfIncomingSvcsRuleCache.find_rule_by_id(rule_id)
    assert ret_val is not None
    rule, idx = ret_val
    assert rule.rule_id == rule_id
    for rule_id in rule_id_list:
        print 'DELETE: ID %d' % rule_id
        assert cfg.VrfIncomingSvcsRuleCache.delete_rule_by_id(rule_id)
    for af in [socket.AF_INET, socket.AF_INET6]:
        assert len(cfg.VrfIncomingSvcsRuleCache.acl_rules[af]) == 0
        assert len(cfg.VrfIncomingSvcsRuleCache.ip_rules[af]) == 0
    assert cfg.VrfIncomingSvcsRuleCache.id_generator.avail_id == 1

    rule_list = generate_random_rules(test_rule_count)
    print 'Test rule cache insert/delete with %d rules' % len(rule_list)
    new_rule_list = []
    for rule in rule_list:
        new_rule = copy.deepcopy(rule)
        new_rule.rule_id = None
        new_rule_list.append(new_rule)
        print 'INSERT: %s' % rule
        assert cfg.VrfIncomingSvcsRuleCache.insert_rule(rule)
    assert len(rule_list) == len(new_rule_list)
    for rule in new_rule_list:
        print 'DELETE: %s' % rule
        assert cfg.VrfIncomingSvcsRuleCache.delete_rule(rule)
    for af in [socket.AF_INET, socket.AF_INET6]:
        assert len(cfg.VrfIncomingSvcsRuleCache.acl_rules[af]) == 0
        assert len(cfg.VrfIncomingSvcsRuleCache.ip_rules[af]) == 0
    assert cfg.VrfIncomingSvcsRuleCache.id_generator.avail_id == 1

    rule_list = generate_random_rules(test_rule_count)
    print 'Test rule cache insert/update with %d rules' % len(rule_list)
    for rule in rule_list:
        print 'INSERT: %s' % rule
        assert cfg.VrfIncomingSvcsRuleCache.insert_rule(rule)
    offset = 1
    for rule in rule_list:
        params = {}
        if get_rand_list_item(bool_list):
            params['seq_num'] = rule.seq_num + random.randint(1, 100)
        if rule.rule_type == cfg.VrfIncomingSvcsRule.RULE_TYPE_ACL:
            if rule.af == socket.AF_INET:
                params['src_ip'] = socket.inet_pton(rule.af, '1.1.1.%d' % offset)
            else:
                params['src_ip'] = socket.inet_pton(rule.af, '5::%d' % offset)
            if get_rand_list_item(bool_list):
                params['action'] = get_rand_list_item(action_list)
        else:
            params['protocol'] = cfg.VrfIncomingSvcsRule.RULE_PROTO_TCP
            params['dst_port'] = 300 + offset
        offset += 1
        print 'UPDATE rule with: %s' % params
        assert cfg.VrfIncomingSvcsRuleCache.update_rule(rule.rule_id, **params)
        ret_val = cfg.VrfIncomingSvcsRuleCache.find_rule_by_id(rule.rule_id)
        assert ret_val is not None
        print 'NEW RULE: %s' % ret_val[0]
        rule_attrs = vars(ret_val[0])
        for key, val in params.items():
            assert key in rule_attrs
            assert val == rule_attrs[key]

    cfg.VrfIncomingSvcsRuleCache.dump_rules()
    for vrf in vrf_name_list:
        for af in [socket.AF_INET, socket.AF_INET6]:
            cfg.VrfIncomingSvcsRuleCache.clear_all_rules(flt_vrf = vrf, flt_af = af)
    for af in [socket.AF_INET, socket.AF_INET6]:
        assert len(cfg.VrfIncomingSvcsRuleCache.acl_rules[af]) == 0
        assert len(cfg.VrfIncomingSvcsRuleCache.ip_rules[af]) == 0
    assert cfg.VrfIncomingSvcsRuleCache.id_generator.avail_id == 1

    rule_list = generate_random_rules(test_rule_count)
    acl_count, ip_count = get_rule_count(rule_list)
    print 'Test get with %d rules' % len(rule_list)
    for rule in rule_list:
        print 'INSERT: %s' % rule
        assert cfg.VrfIncomingSvcsRuleCache.insert_rule(rule)
    ret_list = cfg.VrfIncomingSvcsRuleCache.get_all_rules()

    # Test duplicate rule insert failure
    for rule in rule_list:
        print 'DUPLICATE INSERT: %s' % rule
        assert cfg.VrfIncomingSvcsRuleCache.insert_rule(rule) == False

    assert len(ret_list) == len(rule_list)
    for rule in ret_list:
        try:
            idx = rule_list.index(rule)
        except ValueError:
            assert False
    for af in [socket.AF_INET, socket.AF_INET6]:
        rule_type = cfg.VrfIncomingSvcsRule.RULE_TYPE_IP
        for vrf_name in ip_count[af].keys():
            ret_list = cfg.VrfIncomingSvcsRuleCache.get_all_rules(rule_type, vrf_name, af = af)
            assert len(ret_list) == ip_count[af][vrf_name]
        rule_type = cfg.VrfIncomingSvcsRule.RULE_TYPE_ACL
        for vrf_name in acl_count[af].keys():
            ret_list = cfg.VrfIncomingSvcsRuleCache.get_all_rules(rule_type, vrf_name, af = af)
            assert len(ret_list) == acl_count[af][vrf_name]
    cfg.VrfIncomingSvcsRuleCache.clear_all_rules()
    for af in [socket.AF_INET, socket.AF_INET6]:
        assert len(cfg.VrfIncomingSvcsRuleCache.acl_rules[af]) == 0
        assert len(cfg.VrfIncomingSvcsRuleCache.ip_rules[af]) == 0
    assert cfg.VrfIncomingSvcsRuleCache.id_generator.avail_id == 1

def test_rule_api():
    rid1 = cfg.process_vrf_svcs_rule_add(cfg.VrfIncomingSvcsRule.RULE_TYPE_ACL, 'management',
                                         cfg.VrfIncomingSvcsRule.RULE_ACTION_DENY,
                                         socket.AF_INET,
                                         src_ip = socket.inet_pton(socket.AF_INET, '1.1.1.0'), prefix_len = 24,
                                         seq_num = 100)
    assert rid1 is not None
    rid2 = cfg.process_vrf_svcs_rule_add(cfg.VrfIncomingSvcsRule.RULE_TYPE_ACL, 'management',
                                         cfg.VrfIncomingSvcsRule.RULE_ACTION_ALLOW,
                                         socket.AF_INET6,
                                         src_ip = socket.inet_pton(socket.AF_INET6, '1:1::'), prefix_len = 64,
                                         seq_num = 101)
    assert rid2 is not None
    rid3 = cfg.process_vrf_svcs_rule_add(cfg.VrfIncomingSvcsRule.RULE_TYPE_IP, 'management',
                                         cfg.VrfIncomingSvcsRule.RULE_ACTION_DNAT,
                                         socket.AF_INET,
                                         protocol = cfg.VrfIncomingSvcsRule.RULE_PROTO_TCP, dst_port = 1234,
                                         dst_ip = socket.inet_pton(socket.AF_INET, '3.3.3.3'))
    assert rid3 is not None
    rid4 = cfg.process_vrf_svcs_rule_add(cfg.VrfIncomingSvcsRule.RULE_TYPE_IP, 'management',
                                         cfg.VrfIncomingSvcsRule.RULE_ACTION_DNAT,
                                         socket.AF_INET6,
                                         protocol = cfg.VrfIncomingSvcsRule.RULE_PROTO_TCP, dst_port = 1235,
                                         dst_ip = socket.inet_pton(socket.AF_INET6, '3::3'))
    assert rid4 is not None

    assert cfg.process_vrf_svcs_rule_set(rid1, src_ip = socket.inet_pton(socket.AF_INET, '2.2.2.0'))
    assert cfg.process_vrf_svcs_rule_set(rid2, seq_num = 200)
    assert not cfg.process_vrf_svcs_rule_del(cfg.VrfIncomingSvcsRule.RULE_TYPE_ACL, 'management',
                                             cfg.VrfIncomingSvcsRule.RULE_ACTION_DENY, socket.AF_INET,
                                             src_ip = socket.inet_pton(socket.AF_INET, '1.1.1.0'), prefix_len = 24)
    assert cfg.process_vrf_svcs_rule_del(cfg.VrfIncomingSvcsRule.RULE_TYPE_ACL, 'management',
                                         cfg.VrfIncomingSvcsRule.RULE_ACTION_DENY, socket.AF_INET,
                                         src_ip = socket.inet_pton(socket.AF_INET, '2.2.2.0'), prefix_len = 24)
    assert not cfg.process_vrf_svcs_rule_del_by_id(rid1)
    assert cfg.process_vrf_svcs_rule_del_by_id(rid2)
    resp = []
    assert cfg.process_vrf_svcs_rule_get(resp)
    assert len(resp) == 2
    assert cfg.process_vrf_svcs_rule_del_by_id(rid3)
    assert cfg.process_vrf_svcs_rule_del_by_id(rid4)

def test_show_ipt_rules():
    for vrf_name in vrf_name_list:
        ni_name = vrf_prefix + vrf_name
        for ipt in ['iptables', 'ip6tables']:
            for tbl in ['raw', 'nat']:
                resp = []
                assert orig_run_command(['/sbin/ip', 'netns', 'exec', ni_name, ipt, '-t', tbl, '-L', '-v'], resp) == 0
                print '+++ Rule of vrf %s of %s table %s +++' % (vrf_name, ipt, tbl)
                for r in resp:
                    print r

# Cleanup namespace for testing
def test_deinit_netns():
    print '*** Cleanup network namespace ***'
    resp = []
    for vrf_name in vrf_name_list:
        ni_name = vrf_prefix + vrf_name
        resp = []
        assert orig_run_command(['/sbin/ip', 'netns', 'delete', ni_name], resp) == 0

def dump_all_netns():
    print '-----------------------'
    print ' List of all netns'
    print '-----------------------'
    resp = []
    if orig_run_command(['/sbin/ip', 'netns', 'show'], resp) != 0:
        print 'Failed to read IP netns'
        return
    if len(resp) == 0:
        print '[empty]'
        return
    for token in resp:
        m = re.search('(.*)\s+\(id:\s+(\S+)\)', token)
        if m is not None:
            vrf_name, vrf_id = m.groups()
        else:
            vrf_name = token
            vrf_id = None
        print '%-10s ID %s' % (vrf_name, vrf_id if vrf_id is not None else '-')

def test_delete_no_netns():
    test_init_netns()
    dump_all_netns()
    rule_list = generate_random_rules(test_rule_count)
    rule_id_list = set()
    exp_rule_id = 1
    for rule in rule_list:
        orig_rule_id = rule.rule_id
        if rule.vrf_name == 'default':
            continue
        print 'INSERT: %s' % rule
        assert cfg.VrfIncomingSvcsRuleCache.insert_rule(rule)
        if orig_rule_id is None:
            assert exp_rule_id == rule.rule_id
            exp_rule_id += 1
        assert rule.rule_id not in rule_id_list
        rule_id_list.add(rule.rule_id)
    test_deinit_netns()
    dump_all_netns()
    for rule_id in rule_id_list:
        print 'DELETE: ID %d' % rule_id
        assert cfg.VrfIncomingSvcsRuleCache.delete_rule_by_id(rule_id)
    for af in [socket.AF_INET, socket.AF_INET6]:
        assert len(cfg.VrfIncomingSvcsRuleCache.acl_rules[af]) == 0
        assert len(cfg.VrfIncomingSvcsRuleCache.ip_rules[af]) == 0
    assert cfg.VrfIncomingSvcsRuleCache.id_generator.avail_id == 1
