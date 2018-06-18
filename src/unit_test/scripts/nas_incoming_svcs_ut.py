#!/usr/bin/python

import cps
import cps_object
import cps_utils
import subprocess
import argparse
import socket
import time
import binascii

"""
Example:
nas_incoming_svcs_ut.py create -s 1.2.3.0/24 -f ipv4 -i 100 -a deny
nas_incoming_svcs_ut.py delete -s 1.2.3.0/24 -f ipv4 -a deny
nas_incoming_svcs_ut.py info
nas_incoming_svcs_ut.py delete 1
nas_incoming_svcs_ut.py create -s 1:2::0/64 -a allow -f ipv6 -i 200

nas_incoming_svcs_ut.py create -n management -p udp -d 1234 -f ipv4
nas_incoming_svcs_ut.py delete -n management -p udp -d 1234 -f ipv4

nas_incoming_svcs_ut.py create -n default -s 1.2.3.0/24 -p tcp -d 1234 -f ipv4 -i 100 -a allow
nas_incoming_svcs_ut.py delete -n default -s 1.2.3.0/24 -p tcp -d 1234 -f ipv4 -a allow

nas_incoming_svcs_ut.py create -n default -p tcp -d 21 -f ipv4 -a deny
nas_incoming_svcs_ut.py delete -n default -p tcp -d 21 -f ipv4 -a deny
"""

def parse_ip_mask(key, val):
    ip_mask = val.split('/')
    if len(ip_mask) < 2:
        ip_addr = ip_mask[0]
        mask = None
    else:
        ip_addr, mask = ip_mask[:2]
    for af in [socket.AF_INET, socket.AF_INET6]:
        try:
            ip_bin = socket.inet_pton(af, ip_addr)
            return (af, binascii.hexlify(ip_bin), mask)
        except socket.error:
            continue
    return None

def parse_af(key, val):
    if val.lower() == 'ipv4':
        return socket.AF_INET
    else:
        return socket.AF_INET6

def parse_action(key, val):
    if val.lower() == 'deny':
        return 2
    else:
        return 1

def parse_protocol(key, val):
    if val.lower() == 'tcp':
        return 1
    elif val.lower() == 'udp':
        return 2
    else:
        return 3

arg_cps_attr_map = {
    'rule_id': ('id', None),
    'vrf_name': ('ni-name', None),
    'src_ip': (['af', 'src-ip', 'src-prefix-len'], parse_ip_mask),
    'addr_family': ('af', parse_af),
    'seq_num': ('seq-num', None),
    'action': ('action', parse_action),
    'protocol': ('protocol', parse_protocol),
    'dst_port': ('dst-port', None)
}

def exec_shell(cmd):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    return out

def test_pre_req_cfg(clear = False, mgmt_ip = '10.11.70.22/8'):
    #config test pre requisite - manangement vrf
    mode = 'OPX'
    ret = exec_shell('os10-show-version | grep \"OS_NAME.*Enterprise\"')
    if ret:
        mode = 'DoD'

    if mode is 'DoD':
        #configure the test pre requisites via CLI
        if clear:
            cmd_list =  ['configure terminal',
                         'interface mgmt1/1/1',
                         'no ip address',
                         'exit',
                         'ip vrf management',
                         'no interface management',
                         'exit',
                         'no ip vrf management',
                         'interface mgmt1/1/1',
                         'ip address ' + mgmt_ip,
                         'end']
        else:
            cmd_list =  ['configure terminal',
                         'interface mgmt1/1/1',
                         'no ip address',
                         'no ipv6 address',
                         'exit',
                         'ip vrf management',
                         'interface management',
                         'exit',
                         'interface mgmt1/1/1',
                         'ip address ' + mgmt_ip,
                         'end']
        cfg_file = open('/tmp/test_pre_req', 'w')
        for item in cmd_list:
            print>>cfg_file, item
        cfg_file.close()
        exec_shell('sudo -u admin clish --b /tmp/test_pre_req')
    else:
        print 'UT for BASE is not supported yet.'


parser = argparse.ArgumentParser(description = 'Tool for incoming IP service configuration')
parser.add_argument('operation', choices = ['create', 'delete', 'set', 'info', 'pre-cfg', 'run-test'])
parser.add_argument('rule_id', type = int, nargs = '?', help = 'Rule ID')
parser.add_argument('--clear', action = 'store_true', help = 'Cleanup pre-configuration for testing')
parser.add_argument('--mgmt-ip', help = 'Management IP address and mask for testing')
parser.add_argument('-n', '--vrf-name',  default = 'default', choices = ['default', 'management'], help = 'VRF name')
parser.add_argument('-s', '--src-ip', help = 'Source IP address and mask')
parser.add_argument('-f', '--addr-family', choices = ['ipv4', 'ipv6'], help = 'Address family')
parser.add_argument('-i', '--seq-num', type = int, help = 'Sequence number')
parser.add_argument('-a', '--action', choices = ['allow', 'deny'], help = 'Action')
parser.add_argument('-p', '--protocol', choices = ['tcp', 'udp', 'icmp'], help = 'Protocol')
parser.add_argument('-d', '--dst-port', type = int, help = 'L4 destination port')

test_count = 0

def incoming_svcs_test(is_negative_test = False, *test_args):
    global parser
    global test_count

    if len(test_args) == 0:
        args = vars(parser.parse_args())
    else:
        args = vars(parser.parse_args(test_args))

    op = args['operation']

    if op == 'pre-cfg':
        #config test pre-req
        clear = args['clear']
        print 'Running test pre-configruation %s...' % ('cleanup ' if clear else '')
        if 'mgmt_ip' in args and args['mgmt_ip'] is not None:
            print 'Management IP: %s' % args['mgmt_ip']
            test_pre_req_cfg(clear, args['mgmt_ip'])
        else:
            test_pre_req_cfg(clear)
        time.sleep(20)
        print 'Done with pre-configuration'
        return True

    obj = cps_object.CPSObject('vrf-firewall/ns-incoming-service')
    for arg_name, arg_val in args.items():
        if arg_name in arg_cps_attr_map and arg_val is not None:
            attr_name, func = arg_cps_attr_map[arg_name]
            if func is not None:
                attr_val = func(arg_name, arg_val)
                if type(attr_name) is list:
                    if attr_val is None:
                        raise RuntimeError('Failed to convert input %s' % arg_name)
                    if len(attr_name) != len(attr_val):
                        raise RuntimeError('Invalid argument %s' % arg_name)
                    for idx in range(len(attr_name)):
                        if attr_val[idx] is not None:
                            obj.add_attr(attr_name[idx], attr_val[idx])
                else:
                    if attr_val is not None:
                        obj.add_attr(attr_name, attr_val)
            else:
                obj.add_attr(attr_name, arg_val)

    if op == 'info':
        ret_list = []
        if cps.get([obj.get()], ret_list) == False:
            raise RuntimeError('Failed to get object')
        for ret_obj in ret_list:
            cps_utils.print_obj(ret_obj)
    elif op == 'run-test':
        if run_test_incoming_svcs() == False:
            print 'UT failed'
            return False
        print 'UT success'
        return True
    else:
        upd = (op, obj.get())
        ret_val = cps_utils.CPSTransaction([upd]).commit()
        # exit on success for negative test
        if is_negative_test and ret_val != False:
            raise RuntimeError('Operation %s should have failed but succeed' % op)
        elif not is_negative_test and ret_val == False:
            raise RuntimeError('Failed to %s object' % op)
        if ret_val != False:
            print 'Input object %s' % op
            cps_utils.print_obj(ret_val[0])
    test_count += 1
    return True

def run_test_incoming_svcs():
    #print 'info before run-test'
    #print '--------------------'
    #incoming_svcs_test(False, "info")
    #print '--------------------'

    try:
        # test w/o any vrf name
        incoming_svcs_test(False, "create", "-s", "1.2.3.0/24", "-f", "ipv4", "-i", "100", "-a", "deny")
        incoming_svcs_test(False, "delete", "-s", "1.2.3.0/24", "-f", "ipv4", "-a", "deny")
        incoming_svcs_test(False, "create", "-s", "1:2::0/64", "-a", "allow", "-f", "ipv6", "-i", "100")
        incoming_svcs_test(False, "delete", "-s", "1:2::0/64", "-a", "allow", "-f", "ipv6", "-i", "100")

        ## test for default vrf
        incoming_svcs_test(False, "create", "-n", "default", "-s", "1.2.3.0/24", "-p", "tcp", "-d", "1234", "-f", "ipv4", "-i", "100", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "1.2.3.0/24", "-p", "tcp", "-d", "1234", "-f", "ipv4", "-a", "allow")
        incoming_svcs_test(False, "create", "-n", "default", "-s", "0.0.0.0/0", "-p", "tcp", "-d", "21", "-f", "ipv4", "-a", "deny")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "0.0.0.0/0", "-p", "tcp", "-d", "21", "-f", "ipv4", "-a", "deny")

        ## test for management vrf
        incoming_svcs_test(False, "create", "-n", "management", "-s", "1.2.3.0/24", "-p", "tcp", "-d", "1234", "-f", "ipv4", "-i", "100", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "management", "-s", "1.2.3.0/24", "-p", "tcp", "-d", "1234", "-f", "ipv4", "-a", "allow")
        incoming_svcs_test(False, "create", "-n", "management", "-s", "0.0.0.0/0", "-p", "tcp", "-d", "21", "-f", "ipv4", "-a", "deny")
        incoming_svcs_test(False, "delete", "-n", "management", "-s", "0.0.0.0/0", "-p", "tcp", "-d", "21", "-f", "ipv4", "-a", "deny")

        ## Negative test
        # Duplicate create (this rule should be created by application as default)
        incoming_svcs_test(True,  "create", "-n", "management", "-p", "tcp", "-d", "22", "-f", "ipv4", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "management", "-p", "tcp", "-d", "22", "-f", "ipv4", "-a", "allow")
        incoming_svcs_test(False, "create", "-n", "management", "-p", "tcp", "-d", "22", "-f", "ipv4", "-a", "allow")
        # Delete non-existent rule
        incoming_svcs_test(True,  "delete", "-n", "management", "-s", "3.4.5.0/24", "-p", "tcp", "-d", "4321", "-f", "ipv4", "-i", "100", "-a", "allow")
        # Give dst_port but no tcp/udp protocol
        incoming_svcs_test(True,  "create", "-n", "management", "-s", "1.2.3.0/24", "-d", "8080", "-f", "ipv4", "-i", "101", "-a", "allow")

        incoming_svcs_test(False, "create", "-n", "default", "-s", "11.12.13.0/24", "-p", "tcp", "-d", "22", "-f", "ipv4", "-i", "100", "-a", "allow")
        incoming_svcs_test(True,  "create", "-n", "default", "-s", "11.12.13.0/24", "-p", "tcp", "-d", "22", "-f", "ipv4", "-i", "100", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "11.12.13.0/24", "-p", "tcp", "-d", "22", "-f", "ipv4", "-i", "100", "-a", "allow")
    except RuntimeError as ex:
        print 'UT failed: %s' % ex
        return False
    finally:
        print 'Finished tests: %d' % test_count

    #print 'info after run-test'
    #print '--------------------'
    #incoming_svcs_test(False, "info")
    #print '--------------------'
    print 'All UT finished'
    return True


if __name__ == '__main__':
    try:
        incoming_svcs_test()
    except RuntimeError as ex:
        print 'Failed: %s' % ex
