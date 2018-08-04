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
nas_incoming_svcs_ut.py create -s 1.2.3.0/24 -d 4.5.0.0/16 -f ipv4 -i 100 -a deny
nas_incoming_svcs_ut.py delete -s 1.2.3.0/24 -d 4.5.0.0/16 -f ipv4 -a deny
nas_incoming_svcs_ut.py info
nas_incoming_svcs_ut.py delete 1
nas_incoming_svcs_ut.py create -s 1:2::0/64 -a allow -f ipv6 -i 200

nas_incoming_svcs_ut.py create -n management -p udp -dp 1234 -f ipv4
nas_incoming_svcs_ut.py delete -n management -p udp -dp 1234 -f ipv4

nas_incoming_svcs_ut.py create -n default -s 1.2.3.0/24 -p tcp -dp 1234 -f ipv4 -i 100 -a allow
nas_incoming_svcs_ut.py delete -n default -s 1.2.3.0/24 -p tcp -dp 1234 -f ipv4 -a allow

nas_incoming_svcs_ut.py create -n default -p tcp -dp 21 -f ipv4 -a deny
nas_incoming_svcs_ut.py delete -n default -p tcp -dp 21 -f ipv4 -a deny
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
    elif val.lower() == 'icmp':
        return 3
    else:
        return 4

def parse_dst_port_range(key, val):
    dst_port_range = val.split(':')
    if len(dst_port_range) < 2:
        return None
    else:
        lower_dst_port, upper_dst_port  = dst_port_range[:2]
        return (lower_dst_port, upper_dst_port)


arg_cps_attr_map = {
    'rule_id': ('id', None),
    'vrf_name': ('ni-name', None),
    'src_ip': (['af', 'src-ip', 'src-prefix-len'], parse_ip_mask),
    'dst_ip': (['af', 'dst-ip', 'dst-prefix-len'], parse_ip_mask),
    'addr_family': ('af', parse_af),
    'seq_num': ('seq-num', None),
    'action': ('action', parse_action),
    'protocol': ('protocol', parse_protocol),
    'dst_port': ('dst-port', None),
    'multiport': (['lower-dst-port', 'upper-dst-port'], parse_dst_port_range),
    'in_intf': ('ifname', None)
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
parser.add_argument('-d', '--dst-ip', help = 'Destination IP address and mask')
parser.add_argument('-f', '--addr-family', choices = ['ipv4', 'ipv6'], help = 'Address family')
parser.add_argument('-i', '--seq-num', type = int, help = 'Sequence number')
parser.add_argument('-a', '--action', choices = ['allow', 'deny'], help = 'Action')
parser.add_argument('-p', '--protocol', choices = ['tcp', 'udp', 'icmp', 'all'], help = 'Protocol')
parser.add_argument('-dp', '--dst-port', type = int, help = 'L4 destination port')
parser.add_argument('--multiport', help = 'L4 destination port range')
parser.add_argument('-iif', '--in_intf', help = 'incoming interface')

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

    if op != 'run-test':
        print '*** Running %stest: %s ***' % ('negative ' if is_negative_test else '', ' '.join(test_args))
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

        ## test for ip protocol all
        incoming_svcs_test(False, "create", "-n", "default", "-s", "11.11.11.0/24", "-d", "12.22.0.0/16", "-p", "all", "-f", "ipv4", "-i", "100", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "11.11.11.0/24", "-d", "12.22.0.0/16", "-p", "all", "-f", "ipv4", "-a", "allow")
        incoming_svcs_test(False, "create", "-n", "default", "-s", "11.11.11.0/24", "-d", "12.22.0.0/16", "-p", "all", "-f", "ipv4", "-i", "100", "-a", "deny")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "11.11.11.0/24", "-d", "12.22.0.0/16", "-p", "all", "-f", "ipv4", "-a", "deny")

        ## test for L4 destination port range
        incoming_svcs_test(False, "create", "-n", "default", "-s", "11.12.13.0/24", "-d", "12.13.0.0/16", "-p", "tcp", "--multiport", "100:200", "-f", "ipv4", "-i", "100", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "11.12.13.0/24", "-d", "12.13.0.0/16", "-p", "tcp", "--multiport", "100:200", "-f", "ipv4", "-a", "allow")
        incoming_svcs_test(False, "create", "-n", "default", "-s", "11.12.13.0/24", "-d", "12.13.0.0/16", "-p", "tcp", "--multiport", "100:200", "-f", "ipv4", "-i", "100", "-a", "deny")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "11.12.13.0/24", "-d", "12.13.0.0/16", "-p", "tcp", "--multiport", "100:200", "-f", "ipv4", "-a", "deny")
        incoming_svcs_test(False, "create", "-n", "default", "-s", "11.12.14.0/24", "-d", "12.13.0.0/16", "-p", "udp", "--multiport", "111:120", "-f", "ipv4", "-i", "100", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "11.12.14.0/24", "-d", "12.13.0.0/16", "-p", "udp", "--multiport", "111:120", "-f", "ipv4", "-a", "allow")
        incoming_svcs_test(False, "create", "-n", "default", "-s", "11.12.14.0/24", "-d", "12.13.0.0/16", "-p", "udp", "--multiport", "111:120", "-f", "ipv4", "-i", "100", "-a", "deny")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "11.12.14.0/24", "-d", "12.13.0.0/16", "-p", "udp", "--multiport", "111:120", "-f", "ipv4", "-a", "deny")
        ## dest port range for same ports (negative case)
        incoming_svcs_test(True, "create", "-n", "default", "-s", "11.12.14.0/24", "-p", "tcp", "--multiport", "90:90", "-f", "ipv4", "-i", "100", "-a", "allow")
        incoming_svcs_test(True, "delete", "-n", "default", "-s", "11.12.14.0/24", "-p", "tcp", "--multiport", "90:90", "-f", "ipv4", "-a", "allow")
        ## dest port range invalid range (negative case)
        incoming_svcs_test(True, "create", "-n", "default", "-s", "11.12.14.0/24", "-p", "tcp", "--multiport", "90:80", "-f", "ipv4", "-i", "100", "-a", "allow")
        incoming_svcs_test(True, "delete", "-n", "default", "-s", "11.12.14.0/24", "-p", "tcp", "--multiport", "90:80", "-f", "ipv4", "-a", "allow")
        ## dest port range with dest port option (negative case)
        incoming_svcs_test(True, "create", "-n", "default", "-s", "11.12.15.0/24", "-p", "tcp", "--multiport", "101:110", "-dp", "101", "-f", "ipv4", "-i", "100", "-a", "allow")
        incoming_svcs_test(True, "delete", "-n", "default", "-s", "11.12.15.0/24", "-p", "tcp", "--multiport", "101:110", "-dp", "101", "-f", "ipv4", "-a", "allow")

        #rules with same dest port range, different protocol, same sequence
        incoming_svcs_test(False, "create", "-n", "default", "-s", "11.12.15.0/24", "-p", "tcp", "--multiport", "121:130", "-f", "ipv4", "-i", "100", "-a", "allow")
        incoming_svcs_test(False, "create", "-n", "default", "-s", "11.12.15.0/24", "-p", "udp", "--multiport", "121:130", "-f", "ipv4", "-i", "100", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "11.12.15.0/24", "-p", "tcp", "--multiport", "121:130", "-f", "ipv4", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "11.12.15.0/24", "-p", "udp", "--multiport", "121:130", "-f", "ipv4", "-a", "allow")
        #rules with different dest port range, different sequence
        incoming_svcs_test(False, "create", "-n", "default", "-s", "11.12.16.0/24", "-p", "tcp", "--multiport", "131:135", "-f", "ipv4", "-i", "10", "-a", "allow")
        incoming_svcs_test(False, "create", "-n", "default", "-s", "11.12.16.0/24", "-p", "tcp", "--multiport", "136:140", "-f", "ipv4", "-i", "11", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "11.12.16.0/24", "-p", "tcp", "--multiport", "131:135", "-f", "ipv4", "-i", "10", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "11.12.16.0/24", "-p", "tcp", "--multiport", "136:140", "-f", "ipv4", "-i", "11", "-a", "allow")

        #rule with dest port and dest port range
        incoming_svcs_test(False, "create", "-n", "default", "-s", "11.12.16.0/24", "-p", "udp", "--multiport", "150:151", "-f", "ipv4", "-i", "100", "-a", "allow")
        incoming_svcs_test(False, "create", "-n", "default", "-s", "11.12.16.0/24", "-p", "udp", "-dp", "150", "-f", "ipv4", "-i", "100", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "11.12.16.0/24", "-p", "udp", "--multiport", "150:151", "-f", "ipv4", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "11.12.16.0/24", "-p", "udp", "-dp", "150", "-f", "ipv4", "-i", "100", "-a", "allow")

        ## test for default vrf
        incoming_svcs_test(False, "create", "-n", "default", "-s", "1.2.3.0/24", "-p", "tcp", "-dp", "1234", "-f", "ipv4", "-i", "100", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "1.2.3.0/24", "-p", "tcp", "-dp", "1234", "-f", "ipv4", "-a", "allow")
        incoming_svcs_test(False, "create", "-n", "default", "-s", "0.0.0.0/0", "-p", "tcp", "-dp", "21", "-f", "ipv4", "-a", "deny")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "0.0.0.0/0", "-p", "tcp", "-dp", "21", "-f", "ipv4", "-a", "deny")

        ## test for management vrf
        incoming_svcs_test(False, "create", "-n", "management", "-s", "1.2.3.0/24", "-p", "tcp", "-dp", "1234", "-f", "ipv4", "-i", "100", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "management", "-s", "1.2.3.0/24", "-p", "tcp", "-dp", "1234", "-f", "ipv4", "-a", "allow")
        incoming_svcs_test(False, "create", "-n", "management", "-s", "0.0.0.0/0", "-p", "tcp", "-dp", "21", "-f", "ipv4", "-a", "deny")
        incoming_svcs_test(False, "delete", "-n", "management", "-s", "0.0.0.0/0", "-p", "tcp", "-dp", "21", "-f", "ipv4", "-a", "deny")

        ## Negative test
        # Duplicate create (this rule should be created by application as default)
        incoming_svcs_test(True,  "create", "-n", "management", "-p", "tcp", "-dp", "22", "-f", "ipv4", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "management", "-p", "tcp", "-dp", "22", "-f", "ipv4", "-a", "allow")
        incoming_svcs_test(False, "create", "-n", "management", "-p", "tcp", "-dp", "22", "-f", "ipv4", "-a", "allow")
        # Delete non-existent rule
        incoming_svcs_test(True,  "delete", "-n", "management", "-s", "3.4.5.0/24", "-p", "tcp", "-dp", "4321", "-f", "ipv4", "-i", "100", "-a", "allow")
        # Give dst_port but no tcp/udp protocol
        incoming_svcs_test(True,  "create", "-n", "management", "-s", "1.2.3.0/24", "-dp", "8080", "-f", "ipv4", "-i", "101", "-a", "allow")

        incoming_svcs_test(False, "create", "-n", "default", "-s", "11.12.13.0/24", "-p", "tcp", "-dp", "22", "-f", "ipv4", "-i", "100", "-a", "allow")
        incoming_svcs_test(True,  "create", "-n", "default", "-s", "11.12.13.0/24", "-p", "tcp", "-dp", "22", "-f", "ipv4", "-i", "100", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "11.12.13.0/24", "-p", "tcp", "-dp", "22", "-f", "ipv4", "-i", "100", "-a", "allow")

        ## test for default vrf, eth0
        incoming_svcs_test(False, "create", "-n", "default", "-s", "21.21.21.0/24", "-p", "tcp", "-dp", "123", "-f", "ipv4", "-iif", "eth0", "-i", "100", "-a", "allow")
        incoming_svcs_test(False, "create", "-n", "default", "-s", "21.21.21.0/24", "-p", "tcp", "-dp", "123", "-f", "ipv4", "-i", "101", "-a", "deny")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "21.21.21.0/24", "-p", "tcp", "-dp", "123", "-f", "ipv4", "-iif", "eth0", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "21.21.21.0/24", "-p", "tcp", "-dp", "123", "-f", "ipv4", "-i", "101", "-a", "deny")

        ## test for management vrf, eth0
        incoming_svcs_test(False, "create", "-n", "management", "-s", "22.22.22.0/24", "-p", "tcp", "-dp", "124", "-f", "ipv4", "-iif", "eth0", "-i", "100", "-a", "allow")
        incoming_svcs_test(False, "create", "-n", "management", "-s", "22.22.22.0/24", "-p", "tcp", "-dp", "124", "-f", "ipv4", "-i", "101", "-a", "deny")
        incoming_svcs_test(False, "delete", "-n", "management", "-s", "22.22.22.0/24", "-p", "tcp", "-dp", "124", "-f", "ipv4", "-iif", "eth0", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "management", "-s", "22.22.22.0/24", "-p", "tcp", "-dp", "124", "-f", "ipv4", "-i", "101", "-a", "deny")

        ## test for default vrf, L3 port (vlan 100)
        incoming_svcs_test(False, "create", "-n", "default", "-s", "21.21.21.0/24", "-p", "tcp", "-dp", "125", "-f", "ipv4", "-iif", "br100", "-i", "100", "-a", "allow")
        incoming_svcs_test(False, "create", "-n", "default", "-s", "21.21.21.0/24", "-p", "tcp", "-dp", "125", "-f", "ipv4", "-i", "101", "-a", "deny")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "21.21.21.0/24", "-p", "tcp", "-dp", "125", "-f", "ipv4", "-iif", "br100", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "21.21.21.0/24", "-p", "tcp", "-dp", "125", "-f", "ipv4", "-i", "101", "-a", "deny")

        ## test for management vrf, L3 port (vlan 100)
        incoming_svcs_test(False, "create", "-n", "management", "-s", "22.22.22.0/24", "-p", "tcp", "-dp", "126", "-f", "ipv4", "-iif", "br100", "-i", "100", "-a", "allow")
        incoming_svcs_test(False, "create", "-n", "management", "-s", "22.22.22.0/24", "-p", "tcp", "-dp", "126", "-f", "ipv4", "-i", "101", "-a", "deny")
        incoming_svcs_test(False, "delete", "-n", "management", "-s", "22.22.22.0/24", "-p", "tcp", "-dp", "126", "-f", "ipv4", "-iif", "br100", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "management", "-s", "22.22.22.0/24", "-p", "tcp", "-dp", "126", "-f", "ipv4", "-i", "101", "-a", "deny")

        ## test for default vrf, !eth0
        incoming_svcs_test(False, "create", "-n", "default", "-s", "23.23.23.0/24", "-p", "tcp", "-dp", "127", "-f", "ipv4", "-iif", "!eth0", "-i", "100", "-a", "allow")
        incoming_svcs_test(False, "create", "-n", "default", "-s", "23.23.23.0/24", "-p", "tcp", "-dp", "127", "-f", "ipv4", "-i", "101", "-a", "deny")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "23.23.23.0/24", "-p", "tcp", "-dp", "127", "-f", "ipv4", "-iif", "!eth0", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "default", "-s", "23.23.23.0/24", "-p", "tcp", "-dp", "127", "-f", "ipv4", "-i", "101", "-a", "deny")

        ## test for management vrf, !eth0
        incoming_svcs_test(False, "create", "-n", "management", "-s", "24.24.24.0/24", "-p", "tcp", "-dp", "128", "-f", "ipv4", "-iif", "!eth0", "-i", "100", "-a", "allow")
        incoming_svcs_test(False, "create", "-n", "management", "-s", "24.24.24.0/24", "-p", "tcp", "-dp", "128", "-f", "ipv4", "-i", "101", "-a", "deny")
        incoming_svcs_test(False, "delete", "-n", "management", "-s", "24.24.24.0/24", "-p", "tcp", "-dp", "128", "-f", "ipv4", "-iif", "!eth0", "-a", "allow")
        incoming_svcs_test(False, "delete", "-n", "management", "-s", "24.24.24.0/24", "-p", "tcp", "-dp", "128", "-f", "ipv4", "-i", "101", "-a", "deny")

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
