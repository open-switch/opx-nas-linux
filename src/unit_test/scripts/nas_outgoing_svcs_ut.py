#!/usr/bin/python

import cps
import cps_object
import cps_utils
import sys
import subprocess
import argparse
import socket
import time
import binascii

"""
Example:
nas_outgoing_svcs_ut.py create -f ipv4 --dest-ip 1.1.1.1 -p tcp -d 41 --out-src-ip 8.8.8.8
nas_outgoing_svcs_ut.py delete -f ipv4 --dest-ip 1.1.1.1 -p tcp -d 41 --out-src-ip 8.8.8.8
nas_outgoing_svcs_ut.py info
nas_outgoing_svcs_ut.py create -f ipv4 --dest-ip 2.2.2.2 -p tcp -d 51 --out-src-ip 9.9.9.9
nas_outgoing_svcs_ut.py delete 1

nas_outgoing_svcs_ut.py create -n default -f ipv4 --dest-ip 3.3.3.3 -p tcp -d 61 --out-src-ip 8.1.1.1
nas_outgoing_svcs_ut.py default -n default -f ipv4 --dest-ip 3.3.3.3 -p tcp -d 61 --out-src-ip 8.1.1.1
nas_outgoing_svcs_ut.py create -n management -f ipv4 --dest-ip 3.3.3.3 -p tcp -d 61 --out-src-ip 8.1.1.1
nas_outgoing_svcs_ut.py default -n management -f ipv4 --dest-ip 3.3.3.3 -p tcp -d 61 --out-src-ip 8.1.1.1

"""

def parse_ip_mask(key, val):
    ip_mask = val.split('/')
    if len(ip_mask) < 2:
        ip_addr = ip_mask[0]
    else:
        ip_addr, mask = ip_mask[:2]
    for af in [socket.AF_INET, socket.AF_INET6]:
        try:
            ip_bin = socket.inet_pton(af, ip_addr)
            return (af, binascii.hexlify(ip_bin))
        except socket.error:
            continue
    return None

def parse_af(key, val):
    if val.lower() == 'ipv4':
        return socket.AF_INET
    else:
        return socket.AF_INET6

def parse_protocol(key, val):
    if val.lower() == 'tcp':
        return 1
    elif val.lower() == 'udp':
        return 2
    elif val.lower() == 'icmp':
        return 3
    else:
        return 4

arg_cps_attr_map = {
    'rule_id': ('id', None),
    'vrf_name': ('ni-name', None),
    'addr_family': ('af', parse_af),
    'protocol': ('protocol', parse_protocol),
    'dst_port': ('public-port', None),
    'dest_ip': (['af', 'public-ip'], parse_ip_mask),
    'out_src_ip': (['af', 'outgoing-source-ip'], parse_ip_mask),
    'private_port': ('private-port', None),
    'private_ip': (['af', 'private-ip'], parse_ip_mask)
}

def exec_shell(cmd):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    return out

def test_pre_req_cfg(clear = False, mgmt_ip = '10.11.70.22/8'):
    #config test pre requisite - manangement vrf
    mode = 'OPX'
    ret = exec_shell('opx-show-version | grep \"OS_NAME.*Enterprise\"')
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

            #configure data VRF test pre requisites via CLI
            data_vrf_cmd_list =  ['configure terminal',
                                  'interface vlan 1201',
                                  'no ip address',
                                  'no ip vrf forwarding ',
                                  'exit',
                                  'no interface vlan 1201',
                                  'no ip vrf test-vrf',
                                  'exit',
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

            #configure data VRF test pre requisites via CLI
            data_vrf_cmd_list =  ['configure terminal',
                                  'ip vrf test-vrf',
                                  'exit',
                                  'interface vlan 1201',
                                  'ip vrf forwarding test-vrf',
                                  'ip address 121.121.121.1/24',
                                  'end']

        cfg_file = open('/tmp/test_pre_req', 'w')
        for item in cmd_list:
            print>>cfg_file, item
        for item in data_vrf_cmd_list:
            print>>cfg_file, item
        cfg_file.close()
        exec_shell('sudo -u admin clish --b /tmp/test_pre_req')
    else:
        print 'UT for BASE is not supported yet.'


parser = argparse.ArgumentParser(description = 'Tool for Outgoing IP service configuration')
parser.add_argument('operation', choices = ['create', 'delete', 'set', 'info', 'pre-cfg', 'run-test'])
parser.add_argument('rule_id', type = int, nargs = '?', help = 'Rule ID')
parser.add_argument('--clear', action = 'store_true', help = 'Cleanup pre-configuration for testing')
parser.add_argument('--mgmt-ip', help = 'Management IP address and mask for testing')
parser.add_argument('-n', '--vrf-name',  default = 'default', help = 'VRF name')
parser.add_argument('-f', '--addr-family', choices = ['ipv4', 'ipv6'], help = 'Address family')
parser.add_argument('-p', '--protocol', choices = ['tcp', 'udp', 'icmp', 'all'], help = 'Protocol')
parser.add_argument('-d', '--dst-port', type = int, help = 'L4 destination port')
parser.add_argument('-i', '--seq-num', type = int, help = 'Sequence number')
parser.add_argument('-dip', '--dest-ip', help = 'Destination IP address')
parser.add_argument('-sip', '--out-src-ip', help = 'Outgoing Source IP address')
parser.add_argument('--private-ip', help = 'Private IP address')
parser.add_argument('--private-port', type = int, help = 'Private L4 destination port')

test_count = 0

def outgoing_svcs_test(is_negative_test = False, *test_args):
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
    obj = cps_object.CPSObject('vrf-firewall/ns-outgoing-service')
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
        # exit on success for negative test
        # when obj get returned empty list, return false
        if not ret_list and is_negative_test is False:
            print 'Info get failed'
            raise RuntimeError('Failed to get object')
        if ret_list and is_negative_test is True:
            print 'Info get returned incorrect info'
            raise RuntimeError('Failed to get correct object')
        for ret_obj in ret_list:
            cps_utils.print_obj(ret_obj)
    elif op == 'run-test':
        if run_test_outgoing_svcs() == False:
            print 'UT failed'
            sys.exit(1)
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

def run_test_outgoing_svcs():
    #print 'info before run-test'
    #print '--------------------'
    #outgoing_svcs_test(False, "info")
    #print '--------------------'

    try:
        # test w/o any vrf name
        outgoing_svcs_test(False, "create", "-f", "ipv4", "-dip", "1.1.1.1", "-p", "tcp", "-d", "41", "-sip", "8.8.8.8")
        outgoing_svcs_test(False, "create", "-f", "ipv4", "-dip", "2.2.2.2", "-p", "tcp", "-d", "51", "-sip", "9.9.9.9")
        outgoing_svcs_test(False, "info", "-f", "ipv4", "-dip", "1.1.1.1", "-p", "tcp", "-d", "41", "-sip", "8.8.8.8")
        outgoing_svcs_test(False, "info", "-f", "ipv4", "-dip", "2.2.2.2", "-p", "tcp", "-d", "51", "-sip", "9.9.9.9")
        outgoing_svcs_test(False, "delete", "-f", "ipv4", "-dip", "1.1.1.1", "-p", "tcp", "-d", "41", "-sip", "8.8.8.8")
        outgoing_svcs_test(False, "delete", "-f", "ipv4", "-dip", "2.2.2.2", "-p", "tcp", "-d", "51", "-sip", "9.9.9.9")
        outgoing_svcs_test(True, "info", "-f", "ipv4", "-dip", "1.1.1.1", "-p", "tcp", "-d", "41", "-sip", "8.8.8.8")
        outgoing_svcs_test(True, "info", "-f", "ipv4", "-dip", "2.2.2.2", "-p", "tcp", "-d", "51", "-sip", "9.9.9.9")

        # test for different protocol
        outgoing_svcs_test(False, "create", "-f", "ipv4", "-dip", "1.1.2.1", "-p", "udp", "-d", "41", "-sip", "8.1.1.1")
        outgoing_svcs_test(False, "info", "-f", "ipv4", "-dip", "1.1.2.1", "-p", "udp", "-d", "41", "-sip", "8.1.1.1")
        outgoing_svcs_test(False, "delete", "-f", "ipv4", "-dip", "1.1.2.1", "-p", "udp", "-d", "41", "-sip", "8.1.1.1")
        outgoing_svcs_test(True, "info", "-f", "ipv4", "-dip", "1.1.2.1", "-p", "udp", "-d", "41", "-sip", "8.1.1.1")

        # test for config with vrf name
        outgoing_svcs_test(False, "create", "-n", "default", "-f", "ipv4", "-dip", "1.1.4.1", "-p", "udp", "-d", "42", "-sip", "8.1.1.2")
        outgoing_svcs_test(False, "create", "-n", "default", "-f", "ipv4", "-dip", "1.1.5.1", "-p", "tcp", "-d", "52", "-sip", "9.1.1.2")
        outgoing_svcs_test(False, "info", "-n", "default", "-f", "ipv4", "-dip", "1.1.4.1", "-p", "udp", "-d", "42", "-sip", "8.1.1.2")
        outgoing_svcs_test(False, "info", "-n", "default", "-f", "ipv4", "-dip", "1.1.5.1", "-p", "tcp", "-d", "52", "-sip", "9.1.1.2")
        outgoing_svcs_test(False, "delete", "-n", "default", "-f", "ipv4", "-dip", "1.1.4.1", "-p", "udp", "-d", "42", "-sip", "8.1.1.2")
        outgoing_svcs_test(False, "delete", "-n", "default", "-f", "ipv4", "-dip", "1.1.5.1", "-p", "tcp", "-d", "52", "-sip", "9.1.1.2")
        outgoing_svcs_test(True, "info", "-n", "default", "-f", "ipv4", "-dip", "1.1.4.1", "-p", "udp", "-d", "42", "-sip", "8.1.1.2")
        outgoing_svcs_test(True, "info", "-n", "default", "-f", "ipv4", "-dip", "1.1.5.1", "-p", "tcp", "-d", "52", "-sip", "9.1.1.2")

        # test for config with management vrf name
        outgoing_svcs_test(False, "create", "-n", "management", "-f", "ipv4", "-dip", "1.1.6.1", "-p", "udp", "-d", "43", "-sip", "8.1.1.3")
        outgoing_svcs_test(False, "create", "-n", "management", "-f", "ipv4", "-dip", "1.1.7.1", "-p", "tcp", "-d", "53", "-sip", "9.1.1.3")
        outgoing_svcs_test(False, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.6.1", "-p", "udp", "-d", "43", "-sip", "8.1.1.3")
        outgoing_svcs_test(False, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.7.1", "-p", "tcp", "-d", "53", "-sip", "9.1.1.3")
        outgoing_svcs_test(False, "delete", "-n", "management", "-f", "ipv4", "-dip", "1.1.6.1", "-p", "udp", "-d", "43", "-sip", "8.1.1.3")
        outgoing_svcs_test(False, "delete", "-n", "management", "-f", "ipv4", "-dip", "1.1.7.1", "-p", "tcp", "-d", "53", "-sip", "9.1.1.3")
        outgoing_svcs_test(True, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.6.1", "-p", "udp", "-d", "43", "-sip", "8.1.1.3")
        outgoing_svcs_test(True, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.7.1", "-p", "tcp", "-d", "53", "-sip", "9.1.1.3")


        # test for create w/o vrf name and validate for entry with 'default' vrf name
        outgoing_svcs_test(False, "create", "-f", "ipv4", "-dip", "1.1.8.1", "-p", "tcp", "-d", "44", "-sip", "8.1.1.4")
        outgoing_svcs_test(False, "info", "-n", "default", "-f", "ipv4", "-dip", "1.1.8.1", "-p", "tcp", "-d", "44", "-sip", "8.1.1.4")
        outgoing_svcs_test(False, "delete", "-f", "ipv4", "-dip", "1.1.8.1", "-p", "tcp", "-d", "44", "-sip", "8.1.1.4")
        outgoing_svcs_test(True, "info", "-f", "ipv4", "-dip", "1.1.8.1", "-p", "tcp", "-d", "44", "-sip", "8.1.1.4")

        # test for create with 'default' vrf name and validate for entry w/o vrf name
        outgoing_svcs_test(False, "create", "-n", "default", "-f", "ipv4", "-dip", "1.1.9.1", "-p", "tcp", "-d", "45", "-sip", "8.1.1.5")
        outgoing_svcs_test(False, "info", "-f", "ipv4", "-dip", "1.1.9.1", "-p", "tcp", "-d", "45", "-sip", "8.1.1.5")
        outgoing_svcs_test(False, "delete", "-f", "ipv4", "-dip", "1.1.9.1", "-p", "tcp", "-d", "45", "-sip", "8.1.1.5")
        outgoing_svcs_test(True, "info", "-n", "default", "-f", "ipv4", "-dip", "1.1.9.1", "-p", "tcp", "-d", "45", "-sip", "8.1.1.5")

        ## Negative test
        # Duplicate create (this rule should be created by application as default)
        outgoing_svcs_test(False, "create", "-n", "default", "-f", "ipv4", "-dip", "1.1.10.1", "-p", "tcp", "-d", "46", "-sip", "8.1.1.6")
        outgoing_svcs_test(True, "create", "-n", "default", "-f", "ipv4", "-dip", "1.1.10.1", "-p", "tcp", "-d", "46", "-sip", "8.1.1.6")
        outgoing_svcs_test(False, "info", "-n", "default", "-f", "ipv4", "-dip", "1.1.10.1", "-p", "tcp", "-d", "46", "-sip", "8.1.1.6")
        outgoing_svcs_test(False, "delete", "-n", "default", "-f", "ipv4", "-dip", "1.1.10.1", "-p", "tcp", "-d", "46", "-sip", "8.1.1.6")
        # Delete non-existent rule
        outgoing_svcs_test(True, "delete", "-n", "default", "-f", "ipv4", "-dip", "1.1.10.1", "-p", "tcp", "-d", "46", "-sip", "8.1.1.6")

        ## test for service binding rules

        # test for service binding rules - outgoing service DNAT rules
        outgoing_svcs_test(False, "create", "-n", "management", "-f", "ipv4", "-dip", "1.1.11.1", "-p", "udp", "-d", "121")
        outgoing_svcs_test(False, "create", "-n", "management", "-f", "ipv4", "-dip", "1.1.11.1", "-p", "tcp", "-d", "122")
        outgoing_svcs_test(False, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.11.1", "-p", "udp", "-d", "121", "--private-ip", "127.100.100.1", "--private-port", "62000")
        outgoing_svcs_test(False, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.11.1", "-p", "tcp", "-d", "122", "--private-ip", "127.100.100.1", "--private-port", "62001")
        outgoing_svcs_test(False, "delete", "-n", "management", "-f", "ipv4", "-dip", "1.1.11.1", "-p", "udp", "-d", "121")
        outgoing_svcs_test(False, "delete", "-n", "management", "-f", "ipv4", "-dip", "1.1.11.1", "-p", "tcp", "-d", "122")
        outgoing_svcs_test(True, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.11.1", "-p", "udp", "-d", "121", "--private-ip", "127.100.100.1", "--private-port", "62000")
        outgoing_svcs_test(True, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.11.1", "-p", "tcp", "-d", "122", "--private-ip", "127.100.100.1", "--private-port", "62001")

        # test for service binding rule & SNAT rule
        outgoing_svcs_test(False, "create", "-n", "management", "-f", "ipv4", "-dip", "1.1.12.1", "-p", "udp", "-d", "123")
        outgoing_svcs_test(False, "create", "-n", "management", "-f", "ipv4", "-dip", "1.1.12.1", "-p", "udp", "-d", "123", "-sip", "8.1.1.7")
        outgoing_svcs_test(False, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.12.1", "-p", "udp", "-d", "123", "--private-ip", "127.100.100.1", "--private-port", "62000")
        outgoing_svcs_test(False, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.12.1", "-p", "udp", "-d", "123", "-sip", "8.1.1.7")
        outgoing_svcs_test(False, "delete", "-n", "management", "-f", "ipv4", "-dip", "1.1.12.1", "-p", "udp", "-d", "123")
        outgoing_svcs_test(False, "delete", "-n", "management", "-f", "ipv4", "-dip", "1.1.12.1", "-p", "udp", "-d", "123", "-sip", "8.1.1.7")
        outgoing_svcs_test(True, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.12.1", "-p", "udp", "-d", "123")
        outgoing_svcs_test(True, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.12.1", "-p", "udp", "-d", "123", "-sip", "8.1.1.7")

        # test for service binding rule & SNAT rule and operations involving service binding rules
        outgoing_svcs_test(False, "create", "-n", "management", "-f", "ipv4", "-dip", "1.1.13.1", "-p", "tcp", "-d", "124")
        outgoing_svcs_test(False, "create", "-n", "management", "-f", "ipv4", "-dip", "1.1.13.1", "-p", "tcp", "-d", "124", "-sip", "8.1.1.8")
        outgoing_svcs_test(False, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.13.1", "-p", "tcp", "-d", "124", "--private-ip", "127.100.100.1", "--private-port", "62000")
        outgoing_svcs_test(False, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.13.1", "-p", "tcp", "-d", "124", "-sip", "8.1.1.8")
        outgoing_svcs_test(False, "delete", "-n", "management", "-f", "ipv4", "-dip", "1.1.13.1", "-p", "tcp", "-d", "124")
        #delete of service binding rule should not delete outgoing source ip rule
        outgoing_svcs_test(False, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.13.1", "-p", "tcp", "-d", "124", "-sip", "8.1.1.8")
        outgoing_svcs_test(True, "delete", "-n", "management", "-f", "ipv4", "-dip", "1.1.13.1", "-p", "tcp", "-d", "124")
        outgoing_svcs_test(False, "delete", "-n", "management", "-f", "ipv4", "-dip", "1.1.13.1", "-p", "tcp", "-d", "124", "-sip", "8.1.1.8")
        outgoing_svcs_test(True, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.13.1", "-p", "tcp", "-d", "124")
        outgoing_svcs_test(True, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.13.1", "-p", "tcp", "-d", "124", "-sip", "8.1.1.8")

        # test for service binding rule & delete operations
        outgoing_svcs_test(False, "create", "-n", "management", "-f", "ipv4", "-dip", "1.1.14.1", "-p", "udp", "-d", "131")
        outgoing_svcs_test(False, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.14.1", "-p", "udp", "-d", "131", "--private-ip", "127.100.100.1", "--private-port", "62000")
        outgoing_svcs_test(False, "create", "-n", "management", "-f", "ipv4", "-dip", "1.1.14.1", "-p", "tcp", "-d", "132")
        outgoing_svcs_test(False, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.14.1", "-p", "tcp", "-d", "132", "--private-ip", "127.100.100.1", "--private-port", "62001")

        #delete previously created rules and check same private IP/port is allocated for the rule that is created after this
        outgoing_svcs_test(False, "delete", "1")
        outgoing_svcs_test(True, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.14.1", "-p", "udp", "-d", "131", "--private-ip", "127.100.100.1", "--private-port", "62000")

        outgoing_svcs_test(False, "create", "-n", "management", "-f", "ipv4", "-dip", "1.1.15.1", "-p", "tcp", "-d", "133")
        outgoing_svcs_test(False, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.15.1", "-p", "tcp", "-d", "133", "--private-ip", "127.100.100.1", "--private-port", "62000")
        outgoing_svcs_test(True, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.15.1", "-p", "tcp", "-d", "133", "--private-ip", "127.100.100.1", "--private-port", "62001")
        outgoing_svcs_test(True, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.15.1", "-p", "tcp", "-d", "133", "--private-ip", "127.100.100.3", "--private-port", "62000")

        outgoing_svcs_test(False, "delete", "2")
        outgoing_svcs_test(True, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.14.1", "-p", "tcp", "-d", "132", "--private-ip", "127.100.100.1", "--private-port", "62001")

        #delete with invalid private IP, private port combination (negative test)
        outgoing_svcs_test(True, "delete", "-n", "management", "-f", "ipv4", "-dip", "1.1.15.1", "-p", "tcp", "-d", "133", "--private-ip", "127.100.100.1", "--private-port", "62001")
        outgoing_svcs_test(True, "delete", "-n", "management", "-f", "ipv4", "-dip", "1.1.15.1", "-p", "tcp", "-d", "133", "--private-ip", "127.100.100.3", "--private-port", "62000")
        #delete with valid private IP, private port combination
        outgoing_svcs_test(False, "delete", "-n", "management", "-f", "ipv4", "-dip", "1.1.15.1", "-p", "tcp", "-d", "133", "--private-ip", "127.100.100.1", "--private-port", "62000")
        outgoing_svcs_test(True, "info", "-n", "management", "-f", "ipv4", "-dip", "1.1.15.1", "-p", "tcp", "-d", "133", "--private-ip", "127.100.100.1", "--private-port", "62000")

        # test for data vrf SNAT rules
        outgoing_svcs_test(False, "create", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.16.1", "-p", "udp", "-d", "144", "-sip", "9.1.1.7")
        outgoing_svcs_test(False, "create", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.17.1", "-p", "udp", "-d", "145", "-sip", "9.1.1.8")
        outgoing_svcs_test(False, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.16.1", "-p", "udp", "-d", "144", "-sip", "9.1.1.7")
        outgoing_svcs_test(False, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.16.1", "-p", "udp", "-d", "144", "-sip", "9.1.1.7")
        outgoing_svcs_test(True, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.16.1", "-p", "udp", "-d", "144", "-sip", "9.1.1.7")
        outgoing_svcs_test(True, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.16.1", "-p", "udp", "-d", "144", "-sip", "9.1.1.7")
        outgoing_svcs_test(False, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.17.1", "-p", "udp", "-d", "145", "-sip", "9.1.1.8")
        outgoing_svcs_test(False, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.17.1", "-p", "udp", "-d", "145", "-sip", "9.1.1.8")
        outgoing_svcs_test(True, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.17.1", "-p", "udp", "-d", "145", "-sip", "9.1.1.8")

        # test for data vrf tcp protocol
        outgoing_svcs_test(False, "create", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.18.1", "-p", "tcp", "-d", "41", "-sip", "11.1.1.1")
        outgoing_svcs_test(False, "create", "-n", "test-vrf", "-f", "ipv4", "-dip", "2.2.18.2", "-p", "tcp", "-d", "51", "-sip", "12.1.1.1")
        outgoing_svcs_test(False, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.18.1", "-p", "tcp", "-d", "41", "-sip", "11.1.1.1")
        outgoing_svcs_test(False, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "2.2.18.2", "-p", "tcp", "-d", "51", "-sip", "12.1.1.1")
        outgoing_svcs_test(False, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.18.1", "-p", "tcp", "-d", "41", "-sip", "11.1.1.1")
        outgoing_svcs_test(False, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "2.2.18.2", "-p", "tcp", "-d", "51", "-sip", "12.1.1.1")
        outgoing_svcs_test(True, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.18.1", "-p", "tcp", "-d", "41", "-sip", "11.1.1.1")
        outgoing_svcs_test(True, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "2.2.18.2", "-p", "tcp", "-d", "51", "-sip", "12.1.1.1")

        # test for data vrf different protocol
        outgoing_svcs_test(False, "create", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.19.1", "-p", "udp", "-d", "41", "-sip", "13.1.1.1")
        outgoing_svcs_test(False, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.19.1", "-p", "udp", "-d", "41", "-sip", "13.1.1.1")
        outgoing_svcs_test(False, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.19.1", "-p", "udp", "-d", "41", "-sip", "13.1.1.1")
        outgoing_svcs_test(True, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.19.1", "-p", "udp", "-d", "41", "-sip", "13.1.1.1")

        # Negative test for data vrf config with vrf name and delete/get w/o vrf-name
        outgoing_svcs_test(False, "create", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.20.1", "-p", "udp", "-d", "42", "-sip", "14.1.1.1")
        outgoing_svcs_test(True, "info", "-n", "default", "-f", "ipv4", "-dip", "1.1.20.1", "-p", "udp", "-d", "42", "-sip", "14.1.1.1")
        outgoing_svcs_test(True, "info", "-f", "ipv4", "-dip", "1.1.20.1", "-p", "udp", "-d", "42", "-sip", "14.1.1.1")
        outgoing_svcs_test(True, "delete", "-n", "default", "-f", "ipv4", "-dip", "1.1.20.1", "-p", "udp", "-d", "42", "-sip", "14.1.1.1")
        outgoing_svcs_test(False, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.20.1", "-p", "udp", "-d", "42", "-sip", "14.1.1.1")
        outgoing_svcs_test(False, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.20.1", "-p", "udp", "-d", "42", "-sip", "14.1.1.1")
        outgoing_svcs_test(True, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.20.1", "-p", "udp", "-d", "42", "-sip", "14.1.1.1")

        ## Negative test for data vrf
        # Duplicate create (this rule should be created by application as default)
        outgoing_svcs_test(False, "create", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.21.1", "-p", "tcp", "-d", "46", "-sip", "15.1.1.1")
        outgoing_svcs_test(True, "create", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.21.1", "-p", "tcp", "-d", "46", "-sip", "15.1.1.1")
        outgoing_svcs_test(False, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.21.1", "-p", "tcp", "-d", "46", "-sip", "15.1.1.1")
        outgoing_svcs_test(False, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.21.1", "-p", "tcp", "-d", "46", "-sip", "15.1.1.1")
        # Delete non-existent rule
        outgoing_svcs_test(True, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.21.1", "-p", "tcp", "-d", "46", "-sip", "15.1.1.1")

        ## test for data vrf service binding rules

        # test for data vrf service binding rules - outgoing service DNAT rules
        outgoing_svcs_test(False, "create", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.22.1", "-p", "udp", "-d", "121")
        outgoing_svcs_test(False, "create", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.22.1", "-p", "tcp", "-d", "122")
        outgoing_svcs_test(False, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.22.1", "-p", "udp", "-d", "121", "--private-ip", "127.101.100.1", "--private-port", "62000")
        outgoing_svcs_test(False, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.22.1", "-p", "tcp", "-d", "122", "--private-ip", "127.101.100.1", "--private-port", "62001")
        outgoing_svcs_test(False, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.22.1", "-p", "udp", "-d", "121")
        outgoing_svcs_test(False, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.22.1", "-p", "tcp", "-d", "122")
        outgoing_svcs_test(True, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.22.1", "-p", "udp", "-d", "121", "--private-ip", "127.101.100.1", "--private-port", "62000")
        outgoing_svcs_test(True, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.22.1", "-p", "tcp", "-d", "122", "--private-ip", "127.101.100.1", "--private-port", "62001")

        # test for service binding rule & SNAT rule
        outgoing_svcs_test(False, "create", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.23.1", "-p", "udp", "-d", "123")
        outgoing_svcs_test(False, "create", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.23.1", "-p", "udp", "-d", "123", "-sip", "16.1.1.1")
        outgoing_svcs_test(False, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.23.1", "-p", "udp", "-d", "123", "--private-ip", "127.101.100.1", "--private-port", "62000")
        outgoing_svcs_test(False, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.23.1", "-p", "udp", "-d", "123", "-sip", "16.1.1.1")
        outgoing_svcs_test(False, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.23.1", "-p", "udp", "-d", "123")
        outgoing_svcs_test(False, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.23.1", "-p", "udp", "-d", "123", "-sip", "16.1.1.1")
        outgoing_svcs_test(True, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.23.1", "-p", "udp", "-d", "123")
        outgoing_svcs_test(True, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.23.1", "-p", "udp", "-d", "123", "-sip", "16.1.1.1")

        # test for data vrf service binding rule & SNAT rule and operations involving service binding rules
        outgoing_svcs_test(False, "create", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.24.1", "-p", "tcp", "-d", "124")
        outgoing_svcs_test(False, "create", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.24.1", "-p", "tcp", "-d", "124", "-sip", "17.1.1.1")
        outgoing_svcs_test(False, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.24.1", "-p", "tcp", "-d", "124", "--private-ip", "127.101.100.1", "--private-port", "62000")
        outgoing_svcs_test(False, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.24.1", "-p", "tcp", "-d", "124", "-sip", "17.1.1.1")
        outgoing_svcs_test(False, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.24.1", "-p", "tcp", "-d", "124")
        outgoing_svcs_test(False, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.24.1", "-p", "tcp", "-d", "124", "-sip", "17.1.1.1")

        #data vrf test for delete of service binding rule should not delete outgoing source ip rule
        outgoing_svcs_test(False, "create", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.25.1", "-p", "tcp", "-d", "124", "-sip", "18.1.1.1")
        outgoing_svcs_test(False, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.25.1", "-p", "tcp", "-d", "124", "-sip", "18.1.1.1")
        outgoing_svcs_test(True, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.25.1", "-p", "tcp", "-d", "124")
        outgoing_svcs_test(False, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.25.1", "-p", "tcp", "-d", "124", "-sip", "18.1.1.1")
        outgoing_svcs_test(True, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.25.1", "-p", "tcp", "-d", "124")
        outgoing_svcs_test(True, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.25.1", "-p", "tcp", "-d", "124", "-sip", "18.1.1.1")

        # test for data vrf service binding rule & delete operations
        outgoing_svcs_test(False, "create", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.26.1", "-p", "udp", "-d", "131")
        outgoing_svcs_test(False, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.26.1", "-p", "udp", "-d", "131", "--private-ip", "127.101.100.1", "--private-port", "62000")
        outgoing_svcs_test(False, "create", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.26.1", "-p", "tcp", "-d", "132")
        outgoing_svcs_test(False, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.26.1", "-p", "tcp", "-d", "132", "--private-ip", "127.101.100.1", "--private-port", "62001")

        #delete previously created rules and check same private IP/port is allocated for the rule that is created after this
        outgoing_svcs_test(False, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.26.1", "-p", "udp", "-d", "131")
        outgoing_svcs_test(True, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.26.1", "-p", "udp", "-d", "131", "--private-ip", "127.101.100.1", "--private-port", "62000")

        outgoing_svcs_test(False, "create", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.27.1", "-p", "tcp", "-d", "133")
        outgoing_svcs_test(False, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.27.1", "-p", "tcp", "-d", "133", "--private-ip", "127.101.100.1", "--private-port", "62000")
        outgoing_svcs_test(True, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.27.1", "-p", "tcp", "-d", "133", "--private-ip", "127.101.100.1", "--private-port", "62001")
        outgoing_svcs_test(True, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.27.1", "-p", "tcp", "-d", "133", "--private-ip", "127.101.100.3", "--private-port", "62000")

        outgoing_svcs_test(False, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.26.1", "-p", "tcp", "-d", "132", "--private-ip", "127.101.100.1", "--private-port", "62001")
        outgoing_svcs_test(True, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.26.1", "-p", "tcp", "-d", "132", "--private-ip", "127.101.100.1", "--private-port", "62001")

        #delete with invalid private IP, private port combination (negative test)
        outgoing_svcs_test(True, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.27.1", "-p", "tcp", "-d", "133", "--private-ip", "127.101.100.1", "--private-port", "62001")
        outgoing_svcs_test(True, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.27.1", "-p", "tcp", "-d", "133", "--private-ip", "127.101.100.3", "--private-port", "62000")
        #delete with valid private IP, private port combination
        outgoing_svcs_test(False, "delete", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.27.1", "-p", "tcp", "-d", "133", "--private-ip", "127.101.100.1", "--private-port", "62000")
        outgoing_svcs_test(True, "info", "-n", "test-vrf", "-f", "ipv4", "-dip", "1.1.27.1", "-p", "tcp", "-d", "133", "--private-ip", "127.101.100.1", "--private-port", "62000")

    except RuntimeError as ex:
        print 'UT failed: %s' % ex
        return False
    finally:
        print 'Finished tests: %d' % test_count

    #print 'info after run-test'
    #print '--------------------'
    #outgoing_svcs_test(False, "info")
    #print '--------------------'
    print 'All UT finished'
    return True


if __name__ == '__main__':
    try:
        outgoing_svcs_test()
    except RuntimeError as ex:
        print 'Failed: %s' % ex
        sys.exit(1)
