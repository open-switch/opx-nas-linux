#!/usr/bin/python
import cps
import cps_object
import cps_utils
import dn_base_ip_tool

def get_if_info_ipv4():
    bcast_addr = ""
    res = []
    cmd = ['ifconfig', 'e101-001-0']
    if dn_base_ip_tool.run_command(cmd, res) == 0:
        ip_info = res[1].split()
        if 'broadcast' in ip_info:
            bcast_addr = ip_info[-1]

    return bcast_addr

def get_ipv6_addr_flag():
    res = []
    cmd = ['ifconfig', 'br1']
    if dn_base_ip_tool.run_command(cmd, res) != 0:
        assert 0

    flag = "not_seen"
    for e in res:
        if "101:101:101:101:101:101:101:101" in e:
            flag = "seen"

    return flag

def ip_add_verify(address_family, prefix_length):

    if address_family == "ipv4":
        bcast_addr = get_if_info_ipv4()

        addr = {
                    "8": "1.255.255.255",
                    "16": "1.1.255.255",
                    "24" : "1.1.1.255",
                    "32" : "0.0.0.0"
                }
        assert bcast_addr == addr[prefix_length]

    elif address_family == "ipv6":
        flag = get_ipv6_addr_flag()
        assert flag == "seen"

    else:
        print "Unsupported address family"
        assert 0


def ip_delete_verify(address_family, prefix_length):
    if address_family == "ipv4":
        bcast_addr = get_if_info_ipv4()
        assert bcast_addr == ""
    elif address_family == "ipv6":
        flag = get_ipv6_addr_flag()
        assert flag == "not_seen"
    else:
        print "Unsupported address family"
        assert 0

def ip_address_config(operation, address_family, prefix_length):
    if address_family == "ipv4":
        mod = "base-ip/ipv4/address"
        name_attr = "base-ip/ipv4/name"
        name = "e101-001-0"
        ip_addr = "01010101"

    elif address_family == "ipv6":
        mod = "base-ip/ipv6/address"
        name_attr = "base-ip/ipv6/name"
        name = "br1"
        ip_addr = "01010101010101010101010101010101"
    else:
        print "Unsupported address family"
        assert 0

    cps_obj = cps_object.CPSObject(module = mod)
    cps_obj.add_attr(name_attr, name)
    cps_obj.add_attr('ip', ip_addr)
    cps_obj.add_attr('prefix-length', prefix_length)

    ch = {'operation': operation, 'change': cps_obj.get()}

    if cps.transaction([ch]):
        print "Success"
        cps_utils.print_obj(ch['change'])

    if operation == "create":
        ip_add_verify(address_family, prefix_length)
    elif operation == "delete":
        ip_delete_verify(address_family, prefix_length)
    else:
        print "Unsupported operation"

def test_ip_address_config():
    ip_address_config("create", "ipv4", "8")
    ip_address_config("delete", "ipv4", "8")

    ip_address_config("create", "ipv4", "16")
    ip_address_config("delete", "ipv4", "16")

    ip_address_config("create", "ipv4", "24")
    ip_address_config("delete", "ipv4", "24")

    ip_address_config("create", "ipv4", "32")
    ip_address_config("delete", "ipv4", "32")


    ip_address_config("create", "ipv6", "64")
    ip_address_config("delete", "ipv6", "64")

    ip_address_config("create", "ipv6", "128")
    ip_address_config("delete", "ipv6", "128")

