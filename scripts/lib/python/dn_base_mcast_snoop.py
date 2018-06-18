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

import dn_base_mcast_snoop_utils as mcast_utils
import dn_base_mcast_snoop_events as events
import cps_object
import cps
import bytearray_utils as ba

_snoop_obj_info = {
    'mcast_snooping': { 'obj_path': [mcast_utils.igmp_vlan_key+'/enable',
                        mcast_utils.mld_vlan_key+'/enable'],
                        'publish_events': True,
                        'event_string': "status"
                      },
    'static_l2_mcast_grp_key': { 'obj_path':[mcast_utils.igmp_vlan_key+'/static-l2-multicast-group',
                                mcast_utils.mld_vlan_key+'/static-l2-multicast-group'],
                                'publish_events': True,
                                'event_string': "route"
                                           },
    'static_mrouter_key': { 'obj_path': [mcast_utils.igmp_vlan_key+'/static-mrouter-interface',
                            mcast_utils.mld_vlan_key+'/static-mrouter-interface'],
                            'publish_events': True,
                            'event_string': "mrouter"
                          }
}

#One IGMP,MLD protocol entry is installed in ACL to lift protocols packets. But snooping
#may or may not be enabled on all the VLANs. For enabled VLAN's the snooping application
#will decide what to do with the packets, especially with Reports and Leaves(both v4 and v6)
#So as packet is given to kernel , it will flood on the VLAN members. This might lead to duplicate
#for snooping enabled VLANs as snooping applications also forwards packets.
#So below rules are added to prevent kernel flooding IGMP/MLD Reports, Leaves for snoop enabled
#VLANs. For snoop disabled VLAN's packet gets flooded by kernel.

#How is it achieved

#In ebtables broute table BROTING chain a rule is added per snoop enabled VLAN and marked.
#here with current ebtables package we have IGMP's type cannot determine. So the iptables
# are also used.
#In iptables/ip6tables(for MLD) these marked packets are identified and sent to IGMPSNOOP/MLDSNOOP
#chain(user created chain)
#In IGMP/MLD SNOOP chain the rules are added to drop IGMP(V1,v2,v3 Reports and Levae, but not Queries)
#and MLD(V1,V2 Report, Done but not Queries), so for the snoop enabled VLAN's kernel drops these packets.
#and other IGMP and MLD packets mark will be removed and will be flooded by the kernel.

#By default in the bridge flow iptables are not looked up. this is turned on by enabling bridge-nf-call-iptable
#and bridge-nf-call-ip6tables.

#All above mentioned will happen if kernel snooping is not used and some other snooping application is
#used.

IGMP_CHAIN_NAME = 'IGMPSNOOP '
MLD_CHAIN_NAME = ' MLDSNOOP '

#In iptable now there is no direct way to get the IGMP packet type. So the way type is determined is
#as follows:
#iptables has option "-m" to match the value and "--u32" matches 4 bytes. So as IGMP packet is
#IP packets payload. First IP header length is determined by using "0>>22" Ideally is >>24, but as
#the IP header length need multiplication by 4 (or <<2) so it is >>22 times and get the length and jump till that
#length and from there get the words from the offset, in our case IGMP packet type is in first 4 bytes
#offset is 0 and >>16 times and compare the packet type values.

#IGMP:
# 0x11 - Query, 0x12 - V1 Report, 0x16 - V2 Report, 0x17 - Leave, 0x22 - v3 Report

igmp_add_rules = [IGMP_CHAIN_NAME + '-p igmp -m u32 --u32 0>>22&0x3C@0>>16&0xFF00=0x1200 -j DROP',
IGMP_CHAIN_NAME + '-p igmp -m u32 --u32 0>>22&0x3C@0>>16&0xFF00=0x1600 -j DROP',
IGMP_CHAIN_NAME + '-p igmp -m u32 --u32 0>>22&0x3C@0>>16&0xFF00=0x1700 -j DROP',
IGMP_CHAIN_NAME + '-p igmp -m u32 --u32 0>>22&0x3C@0>>16&0xFF00=0x2200 -j DROP',
IGMP_CHAIN_NAME + '-j MARK --set-mark 0']

#MLD:
# 130 - Query, 131 - v1 Report, 132 - Leave/Done, 143 - v2 Report
mld_add_rules= [MLD_CHAIN_NAME + '-p icmpv6 -m icmp6 --icmpv6-type 131 -j DROP',
        MLD_CHAIN_NAME + '-p icmpv6 -m icmp6 --icmpv6-type 132 -j DROP',
        MLD_CHAIN_NAME + '-p icmpv6 -m icmp6 --icmpv6-type 143 -j DROP',
        MLD_CHAIN_NAME + '-p icmpv6 -j MARK --set-mark 0']


igmp_preroute_rule = ' PREROUTING -p igmp -m mark --mark 0x64 -j ' + IGMP_CHAIN_NAME

mld_preroute_rule = ' PREROUTING -p icmpv6 -m mark --mark 0x64 -j ' + MLD_CHAIN_NAME

bridge_nf_iptables = '/proc/sys/net/bridge/bridge-nf-call-iptables'
bridge_nf_ip6tables = '/proc/sys/net/bridge/bridge-nf-call-ip6tables'

#default using dn_rules.sh IGMP/MLD packets are allowed flooding in BASE using
#ebtable nat table POSTROUTING chain. Before this in ebtables filter table FORWARD
#chain both multicast and broadcast packets are marked.
#On boot up the application will disable snooping globally and these rules will be
#deleted and will be installed again when snooping enabled globally.
mld_global_ebtable_rule = ['-p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type 132/0:255 --mark 0x1 -j ACCEPT',
         '-p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type 131/0:255 --mark 0x1 -j ACCEPT',
         '-p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type 130/0:255 --mark 0x1 -j ACCEPT',
         '-p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type 143/0:255 --mark 0x1 -j ACCEPT']

igmp_global_ebtable_rule = ['-p IPv4 --ip-proto igmp --mark 0x1 -j ACCEPT']

def snoop_add_vlan_rules(is_igmp, vlan_name):
    if is_igmp:
      type_str = "IPv4"
      protocol = " --ip-proto igmp"
    else:
      type_str = "IPv6"
      protocol = " --ip6-proto ipv6-icmp"

    rule = []
    rule = ["-p " + type_str + " --logical-in " +vlan_name + protocol + " -j mark --mark-set 0x64 --mark-target ACCEPT"]
    return add_ebtable_rules(' broute ', ' BROUTING ', rule)

def snoop_remove_vlan_rules(is_igmp, vlan_name):
    if is_igmp:
      type_str = "IPv4"
      protocol = " --ip-proto igmp"
    else:
      type_str = "IPv6"
      protocol = " --ip6-proto ipv6-icmp"

    rule = []
    rule = ["-p " + type_str + " --logical-in " + vlan_name + protocol + " -j mark --mark-set 0x64 --mark-target ACCEPT"]
    return remove_ebtables_rules(' broute ', ' BROUTING ', rule)

def snoop_update_vlan_rules(is_igmp, vlan_name, data):

    ret = False
    if data == 1:
      ret = snoop_add_vlan_rules(is_igmp,vlan_name)
    elif data == 0:
      ret = snoop_remove_vlan_rules(is_igmp,vlan_name)
    else: return False

    return ret

def read_ebtable_rules(table, chain):
    cmd = ('ebtables -t '+ table + ' -L ' + chain).split()
    res = []
    mcast_utils.run_command(cmd, res)
    mcast_utils.log_debug("ebtable dump: %s" %(res))
    return res

def add_ebtable_rules(table, chain, rules):
    ret = True
    res = read_ebtable_rules(table, chain)

    ebtable_prefix = 'ebtables -t ' + table

    for rule in rules:
      if rule not in res:
        cmd = (ebtable_prefix +' -I ' + chain +rule).split()
        if (mcast_utils.run_command(cmd, res) != 0):
          ret = False
          mcast_utils.log_err("Failed to ADD : %s " %(rule))
        else:
          mcast_utils.log_info("Succesfully ADDED : %s " %(rule))

    return ret

def remove_ebtables_rules(table, chain, rules):
    ret = True
    res = read_ebtable_rules(table, chain)

    ebtable_prefix = 'ebtables -t ' + table

    for rule in rules:
      if rule in res:
        cmd = (ebtable_prefix +' -D ' + chain +rule).split()
        if (mcast_utils.run_command(cmd, res) != 0):
          ret = False
          mcast_utils.log_err("Failed to DELETE : %s " %(rule))
        else:
          mcast_utils.log_info("Succesfully DELETED : %s " %(rule))

    return ret

def snoop_create_iptables_chain(is_igmp, table, chain):
    #Create chain and add rules, when snooping is enabled globally.
    ret = True
    res = []
    if is_igmp:
      rule_prefix = 'iptables -t ' + table
      cmd = (rule_prefix + ' -N ' + chain).split()
      chain_rules = igmp_add_rules
    else:
      rule_prefix = 'ip6tables -t ' + table
      cmd = (rule_prefix + ' -N ' + chain).split()
      chain_rules = mld_add_rules

    mcast_utils.run_command(cmd, res)

    for rule in chain_rules:
      cmd = (rule_prefix + ' -C ' + rule).split()
      if (mcast_utils.run_command(cmd, res) != 0):
        cmd = (rule_prefix + ' -A ' + rule).split()
        if (mcast_utils.run_command(cmd, res) != 0): ret = False

    return ret

def snoop_delete_iptables_chain(is_igmp, table, chain):
    #Flush and delete the IGMP/MLD snoop chain when snooping disabled globally.
    ret = True
    res = []
    if is_igmp:
      cmd = ('iptables -t ' +table + ' -F ' + chain).split()
      if(mcast_utils.run_command(cmd, res) != 0): ret = False
      cmd = ('iptables -t ' +table + ' -X ' + chain).split()
      if(mcast_utils.run_command(cmd, res) != 0): ret = False
    else:
      cmd = ('ip6tables -t ' +table + ' -F ' + chain).split()
      if(mcast_utils.run_command(cmd, res) != 0): ret = False
      cmd = ('ip6tables -t ' +table + ' -X ' + chain).split()
      if(mcast_utils.run_command(cmd, res) != 0): ret = False

    return ret

def snoop_bridge_nf_iptables_enable(is_igmp):

    if is_igmp:
      file = bridge_nf_iptables
    else:
      file = bridge_nf_ip6tables

    return mcast_utils._update_file_system(file, 1)

def snoop_bridge_nf_iptables_disable(is_igmp):

    if is_igmp:
      file = bridge_nf_iptables
    else:
      file = bridge_nf_ip6tables

    return mcast_utils._update_file_system(file, 0)

def snoop_add_rule_chain(is_igmp):

    ret = True
    res = []

    mcast_utils.log_debug('Create chain: %d' %(is_igmp))
    #EBTABLES:
    #For each snoop disabled VLAN's, received IGMP/MLD packets are marked
    #and dropped in iptables raw table IGMPSNOOP/MLDSNOOP chain.
    # Here:
    #1. Create IGMPSNOOP/MLDSNOOP chain in iptables raw table to check the
    #   IGMP/MLD packet types and drop all the iGMP/MLD packets other than query
    #   for enabled VLANs. For enabled VLAN's snoop application will decide what
    #   to do with the packet.
    #2. Create a Rule in iptables raw table PREROUTING chain to catch
    #   marked (snooping enabled VLAN's) IGMP/MLD packets and redirect to
    #   IGMPSNOOOP/MLDSNOOP chain
    if is_igmp:
      ret = snoop_create_iptables_chain(is_igmp, 'raw', IGMP_CHAIN_NAME)
      if ret is False:
        mcast_utils.log_err('Failed to create/add iptables rules to %s chain' %(IGMP_CHAIN_NAME))
        return ret

      # Add PREROUTING rule
      rule_prefix = 'iptables -t raw '
      cmd = (rule_prefix + ' -C ' + igmp_preroute_rule).split()
      if (mcast_utils.run_command(cmd, res) != 0):
        cmd = (rule_prefix + ' -A ' + igmp_preroute_rule).split()
        if (mcast_utils.run_command(cmd, res) != 0): ret = ret and False

      if ret is False:
        mcast_utils.log_err('Failed to add iptables rules to PREROUTING chain')
        return ret

      #Add EBTABLES nat POSTROUTING IGMP rules
      ret = add_ebtable_rules(' nat ', ' POSTROUTING ', igmp_global_ebtable_rule)

      if ret is False:
        mcast_utils.log_err('Failed to add IGMP EBTABLE rules to nat POSTROUTING chain')
        return ret

      ret = snoop_bridge_nf_iptables_enable(is_igmp)
      if ret is False:
        mcast_utils.log_err('Failed to enable bridge_nf_call_iptables')
        return ret

    else:
      ret = snoop_create_iptables_chain(is_igmp, 'raw', MLD_CHAIN_NAME)
      if ret is False:
        mcast_utils.log_err('Failed to create/add ip6tables rules to %s chain' %(MLD_CHAIN_NAME))
        return ret

      # Add PREROUTING rule
      rule_prefix = 'ip6tables -t raw '
      cmd = (rule_prefix + ' -C ' + mld_preroute_rule).split()
      if (mcast_utils.run_command(cmd, res) != 0):
        cmd = (rule_prefix + ' -A ' + mld_preroute_rule).split()
        if (mcast_utils.run_command(cmd, res) != 0): ret = ret and False

      if ret is False:
        mcast_utils.log_err('Failed to add ip6tables rules to PREROUTING chain')
        return ret

      mcast_utils.log_debug('%s chain created and rules added succesfully' %(IGMP_CHAIN_NAME if is_igmp else MLD_CHAIN_NAME))

      #Add EBTABLES nat POSTROUTING MLD rules
      ret = add_ebtable_rules(' nat ', ' POSTROUTING ', mld_global_ebtable_rule)

      if ret is False:
        mcast_utils.log_err('Failed to add MLD EBTABLE rules to nat POSTROUTING chain')
        return ret

      ret = snoop_bridge_nf_iptables_enable(is_igmp)
      if ret is False:
        mcast_utils.log_err('Failed to enable bridge_nf_call_ip6tables')
        return ret

    mcast_utils.log_info('All %s global Ebtables/Iptables created and rules added succesfully' %('IGMP' if is_igmp else 'MLD'))

    return ret

def snoop_remove_rule_chain(is_igmp):
    ret = True
    res = []
    mcast_utils.log_info('Remove %s chain' %(IGMP_CHAIN_NAME if is_igmp else MLD_CHAIN_NAME))
    if is_igmp:
      rule_prefix = 'iptables -t raw '
      cmd = (rule_prefix + ' -C ' + igmp_preroute_rule).split()
      if (mcast_utils.run_command(cmd, res) == 0):
        cmd = (rule_prefix + ' -D ' + igmp_preroute_rule).split()
        if (mcast_utils.run_command(cmd, res) != 0): ret = ret and False

      ret = ret and snoop_delete_iptables_chain(is_igmp, 'raw', IGMP_CHAIN_NAME)

      mcast_utils.log_info('Remove %s chain ret = %d' %(IGMP_CHAIN_NAME if is_igmp else MLD_CHAIN_NAME, ret))

      #Delete EBTABLES nat POSTROUTING IGMP rules
      ret = remove_ebtables_rules(' nat ', ' POSTROUTING ', igmp_global_ebtable_rule)

      if ret is False:
        mcast_utils.log_err('Failed to Delete EBTABLE IGMP rules from nat POSTROUTING chain')
        return ret

      ret = snoop_bridge_nf_iptables_disable(is_igmp)
      if ret is False:
        mcast_utils.log_err('Failed to disable bridge_nf_call_iptables')
        return ret

    else:
      rule_prefix = 'ip6tables -t raw '
      cmd = (rule_prefix + ' -C ' + mld_preroute_rule).split()
      if (mcast_utils.run_command(cmd, res) == 0):
        cmd = (rule_prefix + ' -D ' + mld_preroute_rule).split()
        if (mcast_utils.run_command(cmd, res) != 0): ret = ret and False

      ret = ret and snoop_delete_iptables_chain(is_igmp, 'raw', MLD_CHAIN_NAME)

      mcast_utils.log_info('Remove %s chain ret = %d' %(IGMP_CHAIN_NAME if is_igmp else MLD_CHAIN_NAME, ret))

      #Delete EBTABLES nat POSTROUTING IGMP rules
      ret = remove_ebtables_rules(' nat ', ' POSTROUTING ', mld_global_ebtable_rule)

      if ret is False:
        mcast_utils.log_err('Failed to Delete EBTABLE MLD rules from nat POSTROUTING chain')
        return ret

      ret = snoop_bridge_nf_iptables_disable(is_igmp)
      if ret is False:
        mcast_utils.log_err('Failed to disable bridge_nf_call_ip6tables')
        return ret

    mcast_utils.log_info('All %s global Ebtables/Iptables rules removed with ret = %d' %('IGMP' if is_igmp else 'MLD', ret))
    return ret

def snoop_update_global_rules(is_igmp, status):

    ret = True
    if status == 1:
      ret = snoop_add_rule_chain(is_igmp)
    elif status == 0:
      ret = snoop_remove_rule_chain(is_igmp)
    else: return False

    return ret

def snoop_get_cb(methods, params):
    mcast_utils.log_debug('Snoop get not supported')
    return False


_intf_vlan_key = cps.key_from_name('observed', 'base-if-vlan/if/interfaces/interface')

#On Bridge/VLAN creation by default snooping get enabled on bridge in Linux,
#when snooping application is running and kernel snooping is not needed snooping
#needs to be disabled. Monitor thread is created to monitor VLAN create event,
#and on VLAN creation disable the snooping.


def monitor_VLAN_interface_event():
    _vlan_handle = cps.event_connect()
    cps.event_register(_vlan_handle, _intf_vlan_key)
    mcast_utils.log_info('monitor_VLAN_interface_event started')

    while True:
      vlan_event = cps.event_wait(_vlan_handle)
      obj = cps_object.CPSObject(obj=vlan_event)
      if obj is None:
        mcast_utils.log_err('VLAN_MONITOR: Object not present in the event')
        continue
      if obj.get_key() != _intf_vlan_key:
        mcast_utils.log_debug('VLAN_MONITOR: Wrong VLAN interface event, ignore')
        continue

      try:
        vlan_name = obj.get_attr_data('if/interfaces/interface/name')
        # check if if_name is present
        if vlan_name is None:
          mcast_utils.log_err('VLAN_MONITOR: VLAN name not present in the event')
          continue

        if 'operation' in vlan_event:
          mcast_utils.log_info('VLAN_MONITOR: Received %s %s event' %(vlan_name, vlan_event['operation']))
          if (vlan_event['operation'] == 'create'):
            ret = mcast_utils._update_file_system(mcast_utils._get_path_per_vlan_configs(vlan_name, "multicast_snooping") , 0)
            if ret is True:
              mcast_utils.log_info('VLAN_MONITOR: Disabled snooping on %s in kernel' %(vlan_name))
            else:
              mcast_utils.log_err('VLAN_MONITOR: Failed to disable snooping on %s in kernel' %(vlan_name))
          elif (vlan_event['operation'] == 'delete'):
            #On VLAN deletion, not sure application sends the snoop disable, even if it sends it comes
            #with VLAN id, so for getting ifname NAS interface may not have VLAN and will fail to get name.
            #and per VLAN rule in kernel may not get deleted. So here on VLAN deletion the per VLAN IGMP/MLD
            #rules are deleted.
            #
            if (snoop_remove_vlan_rules(True, vlan_name)) is False:
              mcast_utils.log_debug('VLAN_MONITOR: Failed to remove IGMP ebtables rule in kernel for %s' %(vlan_name))
            if (snoop_remove_vlan_rules(False, vlan_name)) is False:
              mcast_utils.log_debug('VLAN_MONITOR: Failed to remove MLD ebtables rule in kernel for %s' %(vlan_name))
        else:
          mcast_utils.log_info('VLAN_MONITOR: Received event without operation' %(vlan_name))

      except Exception as e:
        mcast_utils.log_err('VLAN_MONITOR: Exception: %s' %e)

def _parse_snoop_routes(vlan_id, vlan_info, op, igmp_events,group_info, pub_data):

    for key, val in group_info.items():
      if 'group' not in val:
        mcast_utils.log_err("Route Event: VLAN %d Group not present, skip processing" %(vlan_id))
        continue
      if 'interface' not in val:
        mcast_utils.log_err("Route Event: VLAN %d interface not present, skip processing" %(vlan_id))
        continue

      interface = val['interface']

      #Validate given interface is VLAN member
      if mcast_utils.is_intf_vlan_member(vlan_info, interface, vlan_id) is False:
        mcast_utils.log_err("Route Event: interface %s is not VLAN %d member, skip processing" %(str(interface),vlan_id))
        if (op != "delete"):
          return False

        continue

      if mcast_utils._is_ip_addr(igmp_events, val['group']):
        group = val['group']
      elif igmp_events is True:
        group =  ba.ba_to_ipv4str('ipv4',val['group'])
      else:
        group =  ba.ba_to_ipv6str('ipv6',val['group'])

      pub_data.update( {'vlan-id': vlan_id,
            ('group', key, 'interface'): interface,
            ('group', key, 'address'): group})

      if 'source-addr' in val:
        if mcast_utils._is_ip_addr(igmp_events, val['source-addr']):
          source = val['source-addr']
        elif igmp_events is True:
          source =  ba.ba_to_ipv4str('ipv4',val['source-addr'])
        else:
          source =  ba.ba_to_ipv6str('ipv6',val['source-addr'])

        pub_data.update( { ('group', key, 'source', '0', 'address'): source})
        mcast_utils.log_info( "Route event:VLAN %d Interface: %s Group %s Source %s" %
                                                 (vlan_id, str(interface), group, source))
      else:
        mcast_utils.log_info("Route Event: VLAN %d Interface %s Source not present, (*, %s) route " %(vlan_id, str(interface), group))
    return True

def _parse_snoop_mrouter_ports(vlan_id, vlan_info, op, data, event_data):
    #scan through the leaf-list of mrouter ports.
    for interface in data:
      #Validate given interface is VLAN member
      if mcast_utils.is_intf_vlan_member(vlan_info, interface, vlan_id) is False:
        if op == "delete":
          #For delete case, when flow comes here there is a chance that port is
          # deleted from VLAN and NAS would have cleared multicast info.
          continue
        else:
          mcast_utils.log_err("interface %s is not VLAN %d member, skip processing" %(str(interface),vlan_id))
          return False

    event_data.update ({'vlan-id': vlan_id, 'mrouter-interface' :data})
    return True

def _parse_snoop_status(is_igmp, vlan_id, data, vlan_name,event_data):

    ret = True
    event_data.update ({'vlan-id': vlan_id, 'enable':data})

    ret = snoop_update_vlan_rules(is_igmp, vlan_name, data)
    if ret is False:
      mcast_utils.log_err('Failed to %s ebtable snooping rules in kernel for %s ' %("Add" if data == 1 else "Remove", vlan_name))
      return False

    mcast_utils.log_info('%s ebtable snooping rules in kernel for %s success' %("Add" if data == 1 else "Remove", vlan_name))

    # Disable snooping in kernel.
    ret = mcast_utils._update_file_system(mcast_utils._get_path_per_vlan_configs(vlan_name,
                                          "multicast_snooping") , 0)
    if ret is False:
      #When VLAN/bridge gets created,snooping will be disabled, this is just extra .
      mcast_utils.log_debug('Failed to disable snooping on %s in kernel' %(vlan_name))

    return True

def _parse_mcast_snoop_updates_and_publish(data, vlan_info, vlan_id, igmp_events, op):

    #Parse status, mrouter and route update and publish.
    vlan_name = vlan_info['cps/key_data']['if/interfaces/interface/name']
    try:
      for k in _snoop_obj_info:
        for path in _snoop_obj_info[k]['obj_path']:
          if path in data and _snoop_obj_info[k]['publish_events']:
            # Publish CPS Events if required
            event_data = {}
            mcast_utils.log_info('%s %s %s for VLAN %d' % ('IGMP' if igmp_events else 'MLD',
                                 _snoop_obj_info[k]['event_string'], op, vlan_id))
            if (k == 'static_l2_mcast_grp_key'):
              if(_parse_snoop_routes(vlan_id,vlan_info,op,igmp_events,data[path],event_data)) is False:
                return False
            elif (k == 'static_mrouter_key'):
              if(_parse_snoop_mrouter_ports(vlan_id,vlan_info,op,data[path],event_data)) is False:
                return False
            elif (k == 'mcast_snooping'):
              if(_parse_snoop_status(igmp_events, vlan_id, data[path], vlan_name, event_data)) is False:
                return False

            obj = events.MCast_CpsEvents()
            if event_data :
              if igmp_events:
                obj.publish_igmp_events(event_data, op)
              else:
                obj.publish_mld_events(event_data, op)

              mcast_utils.log_info("Publishing %s %s %s event" %(('IGMP ' if igmp_events else 'MLD '),
                                   _snoop_obj_info[k]['event_string'], op))
              mcast_utils.log_debug("Publish event data: %s" %(str(event_data)))

    except Exception as e:
      mcast_utils.log_err('Exception: %s' %e)

    return True

def handle_snoop_updates(params):

    #This handles only the IGMP/MLD snooping "status", "mrouter port" and "route" updates.
    #This gets called only when kernel snooping functionality is not used and some snooping
    #application is running. This parses and publishes and does not set/update kernel for mrouter
    # and route updates.
    ret = True
    data = mcast_utils.cps_convert_attr_data(params['change'])

    mcast_utils.log_debug("Data: %s" %(str(data)) )

    if mcast_utils.igmp_global_enable_key in data:
      return snoop_update_global_rules(True, data[mcast_utils.igmp_global_enable_key])
    elif mcast_utils.mld_global_enable_key in data:
      return snoop_update_global_rules(False, data[mcast_utils.mld_global_enable_key])

    if mcast_utils._keys['vlan_id_key']['igmp'] not in data and mcast_utils._keys['vlan_id_key']['mld'] not in data:
      mcast_utils.log_err("Missing VLAN ID")
      return False

    igmp_events = True
    if mcast_utils._keys['vlan_id_key']['igmp'] in data:
      vlan_id_key = mcast_utils._keys['vlan_id_key']['igmp']
    else:
      vlan_id_key = mcast_utils._keys['vlan_id_key']['mld']
      igmp_events = False

    vlan_id = data[vlan_id_key]

    mcast_utils.log_debug('%s Snoop update received for VLAN  %d' % ('IGMP' if igmp_events else 'MLD', vlan_id))
    # Get dell-base-if-cmn/if/interfaces/interface object for the given vlan id
    vlan_info_list = mcast_utils._get_vlan_info(vlan_id)
    if vlan_info_list is None or len(vlan_info_list) == 0:
      mcast_utils.log_err('No VLAN Information for VLAN id %d' % vlan_id)
      return False
    vlan_info = vlan_info_list[0]

    ret = _parse_mcast_snoop_updates_and_publish(data, vlan_info, vlan_id, igmp_events, params['operation'])

    mcast_utils.log_debug('Finish processing snoop updates, ret=%d' % ret)
    return ret
