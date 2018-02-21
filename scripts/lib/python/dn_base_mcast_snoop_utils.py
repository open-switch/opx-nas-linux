#!/usr/bin/python
# Copyright (c) 2017 Dell Inc.
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

import subprocess
import re
import types
import event_log as ev
import dn_base_mcast_snoop_events as events
import dn_base_ip_tool as ip_tool
import cps_object
import cps
import cps_utils
import logging
import bytearray_utils as ba
import threading
import time
import Queue

iplink_cmd = '/sbin/ip'
bridge_cmd = '/sbin/bridge'

igmp_global_key = 'igmp-mld-snooping/rt/routing/control-plane-protocols/igmp-snooping/global'
mld_global_key = 'igmp-mld-snooping/rt/routing/control-plane-protocols/mld-snooping/global'

igmp_global_enable_key=igmp_global_key+'/enable'
mld_global_enable_key=mld_global_key+'/enable'

igmp_vlan_key = 'igmp-mld-snooping/rt/routing/control-plane-protocols/igmp-snooping/vlans/vlan'
mld_vlan_key = 'igmp-mld-snooping/rt/routing/control-plane-protocols/mld-snooping/vlans/vlan'

tagged_ports_key = 'dell-if/if/interfaces/interface/tagged-ports'
untagged_ports_key = 'dell-if/if/interfaces/interface/untagged-ports'

# On igmp/mld snooping enable, set the maximum number of groups that can be learnt on a VLAN as 16K (2^14)
max_grps = 16384
def_mcast_hash_elasticity = 8

_keys = {
            'vlan_id_key'                : {
                                            'igmp': igmp_vlan_key+'/vlan-id',
                                            'mld': mld_vlan_key+'/vlan-id'
                                          },
            'static_l2_mcast_grp_key'     : {
                                            'igmp': igmp_vlan_key+'/static-l2-multicast-group',
                                            'mld': mld_vlan_key+'/static-l2-multicast-group'
                                          },
            'static_mrouter_key'        : {
                                            'igmp': igmp_vlan_key+'/static-mrouter-interface',
                                            'mld': mld_vlan_key+'/static-mrouter-interface'
                                          },
            'mcast_querier_key'            : {
                                            'igmp': igmp_vlan_key+'/querier',
                                            'mld' : mld_vlan_key+'/querier'
                                          }
        }

_ip_link_cmd_params = {
                'mcast_snooping': {
                                    'obj_path': [igmp_vlan_key+'/enable',
                                                 mld_vlan_key+'/enable'],
                                    'publish_events': True,
                                    'file_name':  'multicast_snooping'
                                  },
                'mcast_last_member_interval': {
                                    'obj_path': [igmp_vlan_key+'/last-member-query-interval/last-member-query-interval-basic/last-member-query-interval-basic',
                                                 mld_vlan_key+'/last-member-query-interval/last-member-query-interval-basic/last-member-query-interval-basic'],
                                    'publish_events': False,
                                    'file_name': 'multicast_last_member_interval'
                                    },
                'mcast_query_interval': {
                                    'obj_path': [igmp_vlan_key+'/query-interval/query-interval-basic/query-interval-basic',
                                                 mld_vlan_key+'/query-interval/query-interval-basic/query-interval-basic'],
                                    'publish_events': False,
                                    'file_name': 'multicast_query_interval'
                                    },
                'mcast_query_response_interval': {
                                    'obj_path': [igmp_vlan_key+'/query-max-response-time/query-max-response-time-basic/query-max-response-time-basic',
                                                 mld_vlan_key+'/query-max-response-time/query-max-response-time-basic/query-max-response-time-basic'],
                                    'publish_events': False,
                                    'file_name': 'multicast_query_response_interval'
                                    }
                    }

# Factor used to convert from tick to second
HZ = 100.0

# Interval for polling multicast snooping group changes
MCAST_SNOOP_POLLING_INTERVAL = 5

# Maximum trying times to set mdb hash_max after enabling multicast snooping
MAX_HASHMAX_CFG_TRY_COUNT = 50

mcast_path_prefix = "/sys/devices/virtual/net/"

rules = ['-p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type 132/0:255 --mark 0x1 -j ACCEPT',
         '-p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type 131/0:255 --mark 0x1 -j ACCEPT',
         '-p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type 130/0:255 --mark 0x1 -j ACCEPT',
         '-p IPv4 --ip-proto igmp --mark 0x1 -j ACCEPT']


rules_prefix = 'ebtables -t nat'

def _update_file_system(path, value):
    try:
      with open(path, "w") as fd:
        fd.write(str(value))
      log_debug("Updated file %s with value %s"%(path, str(value)))
    except Exception as e:
      log_err('File %s Exception %s' % (path, str(e)))
      return False

    return True

def _read_file_system(path):
    try:
        with open(path, "r") as fd:
            ln = fd.readlines()
            # Picking the first element in the line since the values are multicast snoop configs
            response = ln[0].split()[0]
            return response
    except Exception as e:
        log_err(str(e))
        return False

def _get_path_per_vlan_configs(vlan_name, file_name):
    return mcast_path_prefix+str(vlan_name)+'/bridge/'+str(file_name)

def log_err(msg):
    ev.logging("BASE_MCAST_SNOOP",ev.ERR,"MCAST_UTILS","","",0,msg)

def log_info(msg):
    ev.logging("BASE_MCAST_SNOOP",ev.INFO,"MCAST_UTILS","","",0,msg)

def log_debug(msg):
    ev.logging("BASE_MCAST_SNOOP",ev.DEBUG,"MCAST_UTILS","","",0,msg)

def run_command(cmd, respose, show_debug = True):
    try:
        p = subprocess.Popen(
            cmd,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)

        for line in p.stdout.readlines():
            respose.append(line.rstrip())
        retval = p.wait()
        if show_debug:
            log_debug("Command executed %s with return value %d" %(str(cmd), retval))
        return retval
    except Exception as e:
         log_msg = "Exception: "+ str(e)
         log_err(log_msg)
    return -1

def cps_convert_attr_data( raw_elem ):
    d={}
    obj = cps_object.CPSObject(obj=raw_elem)
    for attr in raw_elem['data']:
        d[attr] = obj.get_attr_data(attr)

    return d

def _get_vlan_info(vlan_id = None, br_name = None):
    result = []

    obj = cps_object.CPSObject(qual="target", module="dell-base-if-cmn/if/interfaces/interface")
    obj.add_attr("if/interfaces/interface/type", "ianaift:l2vlan")
    if vlan_id is not None:
        obj.add_attr("base-if-vlan/if/interfaces/interface/id", vlan_id)
    elif br_name is not None:
        obj.add_attr("if/interfaces/interface/name", br_name)
    cps.get([obj.get()], result)
    vlan_info = []
    for d in result:
        vlan_info.append( cps_convert_attr_data(d))

    log_debug("Vlan Info received: %s" %(str(vlan_info)))
    return vlan_info


def _get_if_name(vlan_info, if_name, vlan_id):
    try:
        # Get ifname (tagged or untagged) from dell-base-if-cmn/if/interfaces/interface object
        if untagged_ports_key in vlan_info and if_name in vlan_info[untagged_ports_key]:
            result = str(if_name)
        elif tagged_ports_key in vlan_info and if_name in vlan_info[tagged_ports_key]:
            result = str(if_name) + '.'+ str(vlan_id)
        else:
            log_err("Failure in getting tagged/untagged port name")
            return False

        log_debug("Interface name: %s" %(str(if_name)))
        return result
    except Exception as e:
        log_err(str(e))
        return False


def _handle_mcast_snoop_configs(cmd, data, vlan_name, igmp_events, op, snoop_cfg_flags):
    if op == "delete":
        log_err("Unsupported operation for mcast snoop configs")
        return False
    res = []
    for k in _ip_link_cmd_params:
        for path in _ip_link_cmd_params[k]['obj_path']:
          if path in data:
            snoop_cfg_flags[0] = True

            cmd = [iplink_cmd, 'link', 'set', vlan_name, 'type', 'bridge']

            if k == 'mcast_last_member_interval' or k == 'mcast_query_interval': val = str( data[path] * 100 )
            else: val = str(data[path])

            cmd.extend((k, val))

            event_data = {}

            if _ip_link_cmd_params[k]['publish_events']:
                ev_key = path.split("/")[-1]
                if _keys['vlan_id_key']['igmp'] in data:  id = data[_keys['vlan_id_key']['igmp']]
                elif _keys['vlan_id_key']['mld'] in data:  id = data[_keys['vlan_id_key']['mld']]
                event_data = {'vlan-id': str(id), ev_key :str( data[path])}

            if run_command(cmd, res) == 0:
                if event_data:
                    # Publish CPS events
                    obj = events.MCast_CpsEvents()
                    if igmp_events: obj.publish_igmp_events(event_data, op)
                    else: obj.publish_mld_events(event_data, op)
                    log_debug("Publishing CPS Event: %s" %(str(event_data)))

                return True
            else: return False

    return True

def _handle_mcast_snoop_configs_fs(data, vlan_name, igmp_events, op):
    ret = True
    for k in _ip_link_cmd_params:
        for path in _ip_link_cmd_params[k]['obj_path']:
          if path in data:
              if op == "delete":
                  log_err("Unsupported operation for mcast snoop configs")
                  return False

              # In case of igmp/mld disable on a vlan, Clear cache
              if k == 'mcast_snooping' and data[path] == 0:
                  try:
                      polling_thread.flush_cache(vlan_name)
                  except Exception as e:
                      logging.exception(e)
                      return False

              if k == 'mcast_last_member_interval' or k == 'mcast_query_interval': val = str( data[path] * 100 )
              else: val = str(data[path])

              # Update Multicast Snooping on a VLAN
              ret = ret and (_update_file_system(_get_path_per_vlan_configs(vlan_name, _ip_link_cmd_params[k]['file_name']), val))

              # Publish CPS Events if required
              event_data = {}
              if _ip_link_cmd_params[k]['publish_events']:
                  ev_key = path.split("/")[-1]
                  if _keys['vlan_id_key']['igmp'] in data:  id = data[_keys['vlan_id_key']['igmp']]
                  elif _keys['vlan_id_key']['mld'] in data:  id = data[_keys['vlan_id_key']['mld']]
                  event_data = {'vlan-id': str(id), ev_key :str( data[path])}

              if ret and event_data:
                 obj = events.MCast_CpsEvents()
                 # Since snoop config variables like mcast status are common for both IPv4 and IPv6, publishing the corresponding events on both igmp and mld state objects
                 obj.publish_igmp_events(event_data, op)
                 obj.publish_mld_events(event_data, op)
                 log_debug("Publishing CPS Event: %s" %(str(event_data)))

              # In case of igmp/mld enable, set the max groups as 16k and hash_elasticity as 8
              if k == 'mcast_snooping' and data[path] == 1:
                  ret = ret and polling_thread.hashmax_cfg_to_queue(vlan_name, max_grps)
                  ret = ret and (_update_file_system(_get_path_per_vlan_configs(vlan_name, "hash_elasticity"),
                                                            def_mcast_hash_elasticity))

              # In case of multicast query interval, kernel doesn't update multicast membership interval file and multicast_querier_interval file, hence updating it manually
              if k == 'mcast_query_interval':
                  mcast_query_response_interval = _read_file_system(_get_path_per_vlan_configs(vlan_name, "multicast_query_response_interval"))
                  if not mcast_query_response_interval: return False

                  #As per RFC The Group Membership Interval value MUST be ((the Robustness Variable) times (the Query Interval)) plus (one Query Response Interval)
                  val = ((data[path]*2)+(int(mcast_query_response_interval)/100))*100
                  ret = ret and (_update_file_system(_get_path_per_vlan_configs(vlan_name, "multicast_membership_interval"), val))

                  #As per RFC The Other Querier Present Interval value MUST be ((the Robustness Variable) times (the Query Interval)) plus (one half of one Query Response Interval)
                  val = ((data[path]*2)+((int(mcast_query_response_interval)/100)/2))*100
                  ret = ret and (_update_file_system(_get_path_per_vlan_configs(vlan_name, "multicast_querier_interval"), val))
    return ret

def _handle_mcast_querier_functionality(op, vlan_name):
    # mcast_querier values
    mcast_querier = '0'
    if op == "create" or op == "set" : mcast_querier = '1'

    obj_paths = ['mcast_querier', 'mcast_query_use_ifaddr']
    cmd = [iplink_cmd, 'link', 'set', vlan_name, 'type', 'bridge']

    ret = True
    for path in obj_paths:
        cmd.extend((path,  mcast_querier))
        res = []
        if (run_command(cmd, res) != 0): ret = ret and False
        cmd = [iplink_cmd, 'link', 'set', vlan_name, 'type', 'bridge']

    return ret

def _is_ip_addr(ipv4_flag, ip_addr):
    try:
        ret = (cps_utils.is_ipv4_addr(ip_addr) if ipv4_flag else cps_utils.is_ipv6_addr(ip_addr))
    except TypeError:
        ret = False
    return ret

def _handle_static_groups(op, data, vlan_info, ipv4_flag, static_l2_mcast_grp_key, vlan_id_key):
    try:
        res = []
        _cps_to_bridge_op = {'create': 'add', 'delete': 'del' }
        _static_grp = data[static_l2_mcast_grp_key]
        ret = True
        for k in _static_grp:
            # Check if the group address is a valid ipv4 or ipv6 address string
            if _is_ip_addr(ipv4_flag, _static_grp[k]['group']):
                grp = _static_grp[k]['group']
            else:
                # Convert the bytearray to ipv4 or ipv6 address string representation
                if ipv4_flag: grp = ba.ba_to_ipv4str('ipv4', _static_grp[k]['group'])
                else: grp = ba.ba_to_ipv6str('ipv6', _static_grp[k]['group'])

            if_name = _get_if_name(vlan_info,  _static_grp[k]['interface'], data[vlan_id_key])
            if not if_name: return False

            vlan_name = vlan_info['cps/key_data']['if/interfaces/interface/name']
            cmd = [bridge_cmd, 'mdb', _cps_to_bridge_op[op], 'dev', vlan_name, 'port', if_name, 'grp', grp, 'permanent']
            res = []
            if (run_command(cmd, res) != 0): ret = ret and False

        return ret
    except Exception as e:
        log_err(str(e))
        return False

def _handle_static_mrouter_config(op, data, vlan_info, static_mrouter_key, vlan_id_key ):
    res = []
    # MCast_router value
    mcast_router_val = '1'
    if op == "create" or op == "set" : mcast_router_val = '2'


    ret = True
    for val in data[static_mrouter_key]:
        if_name = _get_if_name(vlan_info,  val, data[vlan_id_key])
        if not if_name: return False

        cmd = [iplink_cmd, 'link', 'set', if_name, 'type', 'bridge_slave', 'mcast_router', mcast_router_val]
        res = []

        if (run_command(cmd, res) != 0): ret = ret and False

    return ret

def _read_rules():
    cmd = ['ebtables', '-t', 'nat', '-L', 'POSTROUTING']
    res = []
    run_command(cmd, res)
    return res

def _validate_and_insert():
    res = _read_rules()
    ret = True
    for rule in rules:
        if rule not in res:
            cmd = (rules_prefix+' -I POSTROUTING '+rule).split()
            if (run_command(cmd, res) != 0): ret = ret and False
    return ret

def _validate_and_delete():
    res = _read_rules()
    ret = True
    for rule in rules:
        if rule in res:
            cmd = (rules_prefix+' -D POSTROUTING '+rule).split()
            if (run_command(cmd, res) != 0): ret = ret and False
    return ret

def _handle_rules(data):

    # Install/Remove ebtable rule in case of Global IGMP/MLD Snooping enable/disable
    if data[igmp_global_enable_key] == 1:
        # Validate if the rule already exists in case of rule insertion
        return _validate_and_insert()

    if data[igmp_global_enable_key] == 0:
        # Validate if the rule exists and delete the entries
        return _validate_and_delete()

    log_err("Incorrect values for global enable attribute")
    return False

def handle_configs_fs(params):

    ret = True
    data = cps_convert_attr_data(params['change'])

    if igmp_global_enable_key in data or mld_global_enable_key in data:
        return _handle_rules(data)

    if _keys['vlan_id_key']['igmp'] not in data and _keys['vlan_id_key']['mld'] not in data:
        log_err("Missing VLAN ID")
        return False

    igmp_events = True
    if _keys['vlan_id_key']['igmp'] in data:
        vlan_id_key = _keys['vlan_id_key']['igmp']
    else:
        vlan_id_key = _keys['vlan_id_key']['mld']
        igmp_events = False

    log_debug('Start config on file system for %s' % ('IGMP' if igmp_events else 'MLD'))
    # Get dell-base-if-cmn/if/interfaces/interface object for the given vlan id
    vlan_info_list = _get_vlan_info(data[vlan_id_key])
    if vlan_info_list is None or len(vlan_info_list) == 0:
        log_err("No VLAN Information")
        return False
    vlan_info = vlan_info_list[0]
    vlan_name = vlan_info['cps/key_data']['if/interfaces/interface/name']

    # Handle mcast querier functionality
    if _keys['mcast_querier_key']['igmp'] in data or _keys['mcast_querier_key']['mld'] in data:
        # mcast_querier values
        mcast_querier = '0'
        if params['operation'] == "create" or params['operation'] == "set" : mcast_querier = '1'
        files = ['multicast_querier', 'multicast_query_use_ifaddr']
        ret = True
        for f in files:
            ret = ret and (_update_file_system(_get_path_per_vlan_configs(vlan_name, f), mcast_querier ))
    ret = ret and (_handle_mcast_snoop_configs_fs(data, vlan_name, igmp_events, params['operation']) )

    #Handle static group programming
    if _keys['static_l2_mcast_grp_key']['igmp'] in data:
        ret = ret and (_handle_static_groups(params['operation'], data, vlan_info, True, _keys['static_l2_mcast_grp_key']['igmp'], _keys['vlan_id_key']['igmp']) )
    elif _keys['static_l2_mcast_grp_key']['mld'] in data:
        ret = ret and (_handle_static_groups(params['operation'], data, vlan_info, False,  _keys['static_l2_mcast_grp_key']['mld'], _keys['vlan_id_key']['mld']) )

    # Handle Static MRouter configuration
    if _keys['static_mrouter_key']['igmp'] in data or _keys['static_mrouter_key']['mld'] in data:
        # MCast_router value
        mcast_router_val = '1'
        if params['operation'] == "create" or params['operation'] == "set" : mcast_router_val = '2'

        if _keys['static_mrouter_key']['igmp'] in data: static_mrouter_key = _keys['static_mrouter_key']['igmp']
        else: static_mrouter_key = _keys['static_mrouter_key']['mld']
        for val in data[static_mrouter_key]:
            ifname = _get_if_name(vlan_info,  val, data[vlan_id_key])
            if not ifname:
               #As part of port remove from VLAN the multicast cleanup will happen for that port in Linux
               #and NPU and after that app sends static mrouter port deletion to NAS . NAS multicast python
               #service queries nas-interface for VLAN and port info, which will not have that port,
               #so returing failure will cause app to think mrouter port is not deleted and next
               #configuration of mrouter will fail, to avoid this, ignore if vlan info or port not present
               #in VLAN in static mrouter delete case.

               if params['operation'] == "delete":
                  return True
               return False


            file_path = mcast_path_prefix+str(vlan_name)+'/brif/'+ifname+'/multicast_router'
            if not _update_file_system(file_path, mcast_router_val ):
                if params['operation'] == "create" or params['operation'] == "set" :
                    polling_thread.update_static_mrouter_cache(McastRouterInfo(vlan_name, ifname))
            if params['operation'] == "delete":
                polling_thread.clear_static_mrouter_cache(McastRouterInfo(vlan_name, ifname))
    log_debug('Finish config on file system, ret=%d' % ret)
    return ret


def handle_configs(params):
    ret = False
    data = cps_convert_attr_data(params['change'])

    if _keys['vlan_id_key']['igmp'] not in data and _keys['vlan_id_key']['mld'] not in data:
        log_err("Missing VLAN ID")
        return ret

    igmp_events = True
    if _keys['vlan_id_key']['igmp'] in data:
        vlan_id_key = _keys['vlan_id_key']['igmp']
    else:
        vlan_id_key = _keys['vlan_id_key']['mld']
        igmp_events = False

    # Get dell-base-if-cmn/if/interfaces/interface object for the given vlan id
    vlan_info_list = _get_vlan_info(data[vlan_id_key])
    if vlan_info_list is None or len(vlan_info_list) == 0:
        log_err("No VLAN Information")
        return False
    vlan_info = vlan_info_list[0]
    vlan_name = vlan_info['cps/key_data']['if/interfaces/interface/name']

    cmd = []
    snoop_cfg_flags = [False]
    ret = _handle_mcast_snoop_configs(cmd, data, vlan_name, igmp_events, params['operation'], snoop_cfg_flags)
    if snoop_cfg_flags[0]:
        return ret

    # Handle mcast querier functionality
    if _keys['mcast_querier_key']['igmp'] in data or _keys['mcast_querier_key']['mld'] in data:
        return _handle_mcast_querier_functionality(params['operation'], vlan_name)

    #Handle static group programming
    if _keys['static_l2_mcast_grp_key']['igmp'] in data:
        return _handle_static_groups(params['operation'], data, vlan_info, True, _keys['static_l2_mcast_grp_key']['igmp'], _keys['vlan_id_key']['igmp'])
    elif _keys['static_l2_mcast_grp_key']['mld'] in data:
        return _handle_static_groups(params['operation'], data, vlan_info, False,  _keys['static_l2_mcast_grp_key']['mld'], _keys['vlan_id_key']['mld'])


    # Handle Static MRouter configuration
    if _keys['static_mrouter_key']['igmp'] in data:
        return _handle_static_mrouter_config(params['operation'], data, vlan_info, _keys['static_mrouter_key']['igmp'], _keys['vlan_id_key']['igmp'])
    elif _keys['static_mrouter_key']['mld'] in data:
        return _handle_static_mrouter_config(params['operation'], data, vlan_info, _keys['static_mrouter_key']['mld'], _keys['vlan_id_key']['mld'])

    return True

def get_vlan_mapping(vlan_id = None):
    vlan_list = _get_vlan_info(vlan_id)
    vlan_map = {}
    log_info('Got %d VLAN objects in list' % len(vlan_list))
    for vlan_item in vlan_list:
        vlan_id = vlan_item['base-if-vlan/if/interfaces/interface/id']
        vlan_if_name = vlan_item['cps/key_data']['if/interfaces/interface/name']
        vlan_map[vlan_id] = vlan_if_name
    return vlan_map

def get_yang_attr_value(kernel_val, val_type):
    if val_type == 'boolean':
        return True if int(kernel_val) else False
    elif val_type == 'tick':
        return int(float(kernel_val) / HZ)
    else:
        return kernel_val

def remove_ifname_tag(if_name):
    idx = if_name.rfind('.')
    if idx >= 0 and if_name[idx+1:].isdigit():
        return if_name[:idx]
    return if_name

class McastRouterInfo(object):
    def __init__(self, br_name, if_name, expire = None):
        self.br_name = br_name
        self.raw_if_name = if_name
        self.if_name = remove_ifname_tag(if_name)
        self.expire = expire

    def __eq__(self, other):
        return (self.br_name == other.br_name and
                self.if_name == other.if_name)

    def __ne__(self, other):
        return (self.br_name != other.br_name or
                self.if_name != other.if_name)

    def __hash__(self):
        return hash(':'.join([self.br_name, self.if_name]))

    def __str__(self):
        ret = 'MRouter: bridge %s interface %s' % (self.br_name, self.if_name)
        if self.expire is not None:
            ret += ' expire %f' % self.expire
        return ret

    def __raw_str__(self):
        ret = 'MRouter: bridge %s interface %s' % (self.br_name, self.raw_if_name)
        if self.expire is not None:
            ret += ' expire %f' % self.expire
        return ret

class McastGroupInfo(object):
    def __init__(self, br_name, grp_ip, if_name, is_igmp, expire = None):
        self.br_name = br_name
        self.grp_ip_str = grp_ip
        self.grp_ip = ba.ipv4str_to_ba('ipv4', grp_ip) if is_igmp else ba.ipv6str_to_ba('ipv6', grp_ip)
        self.if_name = remove_ifname_tag(if_name)
        self.is_igmp = is_igmp
        self.expire = expire

    def __eq__(self, other):
        return (self.br_name == other.br_name and
                self.grp_ip == other.grp_ip and
                self.if_name == other.if_name)

    def __ne__(self, other):
        return (self.br_name != other.br_name or
                self.grp_ip != other.grp_ip or
                self.if_name != other.if_name)

    def __hash__(self):
        return hash(':'.join([self.br_name, str(self.grp_ip), self.if_name]))

    def __str__(self):
        ret = 'Group: bridge %s group_ip %s interface %s' % (
                            self.br_name, self.grp_ip_str, self.if_name)
        if self.expire is not None:
            ret += ' expire %f' % self.expire
        return ret

def get_igmp_snooping_route(ip_type, br_name = None, cache_update = False):
    cmd_response = []
    if cache_update:
        ret_val = {'mrouter': set(), 'group': set()}
    else:
        ret_val = {}
    if run_command([bridge_cmd, '-s', '-d', 'mdb', 'show'], cmd_response, False) != 0:
        log_err('Show MDB commmand execution failed')
        return None
    for line in cmd_response:
        tokens = line.strip().split(None, 1)
        if len(tokens) >= 2:
            exp_time = None
            rt_type = 'permanent'
            if tokens[0] == 'dev':
                m = re.search(
                        'dev\s+(\S+)\s+port\s+(\S+)\s+grp\s+(\S+)\s+(permanent|temp)(.*)', line)
                if m is None:
                    log_err('Unknown MDB entry line format: %s' % line)
                    return None
                (dev_name, if_name, grp_ip, rt_type, tail_str) = m.groups()
                if len(tail_str) > 0:
                    m1 = re.search('\s+(offload|)\s+(vid\s+\S+\s+|)(\S+)', tail_str)
                    if m1 is not None:
                        (_, _, exp_time) = m1.groups()
                is_entry = True
            elif tokens[0] == 'router':
                m = re.search('router ports on (\S+):(.*)', line)
                if m is None:
                    log_err('Unknown MROUTER entry line format: %s' % line)
                    return None
                (dev_name, tail_str) = m.groups()
                mr_tokens = tail_str.split()
                if len(mr_tokens) == 3 and (mr_tokens[2] == 'temp' or mr_tokens[2] == 'permanent'):
                    try:
                        exp_time = float(mr_tokens[1])
                        single_line = False
                    except ValueError:
                        single_line = True
                else:
                    single_line = True
                if single_line:
                    if_list = mr_tokens
                else:
                    if_list = [mr_tokens[0]]
                    rt_type = mr_tokens[2]
                is_entry = False
            else:
                log_err('Unknown line format: %s' % line)
                return None
            if br_name is not None and br_name != dev_name:
                continue

            if not cache_update and dev_name not in ret_val:
                ret_val[dev_name] = {}

            if is_entry:
                if not ((ip_type == 'ipv4' and cps_utils.is_ipv4_addr(grp_ip)) or
                        (ip_type == 'ipv6' and cps_utils.is_ipv6_addr(grp_ip)) or
                        (ip_type == 'all')):
                    continue
                if ip_type == 'all':
                    if cps_utils.is_ipv4_addr(grp_ip):
                        is_igmp = True
                    elif cps_utils.is_ipv6_addr(grp_ip):
                        is_igmp = False
                    else:
                        log_err('Invalid IP address format: %s' % grp_ip)
                        continue
                else:
                    is_igmp = (ip_type == 'ipv4')

                if cache_update:
                    ret_val['group'].add(McastGroupInfo(dev_name, grp_ip, if_name,
                                                        is_igmp, exp_time))
                else:
                    if rt_type == 'permanent':
                        attr_name = 'static-l2-multicast-group'
                        group_info = {'group': grp_ip, 'interface': if_name}
                    else:
                        attr_name ='group'
                        if exp_time is None:
                            exp_time = 0.0
                        group_info = {'address': grp_ip, 'interface': if_name, 'expire': int(float(exp_time))}
                    if attr_name not in ret_val[dev_name]:
                        ret_val[dev_name][attr_name] = {0: group_info}
                    else:
                        attr_idx = len(ret_val[dev_name][attr_name])
                        ret_val[dev_name][attr_name][attr_idx] = group_info
            else:
                if cache_update:
                    for if_name in if_list:
                        ret_val['mrouter'].add(McastRouterInfo(dev_name, if_name, exp_time))
                else:
                    attr_name = 'static-mrouter-interface' if rt_type == 'permanent' else 'mrouter-interface'
                    if attr_name not in ret_val[dev_name]:
                        ret_val[dev_name][attr_name] = if_list
                    else:
                        ret_val[dev_name][attr_name].extend(if_list)
    return ret_val

def get_intf_ip_addr(ip_type, if_name):
    info_list = ip_tool.get_if_details(if_name)
    if len(info_list) == 0:
        log_err('Failed to get information of interface %s' % if_name)
        return None
    for af, addr, mask in info_list[0].ip:
        if ((af == 'inet' and ip_type == 'ipv4') or
            (af == 'inet6' and ip_type == 'ipv6')):
            return addr
    return ''

def get_igmp_snooping_state(ip_type, br_name, use_iplink_cmd):
    kernel_to_yang_map = {
        'mcast_snooping': ('enable', 'boolean', 'multicast_snooping'),
        'mcast_querier': ('querier', lambda v: (get_intf_ip_addr(ip_type, br_name)) if int(v) != 0 else None,
                          'multicast_querier'),
        'mcast_last_member_interval':
            ('last-member-query-interval/last-member-query-interval-basic/last-member-query-interval-basic', 'tick',
             'multicast_last_member_interval'),
        'mcast_query_interval':
            ('query-interval/query-interval-basic/query-interval-basic', 'tick', 'multicast_query_interval'),
        'mcast_query_response_interval':
            ('query-max-response-time/query-max-response-time-basic/query-max-response-time-basic', 'tick',
             'multicast_query_response_interval'),
        'mcast_querier_interval': ('mrouter-aging-time', 'tick', 'multicast_querier_interval')
    }
    if use_iplink_cmd:
        log_info('Get multicast snooping status by iplink command')
        cmd_response = []
        if run_command([iplink_cmd, '-s', '-d', 'link', 'show', br_name], cmd_response) != 0:
            log_err('Show IP link commmand execution failed')
            return None

        attr_line = None
        for line in cmd_response:
            tokens = line.strip().split(None, 1)
            if len(tokens) >= 2 and tokens[0] == 'bridge':
                attr_line = tokens[1]
                break
        if attr_line is None:
            log_err('No line with bridge attribute found')
            return None
        tokens = attr_line.split()
        if (len(tokens) % 2) != 0:
            log_err('Number of items is %d, should be even number' % len(tokens))
            return None
        attrs = [(tokens[i], tokens[i+1]) for i in range(0, len(tokens), 2)]
    else:
        log_info('Get multicast snooping status by reading system files')
        attrs = []
        for key, (_, _, fname) in kernel_to_yang_map.items():
            full_name = _get_path_per_vlan_configs(br_name, fname)
            try:
                with open(full_name, 'r') as fd:
                    lns = fd.readlines()
                    if len(lns) == 0:
                        log_err('File %s is empty' % full_name)
                        continue
                    attrs.append((key, lns[0].strip()))
            except IOError as e:
                log_err('Failure on file reading: %s' % str(e))
                return None
    ret_val = {}
    for key, val in attrs:
        if key in kernel_to_yang_map:
            yang_key, yang_type, _ = kernel_to_yang_map[key]
            if isinstance(yang_type, types.FunctionType):
                attr_val = yang_type(val)
                if attr_val is not None:
                    ret_val[yang_key] = attr_val
            else:
                ret_val[yang_key] = get_yang_attr_value(val, yang_type)
    return ret_val

def get_igmp_snooping_int(resp, module_name, ip_type, iplink_get_state, vlan_id):
    vlan_map = get_vlan_mapping(vlan_id)
    if vlan_map is None:
        log_err('Failed to get VLAN ID to name mapping')
        return False

    if vlan_id is not None:
        log_info('Get IGMP information for VLAN %d' % vlan_id)
        if not vlan_id in vlan_map:
            log_err('VLAN ID %d is not in map' % vlan_id)
            return False
        route_list = get_igmp_snooping_route(ip_type, vlan_map[vlan_id])
    else:
        route_list = get_igmp_snooping_route(ip_type)
    if route_list is None:
        log_err('Failed to read IGMP route info')
        return False

    for vid, if_name in vlan_map.items():
        elem = cps_object.CPSObject(module = module_name, data = {'vlan-id': vid})

        snoop_state = get_igmp_snooping_state(ip_type, vlan_map[vid], iplink_get_state)
        if snoop_state is None:
            log_err('Failed to get IGMP snooping state of VLAN %d' % vid)
            return False
        for key, val in snoop_state.items():
            if '/' in key:
                key = elem.root_path + key
            log_info('Add attribute: NAME %s VALUE %s' % (key, val))
            elem.add_attr(key, val)

        if if_name in route_list:
            attr_list = route_list[if_name]
            for key, val in attr_list.items():
                if isinstance(val, types.DictType):
                    embed_attrs = [key, '', '']
                    for idx, dict_val in val.items():
                        embed_attrs[1] = str(idx)
                        for sub_key, sub_val in dict_val.items():
                            embed_attrs[2] = sub_key
                            elem.add_embed_attr(embed_attrs, sub_val, 3)
                else:
                    elem.add_attr(key, val)

        resp.append(elem.get())

    return True

def get_igmp_snooping(resp, key, ip_type, iplink_get_state, vlan_id = None):
    log_info('Entering IGMP snooping get function with key %s' % key)
    try:
        return get_igmp_snooping_int(resp, key, ip_type, iplink_get_state, vlan_id)
    except Exception as e:
        logging.exception(e)
        return False

class McastSnoopCacheMgr(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self, name = 'Multicast Snooping cache manager')

        # Set of McastRouterInfo object
        self.mrouter_set = set()
        # Set of McastRouterInfo object
        self.static_mrouter_set = set()
        # Mapping from bridge name to mrouter interface set
        self.br_mrouter_map = {}
        # Set of McastGroupInfo object
        self.group_set = set()
        # Mapping from bridge name to group objects set
        self.br_group_map = {}
        # Mapping from bridge name to VLAN ID
        self.vlan_map = {}
        # Queue for hash_max configuration
        self.hashmax_cfg_q = Queue.Queue()

        self.lock = threading.Lock()

    def get_vlan_id(self, br_name):
        if br_name not in self.vlan_map:
            vlan_list = _get_vlan_info(br_name = br_name)
            if vlan_list is None or len(vlan_list) == 0:
                log_err('Non-exist bridge %s given' % br_name)
                return None
            vlan_id = vlan_list[0]['base-if-vlan/if/interfaces/interface/id']
            self.vlan_map[br_name] = vlan_id
        return self.vlan_map[br_name]

    def update_static_mrouter_cache(self, new_set):
        self.lock.acquire()
        self.static_mrouter_set.add(new_set)
        self.lock.release()

    def clear_static_mrouter_cache(self, old_set):
        self.lock.acquire()
        self.static_mrouter_set.discard(old_set)
        self.lock.release()

    def get_all_static_mrouter_cache(self):
        result = []

        for elem in self.static_mrouter_set:
            try:
                m = re.search('MRouter: bridge\s(\S+)\sinterface\s(\S+)', elem. __raw_str__())
                result.append(m.groups())
            except Exception as e:
                pass
        log_debug("Static Mrouter cache: %s" %(str(result)))
        return result

    def flush_cache(self, br_name =  None):
        self.lock.acquire()
        if br_name is None:
            self.mrouter_set.clear()
            self.br_mrouter_map.clear()
            self.group_set.clear()
            self.br_group_map.clear()
        else:
            if br_name in self.br_mrouter_map:
                for if_name in self.br_mrouter_map[br_name]:
                    self.mrouter_set.discard(McastRouterInfo(br_name, if_name))
                del(self.br_mrouter_map[br_name])
            if br_name in self.br_group_map:
                for group in self.br_group_map[br_name]:
                    self.group_set.discard(group)
                del(self.br_group_map[br_name])
        self.lock.release()

    def publish_event(self, pub_set, op):
        for pub_item in pub_set:
            vlan_id = self.get_vlan_id(pub_item.br_name)
            if vlan_id is None:
                log_err('Failed to get VLAN ID for bridge %s' % pub_item.br_name)
                continue
            if isinstance(pub_item, McastGroupInfo):
                evt_data = {'vlan-id': vlan_id,
                            ('group', '0', 'interface'): pub_item.if_name,
                            ('group', '0', 'address'): pub_item.grp_ip_str}
                is_igmp = pub_item.is_igmp
            elif isinstance(pub_item, McastRouterInfo):
                evt_data = {'vlan-id': vlan_id, 'mrouter-interface': [pub_item.if_name]}
                is_igmp = True
            evt_obj = events.MCast_CpsEvents()
            if is_igmp:
                evt_obj.publish_igmp_events(evt_data, op)
            else:
                evt_obj.publish_mld_events(evt_data, op)

    def update_cache_set(self, new_set, mc_group):
        if mc_group:
            old_set = self.group_set
        else:
            old_set = self.mrouter_set
        del_set = old_set.difference(new_set)
        if len(del_set) > 0:
            log_info('Polling status: %d %s were deleted' % (len(del_set),
                                                             'groups' if mc_group else 'mrouters'))
        add_set = new_set.difference(old_set)
        if len(add_set) > 0:
            log_info('Polling status: %d %s were added' % (len(add_set),
                     'groups' if mc_group else 'mrouters'))
        if mc_group:
            self.publish_event(del_set, 'delete')
            for group in del_set:
                if group.br_name in self.br_group_map:
                    self.br_group_map[group.br_name].discard(group)
                else:
                    log_err('Bridge %s not found in cached group map' % group.br_name)
            self.publish_event(add_set, 'create')
            for group in add_set:
                if group.br_name not in self.br_group_map:
                    self.br_group_map[group.br_name] = set()
                self.br_group_map[group.br_name].add(group)
            self.group_set = new_set
        else:
            self.publish_event(del_set, 'delete')
            for mrouter in del_set:
                if mrouter.br_name in self.br_mrouter_map:
                    self.br_mrouter_map[mrouter.br_name].discard(mrouter.if_name)
                else:
                    log_err('Bridge %s not found in cached mrouter map' % mrouter.br_name)
            self.publish_event(add_set, 'create')
            for mrouter in add_set:
                if mrouter.br_name not in self.br_mrouter_map:
                    self.br_mrouter_map[mrouter.br_name] = set()
                self.br_mrouter_map[mrouter.br_name].add(mrouter.if_name)
            self.mrouter_set = new_set
        return True

    def update_cache(self):
        self.vlan_map.clear()
        mc_snoop_info = get_igmp_snooping_route('all', None, True)
        if mc_snoop_info is None:
            log_err('Failed reading multicast snooping info')
            return
        if not self.update_cache_set(mc_snoop_info['mrouter'], False):
            log_err('Failed to update cached mrouter set')
            return
        if not self.update_cache_set(mc_snoop_info['group'], True):
            log_err('Failed to update cached group set')
            return

    def apply_static_mrouter_configs(self):
        # Apply static mrouter port configuration
        mrouter_list = self.get_all_static_mrouter_cache()
        mcast_router_val = 2

        for elem in mrouter_list:
            (dev_name, if_name) = elem
            file_path = mcast_path_prefix+str(dev_name)+'/brif/'+if_name+'/multicast_router'
            if _update_file_system(file_path, mcast_router_val):
                self.static_mrouter_set.discard(McastRouterInfo(dev_name, if_name))

    def hashmax_cfg_to_queue(self, br_name, max_grps, try_count = 0):
        try:
            self.hashmax_cfg_q.put_nowait((br_name, max_grps, try_count))
        except Queue.Full:
            log_err('Failed to add hashmax cfg to queue, try_count=%d' % try_count)
            return False
        return True

    def run(self):
        polling_timeout = MCAST_SNOOP_POLLING_INTERVAL
        do_polling = True
        while True:
            if do_polling:
                self.lock.acquire()
                self.apply_static_mrouter_configs()
                self.update_cache()
                self.lock.release()
            try:
                start_time = time.time()
                br_name, max_grps, try_count = self.hashmax_cfg_q.get(True, polling_timeout)
                wait_time = time.time() - start_time
                polling_timeout -= wait_time
                if polling_timeout > 0:
                    do_polling = False
                else:
                    polling_timeout = MCAST_SNOOP_POLLING_INTERVAL
                    do_polling = True
            except Queue.Empty:
                polling_timeout = MCAST_SNOOP_POLLING_INTERVAL
                do_polling = True
                continue
            log_debug('Setting hash_max %d to bridge %s' % (max_grps, br_name))
            if not _update_file_system(_get_path_per_vlan_configs(br_name, "hash_max"), max_grps):
                # File update might fail because kernel need some "grace period" to release old hash table after mdb rebuild
                # by multicast snooping enabling operation, and does not allow setting hash_max during the meantime. So we have
                # to wait and re-try
                try_count += 1
                if try_count >= MAX_HASHMAX_CFG_TRY_COUNT:
                    log_err('Failed to set hash_mas after re-trying %d times' % MAX_HASHMAX_CFG_TRY_COUNT)
                else:
                    if self.hashmax_cfg_to_queue(br_name, max_grps, try_count):
                        continue
                    else:
                        log_err('Failed to set task for bridge %s back to queue' % br_name)
            else:
                log_debug('Successfully setting hash_max for bridge %s' % br_name)
            self.hashmax_cfg_q.task_done()

polling_thread = McastSnoopCacheMgr()
polling_thread.daemon = True
