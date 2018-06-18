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
import event_log as ev
import cps_object
import cps_utils
import cps


iplink_cmd = '/sbin/ip'

config_sad_key_prefix = 'eipsec/ipsec/sad/sad-entries'
config_sad_options_key_prefix = 'ipsec-sad/eipsec/ipsec/sad/sad-entries'
config_spd_key_prefix = 'spd/eipsec/ipsec/spd/spd-entries'

_ipsec_keys = {config_sad_key_prefix : cps.key_from_name('target', config_sad_key_prefix),
              config_spd_key_prefix : cps.key_from_name('target', config_spd_key_prefix),
              'eipsec/sad/sad-entries': cps.key_from_name('target', 'eipsec/sad/sad-entries'),
              'eipsec/spd/spd-entries': cps.key_from_name('target', 'eipsec/spd/spd-entries')
              }


def log_err(msg):
    ev.logging("BASE_IP",ev.ERR,"IPSEC-CONFIG-UTILS","","",0,msg)

def log_info(msg):
    ev.logging("BASE_IP",ev.INFO,"IPSEC-CONFIG-UTILS","","",0,msg)

def run_command(cmd, respose):
    """Method to run a command in shell"""
    try:
        p = subprocess.Popen(
            cmd,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)

        for line in p.stdout.readlines():
            respose.append(line.rstrip())
        retval = p.wait()
        return retval
    except Exception as e:
         log_msg = "Exception: "+ str(e)
         log_err(log_msg)
    return False



def cps_convert_attr_data( raw_elem ):
    """ Get type preserved output from a dictionary with bytearray values  """
    d={}
    obj = cps_object.CPSObject(obj=raw_elem)
    for attr in raw_elem['data']:
        d[attr] = obj.get_attr_data(attr)

    return d

# Map between CPS Operations and IP XFRM operations
cps_to_xfrm_op = {'create': 'add', 'set': 'update', 'delete': 'delete'}

# Enumeration map from yang header file
ipsec_enum_map = {
                    'sec-proto': {0: 'ah', 1: 'esp' },
                    'mode': {0: 'transport', 1: 'tunnel'},
                    'direction': {0: 'in', 1: 'out'},
                    'level': {1: 'required', 2: 'use'}
}

# Map which contains IP XFRM ID Params (includes src addr, dst addr, xfrm protocol and security parameter index SPI
# ip xfrm state { add | update } ID where ID := [ src ADDR ] [ dst ADDR ] [ proto XFRM-PROTO ] [ spi SPI ]
_id_obj_map = {
                 'src':   { 'sad_path': config_sad_key_prefix+'/source-address/ip-address/ipv6-address/ipv6-address',
                            'spd_path': config_spd_key_prefix+'/source-address/ip-address/ipv6-address/ipv6-address',
                            'cmd': 'src'
                          },
                 'dst':   { 'sad_path': config_sad_key_prefix+'/destination-address/ip-address/ipv6-address/ipv6-address',
                            'spd_path': config_spd_key_prefix+'/destination-address/ip-address/ipv6-address/ipv6-address',
                            'cmd': 'dst'
                          },
                 'sec-proto': { 'sad_path': config_sad_key_prefix+'/security-protocol',
                            'spd_path': config_spd_key_prefix+'/security-protocol',
                            'cmd': 'proto'
                          },
                 'spi':   { 'sad_path': config_sad_key_prefix+'/spi',
                            'spd_path': config_spd_key_prefix+'/spi',
                            'cmd': 'spi'
                          }
               }

# Map for options of Security Association DB which includes IPSec mode
# ip xfrm state { add | update } [ mode MODE ] [sel SELECTOR] where SELECTOR := [ src ADDR[/PLEN] ] [ dst ADDR[/PLEN] ] [ dev DEV ] [UPSPEC ]
_sad_options_obj_map = {
                         'mode': { 'sad_path': config_sad_key_prefix+'/sa-mode',
                                   'spd_path': config_spd_key_prefix+'/sa-mode',
                                   'cmd': 'mode'
                                 }
                       }

# Map for Selector parameters of Security Policy DB
# ip xfrm policy { add | update } SELECTOR where SELECTOR := [ src ADDR[/PLEN] ] [ dst ADDR[/PLEN] ] [ dev DEV ] [UPSPEC ]
_selector_obj_map = {
                      'src': { 'spd_path': config_spd_key_prefix+'/source-ip-address',
                               'sad_path': config_sad_options_key_prefix+'/source-ip-address',
                               'cmd': 'src'
                             },
                      'dst': { 'spd_path': config_spd_key_prefix+'/destination-ip-address',
                               'sad_path': config_sad_options_key_prefix+'/destination-ip-address',
                               'cmd': 'dst'
                             },
                      'dev': { 'spd_path': config_spd_key_prefix+'/ifname',
                               'sad_path': config_sad_options_key_prefix+'/ifname',
                               'cmd': 'dev'
                             },
                      'upper-proto': { 'spd_path': config_spd_key_prefix+'/upper-protocol',
                                       'sad_path': config_sad_key_prefix+'/upper-protocol',
                                       'cmd': 'proto'
                               }
                    }


def _cmd_from_map(cmd, obj_map, key, data):
    # Build IP XFRM command from CPS Object map
    for xfrm_cmd in obj_map:
        if obj_map[xfrm_cmd][key] in data:
            if xfrm_cmd in ipsec_enum_map:
                val = ipsec_enum_map[xfrm_cmd][data[obj_map[xfrm_cmd][key]]]
            else:  val = str(data[obj_map[xfrm_cmd][key]])
            cmd.extend((obj_map[xfrm_cmd]['cmd'], val))
    return cmd


# Authentication and Encryption details for Security Association DB which includes key string path and key length
sad_algo_map = {
                    'auth': {
                            'hmac(sha1)':  {
                                            'sad_path': [ config_sad_key_prefix+'/ah/authentication-algorithm/hmac-sha1-96/hmac-sha1-96/key-str',
                                                          config_sad_key_prefix+'/esp/authentication/authentication-algorithm/hmac-sha1-96/hmac-sha1-96/key-str'],
                                            'key_len' : {'str': 20, 'hex_str': 40},
                                            'cmd'     : 'hmac(sha1)'

                                           },
                            'hmac(md5)': {
                                            'sad_path': [ config_sad_key_prefix+'/ah/authentication-algorithm/hmac-md5-96/hmac-md5-96/key-str',
                                                          config_sad_key_prefix+'/esp/authentication/authentication-algorithm/hmac-md5-96/hmac-md5-96/key-str'],
                                            'key_len' : {'str': 16, 'hex_str': 32},
                                            'cmd'     : 'hmac(md5)'
                                         },
                            'hmac(aes)': {
                                            'sad_path': [ config_sad_key_prefix+'/ah/authentication-algorithm/hmac-aes-xcbc/hmac-aes-xcbc/key-str',
                                                          config_sad_key_prefix+'/esp/authentication/authentication-algorithm/hmac-aes-xcbc/hmac-aes-xcbc/key-str'],
                                            'key_len' : {'str': 16, 'hex_str': 32},
                                            'cmd'     : 'hmac(aes)'
                                         }
                          },
                    'enc': {
                                'cbc(des3)': {
                                                'sad_path': [ config_sad_key_prefix+'/esp/encryption/encryption-algorithm/des3-cbc/des3-cbc/key-str'],
                                                'key_len' : {'str': 24, 'hex_str': 48},
                                                'cmd'     : 'cbc(des3_ede)'
                                            },
                                'cbc(des)': {
                                                'sad_path': [ config_sad_key_prefix+'/esp/encryption/encryption-algorithm/des-cbc/des-cbc/key-str'],
                                                'key_len' : {'str': 8, 'hex_str': 16},
                                                'cmd'     : 'cbc(des)'
                                            },
                                'cbc(aes-128)': {
                                                'sad_path': [ config_sad_key_prefix+'/esp/encryption/encryption-algorithm/aes-128-cbc/aes-128-cbc/key-str'],
                                                'key_len' : {'str': 16, 'hex_str': 32},
                                                'cmd'     : 'cbc(aes)'
                                               },
                                'cbc(aes-192)' : {
                                                'sad_path': [ config_sad_key_prefix+'/esp/encryption/encryption-algorithm/aes-192-cbc/aes-192-cbc/key-str'],
                                                'key_len' : {'str': 24, 'hex_str': 48},
                                                'cmd'     : 'cbc(aes)'
                                                },
                                'cbc(aes-256)' : {
                                                'sad_path': [ config_sad_key_prefix+'/esp/encryption/encryption-algorithm/aes-256-cbc/aes-256-cbc/key-str'],
                                                'key_len' : {'str': 32, 'hex_str': 64},
                                                'cmd'     : 'cbc(aes)'
                                                }
                           }
               }


def config_sad(change):
    """ Configure Security Association DB from CPS Object  """
    res = []
    cmd = [iplink_cmd, 'xfrm', 'state', cps_to_xfrm_op[change['operation']]]

    data = cps_convert_attr_data(change)

    _state_cmd_list = [_id_obj_map, _sad_options_obj_map]
    for obj_map in _state_cmd_list:
        cmd = _cmd_from_map(cmd, obj_map, 'sad_path', data)

    # Add SELECTOR options
    for elem in _selector_obj_map:
        if _selector_obj_map[elem]['sad_path'] in data:
            cmd.append('sel')
            cmd = _cmd_from_map(cmd, _selector_obj_map, 'sad_path', data)
            break

    for algo in sad_algo_map:
        algo_name = sad_algo_map[algo]
        for k in algo_name:
            for elem in algo_name[k]['sad_path']:
                if elem in data:
                    # Check for the input key str type (string or hex-string)
                    if algo_name[k]['key_len']['str'] == len( data[elem]):
                        val = data[elem]
                    elif algo_name[k]['key_len']['hex_str'] == len( data[elem]):
                        val = "0x"+data[elem]
                    else:
                        log_err("Invalid key length for attr %s" %(elem))
                        return False

                    cmd.extend((algo, algo_name[k]['cmd']))
                    cmd.append(val)

    # If Auth specified in esp, and no encryption then use null encryption
    if any('/esp/authentication' in string for string in data.keys()):
        if all('/esp/encryption' not in string for string in data.keys()):
            cmd.extend(("enc", "ecb(cipher_null)" ))
            cmd.append("")

    if run_command(cmd, res) == 0:
        return True

    log_err("Configure SAD failure")
    return False


# Map for Security Policy DB Parameters which includes direction
# ip xfrm policy { add | update } dir DIR
_spd_cmd_obj_map = { 'direction': {
                                'spd_path': config_spd_key_prefix+'/direction',
                                'cmd': 'dir'
                            }
                    }

# Map for Security Policy DB Options
# ip xfrm policy { add | update } [ priority PRIORITY ]
_spd_options_obj_map = {  'priority': {
                                        'spd_path': config_spd_key_prefix+'/priority',
                                        'cmd' : 'priority'
                                       }
                       }

# Map for Security Policy DB Template list
# ip xfrm policy { add | update } [ TMPL-LIST ] where TMPL := ID [ mode MODE ] [ level LEVEL ]
_spd_tmpl_list_obj_map = {'mode': {
                                    'spd_path': config_spd_key_prefix+'/sa-mode',
                                    'cmd': 'mode'
                                  },
                          'level': {
                                    'spd_path': config_spd_key_prefix+'/policy-level',
                                    'cmd': 'level'
                                   }
                         }


def config_spd(change):
    """ Configure Security Policy DB from CPS Object  """
    res = []
    cmd = [iplink_cmd, 'xfrm', 'policy', cps_to_xfrm_op[change['operation']]]

    data = cps_convert_attr_data(change)

    _policy_cmd_list = [_selector_obj_map, _spd_cmd_obj_map, _spd_options_obj_map]
    for obj_map in _policy_cmd_list:
        cmd = _cmd_from_map(cmd, obj_map, 'spd_path', data)


    # Add Template List to the ip xfrm command
    for tmpl in _id_obj_map:
        if _id_obj_map[tmpl]['spd_path'] in data:
            cmd.append('tmpl')
            break

    if 'tmpl' not in  cmd:
        for tmplate in _spd_tmpl_list_obj_map:
            if _spd_tmpl_list_obj_map[tmplate]['spd_path'] in data:
                cmd.append('tmpl')
                break

    if 'tmpl' in  cmd:
        _tmpl_cmd_list = [_id_obj_map, _spd_tmpl_list_obj_map]
        for obj_map in _tmpl_cmd_list:
            cmd = _cmd_from_map(cmd, obj_map, 'spd_path', data)

    if run_command(cmd, res) == 0:
        return True

    log_err("Configure SPD failure")
    return False


def ipsec_get_cb(methods, params):
    # GET functionality will be supported later
    return True

def ipsec_trans_cb(methods, params):
    """ Transaction callback """
    if _ipsec_keys[config_sad_key_prefix] == params['change']['key']:
        config_sad(params['change'])
    elif _ipsec_keys[config_spd_key_prefix] == params['change']['key']:
        config_spd(params['change'])
    else:
        log_err("Unsupported object")
        return False

    return True

def add_attr_type():
    # Explicitly set attribute type as string for all SAD Authentication and Encryption attrs
    cps_utils.add_attr_type("eipsec/ipsec/sad/sad-entries/ah/authentication-algorithm/hmac-sha1-96/hmac-sha1-96/key-str", "string")
    cps_utils.add_attr_type("eipsec/ipsec/sad/sad-entries/ah/authentication-algorithm/hmac-md5-96/hmac-md5-96/key-str", "string")
    cps_utils.add_attr_type("eipsec/ipsec/sad/sad-entries/ah/authentication-algorithm/hmac-aes-xcbc/hmac-aes-xcbc/key-str", "string")

    cps_utils.add_attr_type("eipsec/ipsec/sad/sad-entries/esp/authentication/authentication-algorithm/hmac-sha1-96/hmac-sha1-96/key-str", "string")
    cps_utils.add_attr_type("eipsec/ipsec/sad/sad-entries/esp/authentication/authentication-algorithm/hmac-md5-96/hmac-md5-96/key-str", "string")
    cps_utils.add_attr_type("eipsec/ipsec/sad/sad-entries/esp/authentication/authentication-algorithm/hmac-aes-xcbc/hmac-aes-xcbc/key-str", "string")


    cps_utils.add_attr_type("eipsec/ipsec/sad/sad-entries/esp/encryption/encryption-algorithm/des-cbc/des-cbc/key-str", "string")
    cps_utils.add_attr_type("eipsec/ipsec/sad/sad-entries/esp/encryption/encryption-algorithm/des3-cbc/des3-cbc/key-str", "string")
    cps_utils.add_attr_type("eipsec/ipsec/sad/sad-entries/esp/encryption/encryption-algorithm/aes-128-cbc/aes-128-cbc/key-str", "string")
    cps_utils.add_attr_type("eipsec/ipsec/sad/sad-entries/esp/encryption/encryption-algorithm/aes-192-cbc/aes-192-cbc/key-str", "string")
    cps_utils.add_attr_type("eipsec/ipsec/sad/sad-entries/esp/encryption/encryption-algorithm/aes-256-cbc/aes-256-cbc/key-str", "string")


    cps_utils.add_attr_type("spd/eipsec/ipsec/spd/spd-entries/source-ip-address", "string")
    cps_utils.add_attr_type("spd/eipsec/ipsec/spd/spd-entries/destination-ip-address", "string")
    cps_utils.add_attr_type("ipsec-sad/eipsec/ipsec/sad/sad-entries/source-ip-address", "string")
    cps_utils.add_attr_type("ipsec-sad/eipsec/ipsec/sad/sad-entries/destination-ip-address", "string")

    return True

def obj_reg():
     # IPSec Object Registration
    ipsec_handle = cps.obj_init()
    reg = {'get': ipsec_get_cb, 'transaction': ipsec_trans_cb}
    for i in _ipsec_keys.keys():
        if i.find('eipsec') == -1:
            continue
        cps.obj_register(ipsec_handle, _ipsec_keys[i], reg)


