import dn_base_vrf_svcs_config as cfg

import subprocess
import time

orig_run_command = cfg.run_command

def local_run_command(cmd, resp, log_fail = True):
    global orig_run_command
    if cmd[0] == '/sbin/iptables' or cmd[0] == '/sbin/ip6tables':
      cmd = ['/sbin/ip', 'netns', 'exec', 'test_default'] + cmd
    print 'RUN_CMD: %s' % ' '.join(cmd)
    ret_val = orig_run_command(cmd, resp)
    if log_fail and ret_val != 0:
      print '*** Command execution failed ***'
      print ' '.join(cmd)
      for r in resp:
        print r
    return ret_val

cfg.run_command = local_run_command

def exec_shell(cmd):
      proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
      (out, err) = proc.communicate()
      return out

""" configure the ip address for interface in default vrf
"""
def default_ip_address_pre_req_cfg(clear, intf_ip):
    mode = 'OPX'
    ret = exec_shell('os10-show-version | grep \"OS_NAME.*Enterprise\"')
    if ret:
      mode = 'DoD'
    if mode is 'DoD':
      if clear:
        cmd_list =  ['configure terminal',
                     'interface ethernet 1/1/10',
                     'no ip address',
                     'switchport mode access',
                     'exit',
                     'end']
      else:
        cmd_list =  ['configure terminal',
                     'interface ethernet 1/1/10',
                     'no switchport',
                     'ip address '+intf_ip,
                     'exit',
                     'end']
  
      cfg_file = open('/tmp/test_pre_req', 'w')
      for item in cmd_list:
        print>>cfg_file, item
      cfg_file.close()
      exec_shell('sudo -u admin clish --b /tmp/test_pre_req')
    else:
      print 'UT for BASE is not supported yet.'


""" configure the interface and vrf cli in mgmt / ethernet port for UT AR-22685
"""
def ip_address_pre_req_cfg(clear = False, mgmt_ip = '10.11.70.22/8',vrf='management'):
#config test pre requisite - manangement vrf
    mode = 'OPX'
    ret = exec_shell('os10-show-version | grep \"OS_NAME.*Enterprise\"')
    if ret:
      mode = 'DoD'
    if mode is 'DoD':
#configure the test pre requisites via CLI
      if clear:
        if vrf == 'management':
          cmd_list =  ['configure terminal',
                       'interface mgmt1/1/1',
                       'no ip address',
                       'exit',
                       'ip vrf ' + vrf,
                       'no interface management',
                       'exit',
                       'no ip vrf '+ vrf,
                       'interface mgmt1/1/1',
                       'ip address ' + mgmt_ip,
                       'end']
        else:
          cmd_list =  ['configure terminal',
                       'interface ethernet 1/1/1',
                       'no ip address',
                       'no ip vrf forwarding ',
                       'switchport mode access',
                       'exit',
                       'no ip telnet server vrf '+ vrf,
                       'yes',
                       'no ip vrf '+vrf,
                       'end']
      else:
        if vrf== 'management':
          cmd_list =  ['configure terminal',
                       'interface mgmt1/1/1',
                       'no ip address',
                       'no ipv6 address',
                       'exit',
                       'ip vrf '+vrf,
                       'interface management',
                       'exit',
                       'interface mgmt1/1/1',
                       'ip address ' + mgmt_ip,
                       'end']
        else:
          cmd_list =  ['configure terminal',
                       'ip vrf '+vrf,
                       'exit',
                       'interface ethernet 1/1/1',
                       'no switchport',
                       'ip vrf forwarding '+vrf,
                       'ip address '+mgmt_ip,
                       'exit',
                       'end']

      cfg_file = open('/tmp/test_pre_req', 'w')
      for item in cmd_list:
        print>>cfg_file, item
      cfg_file.close()
      exec_shell('sudo -u admin clish --b /tmp/test_pre_req')
    else:
      print 'UT for BASE is not supported yet.'

""" Configure ip service on non default vrf
"""
def ip_service_pre_req_cfg(vrf,ip_serv=0):
    mode = 'OPX'
    ret = exec_shell('os10-show-version | grep \"OS_NAME.*Enterprise\"')
    if ret:
      mode = 'DoD'

    if ip_serv:
      cmd_list = ['configure terminal',
                  'ip vrf '+vrf,
                  'ip telnet server vrf '+ vrf,
                  'yes']
    else :
      cmd_list = ['configure terminal',
                  'no ip telnet server vrf '+ vrf,
                  'yes',
                  'interface ethernet 1/1/1',
                  'no ip address',
                  'no ip vrf forwarding ',
                  'switchport mode access',
                  'exit',
                  'no ip vrf ' + vrf,]
    if mode is 'DoD':
      cfg_file = open('/tmp/test_pre_req', 'w')
      for item in cmd_list:
        print>>cfg_file, item
      cfg_file.close()
      exec_shell('sudo -u admin clish --b /tmp/test_pre_req')
    else:
      print 'UT for BASE is not supported yet.'

""" dump the iptable for prerouting chain and verify it has source ip or not
"""
def verify_ip_table_has_rule(vrf_name,ip_addr):
    success = 0
    resp = []
    if vrf_name != 'default':
      if orig_run_command(['/sbin/ip', 'netns','exec', vrf_name,'iptables','-t','nat','-L','PREROUTING'], resp) == 0:
        print resp
        for line in resp:
          print line
          if 'VRF' in line:
            column = line.split('anywhere')
            dest_ip = column[1].split('             ')
            print dest_ip
            if dest_ip[1] == ip_addr:
              print 'Test is successful dest_ip %s' % dest_ip
              success = 1
              return success
            else:
              print 'skip %s' % line
              success = 0
    else:
      if orig_run_command(['iptables','-t','nat','-L','PREROUTING'], resp) == 0:
        print resp
        for line in resp:
          print line
          if ip_addr in resp:
            success=0
            return success
          else:
            success =1

    return success

""" dump the ip6table for prerouting chain and verify it has source ip or not
"""
def verify_ip6_table_has_rule(vrf_name,ip_addr):
    success = 0
    resp = []
    if vrf_name != 'default':
      if orig_run_command(['/sbin/ip', 'netns','exec', vrf_name,'ip6tables','-t','nat','-L','PREROUTING'], resp) == 0:
        print resp
        for line in resp:
          print line
          if 'VRF' in line:
            column = line.split('anywhere')
            dest_ip = column[1].split('             ')
            print dest_ip
            if dest_ip[1] == ip_addr:
              print 'Test is successful dest_ip %s' % dest_ip
              success = 1
              return success
            else:
              print 'skip %s' % line
              success = 0
    else:
      if orig_run_command(['ip6tables','-t','nat','-L','PREROUTING'], resp) == 0:
        print resp
        for line in resp:
          print line
          if ip_addr in resp:
            success=0
            return success
          else:
            success =1

    return success

""" configure the interface and vrf cli in mgmt / ethernet port for UT AR-22685
"""
def ip_address_multiple_interface_pre_req_cfg(clear = False, mgmt_ip = '10.11.70.22/8',vrf='management'):
#config test pre requisite - manangement vrf
    mode = 'OPX'
    ret = exec_shell('os10-show-version | grep \"OS_NAME.*Enterprise\"')
    if ret:
      mode = 'DoD'
    if mode is 'DoD':
#configure the test pre requisites via CLI
      if clear:
        if vrf == 'management':
          cmd_list =  ['configure terminal',
                       'interface mgmt1/1/1',
                       'no ip address',
                       'exit',
                       'ip vrf ' + vrf,
                       'no interface management',
                       'exit',
                       'no ip vrf '+ vrf,
                       'interface mgmt1/1/1',
                       'ip address ' + mgmt_ip,
                       'end']
        else:
          cmd_list =  ['configure terminal',
                       'interface range ethernet 1/1/1-1/1/3',
                       'no ip address',
                       'no ip vrf forwarding ',
                       'switchport mode access',
                       'exit',
                       'no ip telnet server vrf '+ vrf,
                       'yes',
                       'no ip vrf '+vrf,
                       'end']
      else:
        if vrf== 'management':
          cmd_list =  ['configure terminal',
                       'interface mgmt1/1/1',
                       'no ip address',
                       'no ipv6 address',
                       'exit',
                       'ip vrf '+vrf,
                       'interface management',
                       'exit',
                       'interface mgmt1/1/1',
                       'ip address ' + mgmt_ip,
                       'end']
        else:
          cmd_list =  ['configure terminal',
                       'ip vrf '+vrf,
                       'exit',
                       'interface range ethernet 1/1/1-1/1/3',
                       'no switchport',
                       'ip vrf forwarding '+vrf,
                       'exit',
                       'interface ethernet 1/1/1',
                       'ip address 1.1.1.1/24',
                       'interface ethernet 1/1/2',
                       'ip address 2.1.1.1/24',
                       'interface ethernet 1/1/3',
                       'ip address 3.1.1.1/24',
                       'exit',
                       'ip telnet server vrf '+ vrf,
                       'yes',
                       'end']
      cfg_file = open('/tmp/test_pre_req', 'w')
      for item in cmd_list:
        print>>cfg_file, item
      cfg_file.close()
      exec_shell('sudo -u admin clish --b /tmp/test_pre_req')
    else:
      print 'UT for BASE is not supported yet.'

def ip_address_multiple_interface_remove_ip_cfg():
    mode = 'OPX'
    ret = exec_shell('os10-show-version | grep \"OS_NAME.*Enterprise\"')
    if ret:
      mode = 'DoD'
    if mode is 'DoD':
      cmd_list =  ['configure terminal',
                   'interface range ethernet 1/1/1-1/1/3',
                   'no ip address',
                   'end']
      cfg_file = open('/tmp/test_pre_req', 'w')
      for item in cmd_list:
        print>>cfg_file, item
      cfg_file.close()
      exec_shell('sudo -u admin clish --b /tmp/test_pre_req')
    else:
      print 'UT for BASE is not supported yet.'

""" Validate the iptable rule for mangement and non default vrf
"""
def test_ip_table_rule_for_non_default_vrf():
    resp = []

    print '$$$$$$$$$$$$$$$$ TEST-1. IP service for management vrf  $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
    print '#########################################################################################'
    print '################# Make sure no mangement vrf is available in the Linux shell ############'
    print '#########################################################################################'
    if orig_run_command(['/sbin/ip', 'netns','exec', 'management','iptables','-t','nat','-L','PREROUTING'], resp) != 0:
      print resp
      if 'Cannot' in resp[0]:
        print '@@@@@@@@@@@@@@ : Unit test is PASSED. no vrf created yet @@@@@@@@@@@@@@'
      else:
        print '@@@@@@@@@@@@@@ : Unit test is FAILED. vrf is configured @@@@@@@@@@@@@@'
    
    print '#########################################################################################'
    print '####Make sure mangement vrf is available in the Linux shell and src ip configured#######'
    print '#########################################################################################'
    ip_address_pre_req_cfg(False,'10.11.8.100/16','management')
    time.sleep(20)
    success = verify_ip_table_has_rule('management','10.11.8.100')
    if success ==1 :
      print '@@@@@@@@@@@@@@ Unit test is PASSED. Iptable rules are avaiable for MGMT VRF @@@@@@@@@@@@@@'
    else:
      print '@@@@@@@@@@@@@@ Unit test is FAILED. Iptable rules are not avaiable for MGMT VRF @@@@@@@@@@@@@@'

    success = verify_ip6_table_has_rule('management','fe80::/10')
    if success ==1 :
      print '@@@@@@@@@@@@@@ Unit test is PASSED. Ip6table rules are avaiable for MGMT VRF fe80::/10 @@@@@@@@@@@@@@'
    else:
      print '@@@@@@@@@@@@@@ Unit test is FAILED. Iptable rules are not avaiable for MGMT VRF fe80::/10 @@@@@@@@@@@@@@'

    ip_address_pre_req_cfg(True,'10.11.8.100/16','management')
    time.sleep(20)

#Make sure no mangement vrf is available in the Linux shell
    if orig_run_command(['/sbin/ip', 'netns','exec', 'management','iptables','-t','nat','-L','PREROUTING'], resp) != 0:
      print resp
      if 'Cannot' in resp[0]:
        print '@@@@@@@@@@@@@@ Unit test is PASSED. vrf and iptable rules deleted @@@@@@@@@@@@@@'
      else:
        print '@@@@@@@@@@@@@@ Unit test is FAILED. vrf and iptable rules are not deleted @@@@@@@@@@@@@@'

#Make sure no test_vrf is available in the Linux shell

    print '$$$$$$$$$$$$$$$$ TEST-2. Validate ip table rule without ip service config $$$$$$$$$$$$$$$'
    print '#########################################################################################'
    print '#######################Make sure no test_vrf is available in the Linux shell#############'
    print '#########################################################################################'

    if orig_run_command(['/sbin/ip', 'netns','exec', 'test_vrf','iptables','-t','nat','-L','PREROUTING'], resp) != 0:
      print resp
      if 'Cannot' in resp[0]:
        print '@@@@@@@@@@@@@@ Unit test is PASSED. no vrf created yet @@@@@@@@@@@@@@'
      else:
        print '@@@@@@@@@@@@@@ Unit test is FAILED. vrf is configured @@@@@@@@@@@@@@'

    print '#########################################################################################'
    print '####Make sure test_vrf  is available but it shouldnt have ip table rule #################'
    print '#########################################################################################'

    ip_address_pre_req_cfg(False,'25.11.8.70/16','test_vrf')
    time.sleep(20)

    success = verify_ip_table_has_rule('test_vrf','25.11.8.70')
    if success ==0:
      print '@@@@@@@@@@@@@@ Unit test is PASSED. No ip table rule for 25.11.8.70 @@@@@@@@@@@@@@'
    else:
      print '@@@@@@@@@@@@@@ Unit test is FAILED. ip table has a rule with ip 25.11.8.70 @@@@@@@@@@@@@@'
    ip_service_pre_req_cfg('test_vrf',1)
    time.sleep(20)


    print '$$$$$$$$$$$$$$$$ TEST-3. configure ip service after ip address config $$$$$$$$$$$$$$$'
    print '#########################################################################################'
    print '############## Make sure test_vrf vrf is available and it  has ip table rule #####'
    print '#########################################################################################'

#configured ip address first then configure ip service on that vrf. 
    success = verify_ip_table_has_rule('test_vrf','25.11.8.70')
    if success ==1:
      print '@@@@@@@@@@@@@@ Unit test is PASSED. ip table has a rule with ip 25.11.8.70 @@@@@@@@@@@@@@' 
    else:
      print '@@@@@@@@@@@@@@ Unit test is FAILED. No ip table rule for 25.11.8.70 @@@@@@@@@@@@@@'
    ip_service_pre_req_cfg('test_vrf',0)
    time.sleep(10)
    ip_address_pre_req_cfg(True,'25.11.8.70/16','test_vrf')
    time.sleep(20)

   
#Make sure no test_vrf is available in the Linux shell

    if orig_run_command(['/sbin/ip', 'netns','exec', 'test_vrf','iptables','-t','nat','-L','PREROUTING'], resp) != 0:
      print resp
      if 'Cannot' in resp[0]:
        print '@@@@@@@@@@@@@@ Unit test is PASSED.  vrf test_vrf and iptable rule is deleted from linux shell @@@@@@@@@@@@@@'
      else:
        print '@@@@@@@@@@@@@@ Unit test is FAILED. vrf test_vrf is still there in linux shell @@@@@@@@@@@@@@'


    print '$$$$$$$$$$$$$$$$ TEST-4. configure ip address after enable ip service $$$$$$$$$$$$$$$'
    print '#########################################################################################'
    print '############## Make sure test_vrf vrf is available and it  has ip table rule #####'
    print '#########################################################################################'

    ip_service_pre_req_cfg('test_vrf',1)
    time.sleep(10)
    ip_address_pre_req_cfg(False,'25.11.8.70/16','test_vrf')
    time.sleep(20)

#configure ip service first then configure ip address. 
    success = verify_ip_table_has_rule('test_vrf','25.11.8.70')
    if success ==1:
      print '@@@@@@@@@@@@@@ Unit test is PASSED. Ip table rule is available for 25.11.8.70 @@@@@@@@@@@@@@'
    else:
      print '@@@@@@@@@@@@@@ Unit test is FAILED.ip table rule is not available for 25.11.8.7 @@@@@@@@@@@@@@'

    ip_address_pre_req_cfg(True,'25.11.8.70/16','test_vrf')
    time.sleep(20)

#Make sure no test_vrf is available in the Linux shell
    if orig_run_command(['/sbin/ip', 'netns','exec', 'test_vrf','iptables','-t','nat','-L','PREROUTING'], resp) != 0:
      print resp
      if 'Cannot' in resp[0]:
        print '@@@@@@@@@@@@@@ Unit test is PASSED. vrf test_vrf is deleted from linux shell @@@@@@@@@@@@@@'
      else:
        print '@@@@@@@@@@@@@@ Unit test is FAILED. vrf test_vrf is not deleted from linux shell @@@@@@@@@@@@@@'

    print '$$$$$$$$$$$$$$$$ TEST-5. configure ip address in default vrf $$$$$$$$$$$$$$$'
    print '#########################################################################################'
    print '############## Make sure no rule is added for 100.11.55.20 in default vrf  #####'
    print '#########################################################################################'
    default_ip_address_pre_req_cfg(False,'100.11.55.20/16')
    success = verify_ip_table_has_rule('default','100.11.55.20')
    if success ==1:
      print '@@@@@@@@@@@@@@ Unit test is PASSED. Ip table rule is not available for 100.11.55.20 @@@@@@@@@@@@@@'
    else:
      print '@@@@@@@@@@@@@@ Unit test is FAILED.ip table rule is  available for 100.11.55.20 @@@@@@@@@@@@@@'

    default_ip_address_pre_req_cfg(True,'100.11.55.20/16')
    time.sleep(10)

    print '$$$$$$$$$$$$$$$$ TEST-6. configure ip address in multiple interfaces associated in red vrf  $$$$$$$$$$$$$$$'
    print '#########################################################################################'
    print '############## Make sure rule is added for 1.1.1.1/2.1.1.1/3.1.1.1  in red vrf  #####'
    print '#########################################################################################'

    ip_address_multiple_interface_pre_req_cfg(False,'100.1.1.1/16','red')
    time.sleep(20)
      
    success = verify_ip_table_has_rule('red','1.1.1.1')
    if success ==1 :
      print '@@@@@@@@@@@@@@ Unit test is PASSED. Iptable rules are avaiable for red VRF 1.1.1.1 @@@@@@@@@@@@@@'
    else:
      print '@@@@@@@@@@@@@@ Unit test is FAILED. Iptable rules are not avaiable for red VRF 1.1.1.1 @@@@@@@@@@@@@@'

    time.sleep(20)

    success = verify_ip_table_has_rule('red','2.1.1.1')
    if success ==1 :
      print '@@@@@@@@@@@@@@ Unit test is PASSED. Iptable rules are avaiable for red VRF 2.1.1.1 @@@@@@@@@@@@@@'
    else:
      print '@@@@@@@@@@@@@@ Unit test is FAILED. Iptable rules are not avaiable for red VRF 2.1.1.1 @@@@@@@@@@@@@@'

    time.sleep(20)

    success = verify_ip_table_has_rule('red','3.1.1.1')
    if success ==1 :
      print '@@@@@@@@@@@@@@ Unit test is PASSED. Iptable rules are avaiable for red VRF 3.1.1.1 @@@@@@@@@@@@@@'
    else:
      print '@@@@@@@@@@@@@@ Unit test is FAILED. Iptable rules are not avaiable for red VRF 3.1.1.1 @@@@@@@@@@@@@@'

    success = verify_ip6_table_has_rule('red','fe80::/10')
    if success ==1 :
      print '@@@@@@@@@@@@@@ Unit test is PASSED. Ip6table rules are avaiable for red VRF fe80::/10 @@@@@@@@@@@@@@'
    else:
      print '@@@@@@@@@@@@@@ Unit test is FAILED. Iptable rules are not avaiable for red VRF fe80::/10 @@@@@@@@@@@@@@'

    print '$$$$$$$$$$$$$$$$ TEST-7. Remove ip address in multiple interfaces associated in red vrf  $$$$$$$$$$$$$$$'
    print '#########################################################################################'
    print '############## Make sure no rule is available  for 1.1.1.1/2.1.1.1/3.1.1.1  in red vrf  #####'
    print '#########################################################################################'


    ip_address_multiple_interface_remove_ip_cfg()

    success = verify_ip_table_has_rule('red','1.1.1.1')
    if success == 0 :
      print '@@@@@@@@@@@@@@ Unit test is PASSED. Iptable rules are not avaiable for red VRF 1.1.1.1 @@@@@@@@@@@@@@'
    else:
      print '@@@@@@@@@@@@@@ Unit test is FAILED. Iptable rules are avaiable for red VRF 1.1.1.1 @@@@@@@@@@@@@@'

    time.sleep(10)
    success = verify_ip_table_has_rule('red','2.1.1.1')
    if success == 0 :
      print '@@@@@@@@@@@@@@ Unit test is PASSED. Iptable rules are not avaiable for red VRF 2.1.1.1 @@@@@@@@@@@@@@'
    else:
      print '@@@@@@@@@@@@@@ Unit test is FAILED. Iptable rules are avaiable for red VRF 2.1.1.1 @@@@@@@@@@@@@@'

    time.sleep(10)

    success = verify_ip_table_has_rule('red','3.1.1.1')
    if success == 0 :
      print '@@@@@@@@@@@@@@ Unit test is PASSED. Iptable rules are not avaiable for red VRF 3.1.1.1 @@@@@@@@@@@@@@'
    else:
      print '@@@@@@@@@@@@@@ Unit test is FAILED. Iptable rules are avaiable for red VRF 3.1.1.1 @@@@@@@@@@@@@@'
    ip_address_multiple_interface_pre_req_cfg(True,'100.1.1.1/16','red')
    time.sleep(10)

if __name__ == '__main__':
  test_ip_table_rule_for_non_default_vrf()
