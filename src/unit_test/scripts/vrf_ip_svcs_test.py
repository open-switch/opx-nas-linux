#
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
#

from nas_incoming_svcs_ut import test_pre_req_cfg
from nas_incoming_svcs_ut import run_test_incoming_svcs
from nas_outgoing_svcs_ut import run_test_outgoing_svcs
import time

def test_incoming_svcs():
    print 'Running test pre-configuration'
    test_pre_req_cfg()
    time.sleep(20)
    print '------------------------------------------------'
    print ' Running all test cases of incoming IP services'
    print '------------------------------------------------'
    assert run_test_incoming_svcs()
    print '------------------------------------------------'
    print ' Running all test cases of outgoing IP services'
    print '------------------------------------------------'
    assert run_test_outgoing_svcs()
    print 'Test cases running done, cleanup pre-configuration'
    test_pre_req_cfg(True)
    time.sleep(20)
