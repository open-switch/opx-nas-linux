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
