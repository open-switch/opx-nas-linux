from nas_incoming_svcs_ut import test_pre_req_cfg
from nas_incoming_svcs_ut import run_test_incoming_svcs

import pytest
import time

def test_incoming_svcs():
    print 'Running test pre-configuration'
    test_pre_req_cfg()
    time.sleep(20)
    print 'Running all test cases'
    assert run_test_incoming_svcs()
    print 'Test cases running done, cleanup pre-configuration'
    test_pre_req_cfg(True)
    time.sleep(20)
