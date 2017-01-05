import sys
import os

import pytest
THIS_DIR = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(os.path.abspath(THIS_DIR), "../../clijockey/"))
sys.path.insert(0, os.path.abspath(THIS_DIR))

from clijockey.traits import CIPv4AddressStr, CIPv4PrefixStr
from clijockey.traits import CUnicodeRegexMatch
from clijockey.traits import CUnicode
from clijockey.traits import TraitTable
from clijockey.lib import CLIMachine
from clijockey.util import Account

# To be used later
#from fixtures.devices.cisco_ios import TELNET_FAIL01
#from fixtures.session import Chain

class TraitTable01(TraitTable):
    """TraitTable with a _map attribute"""
    attr_unicode = CUnicode()
    attr_unicode_regex_match = CUnicodeRegexMatch('(foo|FOO)')
    attr_ipv4prefix_str = CIPv4PrefixStr()
    attr_ipv4address_str = CIPv4AddressStr()
    _map = ('attr_unicode', 'attr_unicode_regex_match', 'attr_ipv4prefix_str',
        'attr_ipv4address_str')

@pytest.yield_fixture(scope='function')
def cisco_ios_telnet_fail01(request):
    yield CLIMachine(test='./cmd',
        credentials=(Account('cisco', 'cisco'), Account('cisco', 'cisco123'),),
        log_screen=True)

@pytest.yield_fixture(scope='function')
def trait_table01(request):
    yield TraitTable01
