import sys
import os
THIS_DIR = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(os.path.abspath(THIS_DIR), '../clijockey'))

from clijockey.error import TraitTableInvalidInput
from clijockey.lib import CLIMachine
from clijockey.util import Account

import pytest

@pytest.mark.skipif(True, reason = 'Not using cisco_ios_telnet_fail01 for now')
def test_this(cisco_ios_telnet_fail01):
    conn = cisco_ios_telnet_fail01
    assert conn

def test_trait_table_list01a(trait_table01):
    """Test a simple TraitTable with a list input, nothing fancy here"""
    fixture = trait_table01
    test_input = [u'1', u'foo', u'8.8.8.8/32', u'4.2.2.2']
    uut = fixture(test_input)
    assert uut.attr_unicode == unicode("1")
    assert uut.attr_unicode_regex_match == unicode("foo")
    assert uut.attr_ipv4prefix_str == unicode("8.8.8.8/32")
    assert uut.attr_ipv4address_str == unicode("4.2.2.2")

def test_trait_table_list01b(trait_table01):
    """Test a simple TraitTable with a list input, nothing fancy here"""
    fixture = trait_table01
    test_input = [u'1', u'foo', u'8.8.8.8/32', u'4.2.2.2']
    uut = fixture(input=test_input)
    assert uut.attr_unicode == unicode("1")
    assert uut.attr_unicode_regex_match == unicode("foo")
    assert uut.attr_ipv4prefix_str == unicode("8.8.8.8/32")
    assert uut.attr_ipv4address_str == unicode("4.2.2.2")

def test_trait_table_list02(trait_table01):
    """Test a simple TraitTable with a list input, missing the last input"""
    fixture = trait_table01
    test_input = [u'1', u'foo', u'8.8.8.8/32', ]  # <---- missing last value
    with pytest.raises(TraitTableInvalidInput):
        uut = fixture(test_input)

def test_trait_table_list03(trait_table01):
    """Test a simple TraitTable with a list input, too many inputs"""
    fixture = trait_table01
    test_input = [u'1', u'foo', u'8.8.8.8/32', u'4.2.2.2', u'too-much-here']
    with pytest.raises(TraitTableInvalidInput):
        uut = fixture(test_input)

def test_trait_table_dict01(trait_table01):
    """Test a simple TraitTable with a dict input, nothing fancy here"""
    fixture = trait_table01
    test_input = {
        'attr_unicode': u'1',
        'attr_unicode_regex_match': u'foo',
        'attr_ipv4prefix_str': u'8.8.8.8/32',
        'attr_ipv4address_str': u'4.2.2.2',
    }
    uut = fixture(test_input)
    assert uut.attr_unicode == unicode("1")
    assert uut.attr_unicode_regex_match == unicode("foo")
    assert uut.attr_ipv4prefix_str == unicode("8.8.8.8/32")
    assert uut.attr_ipv4address_str == unicode("4.2.2.2")

def test_trait_table_dict02(trait_table01):
    """Test a simple TraitTable with a dict input, one attribute missing"""
    fixture = trait_table01
    test_input = {
        #'attr_unicode': u'1',  <---- intentionally commented out
        'attr_unicode_regex_match': u'foo',
        'attr_ipv4prefix_str': u'8.8.8.8/32',
        'attr_ipv4address_str': u'4.2.2.2',
    }
    uut = fixture(test_input)
    assert uut.attr_unicode == unicode("")  # <------ default value
    assert uut.attr_unicode_regex_match == unicode("foo")
    assert uut.attr_ipv4prefix_str == unicode("8.8.8.8/32")
    assert uut.attr_ipv4address_str == unicode("4.2.2.2")
