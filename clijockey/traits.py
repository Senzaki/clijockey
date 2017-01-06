import sys
import re

from error import InvalidMacError, InvalidIPv4AddressError, InvalidVlanError
from error import InvalidUnicodeRegex
from error import TraitTableInvalidInput

from traitlets import CUnicode, CInt, CFloat, CLong, CBytes, CBool
from traitlets import Unicode, Int, Float, Long, Bytes, Bool
from traitlets import CaselessStrEnum, Enum, UseEnum
from traitlets import CRegExp
from traitlets import HasTraits, Union, TraitType, TraitError
from traitlets import validate, default
from traitlets import Dict, Tuple, Set, List

from netaddr import EUI, mac_cisco, mac_unix_expanded
import netaddr

import arrow

#
#   "David Michael Pennington" <mike@pennington.net>
#   Copyright 2016-2017
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

## TraitTable is useful for parsing from TextFSM or TOML logs
class TraitTable(HasTraits):
    _map = Tuple()
    _dict = Dict()

    def __init__(self, *args, **kwargs):
        """TraitTable(input, _map=())"""
        super(TraitTable, self).__init__()

        input_list = False
        values = kwargs.get('input', None) or args[0]
        assert (len(args) <= 2)   # We can't accept more than two args
        if len(args)==2:
            tmp_map = args[1]
        else:
            tmp_map = kwargs.get('_map', None) or getattr(kwargs, '_map', ())

        if len(args)==0 and getattr(kwargs, '_map', None) and getattr(kwargs, 'values', None):
            raise RuntimeError, "Hit this if-clause: '{0}'".format(kwargs)
            # Inputs must be lists or tuples, submitted with values kwarg...
            tmp_map = kwargs('_map')
            values = kwargs('values')
            assert getattr(tmp_map, 'index')  # is it a list instance?
            assert getattr(values, 'index')   # is it a list instance?

            input_list = True

        elif isinstance(values, dict):
            # Input must be a dict...
            tmp_map = tuple(args[0].keys())
            values = [args[0][ii] for ii in tmp_map] # Remap values as list

            tmp_dict = args[0]

        elif isinstance(values, list) or isinstance(values, tuple):
            # Input must be a list or tuple...
            try:
                assert len(self._map)==len(values)
            except AssertionError:
                raise TraitTableInvalidInput("Length of inputs must be equal to the _map attribute")
            tmp_map = self._map
            #values = args[0]  <--- bug during simplification

            input_list = True

        elif len(args)==2:
            # Inputs must be lists or tuples
            ## TODO Add unit test to ensure this isn't needed...
            assert getattr(args[0], 'index')
            assert getattr(args[1], 'index')
            values = args[0]
            tmp_map = args[1]

            input_list = True

        else:
            raise ValueError('values: "{0}"'.format(values))

        if input_list:
            tmp_dict = dict()
            for attr_name, value in zip(tmp_map, values):
                setattr(self, attr_name, value)
                tmp_dict[attr_name] = getattr(self, attr_name)
        else:
            for attr_name, value in tmp_dict.items():
                setattr(self, attr_name, value)
                tmp_dict[attr_name] = getattr(self, attr_name)

            #kwargs.pop('_map', None)
            #kwargs.pop('values', None)

        self._map = tmp_map
        self._dict = tmp_dict

    # http://stackoverflow.com/a/35282286
    def __iter__(self):
        for attr_name, val in self._dict.items():
            yield attr_name, val

class CUnicodeRegex(TraitType): 
    """Return a unicode string which conforms to a regular expression"""
    default_value = u""

    def __init__(self, regex):
        super(CUnicodeRegex, self).__init__()
        assert isinstance(regex, str) or isinstance(regex, unicode)
        self.regex = regex
        self.regex_compiled = re.compile(regex)

    def validate(self, obj, value):
        try:
            assert isinstance(value, str) or isinstance(value, unicode)
            if value=="":
                return value
            assert self.regex_compiled.search(value) or (value=="")
            return unicode(value)
        except AssertionError:
            raise InvalidUnicodeRegex('"{0}" does not match the regex: "{1}"'.format(
                str(value), self.regex))

class CIPv4AddressStr(TraitType): 
    default_value = "127.0.0.1"

    def validate(self, obj, value):
        try:
            assert isinstance(value, str) or isinstance(value, unicode)
            addr_digits = [int(digit) for digit in value.split('.')]
            assert len(addr_digits)==4
            for digit in addr_digits:
                assert 0 <= digit <= 255
            return unicode(value)
        except AssertionError:
            raise InvalidIPv4AddressError('Cannot parse "{0}" into a valid IPv4 address'.format(
                str(value)))

class CIPv4PrefixStr(TraitType): 
    default_value = "127.0.0.1/8"

    def validate(self, obj, value):
        try:
            assert isinstance(value, str) or isinstance(value, unicode)
            str_parts = value.split('/')
            assert len(str_parts)==2
            prefixlength = int(str_parts[1])
            assert 0 <= prefixlength <= 32
            addr_str = str_parts[0]
            addr_digits = [int(digit) for digit in addr_str.split('.')]
            assert len(addr_digits)==4
            for digit in addr_digits:
                assert 0 <= digit <= 255
            return unicode(value)
        except AssertionError:
            raise InvalidIPv4AddressError('Cannot parse "{0}" into a valid IPv4 address and prefix'.format(
                str(value)))

class CMacAddressCisco(TraitType):
    """Return a netaddr.EUI Mac Address object cast as a Cisco IOS Mac"""
    default_value = EUI("0000.0000.0000")

    def validate(self, obj, value):
        try:
            value = netaddr.EUI(value)
            value.dialect = mac_cisco
            return value
        except netaddr.core.AddrFormatError:
            raise InvalidMacError('Cannot parse "{0}" into a valid mac address'.format(
                str(value)))

class CMacAddressCiscoStr(TraitType):
    """Return a unicode Mac Address string formatted as a Cisco IOS Mac"""
    default_value = EUI("0000.0000.0000")

    def validate(self, obj, value):
        try:
            value = netaddr.EUI(value)
            value.dialect = mac_cisco
            return unicode(value)
        except netaddr.core.AddrFormatError:
            raise InvalidMacError('Cannot parse "{0}" into a valid mac address'.format(
                str(value)))

class CMacAddressUnixPadded(TraitType):
    """Return a netaddr.EUI Mac Address object cast as a zero-padded Unix Mac"""
    default_value = EUI("00:00:00:00:00:00")

    def validate(self, obj, value):
        try:
            value = netaddr.EUI(value)
            value.dialect = mac_unix_expanded
            return value
        except netaddr.core.AddrFormatError:
            raise InvalidMacError('Cannot parse "{0}" into a valid mac address'.format(
                str(value)))

class CMacAddressUnixPaddedStr(TraitType):
    """Return a unicode Mac Address string formatted as a Unix zero-padded Mac"""
    default_value = EUI("00:00:00:00:00:00")

    def validate(self, obj, value):
        try:
            value = netaddr.EUI(value)
            value.dialect = mac_unix_expanded
            return unicode(value)
        except netaddr.core.AddrFormatError:
            raise InvalidMacError('Cannot parse "{0}" into a valid mac address'.format(
                str(value)))


class CVlan(TraitType):
    """Return a Vlan cast as an Integer; default value is 0"""
    default_value = 0

    def validate(self, obj, value):
        try:
            value = int(value)
            assert (0 <= value <= 4095) # Includes default value
            return value
        except AssertionError:
            raise InvalidVlanError('Cannot parse "{0}" into a valid Vlan'.format(
                str(value)))
