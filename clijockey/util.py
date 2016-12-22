from logging.handlers import TimedRotatingFileHandler
from logging.handlers import MemoryHandler
from abc import abstractmethod
import logging
import atexit
import sys

from traitlets import CUnicode, CInt, CFloat, CLong, CBytes, CBool
from traitlets import Unicode, Int, Float, Long, Bytes, Bool
from traitlets import CaselessStrEnum, Enum, UseEnum
from traitlets import CRegExp
from traitlets import HasTraits, Union, validate
from traitlets import Dict, Tuple, Set, List
import arrow

#
#   "David Michael Pennington" <mike@pennington.net>
#   Copyright 2016
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

class Account(object):
    def __init__(self, username="", password="", priv_password=""):
        self.username = username
        self.password = password
        self.priv_password = priv_password

    def __repr__(self):
        return """<Account username: {0}>""".format(self.username)

def CustomLogger(filename, category="", rotate="", 
        buffer=10*1024,
        utc=False, 
        backupCount=0
    ):
    assert isinstance(category, str)
    assert (category!="root") or (category=="")

    logger = logging.getLogger(category)
    if logger.handlers:
        return logger
    else:
        # http://stackoverflow.com/a/34125235
        logLevel = logging.DEBUG
        formatter = logging.Formatter('%(message)s')
        streamhandler = logging.StreamHandler(sys.stderr)
        streamhandler.setLevel(logLevel)
        streamhandler.setFormatter(formatter)
        memoryhandler = MemoryHandler(
            capacity=buffer,
            flushLevel=logging.ERROR,
            target=streamhandler
        )
        #filehandler = logging.FileHandler(filename)
        filehandler = TimedRotatingFileHandler(filename, 
            when=rotate, 
            utc=utc,
            backupCount=backupCount
        )
        filehandler.suffix = "%Y-%m-%d" # http://stackoverflow.com/a/338566
        filehandler.setLevel(logLevel)
        filehandler.setFormatter(formatter)


        ## Check if the hander is already registered...
        # http://stackoverflow.com/q/15870380
        logger.setLevel(logLevel)
        logger.addHandler(memoryhandler)
        logger.addHandler(filehandler)

        return logger, memoryhandler

class RotatingTOMLLog(object):
    def __init__(self, filename="", category="", rotate='midnight', 
        buffer=10*1024, utc=False, backupCount=0):
        assert isinstance(buffer, int)
        assert buffer > 0

        self.category = category
        self.log, self.memoryhandler = CustomLogger(filename,
            category=category,
            rotate=rotate,
            utc=utc,
            backupCount=backupCount,
        )
        atexit.register(self.flush)

    def _toml_value(self, val):
        """Convert a python variable to a valid TOML value (as a string)"""
        if isinstance(val, str) or isinstance(val, unicode):
            # Properly quote strings and unicode
            return '"{0}"'.format(val)
        elif getattr(val, 'isoformat', None):
            # Handle an arrow object...
            return '{0}'.format(val.isoformat())
        elif isinstance(val, bool) and (val is True):
            return 'true'
        elif isinstance(val, bool) and (val is False):
            return 'false'
        else:
            return '{0}'.format(val)

    def write_table(self, table="", info={}, timestamp=False):
        assert table!=""
        assert isinstance(info, dict)
        assert info!={}

        if timestamp and isinstance(timestamp, bool):
            now = arrow.now()
            info.update({'timestamp': now})
        elif timestamp and getattr(timestamp, 'isoformat'):
            now = timestamp
            info.update({'timestamp': now})

        self.log.debug('[{0}]'.format(table))
        for key, val in info.items():
            self.log.debug('{0} = {1}'.format(key, self._toml_value(val)))

    def write_table_list(self, table="", info={}, timestamp=False):
        assert table!=""
        assert isinstance(info, dict)
        assert info!={}

        if timestamp and isinstance(timestamp, bool):
            now = arrow.now()
            info.update({'timestamp': now})
        elif timestamp and getattr(timestamp, 'isoformat'):
            now = timestamp
            info.update({'timestamp': now})

        self.log.debug('[[{0}]]'.format(table))
        for key, val in info.items():
            self.log.debug('{0} = {1}'.format(key, self._toml_value(val)))

    def write(self, msg):
        self.log.debug(msg)

    def flush(self):
        self.memoryhandler.flush()

class TraitTable(HasTraits):
    _map = Tuple()    # Key-Value map
    def __init__(self, *args, **kwargs):
        #map = kwargs.get('map', None) or args[0]
        values = kwargs.get('values', None) or args[0]
        #assert map is not None
        #assert isinstance(map, tuple) or isinstance(map, list)
        assert values is not None
        assert isinstance(values, tuple) or isinstance(values, list)

        self._dict = dict()
        for attr_name, value in zip(self._map, values):
            setattr(self, attr_name, value)  # Set the value, through traitlets
            self._dict[attr_name] = getattr(self, attr_name) # Get the value

    def as_dict(self):
        return self._dict

    # http://stackoverflow.com/a/35282286
    def __iter__(self):
        for attr_name, val in self._dict.items():
            yield attr_name, val
