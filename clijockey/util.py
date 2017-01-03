from logging.handlers import TimedRotatingFileHandler
from logging.handlers import MemoryHandler
from abc import abstractmethod
import logging
import atexit
import sys
import re

from traits import HasTraits, TraitError, UseEnum, CInt, default, validate

from enum import Enum as Enum34
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


class Account(object):
    def __init__(self, username="", password="", priv_password=""):
        self.username = username
        self.password = password
        self._priv_password = priv_password

    def __repr__(self):
        return """<Account username: {0}>""".format(self.username)

    @property
    def priv_password(self):
        """Return the priv_password no matter what; priv_password defaults
        to password unless it's explicitly defined"""
        if self._priv_password:
            return self._priv_password
        else:
            return self.password

class ProtocolEnum(Enum34):
    ssh = 1
    telnet = 2

class TCPProto(HasTraits):
    name = UseEnum(ProtocolEnum)
    port = CInt()

    ## Coerce values that were called without kwargs
    def __init__(self, *args, **kwargs):
        super(TCPProto, self).__init__(*args, **kwargs)
        ## Handle the protocol name
        try:
            if args[0]:
                self.name = args[0]
        except IndexError:
            pass

        ## Handle the port
        try:
            if args[1]:
                self.port = args[1]
        except IndexError:
            pass

    @default('port')
    def _default_port(self):
        if self.name==ProtocolEnum.ssh:
            return 22
        elif self.name==ProtocolEnum.telnet:
            return 23

    @validate('port')
    def _valid_port(self, proposal):
        port = proposal['value']
        if bool(1 <= port <= 65535):
            return port
        else:
            raise TraitError('TCPProtocol port values must be between 1 and 65535.')

    def __repr__(self):
        return "<TCPProto {0}, port {1}>".format(self.name.name, self.port)

    def __iter__(self):
        yield self.name.name, self.port

def CustomLogger(filename,
                 category="",
                 rotate="",
                 buffer=10 * 1024,
                 utc=False,
                 backupCount=0):
    assert isinstance(category, str)
    assert (category != "root") or (category == "")

    logger = logging.getLogger(category)

    ## Check if the hander is already registered...
    # http://stackoverflow.com/q/15870380
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
            capacity=buffer, flushLevel=logging.ERROR, target=streamhandler)
        filehandler = TimedRotatingFileHandler(
            filename, when=rotate, utc=utc, backupCount=backupCount)
        filehandler.suffix = "%Y-%m-%d"  # http://stackoverflow.com/a/338566
        filehandler.setLevel(logLevel)
        filehandler.setFormatter(formatter)

        logger.setLevel(logLevel)
        logger.addHandler(memoryhandler)
        logger.addHandler(filehandler)

        return logger, memoryhandler


class RotatingTOMLLog(object):
    def __init__(self,
                 filename="",
                 category="",
                 rotate='midnight',
                 buffer=10 * 1024,
                 utc=False,
                 backupCount=0):
        assert isinstance(buffer, int)
        assert buffer > 0

        self.category = category
        self.log, self.memoryhandler = CustomLogger(
            filename,
            category=category,
            rotate=rotate,
            utc=utc,
            backupCount=backupCount, )
        ## Flush the logging buffer, no matter what
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
        assert table != ""
        assert isinstance(info, dict)
        assert info != {}

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
        assert table != ""
        assert isinstance(info, dict)
        assert info != {}

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

