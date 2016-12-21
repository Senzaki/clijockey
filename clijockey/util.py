from logging.handlers import TimedRotatingFileHandler
from logging.handlers import MemoryHandler
import logging
import atexit
import sys

import arrow

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
            if isinstance(val, str):
                self.log.debug('{0} = "{1}"'.format(key, val))
            elif getattr(val, 'isoformat', None):
                self.log.debug('{0} = {1}'.format(key, val.isoformat()))
            else:
                self.log.debug('{0} = {1}'.format(key, val))

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
            if isinstance(val, str):
                self.log.debug('{0} = "{1}"'.format(key, val))
            elif getattr(val, 'isoformat', None):
                self.log.debug('{0} = {1}'.format(key, val.isoformat()))
            else:
                self.log.debug('{0} = {1}'.format(key, val))

    def write(self, msg):
        self.log.debug(msg)

    def flush(self):
        self.memoryhandler.flush()

