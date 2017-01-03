class ConnectionFailedError(Exception):
    def __init__(self, *args, **kwargs):
        super(ConnectionFailedError, self).__init__(*args, **kwargs)

class AuthenticationFailedError(Exception):
    def __init__(self, *args, **kwargs):
        super(AuthenticationFailedError, self).__init__(*args, **kwargs)

class ResponseFailException(Exception):
    def __init__(self, *args, **kwargs):
        super(ResponseFailException, self).__init__(*args, **kwargs)

class ExecuteTimeout(Exception):
    def __init__(self, *args, **kwargs):
        super(ExecuteTimeout, self).__init__(*args, **kwargs)

class UnexpectedConnectionClose(Exception):
    def __init__(self, *args, **kwargs):
        super(UnexpectedConnectionClose, self).__init__(*args, **kwargs)

class InvalidMacError(Exception):
    def __init__(self, *args, **kwargs):
        super(InvalidMacError, self).__init__(*args, **kwargs)

class InvalidIPv4Address(Exception):
    def __init__(self, *args, **kwargs):
        super(InvalidIPv4Address, self).__init__(*args, **kwargs)
