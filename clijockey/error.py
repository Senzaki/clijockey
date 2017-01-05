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

## TraitTable errors

class TraitTableInvalidInput(Exception):
    def __init__(self, *args, **kwargs):
        super(TraitTableInvalidInput, self).__init__(*args, **kwargs)

## TraitType errors

class InvalidVlanError(Exception):
    def __init__(self, *args, **kwargs):
        super(InvalidVlanError, self).__init__(*args, **kwargs)

class InvalidMacError(Exception):
    def __init__(self, *args, **kwargs):
        super(InvalidMacError, self).__init__(*args, **kwargs)

class InvalidIPv4AddressError(Exception):
    def __init__(self, *args, **kwargs):
        super(InvalidIPv4AddressError, self).__init__(*args, **kwargs)

class InvalidUnicodeRegexMatch(Exception):
    def __init__(self, *args, **kwargs):
        super(InvalidUnicodeRegexMatch, self).__init__(*args, **kwargs)
