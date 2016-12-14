class ConnectionFailedError(Exception):
    def __init__(self, *args, **kwargs):
        super(ConnectionFailedError, self).__init__(*args, **kwargs)

class AuthenticationFailedError(Exception):
    def __init__(self, *args, **kwargs):
        super(AuthenticationFailedError, self).__init__(*args, **kwargs)
