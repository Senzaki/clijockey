class Account(object):
    def __init__(self, username="", password="", priv_password=""):
        self.username = username
        self.password = password
        self.priv_password = priv_password

    def __repr__(self):
        return """<Account username: {0}>""".format(self.username)
