#
#   Copyright 2016 "David Michael Pennington" <mike@pennington.net>
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

from contextlib import closing
import socket
import time
import sys
import os

from error import ConnectionFailedError, AuthenticationFailedError
from util import Account
import pdb

from transitions import Machine
import pexpect

"""

"""

class CLIMachine(Machine):
    def __init__(self, host, credentials, protocols=('ssh', 'telnet',), 
        auto_priv_mode=True, check_alive=True, log_screen=False):
        STATES = [
            'INIT', 'CHECK_ALIVE', 
            'ITER_CREDENTIALS', 'SEND_USERNAME', 'SEND_CREDENTIALS', 
            'LOGIN_FAIL', 'CONNECT', 'LOGIN_SUCCESS_NOPRIV', 'LOGIN_SUCCESS_PRIV', 
            'ITER_ENABLE_CREDENTIALS', 'INTERACT', 'INTERACT_TIMEOUT', 
            'TERMINATE_CLI', 'TERMINATE_SESSION'
        ]
        super(CLIMachine, self).__init__(states=STATES, initial='INIT')
        assert isinstance(credentials, tuple) or isinstance(credentials, list)

        self.host = host
        self.credentials = credentials
        self.auto_priv_mode = auto_priv_mode
        self.check_alive = check_alive
        self.log_screen = log_screen
        self.child = None
        self.account = None

        self.ports = {'ssh': 22, 'telnet': 23}
        self.protocols = protocols
        self.selected_protocol = None

        self.nopriv_account_iter = self.get_next_credentials()
        self.priv_account_iter = self.get_next_enable_credentials()

        self.add_transition('_go_check_alive', 'INIT', 
            'CHECK_ALIVE', after='after_check_alive_cb')
        self.add_transition('_go_iter_credentials', 'CHECK_ALIVE', 
            'ITER_CREDENTIALS', after='after_iter_credentials_cb')
        self.add_transition('_go_iter_credentials', 'INIT', 
            'ITER_CREDENTIALS', after='after_iter_credentials_cb')
        self.add_transition('_go_connect', 'ITER_CREDENTIALS', 
            'CONNECT', after='after_connect_cb')
        self.add_transition('_go_send_username', 'CONNECT', 
            'SEND_USERNAME', after='after_send_username_cb')
        self.add_transition('_go_send_credentials', 'CONNECT', 
            'SEND_CREDENTIALS', after='after_send_credentials_cb')
        self.add_transition('_go_login_success_nopriv', 'CONNECT', 
            'LOGIN_SUCCESS_NOPRIV', after='after_login_success_nopriv_cb')
        self.add_transition('_go_login_success_priv', 'CONNECT', 
            'LOGIN_SUCCESS_PRIV', after='after_login_success_priv_cb')
        self.add_transition('_go_interact', 'CONNECT', 
            'INTERACT', after='after_interact_cb')
        self.add_transition('_go_send_username', 'SEND_CREDENTIALS', 
            'SEND_USERNAME', after='after_send_username_cb')
        self.add_transition('_go_send_credentials', 'SEND_USERNAME', 
            'SEND_CREDENTIALS', after='after_send_credentials_cb')
        self.add_transition('_go_interact', 'SEND_USERNAME', 
            'INTERACT', after='after_interact_cb')
        self.add_transition('_go_terminate_session', 'SEND_USERNAME', 
            'TERMINATE_SESSION', after='after_terminate_session_cb')
        self.add_transition('_go_login_fail', 'SEND_CREDENTIALS', 
            'LOGIN_FAIL', after='after_login_fail_cb')
        self.add_transition('_go_iter_credentials', 'LOGIN_FAIL', 
            'ITER_CREDENTIALS', after='after_iter_credentials_cb')
        self.add_transition('_go_login_fail', 'SEND_CREDENTIALS', 
            'TERMINATE_SESSION', after='after_terminate_session_cb')
        self.add_transition('_go_login_success_nopriv', 'SEND_CREDENTIALS', 
            'LOGIN_SUCCESS_NOPRIV', after='after_login_success_nopriv_cb')
        self.add_transition('_go_login_success_priv', 'SEND_CREDENTIALS', 
            'LOGIN_SUCCESS_PRIV', after='after_login_success_priv_cb')
        self.add_transition('_go_login_success_priv', 'LOGIN_SUCCESS_NOPRIV', 
            'LOGIN_SUCCESS_PRIV', after='after_login_success_priv_cb')
        self.add_transition('_go_iter_enable_credentials', 'LOGIN_SUCCESS_NOPRIV', 
            'ITER_ENABLE_CREDENTIALS', after='after_iter_enable_credentials_cb')
        self.add_transition('_go_login_success_priv', 'ITER_ENABLE_CREDENTIALS',
            'LOGIN_SUCCESS_NOPRIV', after='after_login_success_nopriv_cb')
        self.add_transition('_go_interact', 'LOGIN_SUCCESS_NOPRIV', 
            'INTERACT', after='after_interact_cb')
        self.add_transition('_go_interact', 'LOGIN_SUCCESS_PRIV', 
            'INTERACT', after='after_interact_cb')
        self.add_transition('_go_terminate_cli', 'INTERACT', 
            'TERMINATE_CLI', after='after_terminate_cli_cb')
        self.add_transition('_go_interact_timeout', 'INTERACT', 
            'INTERACT_TIMEOUT', after='after_interact_timeout_cb')
        self.add_transition('_go_terminate_session', 'TERMINATE_CLI', 
            'TERMINATE_SESSION', after='after_terminate_session_cb')

        if check_alive:
            self._go_check_alive()
        else:
            self._go_iter_credentials()

    def after_check_alive_cb(self):
        for protocol in self.protocols:
            check_alive_port = self.ports.get(protocol)
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(3)
                try:
                    if sock.connect_ex((self.host, check_alive_port)) == 0:
                        # It's alive...
                        # FIXME: Log a port-open and selected_protocol message
                        self.selected_protocol = protocol
                        break
                    else:
                        # FIXME: Log a port-closed message here...
                        raise ConnectionFailedError("Cannot connect to port {0} on host: {1}".format(check_alive_port, self.host))
                except socket.gaierror:
                    raise ValueError("Unknown hostname: '{0}'".format(
                        self.host))

        ## Must break out of the loop above to get here...
        self._go_iter_credentials()

    def after_iter_credentials_cb(self):
        try:
            self.account = self.nopriv_account_iter.next()
        except:
            # FIXME: Log an out-of-credentials error here...
            raise AuthenticationFailedError("Login failure on host {1} using the known credentials".format(self.host))

        self._go_connect()

    def after_iter_enable_credentials_cb(self):
        try:
            self.account = self.priv_account_iter.next()
        except:
            # FIXME: Log an out-of-credentials error here...
            raise AuthenticationFailedError("Enable password failure on host {1} using the known credentials".format(self.host))
        self._go_login_success_nopriv()

    def after_connect_cb(self):
        username = self.account.username
        if self.selected_protocol=='ssh':
            ssh_options = '-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'
            cmd = 'ssh {0} -p {1} -l {2} {3}'.format(ssh_options, 
                self.ports.get('ssh'), username, self.host)
        elif self.selected_protocol=='telnet':
            cmd = 'telnet {0} {1}'.format(self.host, self.ports.get('telnet'))
        else:
            raise ValueError("'{0}' is an unsupported protocol".format(self.selected_protocol))

        if self.child is not None:
            self.child.close()
        self.child = pexpect.spawn(cmd, timeout=30)

        if self.log_screen:
            self.child.logfile = sys.stdout 

        try:
            result = self.child.expect(['assword:', 'name:', 
                r'[\n\r]\S+?>', r'[\n\r]\S+?#'], timeout=10)

            if (result == 0):
                self._go_send_credentials()
            elif (result == 1):
                self._go_send_username()
            elif ((self.auto_priv_mode is True) and (result == 2)):
                self._go_login_success_nopriv()
            elif ((self.auto_priv_mode is False) and (result == 2)):
                self._go_interact()
            elif (result == 3):
                self._go_login_success_priv()
            else:
                raise ValueError("Unknown result code: {0}".format(result))

        except pexpect.TIMEOUT:
            # FIXME: Log an error here...
            raise ConnectionFailedError("Cannot connect to port {0} on host: {1}".format(self.ports.get(self.selected_protocol), self.host))

    def after_send_username_cb(self):
        assert self.account is not None

        try:
            self.child.send(self.account.username+'\r')
            result = self.child.expect(['[\r\n][Pp]assword:', '[\n\r]\S+?>', 
                '[\n\r]\S+?#'], timeout=10)

        except pexpect.TIMEOUT:
            # FIXME: Raise and log an error here...
            self._go_terminate_session()

        if (result == 0):
            self._go_send_credentials()
        elif ((self.auto_priv_mode is False) and (result == 1)):
            self._go_interact()
        elif ((self.auto_priv_mode is True) and (result == 1)):
            self._go_login_success_nopriv()
        elif (result == 2):
            self._go_login_success_priv()

    def after_send_credentials_cb(self):
        assert self.account is not None

        self.child.send(self.account.password+'\r')
        try:
            time.sleep(0.05)
            self.child.flush()
            result = self.child.expect(['[\n\r]\S+?>', '[\n\r]\S+?#', 
                'assword:'], timeout=10)
        except pexpect.TIMEOUT:
            self._go_login_fail()

        if ((self.auto_priv_mode is False) and (result==0)):
            ## FIXME: Log info here that we bypassed enable...
            self._go_interact()
        elif ((self.auto_priv_mode is True) and (result==0)):
            ## FIXME: Log info here that we got to nopriv...
            self._go_login_success_nopriv()
        elif (result==1):
            ## FIXME: Log info here that we got to priv...
            self._go_login_success_priv()
        elif (result==2):
            self._go_login_fail()
        else:
            raise NotImplementedError

    def after_login_fail_cb(self):
        ## FIXME: Log a warning here...
        self._go_iter_credentials()

    def after_login_success_nopriv_cb(self):
        self.child.send('enable\r')
        self.child.expect('assword:')
        self.child.send(self.account.password+'\r')
        result = self.child.expect(['[\n\r]\S+?>', '[\n\r]\S+?#'], 
            timeout=10)
        if ((self.auto_priv_mode is False) and (result==0)):
            ## FIXME: Log info here that we bypassed enable...
            self._go_interact()
        elif ((self.auto_priv_mode is True) and (result==0)):
            ## FIXME: Log info here that we failed to enable...
            self._go_iter_enable_credentials()
        elif (result==1):
            ## FIXME: Log info here that we got to priv...
            self._go_login_success_priv()
        else:
            raise NotImplementedError

    def after_login_success_priv_cb(self):
        ## FIXME: Log that we got to priv mode...
        self._go_interact()

    def after_interact_cb(self):
        ## FIXME: Log that we got to interact mode...
        pass

    def after_interact_timeout_cb(self):
        pass

    def after_terminate_cli_cb(self):
        ## FIXME: Log a message
        pass

    def after_terminate_session_cb(self):
        ## FIXME: Log a message
        if self.child is not None:
            self.child.close(force=True)

    ########################################################
    ########################################################
    ########################################################

    def get_next_credentials(self):
        for account in self.credentials:
            yield account

    def get_next_enable_credentials(self):
        for account in self.credentials:
            yield account

    def execute(self, line):
        assert (self.child is not None), "Cannot execute a command on a closed session"

        try:
            self.child.sendline(line)
            self.child.expect(['[\n\r]\S+?>', '[\n\r]\S+?#'])
        except pexpect.TIMEOUT:
            self._go_interact_timeout()

    def logout(self):
        try:
            self.child.send('exit\r')
            self.child.expect('', timeout=1)
        except pexpect.TIMEOUT:
            self._go_terminate_cli()

    def exit(self):
        self.logout()

    @property
    def before(self):
        return self.child.before

    @property
    def response(self):
        return self.child.before

if __name__=='__main__':

    accts = (Account('itsa-mistake', ''), Account('rviews', 'secret2'),)
    conn = CLIMachine('route-views.routeviews.org', accts, 
        auto_priv_mode=False, log_screen=True)
    conn.execute('term len 0')
    conn.execute('show version')
    conn.execute('show users')
    conn.logout()

