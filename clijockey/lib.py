#
#   "David Michael Pennington" <mike@pennington.net>
#   "Samsung Data Services"
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

from contextlib import closing
from StringIO import StringIO
import logging
import socket
import time
import sys
import re
import os

from error import ConnectionFailedError, AuthenticationFailedError
from error import ResponseFailException, UnexpectedConnectionClose
from util import Account, TCPProto
import pdb

from transitions import Machine
from textfsm import TextFSM
from colorama import Fore, Style
import pexpect

_log = logging.getLogger(__file__)
_CLIJOCKEY_LOG_FORMAT_PREFIX_STR = (
    Fore.WHITE + '[%(module)s %(funcName)s] %(asctime)s ')
_CLIJOCKEY_LOG_FORMAT_MSG_STR = (Fore.GREEN + '%(msg)s' + Fore.RESET)
_CLIJOCKEY_LOG_FORMAT_STR = _CLIJOCKEY_LOG_FORMAT_PREFIX_STR + _CLIJOCKEY_LOG_FORMAT_MSG_STR
_clijockey_log_format = logging.Formatter(_CLIJOCKEY_LOG_FORMAT_STR, '%H:%M:%S')
_log.setLevel(logging.DEBUG)
_LOG_CHANNEL_STDOUT = logging.StreamHandler(sys.stdout)
_LOG_CHANNEL_STDOUT.setFormatter(_clijockey_log_format)
_log.addHandler(_LOG_CHANNEL_STDOUT)


class CLIMachine(Machine):
    def __init__(self, host='', credentials=(), 
        protocols=(TCPProto('ssh', 22), TCPProto('telnet', 23),), 
        auto_priv_mode=True, check_alive=True, log_screen=False, debug=False,
        command_timeout=30, login_timeout=20, test=''):
        STATES = [
            'INIT', 'CHECK_ALIVE', 
            'ITER_CREDENTIALS', 'SEND_USERNAME', 'SEND_CREDENTIALS', 
            'LOGIN_FAIL', 'CONNECT', 'LOGIN_SUCCESS_NOPRIV', 'LOGIN_SUCCESS_PRIV', 
            'ITER_ENABLE_CREDENTIALS', 'INTERACT', 'INTERACT_TIMEOUT', 
            'TERMINATE_CLI', 'TERMINATE_SESSION'
        ]
        super(CLIMachine, self).__init__(states=STATES, initial='INIT')
        assert isinstance(credentials, tuple) or isinstance(credentials, list)
        for acct in credentials:
            assert isinstance(acct, Account), "Accounts must be created with clijockey.util.Account()"
        assert isinstance(command_timeout, int), "command_timeout must be a positive integer"
        assert isinstance(login_timeout, int), "login_timeout must be a positive integer"
        assert command_timeout > 0, "command_timeout must be a positive integer"
        assert login_timeout > 0, "login_timeout must be a positive integer"

        self.hostname = None   # hostname populated by after_interact_cb()
        self.host = host
        self.credentials = credentials
        self.auto_priv_mode = auto_priv_mode
        self.check_alive = check_alive
        self.log_screen = log_screen
        self.debug = debug
        self.command_timeout = command_timeout
        self.login_timeout = login_timeout
        self.test = test

        self.child = None
        self.account = None

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
        self.add_transition('_go_send_credentials', 'SEND_USERNAME', 
            'SEND_CREDENTIALS', after='after_send_credentials_cb')
        self.add_transition('_go_interact', 'SEND_USERNAME', 
            'INTERACT', after='after_interact_cb')
        self.add_transition('_go_login_fail', 'SEND_CREDENTIALS', 
            'LOGIN_FAIL', after='after_login_fail_cb')
        self.add_transition('_go_login_fail', 'SEND_CREDENTIALS', 
            'TERMINATE_SESSION', after='after_terminate_session_cb')
        self.add_transition('_go_login_success_nopriv', 'SEND_CREDENTIALS', 
            'LOGIN_SUCCESS_NOPRIV', after='after_login_success_nopriv_cb')
        self.add_transition('_go_login_success_priv', 'SEND_CREDENTIALS', 
            'LOGIN_SUCCESS_PRIV', after='after_login_success_priv_cb')
        self.add_transition('_go_interact', 'SEND_CREDENTIALS', 
            'INTERACT', after='after_interact_cb')
        self.add_transition('_go_login_success_priv', 'LOGIN_SUCCESS_NOPRIV', 
            'LOGIN_SUCCESS_PRIV', after='after_login_success_priv_cb')
        self.add_transition('_go_interact', 'LOGIN_SUCCESS_NOPRIV', 
            'INTERACT', after='after_interact_cb')
        self.add_transition('_go_iter_enable_credentials', 'LOGIN_SUCCESS_NOPRIV', 
            'ITER_ENABLE_CREDENTIALS', after='after_iter_enable_credentials_cb')
        self.add_transition('_go_login_success_priv', 'ITER_ENABLE_CREDENTIALS',
            'LOGIN_SUCCESS_NOPRIV', after='after_login_success_nopriv_cb')
        self.add_transition('_go_interact', 'LOGIN_SUCCESS_PRIV', 
            'INTERACT', after='after_interact_cb')
        self.add_transition('_go_iter_credentials', 'LOGIN_FAIL', 
            'ITER_CREDENTIALS', after='after_iter_credentials_cb')
        self.add_transition('_go_terminate_cli', 'INTERACT', 
            'TERMINATE_CLI', after='after_terminate_cli_cb')
        self.add_transition('_go_interact_timeout', 'INTERACT', 
            'INTERACT_TIMEOUT', after='after_interact_timeout_cb')
        self.add_transition('_go_terminate_session', 'TERMINATE_CLI', 
            'TERMINATE_SESSION', after='after_terminate_session_cb')

        if check_alive:
            if self.debug:
                _log.debug("INIT -> CHECK_ALIVE")
            self._go_check_alive()
        else:
            if self.debug:
                _log.debug("INIT -> ITER_CREDENTIALS")
            self._go_iter_credentials()

    def after_check_alive_cb(self):
        for protocol in self.protocols:
            if self.debug:
                _log.debug("  Testing TCP port {0}".format(protocol.port))
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(2)
                try:
                    if sock.connect_ex((self.host, protocol.port)) == 0:
                        # It's alive...
                        # FIXME: Log a port-open and selected_protocol message
                        self.selected_protocol = protocol
                        if self.debug:
                            _log.debug("  TCP port {0} alive".format(
                                protocol.port))
                        break
                    else:
                        if self.debug:
                            _log.debug("  TCP port {0} closed".format(
                                protocol.port))
                except socket.gaierror:
                    raise ValueError("Unknown hostname: '{0}'".format(
                        self.host))
        else:
            # FIXME: Log a port-closed message here...
            raise ConnectionFailedError("Cannot connect to host: {0}".format(
                self.host))

        time.sleep(1.5) # Give the platform time to close after "with closing()"

        ## Must break out of the loop above to get here...
        if self.debug:
            _log.debug("CHECK_ALIVE -> ITER_CREDENTIALS")
        self._go_iter_credentials()

    def after_iter_credentials_cb(self):
        try:
            self.account = self.nopriv_account_iter.next()
        except:
            # FIXME: Log an out-of-credentials error here...
            raise AuthenticationFailedError("Login failure on host {0} using the known credentials".format(self.host))

        if self.debug:
            _log.debug("ITER_CREDENTIALS -> CONNECT")
        self._go_connect()

    def after_iter_enable_credentials_cb(self):
        try:
            self.account = self.priv_account_iter.next()
        except:
            # FIXME: Log an out-of-credentials error here...
            raise AuthenticationFailedError("Enable password failure on host {1} using the known credentials".format(self.host))

        if self.debug:
            _log.debug("ITER_ENABLE_CREDENTIALS -> LOGIN_SUCCESS_NOPRIV")
        self._go_login_success_nopriv()

    def after_connect_cb(self):
        username = self.account.username
        if self.test:
            cmd = self.test
        elif self.selected_protocol.name.name=='ssh':
            ssh_options = '-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'
            cmd = 'ssh {0} -p {1} -l {2} {3}'.format(ssh_options, 
                self.selected_protocol.port, username, self.host)
        elif self.selected_protocol.name.name=='telnet':
            cmd = 'telnet {0} {1}'.format(self.host, self.selected_protocol.port)
        else:
            raise ValueError("'{0}' is an unsupported protocol".format(self.selected_protocol.name.name))

        if self.child is not None:
            self.child.close()
        if self.debug:
            _log.debug(cmd)
        self.child = pexpect.spawn(cmd, timeout=self.command_timeout)

        if self.log_screen:
            self.child.logfile = sys.stdout 

        try:
            if self.debug:
                _log.debug("*expect* response")
            try:
                result = self.child.expect(['assword:', 'name:', 
                    r'[\n\r]\S+?>', r'[\n\r]\S+?#'], timeout=self.login_timeout)
            except pexpect.EOF:
                raise UnexpectedConnectionClose("Connection died while trying to connect to '{0}'".format(self.host))

            except pexpect.TIMEOUT:
                raise ResponseFailException("CLIMachine did not anticipate this response '{0}'".format(self.response))

            if (result == 0):
                if self.debug:
                    _log.debug("response '{0}'".format(self.response))
                    _log.debug("CONNECT -> SEND_CREDENTIALS")
                self._go_send_credentials()
            elif (result == 1):
                if self.debug:
                    _log.debug("response '{0}'".format(self.response))
                    _log.debug("CONNECT -> SEND_USERNAME")
                self._go_send_username()
            elif ((self.auto_priv_mode is True) and (result == 2)):
                if self.debug:
                    _log.debug("response '{0}'".format(self.response))
                    _log.debug("CONNECT -> LOGIN_SUCCESS_NOPRIV")
                self._go_login_success_nopriv()
            elif ((self.auto_priv_mode is False) and (result == 2)):
                if self.debug:
                    _log.debug("response '{0}'".format(self.response))
                    _log.debug("CONNECT -> INTERACT")
                self._go_interact()
            elif (result == 3):
                if self.debug:
                    _log.debug("response '{0}'".format(self.response))
                    _log.debug("CONNECT -> LOGIN_SUCCESS_PRIV")
                self._go_login_success_priv()
            else:
                raise ValueError("Unknown result code: {0}".format(result))

        except pexpect.TIMEOUT:
            # FIXME: Log an error here...
            raise ConnectionFailedError("Cannot connect to port {0} on host: {1}".format(self.selected_protocol.name.port, self.host))

    def after_send_username_cb(self):
        assert self.account is not None

        try:
            if self.debug:
                _log.debug("*send*")
            self.child.sendline(self.account.username)
            if self.debug:
                _log.debug("*expect*")
            result = self.child.expect(['[\r\n][Pp]assword:', '[\n\r]\S+?>', 
                '[\n\r]\S+?#'], timeout=self.login_timeout)

        except pexpect.TIMEOUT:
            raise ResponseFailException("CLIMachine did not anticipate this response '{0}'".format(self.response))

        if (result == 0):
            if self.debug:
                _log.debug("SEND_USERNAME -> SEND_CREDENTIALS")
            self._go_send_credentials()
        elif ((self.auto_priv_mode is False) and (result == 1)):
            if self.debug:
                _log.debug("SEND_USERNAME -> INTERACT")
            self._go_interact()
        elif ((self.auto_priv_mode is True) and (result == 1)):
            if self.debug:
                _log.debug("SEND_USERNAME -> LOGIN_SUCCESS_NOPRIV")
            self._go_login_success_nopriv()
        elif (result == 2):
            if self.debug:
                _log.debug("SEND_USERNAME -> LOGIN_SUCCESS_PRIV")
            self._go_login_success_priv()

    def after_send_credentials_cb(self):
        assert self.account is not None

        if self.debug:
            _log.debug("*send*")
        self.child.sendline(self.account.password)
        try:
            if self.debug:
                _log.debug("*expect*")
            result = self.child.expect(['[\n\r]\S+?>', '[\n\r]\S+?#', 
                'assword:'], timeout=self.login_timeout)
        except pexpect.TIMEOUT:
            if self.debug:
                _log.debug("SEND_CREDENTIALS -> LOGIN_FAIL")
            self.child.close()
            self._go_login_fail()

        try:
            if ((self.auto_priv_mode is False) and (result==0)):
                if self.debug:
                    _log.debug("SEND_CREDENTIALS -> INTERACT")
                self._go_interact()
            elif ((self.auto_priv_mode is True) and (result==0)):
                if self.debug:
                    _log.debug("SEND_CREDENTIALS -> LOGIN_SUCCESS_NOPRIV")
                self._go_login_success_nopriv()
            elif (result==1):
                if self.debug:
                    _log.debug("SEND_CREDENTIALS -> LOGIN_SUCCESS_PRIV")
                self._go_login_success_priv()
            elif (result==2):
                if self.debug:
                    _log.debug("SEND_CREDENTIALS -> LOGIN_FAIL")
                self._go_login_fail()
            else:
                raise NotImplementedError
        except UnboundLocalError:
            if self.debug:
                _log.debug('WORKAROUND: pexpect keeps state from a stale and closed pexpect.spawn session (looks like a bug)')

    def after_login_fail_cb(self):
        ## FIXME: Log a warning here...
        if self.debug:
            _log.debug("LOGIN_FAIL -> ITER_CREDENTIALS")
        self._go_iter_credentials()

    def after_login_success_nopriv_cb(self):
        self.child.send('enable\r')
        self.child.expect('assword:')
        self.child.send(self.account.password+'\r')
        result = self.child.expect(['[\n\r]\S+?>', '[\n\r]\S+?#'], 
            timeout=self.login_timeout)

        

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
        if self.debug:
            _log.debug("LOGIN_SUCCESS -> INTERACT")
        self._go_interact()

    def after_interact_cb(self):
        # Populate self.hostname with a string
        self.child.send('\r')  # Get ready to parse out the hostname
        result = self.child.expect(['[\n\r]\S+?>', '[\n\r]\S+?#'], 
            timeout=self.login_timeout)
        self.hostname = re.escape(self.response.strip().replace('>', '').replace('#', ''))
        if self.debug:
            _log.debug("Set hostname to '{0}'".format(self.hostname))
            _log.debug("INTERACT mode")
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

    def execute(self, line, timeout=-1, wait=0.0, regex="", auto_endline=True,
        template="", timeout_fail=False):

        retval = list()  # Always return a list, even if no template is given
        fh = None

        if timeout < 0:
            timeout = self.command_timeout

        assert (self.child is not None), "Cannot execute a command on a closed session"
        assert self.hostname is not None
        assert isinstance(line, str) or isinstance(line, unicode)
        assert isinstance(timeout, int)
        assert isinstance(wait, float) or isinstance(wait, int)
        assert isinstance(regex, str)
        assert isinstance(auto_endline, bool)
        assert isinstance(template, str)
        assert timeout > 0
        assert float(wait) >= 0.0

        expect_prompts = ['[\n\r]{0}\S*?>'.format(self.hostname), 
            '[\n\r]{0}\S*?#'.format(self.hostname)]
        if regex:
            expect_prompts.append(regex)

        try:
            if self.debug:
                _log.debug('sending: "{0}"'.format(line))

            if auto_endline:
                self.child.sendline(line)
            else:
                self.child.send(line)
            if self.debug:
                _log.debug('Waiting for prompts: "{0}"'.format(expect_prompts))

            result = self.child.expect(expect_prompts, timeout)

            if self.debug:
                _log.debug("Matched prompt {0}".format(result))

            time.sleep(wait)
        except pexpect.TIMEOUT:
            if timeout_fail:
                raise ExecuteTimeout("Timeout after executing '{0}'".format(
                    line))
            else:
                self._go_interact_timeout()
        except pexpect.EOF:
            raise UnexpectedConnectionClose("Connection died while executing".format(line))

        if template:
            if os.path.isfile(template):
                fh = open(template)
            else:
                fh = StringIO(template)
            fsm = TextFSM(fh)
            retval = fsm.ParseText(self.response)
            fh.close()

        return retval

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
        return str(self.child.before) + str(self.child.after)

if __name__=='__main__':

    accts = (Account('itsa-mistake', ''), Account('rviews', 'secret2'),)
    conn = CLIMachine('route-views.routeviews.org', accts, 
        auto_priv_mode=False, log_screen=True, debug=False)
    conn.execute('term len 0')
    conn.execute('show version')
    conn.execute('show users', timeout=60)
    print conn.execute('show ip int brief', template='template.txt')
    conn.logout()
