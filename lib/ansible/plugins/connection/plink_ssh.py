# (c) 2015, Ali Rizvi-Santiago <arizvisa@gmail.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
import time

import os
import portable,expect,array,itertools
import ansible
from ansible.errors import AnsibleError, AnsibleConnectionFailure, AnsibleFileNotFound
from ansible.plugins.connection import ConnectionBase
from ansible import constants as C
from expect import State

Executable = {
    'plink' : portable.which('plink'),
}

class PlinkMachine(expect.Machine):
    Callbacks = {'Hostkey','Username','Password'}
    def __init__(self):
        super(PlinkMachine,self).__init__()
        self._negotiation = []
        self._lasterror = []
        self._fingerprintType = 'none'
        self._fingerprintBits = 0
        self._fingerprintHash = ''
        self._username = ''

    # callbacks
    def fingerprintType(self, token, (state,nextstate)):
        self._fingerprintType = token.strip()
    def fingerprintBits(self, token, (state,nextstate)):
        self._fingerprintBits = int(token.strip(),10)
    def fingerprintHash(self, token, (state,nextstate)):
        self._fingerprintHash = token.strip()
    def storeUsername(self, token, (state,nextstate)):
        self._username = token[:-1].strip() if token.endswith('@') else token.strip()
    def negotiate(self, token, (state,nextstate)):
        self._negotiation.append( token.strip() )
    def error(self, token, (state,nextstate)):
        self._lasterror.append( token.strip() )

    # machine
    def Table(self, M):
        # hostkey warning
        M.transition(State.Start, expect.MatchPattern("^The server's host key is not cached in the registry."), State.unknownHostkey)
        M.transition(State.unknownHostkey, expect.Match('\n'), State.unknownHostkey, priority=1)
        M.transition(State.unknownHostkey, expect.Match("The server's rsa2 key fingerprint is:"), State.fpStatement)

        # store the hostkey fingerprint
        M.transition(State.fpStatement, expect.MatchNewline(), State.fpType)
        M.transition(State.fpType, expect.Match(' '), State.fpBits)
        M.handle(State.fpType, State.Any, self.fingerprintType)  # get type (ssh-dss, or ssh-rsa)

        M.transition(State.fpBits, expect.Match(' '), State.fpHash)
        M.handle(State.fpBits, State.Any, self.fingerprintBits)  # get bits

        M.transition(State.fpHash, expect.MatchNewline(), State.storeFingerprint)
        M.handle(State.fpHash, State.Any, self.fingerprintHash)  # get hash

        # reply to hostkey fingerprint response
        M.transition(State.storeFingerprint, expect.Match("Store key in cache? "), State.AskYN)
        M.transition(State.AskYN, expect.Match("(y/n) "), State.Start)
        M.handle(State.AskYN, State.Any, self.callback('Hostkey'))     # answer yes or no

        # type in username
        M.transition(State.Start, expect.Match("login as:"), State.Negotiate)
        M.handle(State.Start, State.Negotiate, self.callback('Username'))  # type in username

        # grab user info (testcase version)
        M.transition(State.Start, expect.MatchPattern('Using username "'), State.UsingUser)
        M.transition(State.UsingUser, expect.Match('"'), State.Negotiate)
        M.handle(State.UsingUser, State.Any, self.storeUsername)    # grab username

        # grab user info (another version)
        M.transition(State.Start, expect.Match('@'), State.GetUser)
        M.transition(State.GetUser, expect.Match("'s"), State.Negotiate)
        M.handle(State.Start, State.GetUser, self.storeUsername)

        # deal with negotiation stuff
        M.transition(State.Negotiate, expect.Match("\n"), State.Negotiate)
        M.handle(State.Negotiate, State.Negotiate, self.negotiate)
        M.transition(State.Negotiate, expect.Match("Store key in cache? "), State.storeFingerprint)

        # type in password numerous times
        M.transition(State.Negotiate, expect.Match("Password:"), State.InputPassword)
        M.transition(State.Negotiate, expect.Match("password:"), State.InputPassword)
        M.handle(State.Negotiate, State.InputPassword, self.callback('Password'))
        M.transition(State.InputPassword, expect.Match("password:"), State.InputPassword)
        M.handle(State.InputPassword, State.InputPassword, self.callback('Password'))

        M.transition(State.InputPassword, expect.Match("Access denied"), State.Negotiate)
        M.transition(State.Negotiate, expect.Match("Access denied"), State.Negotiate)
        M.transition(State.Negotiate, expect.Match("FATAL ERROR:"), State.Error)
        M.transition(State.Error, expect.Match('\n'), State.End)
        M.handle(State.Error, State.Any, self.error)
        return M

class ShellMachine(expect.Machine):
    Callbacks = {'becomePass','escalateSuccess','escalateError'}

    def __init__(self, connection):
        self._connection = connection
        super(ShellMachine, self).__init__()

    # Error callbacks that output similar debug-information to the original ssh module
    def escalateErrorRepeat(self, token, (state,nextstate)):
        self.connection._display.debug('Escalation prompt repeated')
        cb = self.callback('escalateError')
        return cb((state,nextstate))
    def escalateErrorInvalid(self, token, (state,nextstate)):
        self.connection._display.debug('Escalation failed')
        cb = self.callback('escalateError')
        return cb((state,nextstate))
    def escalateErrorMissing(self, token, (state,nextstate)):
        self.connection._display.debug('Escalation requires password')
        cb = self.callback('escalateError')
        return cb((state,nextstate))

    def Table(self, M):
        #M.set(State.Start)          # 'ssh' in cmd and self._play_context.prompt
        #M.set(State.Escalation)     # 'ssh' in cmd and self._play_context.become and self._play_context.success_key
        #M.set(State.Exit)           # 'ssh' not in cmd

        connection = self._connection
        cfg = lambda p,*r: expect.MatchAnd(expect.MatchTruth(lambda d:p),*r)

        # If we see a privilege escalation prompt, we send the password.
        M.transition(State.Start, cfg(connection._play_context.prompt, expect.MatchTruth(connection.check_password_prompt)), State.Escalation)
        M.handle(State.Start, State.Escalation, self.callback('becomePass'))
        M.transition(State.Start, expect.Timeout(connection._play_context.timeout), State.Timedout)

        # Check if escalation was successful
        M.transition(State.Escalation, cfg(connection._play_context.success_key, expect.MatchTruth(connection.check_become_success)), State.Exit)
        M.handle(State.Escalation, State.Exit, self.callback('escalateSuccess'))
        M.transition(State.Escalation, expect.Timeout(connection._play_context.timeout), State.Timedout)

        # Check if escalation caused the state to repeat itself
        M.transition(State.Escalation, cfg(connection._play_context.prompt, expect.MatchTruth(connection.check_password_prompt)), State.Error)
        M.handle(State.Escalation, State.ErrorRepeat, self.escalateErrorRepeat)
        M.transition(State.ErrorRepeat, expect.MatchAnything(), State.ErrorRepeat)

        # Check if escalating returned an incorrect password
        # sudoable
        M.transition(State.Escalation, expect.MatchTruth(connection.check_incorrect_password), State.Error)
        M.handle(State.Escalation, State.ErrorInvalid, self.escalateErrorInvalid)
        M.transition(State.ErrorInvalid, expect.MatchAnything(), State.ErrorInvalid)

        # Check if escalating returned a missing password
        # sudoable
        M.transition(State.Escalation, expect.MatchTruth(connection.check_missing_password), State.Error)
        M.handle(State.Escalation, State.ErrorMissing, self.escalateErrorMissing) # XXX
        M.transition(State.ErrorMissing, expect.MatchAnything(), State.ErrorMissing)

        return M

### Connection class
class Connection(ConnectionBase):
    ''' ssh based connections '''

    Cache = {}

    def __init__(self, *args, **kwargs):
        super(Connection, self).__init__(*args, **kwargs)
        self.args = args = {}
        self.command = '-C -P {port} -l {user} {options} {host}'
        self.plinkmachine = PlinkMachine()
        self.shellmachine = ShellMachine(self)

    @property
    def transport(self):
        ''' used to identify this connection object from other classes '''
        return 'plink'

    def _get_command(self, program):
        args = self.args
        # general options
        args['host'] = self._play_context.remote_addr
        if self._play_context.remote_user:
            args['user'] = _ = '{:s}'.format(self._play_context.remote_user)
            self._display.vvvvv('PLINK: ANSIBLE_REMOTE_USER/remote_user/ansible_user/user/-u set : ({:s})'.format(_, host=self._play_context.remote_addr))

        if self._play_context.port is not None:
            args['port'] = '{:d}'.format(self._play_context.port)
        else:
            args['port'] = ansible.constants.DEFAULT_REMOTE_PORT or 22

        # custom options
        options = []
        if self._play_context.password:
            options.append('-pw "{:s}"'.format(self._play_context.password))
#        if self._play_context.verbosity > 3:
#            options.append('-v')
        if hasattr(self._play_context, 'plink_args') and self._play_context.plink_args:
            _ = ' '.split(self._play_context.plink_args)
            options.extend(_)
            self._display.vvvvv('PLINK: ansible.cfg set plink_args : ({:s})'.format(')('.join(_), host=self._play_context.remote_addr))
        if not C.HOST_KEY_CHECKING:
            pass
        if self._play_context.private_key_file:
            _ = '-i "{:s}"'.format(os.path.expanduser(self._play_context.private_key_file))
            options.append(_)
            self._display.vvvvv('PLINK: ANSIBLE_PRIVATE_KEY_FILE/private_key_file/ansible_ssh_private_key_file set : ({:s})'.format(_, host=self._play_context.remote_addr))
        args['options'] = ' '.join(options)

        # and we're done
        return '{:s} {:s}'.format(program, self.command.format(**args))

    def _connect(self):
        self._connected = True

    @staticmethod
    def _escape(string, characters):
        res,characters = string,list(characters)
        while len(characters) > 0:
            ch = characters.pop(0)
            res = res.replace(ch, '\\'+ch)
        return res

    def plink(self, command):
        state = type('', (object,), {})
        # plink
        def sendHostkey((s,n), self=self, state=state):
            self._display.debug("Ignoring value of HOST_KEY_CHECKING variable : {!r}".format(C.HOST_KEY_CHECKING))
            # FIXME: check if user wants to accept hostkey
            state.P.write("n\n")
        def sendUsername((s,n), self=self, state=state):
            state.P.write(self._play_context.remote_user + "\n")
        def sendPassword((s,n), self=self, state=state):
            state.P.write(self._play_context.password + "\n")
        self.plinkmachine.handle('Hostkey', sendHostkey)
        self.plinkmachine.handle('Username', sendUsername)
        self.plinkmachine.handle('Password', sendPassword)

        #shell
        def becomePassPrompt((s,n), self=self, state=state):
            self._display.debug('Sending become_pass in response to prompt')
            state.P.write(self._play_context.become_pass + '\n')
        def escalationSuccess((s,n), self=self, state=state):
            self._display.debug('Escalation succeeded')
        def escalationFailure((s,n), self=self, state=state):
            state.P.kill()
            if n == State.ErrorRepeat:
                raise AnsibleError('Incorrect %s password'% self._play_context.become_method)
            elif n == State.ErrorInvalid:
                raise AnsibleError('Incorrect %s password'% self._play_context.become_method)
            elif n == State.ErrorMissing:
                raise AnsibleError('Missing %s password'% self._play_context.become_method)
            raise AnsibleError('Invalid state transition %r -> %r'% (s,n))
        self.shellmachine.handle('becomePass', becomePassPrompt)
        self.shellmachine.handle('escalateSuccess', escalationSuccess)
        self.shellmachine.handle('escalateError', escalationFailure)

        state.stdout = array.array('c')
        state.stderr = array.array('c')
        def monitor(self, state):
            st,data1 = None,''
            try:
                while st != State.Exit:
                    ch = (yield)
                    data1 += ch
                    st = state.plinkmachine.send(ch)
            finally:
                self._display.debug('data1:{!r}'.format(data1))
            if self.plinkmachine._lasterror:
                self._display.debug("Fatal error:")
                map(self._display.debug,self.plinkmachine._lasterror)
                state.P.stop()
                return

            self._display.debug("Authenticated:")
            st,data2 = None,''
            try:
                while st != State.Exit:
                    ch = (yield)
                    data2 += ch
                    print data2
                    #st = state.shellmachine.send(ch)
            finally:
                self._display.debug('data2:{!r}'.format(data2))
            state.stdout = array.array('c',data2)
            state.stderr = array.array('c')
            return

        # initialize plink machine
        state.plinkmachine = self.plinkmachine.iterate()
        state.plinkmachine.next()

        # initialize shell machine
        if 'ssh' in command and self._play_context.prompt:
            state.shellmachine = self.shellmachine.iterate(State.Start)
        elif 'ssh' in command and self._play_context.become and self._play_contxt.success_key:
            state.shellmachine = self.shellmachine.iterate(State.Escalation)
        else:
            state.shellmachine = self.shellmachine.iterate(State.Exit)
        state.shellmachine.next()
        #M.set(State.Start)          # 'ssh' in cmd and self._play_context.prompt
        #M.set(State.Escalation)     # 'ssh' in cmd and self._play_context.become and self._play_context.success_key
        #M.set(State.Exit)           # 'ssh' not in cmd

        #state.P = expect.spawn(_monitor_command(self, state, Output), command, stderr=_monitor_output(state, Error))
        self._display.debug("Spawning {!r}".format(command))
        state.P = expect.spawn(monitor(self, state), command, show=True)
        return state

    def exec_command(self, cmd, in_data=None, sudoable=True):
        super(Connection, self).exec_command(cmd=cmd, in_data=in_data, sudoable=sudoable)
        self._display.vvv("ESTABLISH SSH CONNECTION FOR USER: {0}".format(self._play_context.remote_user), host=self._play_context.remote_addr)

        command = self._get_command(Executable['plink']) + ' "{:s}"'.format(cmd.replace('"', '\\"'))
        self._display.vvvvv("Executing {!r}".format(command))
        st = self.plink(command)
        self._display.debug("Waiting")

        returncode = st.P.wait()

        self._display.debug("Done {!r}".format(returncode))
        assert not st.P.running

#        Output,Error = array.array('c'),array.array('c')
#        state = type('', (object,), {})
#        state.CaptureOutput = False
#        def _monitor_output(state, Error):
#            while not state.CaptureOutput:
#                data = yield
#                state.P.updater.stdout.send(data)
#            while state.CaptureOutput:
#                data = yield
#                Error += array.array('c',data)
#            return
#        def _monitor_command(self, state, Output):
#            # privilege escalation from ssh's _exec_command
#            if self._play_context.prompt:
#                self._display.debug("Handling privilege escalation password prompt.")
#                if self._play_context.become and self._play_context.become_pass:
#                    authenticated = None
#                    tick = tock = time.time()
#                    while state.P.running and tock-tick < self._play_context.tieout:
#                        self._display.debug('Waiting for Privilege Escalation input')
#                        input = yield
#                        if self.check_become_success(input):
#                            self._display.debug('Succeded!')
#                            authenticated = True
#                            break
#                        elif self.check_password_prompt(input):
#                            self._display.debug("Password prompt! Sending privilege escalation password.")
#                            state.P.write(self._play_context.become_pass + '\n')
#                            break
#                        elif self.check_incorrect_password(input):
#                            self._display.debug('Invalid password!')
#                            authenticated = False
#                            break
#                        else:
#                            self._display.debug("Unknown input: {:s}".format(input))
#                        tock = time.time()
#                self._display.debug("Handled privilege escalation password prompt.")
#
#            # now from _communicate
#            if in_data is not None:
#                state.P.write(in_data)
#
#            # capture stdout/stderr
#            state.CaptureOutput = True
#            while True:
#                input = yield
#                if self._play_context.become and sudoable:
#                    if self._play_context.become_pass and authenticated == False:
#                        raise AnsibleError, 'Incorrect %s password' % self._play_context.become_method
#                    elif self.check_password_prompt(input) and authenticated == None:
#                        raise AnsibleError, 'Missing %s password' % self._play_context.become_method
#                Output += array.array('c',(input))
#            return

        # FIXME: handle this the way that ansible is supposed to handle it
#        self._display.vvv("ESTABLISH SSH CONNECTION FOR USER: {0}".format(self._play_context.remote_user), host=self._play_context.remote_addr)
#        command = self._get_command(Executable['plink']) + ' "{:s}"'.format(cmd.replace('"', '\\"'))
#        self._display.vvvvv("Executing {!r}".format(command))
#        state.P = portable.spawn(_monitor_command(self, state, Output), command, stderr=_monitor_output(state, Error))
#        returncode = state.P.wait()
#        assert not state.P.running
        return (returncode, st.stdout.tostring(), st.stderr.tostring())

    def put_file(self, in_path, out_path):
        super(Connection, self).put_file(in_path, out_path)

        Output = array.array('c')
        def _monitor_psftp(write, Output):
            while 'psftp>' not in (yield): pass
            write('put "{:s}" "{:s}"\n'.format(self._escape(in_path,'"'),self._escape(out_path,'"')))

            res = ''
            while 'psftp>' not in res:
                res = yield
                Output += array.array('c',res)
            write('exit\n')

        self._display.vvv("PUT {0} TO {1}".format(in_path, out_path), host=self.host)
        command = self._get_command(Executable['psftp'])
        p = portable.spawn(_monitor_psftp(p.write, Output), command)
        returncode = p.wait()
        assert not p.running

        # FIXME
        if returncode != 0:
            raise AnsibleError, "failed to transfer file to {0}:\n{1}".format(out_path, Output.tostring())

    def fetch_file(self, in_path, out_path):
        super(Connection, self).fetch_file(in_path, out_path)

        Output = array.array('c')
        def _monitor_psftp(write, Output):
            while 'psftp>' not in (yield): pass
            write('get "{:s}" "{:s}"\n'.format(self._escape(in_path, '"'),self._escape(out_path, '"')))

            res = ''
            while 'psftp>' not in res:
                res = yield
                Output += array.array('c',res)
            write('exit\n')

        self._display.vvv("FETCH {0} TO {1}".format(in_path, out_path), host=self.host)
        command = self._get_command(Executable['psftp'])
        p = portable.spawn(_monitor_psftp(p.write, Output), command)
        returncode = p.wait()
        assert not p.running

        # FIXME
        if returncode != 0:
            raise AnsibleError, "failed to transfer file from {0}:\n{1}".format(in_path, ''.join(Output))

    def close(self):
        super(Connection, self).close()
        self._connected = False

if __name__ == '__main__':
    pass

hostkey = """
#c:\Users\aliri\tools\plink.EXE -C -P 22 -l user -i "./lin-xubu-x86.priv" 172.22.22.120 "(umask 22 && mkdir -p \"$(echo $HOME/.ansible/tmp/ansible-tmp-1446123732.63-161318690911470)\" && echo \"$(echo $HOME/.ansible/tmp/ansible-tmp-1446123732.63-161318690911470)\")"
# with key, user, invalid pass
The server's host key is not cached in the registry. You
have no guarantee that the server is the computer you
think it is.
The server's rsa2 key fingerprint is:
ssh-rsa 2048 b3:32:69:15:38:80:84:d3:74:37:92:fb:f3:02:3d:60
If you trust this host, enter "y" to add the key to
PuTTY's cache and carry on connecting.
If you want to carry on connecting just once, without
adding the key to the cache, enter "n".
If you do not trust this host, press Return to abandon the
connection.
Store key in cache? (y/n) n
"""

errorhostkey = """Unable to use key file "./lin-xubu-x86.priv" (OpenSSH SSH-2 private key)"""

usingusername = """Using username "user"."""

passwordprompt = """user@172.22.22.120's password:"""
passworddeny = """Access denied"""
error = """FATAL ERROR: Server sent disconnect message"""
error = """type 2 (protocol error):"""
"Too many authentication failures for user"

invalidkey = """Unable to use key file "./lin-xubu-x86.priv" (OpenSSH SSH-2 private key)"""
banner = """
Welcome to Ubuntu 14.04.3 LTS (GNU/Linux 3.16.0-30-generic i686)

 * Documentation:  https://help.ubuntu.com/

11 packages can be updated.
0 updates are security updates.

Last login: Thu Oct 29 06:09:42 2015 from 172.22.22.1
addpythonpath: directory /home/user/.python does not exist
[501] user@lin-xubu-x86 ~$
"""

# with user, valid pass
"""
Using username "user".
The server's host key is not cached in the registry. You
have no guarantee that the server is the computer you
think it is.
The server's rsa2 key fingerprint is:
"""

# with user, invalid pass
"""
The server's host key is not cached in the registry. You
have no guarantee that the server is the computer you
think it is.
The server's rsa2 key fingerprint is:
ssh-rsa 2048 b3:32:69:15:38:80:84:d3:74:37:92:fb:f3:02:3d:60
If you trust this host, enter "y" to add the key to
PuTTY's cache and carry on connecting.
If you want to carry on connecting just once, without
adding the key to the cache, enter "n".
If you do not trust this host, press Return to abandon the
connection.
Store key in cache? (y/n) n
"""

invalidpass = """
Access denied
user@172.22.22.120's password:
Access denied
user@172.22.22.120's password:
Access denied
user@172.22.22.120's password:
Access denied
user@172.22.22.120's password:
Access denied
user@172.22.22.120's password:
"""
FATAL ERROR: Server sent disconnect message
type 2 (protocol error):
"Too many authentication failures for user"

# without user, valid pass
The server's host key is not cached in the registry. You
have no guarantee that the server is the computer you
think it is.
The server's rsa2 key fingerprint is:
ssh-rsa 2048 b3:32:69:15:38:80:84:d3:74:37:92:fb:f3:02:3d:60
If you trust this host, enter "y" to add the key to
PuTTY's cache and carry on connecting.
If you want to carry on connecting just once, without
adding the key to the cache, enter "n".
If you do not trust this host, press Return to abandon the
connection.
Store key in cache? (y/n) n
loginuser = """login as: user"""
The server's host key is not cached in the registry. You
have no guarantee that the server is the computer you
think it is.
The server's rsa2 key fingerprint is:
ssh-rsa 2048 b3:32:69:15:38:80:84:d3:74:37:92:fb:f3:02:3d:60
If you trust this host, enter "y" to add the key to
PuTTY's cache and carry on connecting.
If you want to carry on connecting just once, without
adding the key to the cache, enter "n".
If you do not trust this host, press Return to abandon the
connection.
Store key in cache? (y/n) n
Welcome to Ubuntu 14.04.3 LTS (GNU/Linux 3.16.0-30-generic i686)

 * Documentation:  https://help.ubuntu.com/

11 packages can be updated.
0 updates are security updates.

Last login: Thu Oct 29 13:56:12 2015 from 172.22.22.1
addpythonpath: directory /home/user/.python does not exist
[501] user@lin-xubu-x86 ~$

#without user, invalid pass
The server's host key is not cached in the registry. You
have no guarantee that the server is the computer you
think it is.
The server's rsa2 key fingerprint is:
ssh-rsa 2048 b3:32:69:15:38:80:84:d3:74:37:92:fb:f3:02:3d:60
If you trust this host, enter "y" to add the key to
PuTTY's cache and carry on connecting.
If you want to carry on connecting just once, without
adding the key to the cache, enter "n".
If you do not trust this host, press Return to abandon the
connection.
Store key in cache? (y/n) n
login as: user
Access denied
user@172.22.22.120's password:
Access denied
user@172.22.22.120's password:
Access denied
user@172.22.22.120's password:
Access denied
user@172.22.22.120's password:
Access denied
user@172.22.22.120's password:
FATAL ERROR: Server sent disconnect message
type 2 (protocol error):
"Too many authentication failures for user"

# without user, invalid key
The server's host key is not cached in the registry. You
have no guarantee that the server is the computer you
think it is.
The server's rsa2 key fingerprint is:
ssh-rsa 2048 b3:32:69:15:38:80:84:d3:74:37:92:fb:f3:02:3d:60
If you trust this host, enter "y" to add the key to
PuTTY's cache and carry on connecting.
If you want to carry on connecting just once, without
adding the key to the cache, enter "n".
If you do not trust this host, press Return to abandon the
connection.
Store key in cache? (y/n) n
Unable to use key file "./lin-xubu-x86.priv" (OpenSSH SSH-2 private key)
login as: user
user@172.22.22.120's password:

# no user, valid key
The server's host key is not cached in the registry. You
have no guarantee that the server is the computer you
think it is.
The server's rsa2 key fingerprint is:
ssh-rsa 2048 b3:32:69:15:38:80:84:d3:74:37:92:fb:f3:02:3d:60
If you trust this host, enter "y" to add the key to
PuTTY's cache and carry on connecting.
If you want to carry on connecting just once, without
adding the key to the cache, enter "n".
If you do not trust this host, press Return to abandon the
connection.
Store key in cache? (y/n) n
login as: user
The server's host key is not cached in the registry. You
have no guarantee that the server is the computer you
think it is.
The server's rsa2 key fingerprint is:
ssh-rsa 2048 b3:32:69:15:38:80:84:d3:74:37:92:fb:f3:02:3d:60
If you trust this host, enter "y" to add the key to
PuTTY's cache and carry on connecting.
If you want to carry on connecting just once, without
adding the key to the cache, enter "n".
If you do not trust this host, press Return to abandon the
connection.
Store key in cache? (y/n) n
Welcome to Ubuntu 14.04.3 LTS (GNU/Linux 3.16.0-30-generic i686)

 * Documentation:  https://help.ubuntu.com/

11 packages can be updated.
0 updates are security updates.

Last login: Thu Oct 29 13:57:53 2015 from 172.22.22.1
addpythonpath: directory /home/user/.python does not exist

# user, valid key
The server's host key is not cached in the registry. You
have no guarantee that the server is the computer you
think it is.
The server's rsa2 key fingerprint is:
ssh-rsa 2048 b3:32:69:15:38:80:84:d3:74:37:92:fb:f3:02:3d:60
If you trust this host, enter "y" to add the key to
PuTTY's cache and carry on connecting.
If you want to carry on connecting just once, without
adding the key to the cache, enter "n".
If you do not trust this host, press Return to abandon the
connection.
Store key in cache? (y/n) n
Using username "user".
The server's host key is not cached in the registry. You
have no guarantee that the server is the computer you
think it is.
The server's rsa2 key fingerprint is:
ssh-rsa 2048 b3:32:69:15:38:80:84:d3:74:37:92:fb:f3:02:3d:60
If you trust this host, enter "y" to add the key to
PuTTY's cache and carry on connecting.
If you want to carry on connecting just once, without
adding the key to the cache, enter "n".
If you do not trust this host, press Return to abandon the
connection.
Store key in cache? (y/n) n
Welcome to Ubuntu 14.04.3 LTS (GNU/Linux 3.16.0-30-generic i686)

 * Documentation:  https://help.ubuntu.com/

11 packages can be updated.
0 updates are security updates.

Last login: Thu Oct 29 14:02:16 2015 from 172.22.22.1
addpythonpath: directory /home/user/.python does not exist
[501] user@lin-xubu-x86 ~$
"""
