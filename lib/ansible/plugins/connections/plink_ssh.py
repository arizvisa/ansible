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

import ansible
from ansible.errors import AnsibleError, AnsibleConnectionFailure, AnsibleFileNotFound
from ansible.plugins.connections import ConnectionBase
import portable

Executables = {
    'plink' : portable.which('plink'),
}

class Connection(ConnectionBase):
    ''' ssh based connections '''

    Cache = {}

    def __init__(self, *args, **kwargs):
        super(Connection, self).__init__(*args, **kwargs)
        self.args = args = {}
        self.command = '-s -C -P {port} -l {user} {options} {host}'

    @property
    def transport(self):
        ''' used to identify this connection object from other classes '''
        return 'plink'

    def _get_command(self, program):
        args = self.args
        # general options
        args['host'] = self._play_context.remote_addr
        if self._play_context.remote_user:
            args['user'] = '{:s}'.format(self._play_context.remote_user)
            self._display.vvvvv('PLINK: ANSIBLE_REMOTE_USER/remote_user/ansible_user/user/-u set : ({:s})'.format(_, host=self._play_context.remote_addr))

        if self._play_context.port is not None:
            args['port'] = '{:d}'.format(self._play_context.port)
        else:
            args['port'] = ansible.constants.DEFAULT_REMOTE_PORT or 22

        # custom options
        options = []
        if self._play_context.password:
            options.append('-pw "{:s}"'.format(self._play_context.password)
        if self._play_context.verbosity > 3:
            options.append('-v')
        if self._play_context.plink_args:
            _ = ' '.split(self._play_context.plink_args)
            options.extend(_)
            self._display.vvvvv('PLINK: ansible.cfg set plink_args : ({:s})'.format(')('.join(_), host=self._play_context.remote_addr))
        if not C.HOST_KEY_CHECKING:
            pass
        if self._play_context.private_key_file:
            _ = '-i "{:s}"'.format(os.path.expanduser(self._play_context.private_key_file)
            options.append(_)
            self._display.vvvvv('PLINK: ANSIBLE_PRIVATE_KEY_FILE/private_key_file/ansible_ssh_private_key_file set : ({:s})'.format(_, host=self._play_context.remote_addr))
        args['options'] = ' '.join(options)

        # and we're done
        return '"{:s}" {:s}'.format(program, self.command.format(**args))

    def who_is_the_lamest_of_them_all(self):
        done = False
        def check(data):
            if "(y/n)" in data:
                p.write('y\n')
                done = True
            return

        # is it putty, or is it ansible...
        if not ansible.constant.HOST_KEY_CHECKING:
            p = portable.spawn(check, '{:s} nobody@{:s} exit'.format(Executable['plink'], self._play_context.remote_addr)
            tick = tock = time.time()
            while not done and p.running and tock-tick < self._play_context.timeout:
                tock = time.time()
            if tock-tick >= self._play_context.timeout:
                self._display.vv('PLINK: Host key acceptance check has timed out', host=self._play_context.remote_addr)
            if p.running: p.stop()
        return

    def _connect(self):
        self._connected = True
        who_is_the_lamest_of_them_all()

    @staticmethod
    def _escape(string, characters):
        res,characters = string,list(characters)
        while len(characters) > 0:
            ch = characters.pop(0)
            res = res.replace(ch, '\\'+ch)
        return res

    def exec_command(self, cmd, tmp_path, in_data=None, executable=None, sudoable=True):
        super(Connection, self).exec_command(cmd=cmd, tmp_path=tmp_path, in_data=in_data, executable=executable, sudoable=sudoable)

        Output,Error = [],[]
        CaptureOutput = False
        def _monitor_output(self=self, Output=Output, Error=Error):
            while CaptureOutput == False:
                P.updater.stdout.send(yield)
            while CaptureOutput:
                Error.append(yield)
            return
        def _monitor_command(self=self, Output=Output):
            # privilege escalation from ssh's _exec_command
            if self._play_context.prompt:
                self._display.debug("Handling privilege escalation password prompt.")
                if self._play_context.become and self._play_context.become_pass:
                    authenticated = None
                    tick = tock = time.time()
                    while P.running and tock-tick < self._play_context.tieout:
                        self._display.debug('Waiting for Privilege Escalation input')
                        input = yield
                        if self.check_become_success(input):
                            self._display.debug('Succeded!')
                            authenticated = True
                            break
                        elif self.check_password_prompt(input):
                            self._display.debug("Password prompt! Sending privilege escalation password.")
                            P.write(self._play_context.become_pass + '\n')
                            break
                        elif self.check_incorrect_password(input):
                            self._display.debug('Invalid password!')
                            authenticated = False
                            break
                        else:
                            self._display.debug("Unknown input: {:s}".format(input))
                        tock = time.time()
                self._display.debug("Handled privilege escalation password prompt.")

            # now from _communicate
            if in_data is not None:
                P.write(in_data)

            # capture stdout/stderr
            CaptureOutput = True
            while True:
                input = yield
                if self._play_context.become and sudoable:
                    if self._play_context.become_pass and authenticated == False:
                        raise AnsibleError, 'Incorrect %s password' % self._play_context.become_method
                    elif self.check_password_prompt(input) and authenticated == None:
                        raise AnsibleError, 'Missing %s password' % self._play_context.become_method
                Output.append(input)
            return

        # FIXME: handle this the way that ansible is supposed to handle it
        self._display.vvv("ESTABLISH SSH CONNECTION FOR USER: {0}".format(self._play_context.remote_user), host=self._play_context.remote_addr)
        command = self._get_command(Executable['plink']) + ' ' + cmd.replace('"', '\\"')
        P = portable.spawn(_monitor_command(), command, stderr=_monitor_output())
        returncode = P.wait()
        assert not p.running:
        stdout,stderr = ''.join(Output),''.join(Error)
        return (returncode, stdout, stderr)

    def put_file(self, in_path, out_path):
        super(Connection, self).put_file(in_path, out_path)

        Output = []
        def _monitor_psftp(write, Output=Output):
            while 'psftp>' not in (yield): pass
            write('put "{:s}" "{:s}"\n'.format(self._escape(in_path,'"'),self._escape(out_path,'"')))

            res = ''
            while 'psftp>' not in res:
                res = yield
                Output.append(res)
            write('exit\n')

        self._display.vvv("PUT {0} TO {1}".format(in_path, out_path), host=self.host)
        command = self._get_command(Executable['psftp'])
        p = portable.spawn(_monitor_psftp(p.write), command)
        returncode = p.wait()
        assert not p.running

        # FIXME
        if returncode != 0:
            raise AnsibleError, "failed to transfer file to {0}:\n{1}".format(out_path, ''.join(Output))

    def fetch_file(self, in_path, out_path):
        super(Connection, self).fetch_file(in_path, out_path)

        Output = []
        def _monitor_psftp(write, Output=Output):
            while 'psftp>' not in (yield): pass
            write('get "{:s}" "{:s}"\n'.format(self._escape(in_path, '"'),self._escape(out_path, '"')))

            res = ''
            while 'psftp>' not in res:
                res = yield
                Output.append(res)
            write('exit\n')

        self._display.vvv("FETCH {0} TO {1}".format(in_path, out_path), host=self.host)
        command = self._get_command(Executable['psftp'])
        p = portable.spawn(_monitor_psftp(p.write), command)
        returncode = p.wait()
        assert not p.running

        # FIXME
        if returncode != 0:
            raise AnsibleError, "failed to transfer file from {0}:\n{1}".format(in_path, ''.join(Output))

    def close(self):
        super(Connection, self).close()
        self._connected = False

    # ansible methods that were copied from the base class
    def check_become_success(self, output):
        return self._play_context.success_key in output

    def check_password_prompt(self, output):
        if self._play_context.prompt is None:
            return False
        elif isinstance(self._play_context.prompt, basestring):
            return output.endswith(self._play_context.prompt)
        else:
            return self._play_context.prompt(output)

    def check_incorrect_password(self, output):
        incorrect_password = gettext.dgettext(self._play_context.become_method, C.BECOME_ERROR_STRINGS[self._play_context.become_method])
        return True if incorrect_password in output else False

