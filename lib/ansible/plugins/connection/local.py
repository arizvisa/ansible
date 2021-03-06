# (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
# (c) 2015 Toshio Kuratomi <tkuratomi@ansible.com>
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
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import traceback
import os
import portable,array
import shutil
import time

import ansible.constants as C

from ansible.errors import AnsibleError, AnsibleFileNotFound
from ansible.plugins.connection import ConnectionBase

class Connection(ConnectionBase):
    ''' Local based connections '''

    def __init__(self, *args, **kwargs):
        if os.name == 'nt':
            self._shell_type = 'powershell'
            self._shell_location = portable.which('Powershell')
            #self.module_implementation_preferences = ('.ps1', '')
            #self.become_methods_supported=[]
        super(Connection, self).__init__(*args, **kwargs)

    @property
    def transport(self):
        ''' used to identify this connection object '''
        return 'local'

    def _connect(self, port=None):
        ''' connect to the local host; nothing to do here '''

        if not self._connected:
            self._display.vvv("ESTABLISH LOCAL CONNECTION FOR USER: {0}".format(self._play_context.remote_user, host=self._play_context.remote_addr))
            self._connected = True
        return self

    def exec_command(self, cmd, in_data=None, sudoable=True):
        ''' run a command on the local host '''

        super(Connection, self).exec_command(cmd, in_data=in_data, sudoable=sudoable)

        self._display.debug("in local.exec_command()")

        if in_data:
            raise AnsibleError("Internal Error: this module does not support optimized module pipelining")
        executable = C.DEFAULT_EXECUTABLE.split()[0] if C.DEFAULT_EXECUTABLE else None

        self._display.vvv("{0} EXEC {1}".format(self._play_context.remote_addr, cmd))

        def process_stdout(chunk, output):
            if not chunk:
                raise AnsibleError('privilege output closed while waiting for password prompt:\n' + become_output.tostring())
            output += array.array('c', chunk)
        def process_stderr(chunk, output, error):
            if not chunk:
                raise AnsibleError('privilege output closed while waiting for password prompt:\n' + become_output.tostring())
            if os.name != 'nt':
                output += array.array('c', chunk)
            error += array.array('c', chunk)

        # FIXME: cwd= needs to be set to the basedir of the playbook
        become_output,become_error = array.array('c'),array.array('c')
        self._display.debug("opening command with portable.spawn()")
        # FIXME: cmd= needs to be tested
        if self._shell_type == 'powershell':
            #p = portable.spawn(lambda data,output=become_output: process_stdout(data, output), "\"{:s}\" -encodeCommand \"{:s}\"".format(pspath, cmd.encode('base64')), stderr=lambda data,output=become_output,error=become_error:process_stderr(data,output,error), shell=isinstance(cmd,basestring))
            p = portable.spawn(lambda data,output=become_output: process_stdout(data, output), "\"{:s}\" -Command \"{:s}\"".format(self._shell_location, cmd), stderr=lambda data,output=become_output,error=become_error:process_stderr(data,output,error), shell=False)
        else:
            p = portable.spawn(lambda data,output=become_output: process_stdout(data, output), cmd, stderr=lambda data,output=become_output,error=become_error:process_stderr(data,output,error), shell=False)
        self._display.debug("done running command with portable.spawn()")

        if self._play_context.prompt and self._play_context.become_pass and sudoable:
            tick = tock = time.now()
            while p.running and not self.check_become_success(become_output.tostring()) and (tock - tick) < self._play_context.timeout:
                p.write(self._play_context.become_pass + '\n')
                tock = time.now()
            if tock-tick >= self._play_context.timeout:
                raise AnsibleError('timeout waiting for privilege escalation password prompt:\n' + become_output.tostring())
            if not self.check_become_success(become_output.tostring()):
                p.write(self._play_context.become_pass + '\n')

        self._display.debug("getting output with communicate()")
        returncode = p.wait()
        self._display.debug("done communicating")

        self._display.debug("done with local.exec_command()")
        return (returncode, become_output.tostring(), become_error.tostring())

    def put_file(self, in_path, out_path):
        ''' transfer a file from local to local '''

        super(Connection, self).put_file(in_path, out_path)

        if self._shell_type == 'powershell':
            out_path = self._shell._unquote(out_path)

        self._display.vvv("{0} PUT {1} TO {2}".format(self._play_context.remote_addr, in_path, out_path))
        if not os.path.exists(in_path):
            raise AnsibleFileNotFound("file or module does not exist: {0}".format(in_path))
        try:
            shutil.copyfile(in_path, out_path)
        except shutil.Error:
            raise AnsibleError("failed to copy: {0} and {1} are the same".format(in_path, out_path))
        except IOError as e:
            raise AnsibleError("failed to transfer file from {0} to {1}: {2}".format(in_path, out_path, e))

    def fetch_file(self, in_path, out_path):
        ''' fetch a file from local to local -- for copatibility '''

        super(Connection, self).fetch_file(in_path, out_path)

        self._display.vvv("{0} FETCH {1} TO {2}".format(self._play_context.remote_addr, in_path, out_path))
        self.put_file(in_path, out_path)

    def close(self):
        ''' terminate the connection; nothing to do here '''
        self._connected = False
