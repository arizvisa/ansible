# (c) 2012-2014, Michael DeHaan <michael.dehaan@gmail.com>
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

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import sys,time,traceback
import gevent
import gevent.queue
import gevent.pool
import gevent.monkey
from gevent.queue import Queue
from gevent.pool import Pool

#from ansible.playbook.handler import Handler
#from ansible.playbook.task import Task
from ansible.errors import AnsibleError, AnsibleConnectionFailure
from ansible.executor.task_executor import TaskExecutor
from ansible.executor.task_result import TaskResult

from ansible.utils.debug import debug

class IOGenerator(object):
    __slots__ = ['task','input','output','attributes','running']
    def __init__(self, input=None, output=None, **attributes):
        self.input = input or Queue()
        self.output = output or Queue()
        self.attributes = attributes
        self.running = True
        self.task = gevent.spawn(self)
        return
    def send(self, result):
        self.output.put(result)
    def run(self, input):
        raise NotImplementedError
    def exception(self, record, (type, value, trace)):
        raise NotImplementedError
    def __call__(self, *args, **kwds):
        while self.task:
            gevent.idle()
            record = self.input.get()
            try:
                res = self.run(record)
            except (IOError, EOFError, KeyboardInterrupt):
                break
            except:
                res = self.exception(record, sys.exc_info())
            if not res:
                break
        return
    def terminate(self):
        self.task.kill()

class Worker(IOGenerator):
    _slots_ = ['_loader','_TaskExecutorPool']
    def __init__(self, output, taskpool, loader):
        super(Worker,self).__init__(output=output)
        self._loader = loader
        self._TaskExecutorPool = taskpool
        self._new_stdin = sys.stdin

    def exception(self, record, (type, value, trace)):
        (host, task, basedir, job_vars, play_context, shared_loader_obj) = record
        if type == AnsibleConnectionFailure:
            try:
                if task:
                    result = TaskResult(host, task, dict(unreachable=True))
                    self.send(result)
            except:
                return False
            return True

        debug("WORKER EXCEPTION: %s" % value)
        debug("WORKER EXCEPTION: %s" % '\n'.join(traceback.format_exception(type, value, trace)))
        try:
            if task:
                result = TaskResult(host, task, dict(failed=True, exception='\n'.join(traceback.format_exception(type, value, trace)), stdout=''))
                self.send(result)
        except:
            return False
        return True

    def run(self, (host, task, basedir, job_vars, play_context, shared_loader_obj)):
        debug("there's work to be done!")
        debug("got a task/handler to work on: %s" % task)

        self._loader.set_basedir(basedir)
        task.set_loader(self._loader)

        debug("running TaskExecutor() for %s/%s" % (host, task))
        executor = TaskExecutor(host, task, job_vars, play_context, self._new_stdin, self._loader, shared_loader_obj)
        self._TaskExecutorPool.apply_async(executor.run, callback=(lambda result,host=host,task=task: self.send_result(result,host,task)))
        return True

    def send_result(self, result, host, task):
        debug("done running TaskExecutor() for %s/%s" % (host, task))
        res = TaskResult(host, task, result)
        self.send(res)

class Result(IOGenerator):
    def exception(self, record, (type, value, trace)):
        traceback.print_exception(type, value, trace)
        return False

    def run(self, result):
        if result._task.register:
            self.send(('register_host_var', result._host, result._task.register, result._result))
        if result.is_unreachable():
            self.send(('host_unreachable', result))
            return True
        elif result.is_failed():
            self.send(('host_task_failed', result))
            return True
        elif result.is_skipped():
            self.send(('host_task_skipped', result))
            return True

        if result._task.loop:
            result_items = result._result['results']
        else:
            result_items = [ result._result ]

        for result_item in result_items:
            if '_ansible_notify' in result_item:
                if result.is_changed():
                    for notify in result_item['_ansible_notify']:
                        if result._task._role:
                            role_name = result._task._role.get_name()
                            notify = "%s : %s" % (role_name, notify)
                        self.send(('notify_handler', result, notify))
                result_item.pop('_ansible_notify')

            if 'add_host' in result_item:
                # this task added a new host (add_host module)
                self.send(('add_host', result_item))
                return
            elif 'add_group' in result_item:
                # this task added a new group (group_by module)
                self.send(('add_group', result._task))
                return
            elif 'ansible_facts' in result_item:
                # if this task is registering facts, do that now
                item = result_item.get('item', None)
                if result._task.action in ('set_fact', 'include_vars'):
                    for (key, value) in result_item['ansible_facts'].iteritems():
                        self.send(('set_host_var', result._host, result._task, item, key, value))
                else:
                    self.send(('set_host_facts', result._host, result._task, item, result_item['ansible_facts']))
            self.send(('host_task_ok', result))
        return True
