import __builtin__,sys,os,itertools,stat
import ctypes
executable = lambda(_): os.path.isfile(_) and os.access(_,os.X_OK)
which = lambda _,envvar="PATH",extvar='PATHEXT':_ if executable(_) else iter(filter(executable,itertools.starmap(os.path.join,itertools.product(os.environ.get(envvar,os.defpath).split(os.pathsep),(_+e for e in os.environ.get(extvar,'').split(os.pathsep)))))).next()

### Constants
STD_INPUT_HANDLE = -10
STD_OUTPUT_HANDLE = -11
STD_ERROR_HANDLE = -12

LOCKFILE_EXCLUSIVE_LOCK = 0x00000002
LOCKFILE_FAIL_IMMEDIATELY = 0x00000001

### Structures
class BYTE(ctypes.c_uint8): pass
class WORD(ctypes.c_uint16): pass
class DWORD(ctypes.c_uint32): pass
class ULONG_PTR(ctypes.c_ulong if ctypes.sizeof(ctypes.c_ulong) == ctypes.sizeof(ctypes.c_voidp) else ctypes.c_uint64): pass
class PVOID(ctypes.c_voidp):pass
class HANDLE(PVOID): pass

class COORD(ctypes.Structure):
    _fields_ = [
        ('X', ctypes.c_short),
        ('Y', ctypes.c_short),
    ]
class SMALL_RECT(ctypes.Structure):
    _fields_ = [
        ('Left', ctypes.c_short),
        ('Top', ctypes.c_short),
        ('Right', ctypes.c_short),
        ('Bottom', ctypes.c_short),
    ]

class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
    _fields_ = [
        ('dwSize', COORD),
        ('dwCursorPosition', COORD),
        ('wAttributes', WORD),
        ('srWindow', SMALL_RECT),
        ('dwMaximumWindowSize', COORD),
    ]

class WINSZ(ctypes.Structure):
    _fields_ = [
        ('ws_row', ctypes.c_ushort),
        ('ws_col', ctypes.c_ushort),
        ('ws_xpixel', ctypes.c_ushort),
        ('ws_ypixel', ctypes.c_ushort),
    ]

class OVERLAPPED(ctypes.Structure):
    class POINTEROFFSET(ctypes.Union):
        class OFFSET(ctypes.Structure):
            _fields_ = [
                ('Offset', DWORD),
                ('OffsetHigh', DWORD),
            ]
        _fields_ = [
            ('Offset', OFFSET),
            ('Pointer', PVOID),
        ]
    _fields_ = [
        ('Internal', ULONG_PTR),
        ('InternalHigh', ULONG_PTR),
        ('PointerOffset', POINTEROFFSET),
        ('hEvent', HANDLE),
    ]

class LockFile(object):
    def __init__(self, path, mode='r+'):
        if isinstance(path, basestring):
            self.file = open(path, mode)
        elif isinstance(path, (int,long)):
            self.file = os.fdopen(path, mode)
        return
    def __enter__(self):
        self.acquire()
        return self.file
    def __exit__(self):
        self.release()
    def acquire(self):
        raise NotImplementedError
    def release(self):
        raise NotImplementedError

class SID:
    @staticmethod
    def unpack(sid):
        SidVersion = '-'.join(sid.split('-',2)[:2])
        SubAuthorityCount = int(sid.split('-')[2])
        assert SubAuthorityCount > 2, 'Invalid SID'
        res = sid.split('-')[3:]
        AuthorityIdentifier = int(res.pop(0))
        #FIXME: is raymond wrong when dealing with group SIDs here?
        #MachineId = map(res.pop, (0,)*(SubAuthorityCount-2))
        MachineId = map(res.pop, (0,)*(len(res)-1))
        UserId = res.pop(0)
        assert len(res) == 0, 'Invalid SID'
        return SidVersion,SubAuthorityCount,AuthorityIdentifier,map(int,MachineId),UserId
    @classmethod
    def SidVersion(cls, sid):
        return int(cls.unpack(sid)[0].split('-',1)[1])
    @classmethod
    def SubAuthority(cls, sid):
        return cls.unpack(sid)[1]
    @classmethod
    def AuthorityIdentifier(cls, sid):
        return cls.unpack(sid)[2]
    @classmethod
    def MachineIdentifier(cls, sid):
        # FIXME: raymond chen says that these should be endian-flipped.
        #        It's a unique id for machines, so it only matters if we actually
        #        compare them to another one
        return reduce(lambda t,v: t*0x100000000+v, cls.unpack(sid)[3], long(0))
    @classmethod
    def Identifier(cls, sid):
        return int(cls.unpack(sid)[4])

### Conditional Functions
if os.name == 'nt':
    from ctypes import windll
    def GetConsoleDimensions():
        h = windll.kernel32.GetStdHandle(STD_ERROR_HANDLE)
        csbi = CONSOLE_SCREEN_BUFFER_INFO()
        res = windll.kernel32.GetConsoleScreenBufferInfo(h, ctypes.pointer(csbi))
        err = windll.kernel32.GetLastError()
        if res == 0 and err != 6:
            raise RuntimeError, err
        return WINSZ(csbi.dwSize.Y, csbi.dwSize.X, csbi.dwCursorPosition.X, csbi.dwCursorPosition.Y)

    class LockFile(LockFile):
        def acquire(self):
            handle = windll.msvcrt.get_osfhandle(self.file)
            ol = OVERLAPPED()
            res = windll.kernel32.LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK, 0, 0, 0xFFFFFFFF, ctypes.pointer(ol))
            if res == 0: raise RuntimeError, 'Unable to lock file %s'% self.file.name

        def release(self):
            handle = windll.msvcrt.get_osfhandle(self.file)
            ol = OVERLAPPED()
            res = windll.kernel32.UnlockFileEx(handle, 0, 0, 0, 0xFFFFFFFF, ctypes.pointer(ol))
            if res == 0: raise RuntimeError, 'Unable to unlock file %s'% self.file.name

    import win32com.client,win32net,win32security,ntsecuritycon
    WmiClient = win32com.client.GetObject('WinMgmts://')
    def getuid():
        process = win32com.client.GetObject(r'WinMgmts:\\.\root\cimv2:Win32_Process.Handle="%s"'%str(os.getpid()))
        return SID.Identifier(process.ExecMethod_('GetOwnerSid').Sid)
    sys.modules['os'].getuid = getuid
    def geteuid():
        process = win32com.client.GetObject(r'WinMgmts:\\.\root\cimv2:Win32_Process.Handle="%s"'%str(os.getpid()))
        return SID.Identifier(process.ExecMethod_('GetOwnerSid').Sid)
    sys.modules['os'].geteuid = geteuid
    def getgid():
        process = win32com.client.GetObject(r'WinMgmts:\\.\root\cimv2:Win32_Process.Handle="%s"'%str(os.getpid()))
        account = process.ExecMethod_('GetOwner')
        groups = WmiClient.ExecQuery('Select GroupComponent From Win32_GroupUser Where PartComponent = "Win32_UserAccount.Domain=\'%s\',Name=\'%s\'"'% (account.Domain,account.User))
        firstgroup = win32com.client.GetObject(r'WinMgmts:%s'% groups[0].GroupComponent)
        return SID.Identifier(firstgroup.SID)
    sys.modules['os'].getgid = getgid
#    def isatty(fd):
#        if fd != 0:
#            raise NotImplementedError, "os.isatty({:d}) not implemented on windows".format(fd)
#        return False
#    sys.modules['os'].isatty = isatty

    def chmod(path, mode):
        # get the ugo out of the dacl
        Everyone,_,_ = win32security.LookupAccountName("", "Everyone")
        User,Group = None,None

        import pwd
        sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        for index in xrange(dacl.GetAceCount()):
            _,_,sid = dacl.GetAce(index)
            name,domain,sidtype = win32security.LookupAccountSid(None,sid)

            # figure out the account type
            if sidtype == ntsecuritycon.SidTypeUser and User is None:
                User = sid
            if sidtype == ntsecuritycon.SidTypeGroup and Group is None:
                Group = sid
            continue

        # default to Guest
        if User is None:
            User,_,_ = win32security.LookupAccountName("", "Guest")
        # find the first group associated with User
        if Group is None:
            name,domain,_ = win32security.LookupAccountSid(None,User)
            acct = pwd.Query.ByName(domain,name)
            Group = pwd.Query.Group(acct)['user_sid']

        # generate ACL from mode
        dacl = win32security.ACL()
        res = 0
        if mode & stat.S_IXOTH:
            res |= ntsecuritycon.FILE_GENERIC_EXECUTE
        if mode & stat.S_IWOTH:
            res |= ntsecuritycon.FILE_GENERIC_WRITE
        if mode & stat.S_IROTH:
            res |= ntsecuritycon.FILE_GENERIC_READ
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, res, Everyone)
        res = 0
        if mode & stat.S_IXGRP:
            res |= ntsecuritycon.FILE_GENERIC_EXECUTE
        if mode & stat.S_IWGRP:
            res |= ntsecuritycon.FILE_GENERIC_WRITE
        if mode & stat.S_IRGRP:
            res |= ntsecuritycon.FILE_GENERIC_READ
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, res, Group)
        res = 0
        if mode & stat.S_IXUSR:
            res |= ntsecuritycon.FILE_GENERIC_EXECUTE
        if mode & stat.S_IWUSR:
            res |= ntsecuritycon.FILE_GENERIC_WRITE
        if mode & stat.S_IRUSR:
            res |= ntsecuritycon.FILE_GENERIC_READ
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, res, User)

        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        res = win32security.SetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION, sd)
        return -1 if res == 0 else 0
    sys.modules['os'].chmod = chmod

    def lchown(path,uid,gid):
        return chown(path,uid,gid)
    sys.modules['os'].lchown = lchown

    def chown(path, uid, gid):
        # get the sid for the uid, and the gid
        user = group = None
        import pwd,grp
        for acct in pwd.Query.All():
            id = SID.Identifier(win32security.ConvertSidToStringSid(acct['user_sid']))
            if id == uid and acct.SidType == ntsecuritycon.SidTypeUser:
                user = acct['user_sid']
                break
            continue
        for acct in grp.Query.All():
            id = SID.Identifier(win32security.ConvertSidToStringSid(acct['user_sid']))
            if id == gid and acct.SidType == ntsecuritycon.SidTypeGroup:
                group = acct['user_sid']
                break
            continue

        # ripped from http://timgolden.me.uk/python/win32_how_do_i/add-security-to-a-file.html#the-short-version
        sd = win32security.GetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION)

        # grab original owner
        if user is None and uid != -1:
            user = sd.GetSecurityDescriptorOwner()
        if group is None and gid != -1:
            name,domain,_ = win32security.LookupAccountSid(None,user)
            acct = pwd.Query.ByName(domain,name)
            group = pwd.Query.Group(acct)['user_sid']

        if uid != -1:
            sd.SetSecurityDescriptorOwner(user, True)
        if gid != -1:
            sd.SetSecurityDescriptorGroup(group, True)

        res = win32security.SetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION, sd)
        return -1 if res == 0 else 0
    sys.modules['os'].chown = chown

else:
    import termios
    def GetConsoleDimensions():
        ws = WINSZ()
        res = fcntl.ioctl(0, termios.TIOCGWINSZ, ctypes.pointer(ws))
        if res != 0:
            raise RuntimeError, res
        return ws

    import fcntl
    class LockFile(LockFile):
        def acquire(self):
            res = fcntl.lockf(self.file, fcntl.LOCK_EX)
            if res != 0: raise RuntimeError, res
        def release(self):
            res = fcntl.lockf(self.file, fcntl.LOCK_UN)
            if res != 0: raise RuntimeError, res

    def getuid():
        return os.getuid()
    def geteuid():
        return os.geteuid()
    def getgid():
        return os.getgid()
    def chown(*args,**kwds):
        return os.chown(*args, **kwds)
    def lchown(*args,**kwds):
        return os.lchown(*args, **kwds)

### Asynchronous process monitoring
import sys,os,threading,weakref,subprocess,time,itertools,operator
#import logging
#assert len(logging.root.handlers) == 0
#logging.basicConfig(level=logging.DEBUG)

# monitoring an external process' i/o via threads/queues
class process(object):
    """Spawns a program along with a few monitoring threads for allowing asynchronous(heh) interaction with a subprocess.

    mutable properties:
    program -- subprocess.Popen instance
    commandline -- subprocess.Popen commandline
    eventWorking -- threading.Event() instance for signalling task status to monitor threads
    stdout,stderr -- callables that are used to process available work in the taskQueue

    properties:
    id -- subprocess pid
    running -- returns true if process is running and monitor threads are workingj
    working -- returns true if monitor threads are working
    threads -- list of threads that are monitoring subprocess pipes
    taskQueue -- Queue.Queue() instance that contains work to be processed
    exceptionQueue -- Queue.Queue() instance containing exceptions generated during processing
    (process.stdout, process.stderr)<Queue> -- Queues containing output from the spawned process.
    """

    program = None              # subprocess.Popen object
    id = property(fget=lambda s: s.program and s.program.pid or -1)
    running = property(fget=lambda s: False if s.program is None else s.program.poll() is None)
    working = property(fget=lambda s: s.running and not s.eventWorking.is_set())
    threads = property(fget=lambda s: list(s.__threads))

    taskQueue = property(fget=lambda s: s.__taskQueue)
    exceptionQueue = property(fget=lambda s: s.__exceptionQueue)

    def __init__(self, command, **kwds):
        """Creates a new instance that monitors subprocess.Popen(/command/), the created process starts in a paused state.

        Keyword options:
        env<dict> = os.environ -- environment to execute program with
        cwd<str> = os.getcwd() -- directory to execute program  in
        shell<bool> = True -- whether to treat program as an argument to a shell, or a path to an executable
        newlines<bool> = True -- allow python to tamper with i/o to convert newlines
        show<bool> = False -- if within a windowed environment, open up a console for the process.
        paused<bool> = False -- if enabled, then don't start the process until .start() is called
        timeout<float> = -1 -- if positive, then raise a Queue.Empty exception at the specified interval.
        """
        # default properties
        self.__threads = weakref.WeakSet()
        self.__kwds = kwds
        self.commandline = command

        import Queue
        self.eventWorking = threading.Event()
        self.__taskQueue = Queue.Queue()
        self.__exceptionQueue = Queue.Queue()

        self.stdout = kwds.pop('stdout')
        self.stderr = kwds.pop('stderr')

        # start the process
        not kwds.get('paused',False) and self.start(command)

    def start(self, command=None, **options):
        """Start the specified ``command`` with the requested **options"""
        kwds = dict(self.__kwds)
        kwds.update(options)
        command = command or self.commandline

        env = kwds.get('env', os.environ)
        cwd = kwds.get('cwd', os.getcwd())
        newlines = kwds.get('newlines', True)
        shell = kwds.get('shell', False)
        stdout,stderr = options.pop('stdout',self.stdout),options.pop('stderr',self.stderr)
        self.program = process.subprocess(command, cwd, env, newlines, joined=(stderr is None) or stdout == stderr, shell=shell, show=kwds.get('show', False))
        self.commandline = command

        # monitor program's i/o
        self.__start_monitoring(stdout, stderr)
        self.__start_updater(timeout=kwds.get('timeout',-1))

        # start monitoring
        self.eventWorking.set()
        return self

    def __start_updater(self, daemon=True, timeout=0):
        """Start the updater thread. **used internally**"""
        import Queue
        def task_exec(emit, data):
            if hasattr(emit,'send'):
                res = emit.send(data)
                res and P.write(res)
            else: emit(data)

        def task_get_timeout(P, timeout):
            try:
                emit,data = P.taskQueue.get(block=True, timeout=timeout)
            except Queue.Empty:
                _,_,tb = sys.exc_info()
                P.exceptionQueue.put(StopIteration,StopIteration(),tb)
                return ()
            return emit,data

        def task_get_notimeout(P, timeout):
            return P.taskQueue.get(block=True)

        task_get = task_get_timeout if timeout > 0 else task_get_notimeout

        def update(P, timeout):
            import Queue
            P.eventWorking.wait()
            while P.eventWorking.is_set():
                res = task_get(P, timeout)
                if not res: continue
                emit,data = res

                try:
                    task_exec(emit,data)
                except StopIteration:
                    P.eventWorking.clear()
                except:
                    P.exceptionQueue.put(sys.exc_info())
                finally:
                    P.taskQueue.task_done()
                continue
            return

        self.updater = updater = threading.Thread(target=update, name="thread-%x.update"% self.id, args=(self,timeout))
        updater.daemon = daemon
        updater.start()
        return updater

    def __start_monitoring(self, stdout, stderr=None):
        """Start monitoring threads. **used internally**"""
        program = self.program
        name = 'thread-{:x}'.format(program.pid)

        # create monitoring threads + coroutines
        if stderr:
            res = process.monitorPipe(self.taskQueue, (stdout,program.stdout),(stderr,program.stderr), name=name)
        else:
            res = process.monitorPipe(self.taskQueue, (stdout,program.stdout), name=name)

        res = map(None,res)
        # attach a method for injecting data into a monitor
        for t,q in res: t.send = q.send
        threads,senders = zip(*res)

        # update threads for destruction later
        self.__threads.update(threads)

        # set things off
        for t in threads: t.start()

    @staticmethod
    def subprocess(program, cwd, environment, newlines, joined, shell=True, show=False):
        """Create a subprocess using subprocess.Popen."""
        stderr = subprocess.STDOUT if joined else subprocess.PIPE
        if os.name == 'nt':
            si = subprocess.STARTUPINFO()
            si.dwFlags = subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0 if show else subprocess.SW_HIDE
            cf = subprocess.CREATE_NEW_CONSOLE if show else 0
            return subprocess.Popen(program, universal_newlines=newlines, shell=shell, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, close_fds=False, startupinfo=si, creationflags=cf, cwd=cwd, env=environment)
        return subprocess.Popen(program, universal_newlines=newlines, shell=shell, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, close_fds=True, cwd=cwd, env=environment)

    @staticmethod
    def monitorPipe(q, (id,pipe), *more, **options):
        """Attach a coroutine to a monitoring thread for stuffing queue `q` with data read from `pipe`

        Yields a list of (thread,coro) tuples given the arguments provided.
        Each thread will read from `pipe`, and stuff the value combined with `id` into `q`.
        """
        def stuff(q,*key):
            while True: q.put(key+((yield),))

        for id,pipe in itertools.chain([(id,pipe)],more):
            res,name = stuff(q,id), '{:s}<{!r}>'.format(options.get('name',''),id)
            yield process.monitor(res.next() or res.send, pipe, name=name),res
        return

    @staticmethod
    def monitor(send, pipe, blocksize=1, daemon=True, name=None):
        """Spawn a thread that reads `blocksize` bytes from `pipe` and dispatches it to `send`

        For every single byte, `send` is called. The thread is named according to
        the `name` parameter.

        Returns the monitoring threading.thread instance 
        """
        def shuffle(send, pipe):
            while not pipe.closed:
                data = pipe.read(blocksize)
                if len(data) == 0:
                    # pipe.read syscall was interrupted. so since we can't really
                    # determine why (cause...y'know..python), stop dancing so
                    # the parent will actually be able to terminate us
                    break
                map(send,data)
            return
        if name:
            monitorThread = threading.Thread(target=shuffle, name=name, args=(send,pipe))
        else:
            monitorThread = threading.Thread(target=shuffle, args=(send,pipe))
        monitorThread.daemon = daemon
        return monitorThread

    def write(self, data):
        """Write `data` directly to program's stdin"""
        if self.program is not None and self.program.poll() is None and not self.program.stdin.closed:
            return self.program.stdin.write(data)

        pid,result = self.program.pid,self.program.poll()
        raise IOError, 'Unable to write to stdin for process %d. Process %s'% (pid, 'is still running.' if result is None else 'has terminated with code %d.'% result)

    def close(self):
        """Closes stdin of the program"""
        if self.program is not None and self.program.poll() is None and not self.program.stdin.closed:
            return self.program.stdin.close()

        pid,result = self.program.pid,self.program.poll()
        raise IOError, 'Unable to close stdin for process %d. Process %s'% (pid, 'is still running.' if result is None else 'has terminated with code %d.'% result)

    def signal(self, signal):
        """Raise a signal to the program"""
        if self.program is not None and self.program.poll() is None:
            return self.program.send_signal(signal)

        pid,result = self.program.pid,self.program.poll()
        raise IOError, 'Unable to raise signal %r in process %d. Process %s'% (signal, pid, 'is still running.' if result is None else 'has terminated with code %d.'% result)

    def throw(self):
        """Grab an exception if there's any available"""
        res = self.exceptionQueue.get()
        self.exceptionQueue.task_done()
        return res

    def wait(self, timeout=0.0):
        """Wait a given amount of time for the process to terminate"""
        program = self.program
        if program is None:
            raise RuntimeError, 'Program %s is not running'% self.commandline

        if not self.running: return program.returncode
        self.eventWorking.wait()

        if timeout:
            t = time.time()
            while self.running and self.eventWorking.is_set() and time.time() - t < timeout:        # spin cpu until we timeout
                if not self.exceptionQueue.empty():
                    res = self.throw()
                    raise res[0],res[1],res[2]
                continue
            if not self.eventWorking.is_set():
                return self.__terminate()
            return program.returncode

        # return program.wait() # XXX: doesn't work correctly with PIPEs due to
        #   pythonic programmers' inability to understand os semantics

        while self.running and self.eventWorking.is_set():
            if not self.exceptionQueue.empty():
                res = self.throw()
                raise res[0],res[1],res[2]
            continue    # ugh...poll-forever/kill-cpu until program terminates...
        if not self.eventWorking.is_set():
            return self.__terminate()
        return program.returncode

    def stop(self):
        self.eventWorking.clear()
        return self.__terminate()

    def __terminate(self):
        """Sends a SIGKILL signal and then waits for program to complete"""
        self.program.kill()
        while self.running:
            if not self.exceptionQueue.empty():
                res = self.throw()
                raise res[0],res[1],res[2]
            continue
        self.__stop_monitoring()
        return self.program.returncode

    def __stop_monitoring(self):
        """Cleanup monitoring threads"""
        P = self.program
        if P.poll() is None:
            raise RuntimeError, "Unable to stop monitoring while process {!r} is still running.".format(P)

        # stop the update thread
        self.eventWorking.clear()

        # forcefully close pipes that still open, this should terminate the monitor threads
        #   also, this fixes a resource leak since python doesn't do this on subprocess death
        for p in (P.stdin,P.stdout,P.stderr):
            while p and not p.closed:
                try: p.close()
                except: pass

        def forever(iterable):
            while len(iterable) > 0:
                for n in list(iterable):
                    yield n
                    del(n)
            return

        # join all monitoring threads, and spin until none of them are alive
        [ x.join() for x in self.__threads]
        for th in forever(self.__threads):
            if not th.is_alive():
                self.__threads.discard(th)
            continue

        # join the updater thread, and then remove it
        self.updater.join()
        assert not self.updater.is_alive()
        self.updater = None
        return

    def __repr__(self):
        if self.running:
            return '<process running pid:%d>'%( self.id )
        return '<process not-running cmd:"%s">'%( self.commandline )

## interface for wrapping the process class
def spawn(stdout, command, **options):
    """Spawn `command` with the specified `**options`.

    If program writes anything to stdout, dispatch it to the `stdout` callable.
    If `stderr` is defined, call `stderr` with anything written to the program's stderr.
    """
    # grab arguments that we care about
    stderr = options.pop('stderr', None)
    daemon = options.pop('daemon', True)

    # empty out the first generator result if a coroutine is passed
    if hasattr(stdout,'send'):
        res = stdout.next()
        res and P.write(res)
    if hasattr(stderr,'send'):
        res = stderr.next()
        res and P.write(res)

    # spawn the sub-process
    return process(command, stdout=stdout, stderr=stderr, **options)

### Memoize function
def memoize(*kargs,**kattrs):
    '''Converts a function into a memoized callable
    kargs = a list of positional arguments to use as a key
    kattrs = a keyword-value pair describing attributes to use as a key

    if key='string', use kattrs[key].string as a key
    if key=callable(n)', pass kattrs[key] to callable, and use the returned value as key

    if no memoize arguments were provided, try keying the function's result by _all_ of it's arguments.
    '''
    F_VARARG = 0x4
    F_VARKWD = 0x8
    F_VARGEN = 0x20
    kargs = map(None,kargs)
    kattrs = tuple((o,a) for o,a in sorted(kattrs.items()))
    def prepare_callable(fn, kargs=kargs, kattrs=kattrs):
        if hasattr(fn,'im_func'):
            fn = fn.im_func
        assert isinstance(fn,memoize.__class__), 'Callable {!r} is not of a function type'.format(fn)
        functiontype = type(fn)
        cache = {}
        co = fn.func_code
        flags,varnames = co.co_flags,iter(co.co_varnames)
        assert (flags & F_VARGEN) == 0, 'Not able to memoize %r generator function'% fn
        argnames = itertools.islice(varnames, co.co_argcount)
        c_positional = tuple(argnames)
        c_attribute = kattrs
        c_var = (varnames.next() if flags & F_VARARG else None, varnames.next() if flags & F_VARKWD else None)
        if not kargs and not kattrs:
            kargs[:] = itertools.chain(c_positional,filter(None,c_var))
        def key(*args, **kwds):
            res = iter(args)
            p = dict(zip(c_positional,res))
            p.update(kwds)
            a,k = c_var
            if a is not None: p[a] = tuple(res)
            if k is not None: p[k] = dict(kwds)
            k1 = (p.get(k, None) for k in kargs)
            k2 = ((n(p[o]) if callable(n) else getattr(p[o],n,None)) for o,n in c_attribute)
            return tuple(itertools.chain(k1, (None,), k2))
        def callee(*args, **kwds):
            res = key(*args, **kwds)
            if res in cache:
                return cache[res]
            return cache.setdefault(res, fn(*args,**kwds))

        # set some utilies on the memoized function
        callee.memoize_key = lambda: key
        callee.memoize_key.__doc__ = """Generate a unique key based on the provided arguments"""
        callee.memoize_cache = lambda: cache
        callee.memoize_cache.__doc__ = """Return the current memoize cache"""
        callee.memoize_clear = lambda: cache.clear()
        callee.memoize_clear.__doc__ = """Empty the current memoize cache"""

        callee.func_name = fn.func_name
        callee.func_doc = fn.func_doc
        callee.callable = fn
        return callee if isinstance(callee,functiontype) else functiontype(callee)
    return prepare_callable(kargs.pop(0)) if not kattrs and len(kargs) == 1 and callable(kargs[0]) else prepare_callable
