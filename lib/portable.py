import __builtin__,sys,os,itertools
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
    def __init__(self, path, mode):
        self.file = open(path, mode)
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
        if res == 0:
            raise RuntimeError, windll.kernel32.GetLastError()
        return WINSZ(csbi.dwSize.Y, csbi.dwSize.X, csbi.dwCursorPosition.X, csbi.dwCursorPosition.Y)

    class LockFile(file):
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

    def chmod(path, mode):
        # get the ugo out of the dacl
        Everyone,_,_ = win32security.LookupAccountName("", "Everyone")
        User = Group = None,None

        import pwd
        sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        for index in xrange(dacl.GetAceCount()):
            _,_,sid = dacl.GetAce(index)
            name,domain,_ = win32security.LookupAccountSid(None,sid)

            # figure out the account type
            acct = win32com.client.GetObject(r'WinMgmts:\\.\root\cimv2:Win32_Account.Domain="%s",Name="%s"'%(domain,name))
            if acct.SIDType == ntsecuritycon.SidTypeUser and User is None:
                User = acct.Sid
            if acct.SIDType == ntsecuritycon.SidTypeGroup and Group is None:
                Group = acct.Sid
            continue

        # default to Guest
        if User is None:
            User,_,_ = win32security.LookupAccountName("", "Guest")
        # find the first group associated with User
        if Group is None:
            name,domain,_ = win32security.LookupAccountSid(None,User)
            acct = pwd.Query.ByName(domain,name)
            Group = win32security.ConvertStringSidToSid(pwd.Query.Group(acct).Sid)

        # convert mode to a shiftable list
        res = []
        for _ in range(8):
            res.append(mode & 1)
            mode >>= 1
        mode = res

        # generate ACL from list
        flags = [ntsecuritycon.FILE_GENERIC_EXECUTE, ntsecuritycon.FILE_GENERIC_WRITE, ntsecuritycon.FILE_GENERIC_READ]
        dacl = win32security.ACL()
        res = 0
        for i in xrange(3):
            if mode.pop(0):
                res |= flags[i]
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, res, Everyone)
        res = 0
        for i in xrange(3):
            if mode.pop(0):
                res |= flags[i]
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, res, Group)
        res = 0
        for i in xrange(3):
            if mode.pop(0):
                res |= flags[i]
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
        for acct in WmiClient.InstancesOf('Win32_Account'):
            id = SID.Identifier(acct.SID)
            if id == uid and acct.SidType == ntsecuritycon.SidTypeUser: user = acct.SID
            if id == gid and acct.SidType == ntsecuritycon.SidTypeGroup: group = acct.SID
            if uid is not None and gid is not None: break

        # ripped from http://timgolden.me.uk/python/win32_how_do_i/add-security-to-a-file.html#the-short-version
        import pwd
        sd = win32security.GetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION)

        # grab original owner
        if user is None and uid != -1:
            user = sd.GetSecurityDescriptorOwner()
        if group is None and gid != -1:
            name,domain,_ = win32security.LookupAccountSid(None,user)
            acct = pwd.Query.ByName(domain,name)
            group = win32security.ConvertStringSidToSid(pwd.Query.Group(acct).Sid)

        if uid != -1:
            sd.SetSecurityDescriptorOwner(user, True)
        if gid != -1:
            sd.SetSecurityDescriptorGroup(group, True)

        res = win32security.SetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION, sd)
        return -1 if res == 0 else 0
    sys.modules['os'].chown = chown

else:
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
import sys,os,threading,weakref,subprocess,time,itertools

# monitoring an external process' i/o via threads/queues
class process(object):
    """Spawns a program along with a few monitoring threads for allowing asynchronous(heh) interaction with a subprocess.

    Properties:
    (process.stdout, process.stderr)<Queue> -- Queues containing output from the spawned process.
    id<pid_t> -- The pid of the spawned process
    running<bool> -- The current running state of the process
    """

    program = None              # subprocess.Popen object
    stdout,stderr = None,None   # queues containing stdout and stderr
    id = property(fget=lambda s: s.program and s.program.pid or -1)
    running = property(fget=lambda s: False if s.program is None else s.program.poll() is None)
    threads = property(fget=lambda s: list(s.__threads))

    #Queue = __import__('multiprocessing').Queue
    Queue = __import__('Queue').Queue       # Queue.Queue allows us to grab a mutex to prevent another thread from interacting w/ it

    def __init__(self, command, **kwds):
        """Creates a new instance that monitors subprocess.Popen(/command/), the created process starts in a paused state.

        Keyword options:
        env<dict> = os.environ -- environment to execute program with
        cwd<str> = os.getcwd() -- directory to execute program  in
        joined<bool> = True -- if disabled, use separate monitoring pipes/threads for both stdout and stderr.
        shell<bool> = True -- whether to treat program as an argument to a shell, or a path to an executable
        newlines<bool> = True -- allow python to tamper with i/o to convert newlines
        show<bool> = False -- if within a windowed environment, open up a console for the process.
        paused<bool> = False -- if enabled, then don't start the process until .start() is called
        """
        # default properties
        self.__threads = weakref.WeakSet()
        self.__kwds = kwds
        self.commandline = command
        self.exceptionQueue = self.Queue()

        # start the process
        not kwds.get('paused',False) and self.start(command)

    def start(self, command=None):
        command,kwds = command or self.commandline,self.__kwds

        env = kwds.get('env', os.environ)
        cwd = kwds.get('cwd', os.getcwd())
        joined = kwds.get('joined', True)
        newlines = kwds.get('newlines', True)
        shell = kwds.get('shell', False)
        self.program = process.subprocess(command, cwd, env, newlines, joined=joined, shell=shell, show=kwds.get('show', False))
        self.commandline = command

        # monitor program's i/o
        self.start_monitoring(joined)

    def start_monitoring(self, joined=True, **kwds):
        program = self.program

        ## monitor threads (which aren't important if python didn't suck with both threads and gc)
        name = 'thread-%x'% program.pid
        if joined:
            res = process.monitor((name+'.stdout',program.stdout), **kwds)
        else:
            res = process.monitor((name+'.stdout',program.stdout),(name+'.stderr',program.stderr), **kwds)

        # assign the queue to the thread for ease-of-access
        for t,q in res: t.queue = q
        threads,queues = zip(*res)

        # assign queues containing stdout and stderr
        self.__threads.update(threads)
        self.stdout,self.stderr = (q for q,_ in map(None, queues, range(2)))

        # set things off
        for t in threads:
            t.start()
        return

    @staticmethod
    def subprocess(program, cwd, environment, newlines, joined, shell=True, show=False):
        """Create a subprocess using subprocess.Popen"""
        stderr = subprocess.STDOUT if joined else subprocess.PIPE
        if os.name == 'nt':
            si = subprocess.STARTUPINFO()
            si.dwFlags = subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0 if show else subprocess.SW_HIDE
            cf = subprocess.CREATE_NEW_CONSOLE if show else 0
            return subprocess.Popen(program, universal_newlines=newlines, shell=shell, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, close_fds=False, startupinfo=si, creationflags=cf, cwd=cwd, env=environment)
        return subprocess.Popen(program, universal_newlines=newlines, shell=shell, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, close_fds=True, cwd=cwd, env=environment)

    @staticmethod
    def monitor((name,pipe), *more, **kwds):
        """Create multiple monitoring threads for a number of pipes

        Returns a list of (thread,queue) tuples given the number of tuples provided as an argument.
        This creates a list of threads responsible for reading from /pipe/ and storing it into an asynchronous queue
        """
        return [ process.monitorPipe(name,pipe, **kwds) for name,pipe in [(name,pipe)]+list(more) ]

    @staticmethod
    def monitorPipe(id, pipe, blocksize=1, daemon=True):
        """Create a monitoring thread that stuffs data from a pipe into a queue.

        Returns a (threading.Thread, Queue)
        (Queues are the only python object that allow you to timeout if data isn't currently available)
        """

        def shuffle(queue, pipe):
            while not pipe.closed:
                data = pipe.read(blocksize)
                if len(data) == 0:
                    # pipe.read syscall was interrupted. so since we can't really
                    # determine why (cause...y'know..python), stop dancing so
                    # the parent will actually be able to terminate us
                    break
                queue.put(data)
            return

        q = process.Queue()
        if id is None:
            monitorThread = threading.Thread(target=shuffle, args=(q,pipe))
        else:
            monitorThread = threading.Thread(target=shuffle, name=id, args=(q,pipe))
        monitorThread.daemon = daemon
        return monitorThread,q

    def write(self, data):
        """Write data directly to program's stdin"""
        if self.running:
            return self.program.stdin.write(data)

        pid,result = self.program.pid,self.program.poll()
        raise IOError, 'Unable to write to terminated process %d. Process terminated with a returncode of %d'% (pid,result)

    def signal(self, signal):
        """Raise a signal to the program"""
        if self.running:
            return self.program.send_signal(signal)

        pid,result = self.program.pid,self.program.poll()
        raise IOError, 'Unable to signal terminated process %d. Process terminated with a returncode of %d'% (pid,result)

    def wait(self, timeout=0.0):
        """Wait a given amount of time for the process to terminate"""
        program = self.program
        if program is None:
            raise RuntimeError, 'Program %s is not running'% self.commandline

        if timeout:
            t = time.time()
            while program.poll() is None and t + timeout > time.time():        # spin cpu until we timeout
                if not self.exceptionQueue.empty():
                    res = self.exceptionQueue.get()
                    raise res[0],res[1],res[2]
                continue
            return program.returncode

        # return program.wait() # XXX: doesn't work correctly with PIPEs due to
        #   pythonic programmers' inability to understand os semantics

        while program.poll() is None:
            if not self.exceptionQueue.empty():
                res = self.exceptionQueue.get()
                raise res[0],res[1],res[2]
            pass    # ugh...poll-forever/kill-cpu until program terminates...
        return program.returncode

    def stop(self):
        """Sends a SIGKILL signal and then waits for program to complete"""
        if not self.running:
            self.stop_monitoring()
            return self.program.poll()

        p,_ = self.program,self.program.kill()
        while p.poll() is not None:
            if not self.exceptionQueue.empty():
                res = self.exceptionQueue.get()
                raise res[0],res[1],res[2]
            continue
        self.stop_monitoring()
        self.program = None
        return p.returncode

    def stop_monitoring(self):
        """Cleanup monitoring threads"""

        # close pipes that have been left open since python fails to do this on program death
        p,stdout,stderr = self.program,self.stdout,self.stderr

        p.stdin.close()
        for q,p in ((stdout,p.stdout), (stderr,p.stderr)):
            if q is None:
                continue
            q.mutex.acquire()
            while not p.closed:
                try: p.close()
                except IOError:
                    continue
            q.mutex.release()

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

        # pull an exception out of the exceptionQueue if there's any left
        if not self.exceptionQueue.empty():
            res = self.exceptionQueue.get()
            raise res[0],res[1],res[2]
        return

    def __repr__(self):
        if self.running:
            return '<process running pid:%d>'%( self.id )
        return '<process not-running cmd:"%s">'%( self.commandline )

## interface for wrapping the process class
def spawn(stdout, command, **options):
    """Spawn /command/ with the specified /options/. If program writes anything to it's screen, send it to the stdout function.

    If /stderr/ is defined, call stderr with any error output from the program.
    """
    def update(program, output, error, timeout=1.0):
        # wait until we're running
        while not program.running: pass

        # empty out the first generator result if one is passed as an output handler
        hasattr(stdout,'send') and program.write(stdout.send(None) or '')
        hasattr(stderr,'send') and program.write(stderr.send(None) or '')

        while True:
            while program.running:
                try:
                    if program.stderr and not program.stderr.empty():
                        data = program.stderr.get(block=True)
                        program.write(error.send(data) or '') if hasattr(error,'send') else error(data)
                    data = program.stdout.get(block=True)
                    program.write(output.send(data) or '') if hasattr(output,'send') else output(data)
                except StopIteration:
                    #sys.stderr.write("Update callbacks for %r have raised a StopIteration, stopping process.\n"% (program))
                    program.stop()
                    break
                except:
                    program.exceptionQueue.put(sys.exc_info())
                    #import traceback
                    #_ = traceback.format_exception( *sys.exc_info() )
                    #sys.stderr.write("Unexpected exception in update thread for %r:\n%s"% (program, '\n'.join(_)) )
                continue
            #sys.stderr.write("Program %r has terminated, spinning at %d intervals.\n"% (program, timeout))
            while not program.running: time.sleep(1.0)
        return

    # grab arguments that we care about
    stderr = options.pop('stderr', lambda s: None)
    daemon = options.pop('daemon', True)
    options.setdefault('joined', True)

    # spawn the sub-process
    program = process(command, **options)

    # create the updating thread that dispatches to each handler
    updater = threading.Thread(target=update, name="thread-%x.update"% program.id, args=(program,stdout,stderr))
    updater.daemon = daemon
    updater.stdout = stdout
    updater.stderr = stderr
    updater.start()

    program.updater = updater   # keep a publically available ref of it
    return program

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
