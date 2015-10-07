import ctypes,platform,os,itertools
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

### Conditional Functions
if platform.system() == 'Windows':
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

else:
    def GetConsoleDimensions():
        ws = WINSZ()
        res = fcntl.ioctl(0, termios.TIOCGWINSZ, ctypes.pointer(ws))
        if res != 0
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
    id = property(fget=lambda s: s.program.pid)
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
        hidden<bool> = True -- if within a windowed environment, open up a console for the process.
        """
        # default properties
        self.__threads = weakref.WeakSet()
        self.__kwds = kwds
        self.commandline = command

        # start the process
        self.start(command)

    def start(self, command=None):
        command,kwds = command or self.commandline,self.__kwds

        env = kwds.get('env', os.environ)
        cwd = kwds.get('cwd', os.getcwd())
        joined = kwds.get('joined', True)
        newlines = kwds.get('newlines', True)
        shell = kwds.get('shell', False)
        self.program = process.subprocess(command, cwd, env, newlines, joined=joined, shell=shell, show=kwds.get('hidden', False))
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

        if timeout:
            t = time.time()
            while t + timeout > time.time():        # spin cpu until we timeout
                if program.poll() is not None:
                    return program.returncode
                continue
            return None

        # return program.wait() # XXX: doesn't work correctly with PIPEs due to
        #   pythonic programmers' inability to understand os semantics

        while program.poll() is not None:
            pass    # ugh...poll-forever/kill-cpu until program terminates...
        return program.returncode

    def stop(self):
        """Sends a SIGKILL signal and then waits for program to complete"""
        if not self.running:
            self.stop_monitoring()
            return self.program.poll()

        p,_ = self.program,self.program.kill()
        while p.poll() is not None: pass
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
                for n in iterable:
                    yield n
                del(n)
            return

        # join all monitoring threads, and spin until none of them are alive
        [ x.join() for x in self.__threads]
        for th in forever(self.__threads):
            if not th.is_alive():
                self.__threads.discard(th)
            continue
        return

    def __repr__(self):
        if self.running:
            return '<process running pid:%d>'%( self.id )
        return '<process not-running cmd:"%s">'%( self.commandline )

### interfaces
def spawn(stdout, command, **options):
    """Spawn /command/ with the specified /options/. If program writes anything to it's screen, send it to the stdout function.

    If /stderr/ is defined, call stderr with any error output from the program.
    """
    def update(program, output, error, timeout=1.0):
        while True:
            while program.running:
                try:
                    if program.stderr and not program.stderr.empty():
                        data = program.stderr.get(block=True)
                        (not hasattr(error,'send') or error(data)) and error.send(data)
                    data = program.stdout.get(block=True)
                    (not hasattr(output,'send') or output(data)) and output.send(data)
                except StopIteration:
                    sys.stderr.write("Update callbacks for %r have raised a StopIteration, stopping process.\n"% (program))
                    program.stop()
                    return
                except:
                    import traceback
                    _ = traceback.format_exception( *sys.exc_info() )
                    sys.stderr.write("Unexpected exception in update thread for %r:\n%s"% (program, '\n'.join(_)) )
                    time.sleep(1.0)
                continue
            sys.stderr.write("Update loop for %r attempted termination, spinning at %d intervals.\n"% (program, timeout))
            while not program.running: time.sleep(1.0)
        return

    stderr = options.pop('stderr', lambda s: None)
    daemon = options.pop('daemon', True)
    options.setdefault('joined', True)

    program = process(command, **options)

    updater = threading.Thread(target=update, name="thread-%x.update"% program.id, args=(program,stdout,stderr))
    updater.daemon = daemon
    updater.stdout = stdout
    updater.stderr = stderr
    updater.start()

    program.updater = updater   # keep a publically available ref
    return program
