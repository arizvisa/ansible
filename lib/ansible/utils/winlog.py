import sys,logging,logging.handlers,os,platform

## Globals
Logger = logging.getLogger()

## Constants
# Priority
LOG_EMERG=logging.handlers.SysLogHandler.LOG_EMERG
LOG_ALERT=logging.handlers.SysLogHandler.LOG_ALERT
LOG_CRIT=logging.handlers.SysLogHandler.LOG_CRIT
LOG_ERR=logging.handlers.SysLogHandler.LOG_ERR
LOG_WARNING=logging.handlers.SysLogHandler.LOG_WARNING
LOG_NOTICE=logging.handlers.SysLogHandler.LOG_NOTICE
LOG_INFO=logging.handlers.SysLogHandler.LOG_INFO
LOG_DEBUG=logging.handlers.SysLogHandler.LOG_DEBUG

# Facilities
LOG_KERN=logging.handlers.SysLogHandler.LOG_KERN
LOG_USER=logging.handlers.SysLogHandler.LOG_USER
LOG_MAIL=logging.handlers.SysLogHandler.LOG_MAIL
LOG_DAEMON=logging.handlers.SysLogHandler.LOG_DAEMON
LOG_AUTH=logging.handlers.SysLogHandler.LOG_AUTH
LOG_LPR=logging.handlers.SysLogHandler.LOG_LPR
LOG_NEWS=logging.handlers.SysLogHandler.LOG_NEWS
LOG_UUCP=logging.handlers.SysLogHandler.LOG_UUCP
LOG_CRON=logging.handlers.SysLogHandler.LOG_CRON
LOG_LOCAL0=logging.handlers.SysLogHandler.LOG_LOCAL0
LOG_LOCAL1=logging.handlers.SysLogHandler.LOG_LOCAL1
LOG_LOCAL2=logging.handlers.SysLogHandler.LOG_LOCAL2
LOG_LOCAL3=logging.handlers.SysLogHandler.LOG_LOCAL3
LOG_LOCAL4=logging.handlers.SysLogHandler.LOG_LOCAL4
LOG_LOCAL5=logging.handlers.SysLogHandler.LOG_LOCAL5
LOG_LOCAL6=logging.handlers.SysLogHandler.LOG_LOCAL6
LOG_LOCAL7=logging.handlers.SysLogHandler.LOG_LOCAL7

# Options
LOG_PID=1
LOG_CONS=2
LOG_NDELAY=8
LOG_NOWAIT=16
LOG_PERROR=32

### Filters
class SysLogFilter(logging.Filter):
    def __init__(self, logopt, facility):
        super(SysLogFilter,self).__init__()
        self.logopt = logopt
        self.facility = facility

    def filter(self, record):
        record.pid = os.getpid()
        record.hostname = platform.node()
        record.facility = self.facility
        return True
#        if Logger.mask == -1:
#            return True
#        return record.priority & Logger.mask == record.priority

### Handlers
class NTEventLogHandler(logging.handlers.NTEventLogHandler):
    def __init__(self, appname='Windows Error Reporting', dllname=None, logtype="Application"):
        logging.Handler.__init__(self)
        try:
            import win32evtlogutil, win32evtlog
            self.appname = appname
            self._welu = win32evtlogutil
            if not dllname:
                dllname = os.path.split(self._welu.__file__)
                dllname = os.path.split(dllname[0])
                dllname = os.path.join(dllname[0], r'win32service.pyd')
            self.dllname = dllname
            self.logtype = logtype
            try: self._welu.AddSourceToRegistry(appname, dllname, logtype)
            except: pass
            self.deftype = win32evtlog.EVENTLOG_ERROR_TYPE
            self.typemap = {
                logging.DEBUG   : win32evtlog.EVENTLOG_INFORMATION_TYPE,
                logging.INFO    : win32evtlog.EVENTLOG_INFORMATION_TYPE,
                logging.WARNING : win32evtlog.EVENTLOG_WARNING_TYPE,
                logging.ERROR   : win32evtlog.EVENTLOG_ERROR_TYPE,
                logging.CRITICAL: win32evtlog.EVENTLOG_ERROR_TYPE,
         }
        except ImportError:
            print("The Python Win32 extensions for NT (service, event "\
                        "logging) appear not to be available.")
            self._welu = None
    pass

class SysLogHandler(logging.handlers.SysLogHandler):
    def mapPriority(self, levelname):
        if levelname == 'DEBUG':
            return LOG_DEBUG
        elif levelname == 'INFO':
            return LOG_INFO
        elif levelname == 'WARNING':
            return LOG_WARNING
        elif levelname == 'ERROR':
            return LOG_ERROR
        elif levelname == 'CRITICAL':
            return LOG_CRITICAL
        return LOG_WARNING

### Exposed API
def syslog(priority, message):
    global Logger
    Logger.info(message, priority=priority)

def openlog(ident=sys.argv[0], logoption=LOG_PERROR, facility=LOG_USER):
    global Logger
    Logger = logging.getLogger(ident)
    Logger.addFilter(SysLogFilter(logoption,facility))

    # add formatter with pid
    if logoption & LOG_PID:
        formatter = logging.Formatter('%(asctime)s %(hostname)s %(facility)s: %(name)s:%(levelname)s:%(message)s')
    else:
        formatter = logging.Formatter('%(asctime)s %(hostname)s %(facility)s: pid[%(pid)]:%(name)s:%(levelname)s:%(message)s')

    if platform.system() == 'Windows':
        h = NTEventLogHandler()
    else:
        h = SysLogHandler(facility=facilitiy)
    h.setFormatter(formatter)
    Logger.addHandler(h)

    # output to stderr too if requested
    if logoption & LOG_PERROR == LOG_PERROR:
        err = logging.StreamHandler(sys.stderr)
        err.setFormatter(formatter)
        Logger.addHandler(err)

    setlogmask(-1)
    return

def closelog():
    setlogmask(0)

def setlogmask(maskpri):
    global Logger
    Logger.mask = maskpri

openlog()
