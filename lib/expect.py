import portable,machine
import re,time,abc
from machine import State
from portable import spawn

### Base state machine
class Machine(object):
    __metaclass__ = abc.ABCMeta
    __slots__ = ('_callbacks','_machine')

    def __init__(self, *args, **kwds):
        self._callbacks = {}
        self._machine = self.Table(machine.Machine())

    @abc.abstractmethod
    def Table(self, M):
        """Generate transitions for state machine's table"""
        raise NotImplementedError

    @property
    def M(self):
        """Return the current state machine object"""
        return self._machine

    def handle(self, name, fn):
        """Map the requested callback to the provided callable for state-transitions.

        Callable takes the arguments ((previous-state,current-state)).
        """
        if name not in self.Callbacks:
            raise NameError, '{!r} : Unknown callback `{:s}`'.format(self, name)
        self._callbacks[name] = fn

    def callback(self, name):
        """Return the callback wrapper for the requested callback.

        Intended to be used during generation of the state-transition table.
        """
        def _callback(token, (state,next)):
            cb = self._callbacks[name]
            return cb((state,next))
        _callback.__name__ = 'handle_{:s}'.format(name)
        _callback.__doc__ = 'Callback wrapper for {:s}'.format(name)
        return _callback

    def validate(self):
        """Validate all callbacks to make sure they're assigned."""
        res = set(self._callbacks.iterkeys())
        if self.Callbacks.difference(res):
            raise NameError, '{!r} : Undefined callbacks : `{:s}`'.format(self, '`, `'.join(self.Callbacks.difference(res)))
        return

    def iterate(self, start=None):
        """Contains a coroutine for processing output from a process.

        Each iteration returns the current state before a transition happens. If
        start is provided, begin at the specified state.
        """
        self.validate()
        self.M.set(start or State.Start)
        state,data = self.M.get(),''
        while state != State.End:
            res = None
            while res is None:
                data += (yield state)
                res = self.M.process(data)
            state,data = res,''
        return

### Rule base-classes
class BaseRule(machine.Rule):
    def enter(self, state): return
    def leave(self, state): return

class BaseStringRule(BaseRule):
    __slots__ = ('_string',)
    def __init__(self, string):
        self._string = string

### Generic Rules
class Timeout(machine.Rule):
    __slots__ = ('_timeout', '_tick')
    def __init__(self, timeout):
        self._timeout = timeout
    def enter(self, state):
        self._tick = time.now()
    def leave(self, state):
        return
    def process(self, data):
        self._tock = time.now()
        return self._tock - self._tick > self._timeout

### string matching
class MatchWhitespace(BaseRule):
    def process(self, data):
        return any(data[-1] == ch for ch in ' \t\n')

class MatchPattern(machine.Rule):
    __slots__ = ('_regex',)
    def __init__(self, pattern, flags=0):
        self._regex = re.compile(pattern, flags)
    def enter(self, state): return
    def leave(self, state): return
    def process(self, data):
        return self._regex.match(data) is not None

### String-matching Rules
class Match(BaseStringRule):
    def process(self, data):
        return data.endswith(self._string)
class MatchContains(BaseStringRule):
    def process(self, data):
        return self._string in data
class MatchEqual(BaseStringRule):
    def process(self, data):
        return self._string == data
class MatchNewline(Match):
    def __init__(self):
        super(MatchNewline,self).__init__('\n')

### Boolean-order logic
class MatchTruth(machine.RulePredicate): pass
class MatchAnything(BaseRule):
    def process(self, data):
        return True
class MatchNot(machine.RuleNot): pass
class MatchAnd(machine.RuleAll): pass
class MatchOr(machine.RuleAny): pass

if __name__ == '__main__':
    import expect
    from expect import *

    def cb(token, (state,nextstate)):
        print "{!r}->{!r} : {!r}".format(state,nextstate,token)

    ### Plink parsing state
    M = expect.Machine()
    M.transition(State.Start, MatchPattern("^The server's host key is not cached in the registry."), State.unknownHostKey)
    M.transition(State.unknownHostKey, Match('\n'), State.unknownHostKey, prority=1)
    M.transition(State.unknownHostKey, Match("The server's rsa2 key fingerprint is:"), State.fpStatement)

    M.transition(State.fpStatement, MatchNewline(), State.fpType)
    M.transition(State.fpType, Match(' '), State.fpBits)
    M.handle(State.fpType, State.Any, cb)  # get type (ssh-dss, or ssh-rsa)

    M.transition(State.fpBits, Match(' '), State.fpHash)
    M.handle(State.fpBits, State.Any, cb)  # get bits

    M.transition(State.fpHash, MatchNewline(), State.storeFingerprint)
    M.handle(State.fpHash, State.Any, cb)  # get hash
    #    "ssh-rsa 2048 4f:0f:67:fb:0c:6b:1b:82:fa:7b:6d:17:51:f7:41:29"

    M.transition(State.storeFingerprint, Match("Store key in cache? "), State.AskYN)
    M.transition(State.AskYN, MatchContains("(y/n)"), State.Start)
    M.handle(State.AskYN, State.Any, cb)     # answer yes or no

    M.transition(State.Start, Match("login as:"), State.Negotiate)
    M.handle(State.Start, State.Negotiate, cb)  # type in username
    M.transition(State.Start, MatchPattern('Using username "'), State.GetUser)
    M.transition(State.GetUser, Match('"'), State.Negotiate)
    M.handle(State.GetUser, State.Any, cb)    # grab username

    M.transition(State.Negotiate, Match("\n"), State.Negotiate)
    M.handle(State.Negotiate, State.Negotiate, cb)  # grab negotiation
    M.transition(State.Negotiate, Match("Password:"), State.InputPassword)
    M.handle(State.Negotiate, State.InputPassword, cb)  # type in password

    M.transition(State.InputPassword, Match("Access denied"), State.Negotiate)
    M.transition(State.Negotiate, Match("FATAL ERROR:"), State.Error)
    M.transition(State.Error, Match('\n'), State.End)
    M.handle(State.Error, State.Any, cb)

    example="""The server's host key is not cached in the registry. You
have no guarantee that the server is the computer you
think it is.
The server's rsa2 key fingerprint is:
ssh-rsa 2048 4f:0f:67:fb:0c:6b:1b:82:fa:7b:6d:17:51:f7:41:29
If you trust this host, enter "y" to add the key to
PuTTY's cache and carry on connecting.
If you want to carry on connecting just once, without
adding the key to the cache, enter "n".
If you do not trust this host, press Return to abandon the
connection.
Store key in cache? (y/n)
login as:
Using keyboard-interactive authentication.
Password:
Access Denied
"""

    example="""Using username "s".
Using keyboard-interactive authentication.
Password:
"""

    example = """login as:
Using keyboard-interactive authentication.
Password:
"""

    example = """Using username "s".
Using keyboard-interactive authentication.
Password:
Access denied
Using keyboard-interactive authentication.
Password:
Access denied
Using keyboard-interactive authentication.
Password:
Access denied
FATAL ERROR: Network error: Software caused connection abort
"""

    data = iter(example)
    input,state = '',M.get()
    while state != State.End:
        res = None
        while res is None:
            input += data.next()
            res = M.process(input)
#        print 'Input ({!r})'.format(input)
#        print 'Next state ({!r})'.format(res)
        if state == res: continue
        input,state = '',res

#    print repr(''.join(data.next() for x in range(10)))
