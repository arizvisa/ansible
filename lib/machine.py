import abc,functools,itertools,collections,heapq,weakref
from abc import ABCMeta,abstractmethod,abstractproperty

__all__ = ('Rule', 'RulePredicate', 'RuleNot', 'RuleAll', 'RuleAny')
__all__+= ('State', 'Machine')

### Rules for transitioning between states
class Rule(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def enter(self, state):
        """Callback when entering a specific state.

        Typically used for initializing a given rule.
        """
        return

    @abstractmethod
    def leave(self, state):
        """Callback when leaving a specific state.

        Typically used for uninitializing a given rule.
        """
        return

    @abstractmethod
    def process(self, data):
        """Callback to use when processing input.

        Returns False if more input is required, True if there's enough input for this rule to work.
        """
        raise NotImplementedError

class RulePredicate(Rule):
    def __init__(self, P):
        self._predicate = P
    enter = lambda self,state: None
    leave = lambda self,state: None
    process = lambda self,data: self._predicate(data)

class RuleNot(Rule):
    __slots__ = ('_predicate',)
    def __init__(self, P): self._predicate = P
    enter = lambda self,state: self._predicate.enter(state)
    leave = lambda self,state: self._predicate.leave(state)
    process = lambda self,data: not self._predicate.process(data)

class RuleAll(Rule):
    __slots__ = ('_rules',)
    def __init__(self, *subrules):
        self._rules = subrules
    enter = lambda self,state: [r.enter(state) for r in self._rules]
    leave = lambda self,state: [r.leave(state) for r in self._rules]
    process = lambda self,data: all((r.process(data) for r in self._rules))

class RuleAny(Rule):
    __slots__ = ('_rules',)
    def __init__(self, *subrules):
        self._rules = subrules
    enter = lambda self,state: [r.enter(state) for r in self._rules]
    leave = lambda self,state: [r.leave(state) for r in self._rules]
    process = lambda self,data: any((r.process(data) for r in self._rules))

### State identifiers for describing transitions
class StateFactory(object):
    __slots__ = ('__cache__','__retain__')
    State,__cache__ = type('State',(object,),{'__repr__':lambda s:'|{:s}|'.format(s.__name__)}),weakref.WeakValueDictionary()
    def __init__(self, *default):
        getter = functools.partial(getattr, self)
        self.__retain__ = map(getter, default)
    def __getattribute__(self, name):
        cache,State = map(functools.partial(object.__getattribute__,self), ('__cache__','State'))
        res = State()
        res.__name__ = name.capitalize()
        return cache.setdefault(res.__name__, res)
State = StateFactory('Start','End','Any')

### Priority set for managing the order that Rules are evaluated
class PrioritySet(object):
    """List for managing a set of rules sorted by a priority value.
    The priority is used to give each rule a priority when processing data.

    This is internally represented as a heapq. Each value is a tuple of (priority, value).
    """
    def __init__(self, iterable=(), priority=-1):
        super(PrioritySet,self).__init__()

        # add each value from the iterable into our set for dealing with membership
        self._value,self._container = [],{n for n in iterable}

        # push each value in iterable onto the heapq
        push = functools.partial(heapq.heappush, self._value)
        map(push, itertools.imap(lambda n:(priority,n), iterable))

    def __deepcopy__(self):
        from copy import deepcopy
        res = self.__class__()
        res._value,res._container = deepcopy(self._value),deepcopy(self._container)
        return res

    def __copy__(self):
        res = self.__class__()
        res._value,res._container = self._value,self._container
        return res

    ## heapq/set functions
    def push(self, priority, value):
        """Push a value onto the Set with the specified priority.

        A priority of 0 will give it the most priority.
        A priority of larger than 0 will give it less priority.
        """
        if value in self._container:
            raise KeyError, "{!r} already in Set".format(value)

        heapq.heappush(self._value, (priority,value))
        self._container.add(value)

    def discard(self, value):
        """Remove the specified value out of the Set and returns it. Returns None if it's not in the Set."""
        if value not in self._container:
            return
        return self.remove(value)

    def remove(self, value):
        """Remove the specified value from the Set. Raise a KeyError if value is not in the Set."""
        if value not in self._container:
            raise KeyError, '{!r} not contained in Set'.format(value)

        # Figure out the index of the specified value
        idx = [v for _,v in self._value].index(value)
        _,res = self._value.pop(idx)

        # Remove it from the membership container
        self._container.discard(res)
        return res

    def pop(self):
        """Pop a value with the highest priority out of the Set."""
        try:
            _,res = heapq.heappop(self._value)
        except IndexError:
            raise KeyError, 'pop from empty Set'
        self._container.discard(res)
        return res

    def shift(self):
        """Shift a value with the lowest priority out of the Set."""
        try:
            _,res = self._value.pop(-1)
        except IndexError:
            raise KeyError, 'shift from empty Set'
        self._container.discard(res)
        return res

    def add(self, value, priority=-1):
        """Add the specified value into the Set with the least priority unless specified otherwise."""
        return self.push(priority, value)

    def update(self, value, priority=-1):
        """Update the specified value with the given priority. Returns the original priority."""
        if value not in self._container:
            raise KeyError, '{!r} is not in set'.format(value)
        idx = [v for _,v in self._value].index(value)
        prio,res = self._value.pop(idx)
        heapq.heappush(self._value, (priority,res))
        return prio

    def priority(self, value):
        """Return the priority of the specified value."""
        try:
            idx = [v for _,v in self._value].index(value)
        except ValueError:
            raise KeyError, '{!r} is not in Set'.format(value)

        p,_ = super(PrioritySet,self).__getitem__(idx)
        return -p

    # iteration methods
    def larger(self, prio):
        """Return a list containing all elements that have a higher priority than the one requested"""
        # use heapq.nsmallest since our priorities are inverted
        res = itertools.takewhile(lambda (p,v): p >= prio, heapq.nlargest(len(self._value), self._value))
        return [v for _,v in res]
    def smaller(self, prio):
        """Return a list containing the (priority,value) of each element within the set up to n."""
        res = itertools.takewhile(lambda (p,v): p <= prio, heapq.nsmallest(len(self._value), self._value))
        return [v for _,v in res]
    def iterate(self):
        """Return each (priority,value) within the Set sorted from highest priority to least."""
        for p,n in self._value:
            yield p,n
        return

    # List functions
    __repr__ = lambda self: '{!r} {{{:s}}}'.format(type(self), ', '.join(map(str, iter(self))))
    __len__ = lambda self: len(self._container)
    def __iter__(self):
        for _,n in self.iterate():
            yield n
        return

    # Set Membership
    def __contains__(self, *args, **kwds): return self._container.__contains__(*args, **kwds)
    def union(self, *args, **kwds): return self._container.union(*args, **kwds)
    def intersection(self, *args, **kwds): return self._container.intersection(*args, **kwds)
    def isdisjoint(self, *args, **kwds): return self._container.isdisjoint(*args, **kwds)
    def issubset(self, *args, **kwds): return self._container.issubset(*args, **kwds)
    def issuperset(self, *args, **kwds): return self._container.issuperset(*args, **kwds)
    def difference(self, *args, **kwds): return self._container.difference(*args, **kwds)

### State machine that uses rules to determine how to transition between states
class Machine(object):
    """Creates a finite state machine.

    The starting state is Start. The Any state can be used for wildcard matching.
    """

    __slots__ = ('_table','_current','_transition')

    def __init__(self):
        self._table = collections.defaultdict(PrioritySet)
        self._current = State.Start
        self._transition = {}

    def __copy__(self):
        res = self.__class()
        res._table = self._table
        res._current = self._current
        res._transition = dict(self._transition)

    def __deepcopy__(self):
        from copy import deepcopy
        res = self.__class()
        res._table = deepcopy(self._table)
        res._current = deepcopy(self._current)
        res._transition = deepcopy(self._transition)
        return res

    def set(self, state=State.Start):
        res,self._current = self._current,state
        return res

    def get(self):
        return self._current

    def handle(self, state, next, callback):
        """Add a call to callback if the state switches from state to next.

        callback has the prototype of (data, (current state, next state)).
        """
        self._transition[(state,next)] = callback

    def transition(self, state, match, next, priority=-1):
        """Add a transition for state to next if matcher returns True.

        The priority specifies the priority of the rule. The larger the priority, the more important the rule is.
        """
        # if the specified argument matches, execute callback
        assert isinstance(match, Rule)
        states = self._table[state]
        states.push(priority, (match, next))
        return self._table[state]

    def process(self, data):
        """Transition to the next state depending on the value of input

        Returns None if input does not match any states, or the next State if it does.
        """

        # Determine the potential candidates for the next state
        current,transitions = self._current,self._table[self._current]
        candidates = [(p,(r,st)) for p,(r,st) in transitions.iterate() if r.process(data)]

        # If there's no candidates, then there's not enough data to transition to another state
        if len(candidates) == 0:
            return

        # Check the priority against other rules
        prio,_ = candidates[0]   # FIXME: It seems that a PrioritySet should not be allowed to have more than one value with the same priority.
        if sum(1 for p,_ in candidates if p == prio) > 1:
            raise RuntimeError, 'Multiple candidates with the priority {:d} for next state found : {!r}'.format(prio, candidates)

        # Grab the next expected state
        _,next = [v for _,v in candidates][0]

        # Execute the leave callback for all the previous rules
        [r.leave(current) for r,_ in self._table[current]]

        # Execute callback if one's available to get the next state
        if (current,next) in self._transition:
            cb = self._transition[(current,next)]

        # Or check if there's a vague callback (Any) to get to the next state
        elif (current,State.Any) in self._transition:
            cb = self._transition[(current,State.Any)]

        # Otherwise fallback to a callback that just returns the next state
        else:
            cb = lambda input,(cur,next): next

        self._current = current = cb(data, (current,next)) or next

        # Execute the enter callback for all of the current rules
        [r.enter(current) for r,_ in self._table[current]]

        # Return the state that was called
        return current

if __name__ == '__main__':
    import re

    ### Rule baseclasses
    class Matcher(Rule):
        def enter(self, state):
            return
        def leave(self, state):
            return
    class Matcher_string(Matcher):
        __slots__ = ('_string',)
        def __init__(self, string):
            self._string = string

    ### Container for rule types
    class rules:
        class match_anything(Matcher):
            def process(self, data):
                return True
        class match_something(match_anything):
            def process(self, data):
                return len(data) > 0
        class match_nothing(match_anything):
            def process(self, data):
                return len(data) == 0
        class match_start(Matcher_string):
            def process(self, data):
                return data.startswith(self._string)
        class match_end(Matcher_string):
            def process(self, data):
                return data.endswith(self._string)
        class match_contains(Matcher_string):
            def process(self, data):
                return self._string in data
        class match_pattern(Matcher):
            __slots__ = ('_regex','_complete')
            def __init__(self, pattern, flags=0):
                self._regex = re.compile(pattern, flags)
            def process(self, data):
                return self._regex.match(data) is not None
        class match_newline(match_end):
            def __init__(self):
                super(rules.match_newline,self).__init__('\n')

if __name__ == '__main__':
    M = Machine()
    M.transition(State.Start, rules.match_start('Python 2.7.10'), State.Version)
    M.transition(State.Version, rules.match_anything(), State.Version)
    M.transition(State.Version, rules.match_newline(), State.Help, priority=0)

    M.transition(State.Help, rules.match_end('for more information.\n'), State.Prompt)

    M.transition(State.Prompt, rules.match_end('>>>'), State.Spin)
    M.transition(State.Spin, rules.match_end('>>> '), State.Spin)
    M.transition(State.Spin, rules.match_newline(), State.Spin)
    M.transition(State.Spin, rules.match_start('adios'), State.End)

    def version(input, (cur,nxt)):
        print 'version : {!s}'.format(input.split(' ')[1])
    M.handle(State.Start, State.Version, version)

    def prompt(input, (cur,next)):
        print 'got to the prompt : {!s}'.format(input)
    M.handle(State.Prompt, State.Any, prompt)

    def atprompt(input, (cur,next)):
        print 'sitting at the prompt : {!s}'.format(input)
    M.handle(State.Spin, State.Spin, atprompt)

    # initialize input for state machine
    data = """Python 2.7.10 (default, May 23 2015, 09:40:32) [MSC v.1500 32 bit (Intel)] on win32
    Type "help", "copyright", "credits" or "license" for more information.
    >>> print 500
    >>> 
    >>> print 'adios'
    adios
    """
    data = iter(data)

    # for each state
    input,state = '',M.get()
    while state != State.End:
        res = None
        while res is None:
            input += data.next()
            res = M.process(input)
        print res,repr(input)
        input = ''
    print state

if __name__ == '__main__':
    #con = consumer()
    #con.expect("(y/n)")

    #Q = Queue.Queue()
    #def output(q):
    #    while True:
    #        q.put((yield))
    #P = incpy.spawn(output(Q), ['c:/Python27/python.exe', '-i'])
    #print P.running
    #print P.stop()
    pass
