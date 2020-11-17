import binascii
import collections
import enum
import inspect
import itertools
import os
import random
import re
import socket
import string
import subprocess
import sys
import traceback
import select
import operator
import time
import shutil
import argparse

# third-party modules are imported in their calling functions. this allows
# utils.py to be used for multiple scripts without cluttering up their
# dependencies lists.

def basedir(append='', relative=__file__):
    """
    Get base directory relative to 'relative' or the location of the utils.py
    file.

    :param append: Text to append to base directory
    :param relative: Get base directory relative to this
    :return: The base directory of this script (or relative) with append on the end
    """

    return os.path.realpath(os.path.dirname(relative)) + '/' + append


def file_items(files):
    """
    Read a list of items from files

    :param files: File names to read (any iterable)
    :return: Generator producing items. Each item is strip()ed. Returns an
             empty generator if None or [] is passed.
    """

    if not files:
        return

    for fname in files:
        with open(fname, 'r') as fp:
            yield from (item.strip() for item in fp)


def resolve_domain(domain, tcp=True):
    """ 
    Resolve a domain to its IP addresses

    :param domain: Domain to resolve
    :param tcp: Use TCP to talk to the nameserver
    :return: Set of IP addresses for the domain. None if it's NoAnswer or
             NXDOMAIN. Throws all other resolution exceptions.
    """

    import dns.resolver

    try:
        ips = set([str(record) for record in dns.resolver.query(domain, 'A', tcp=tcp)])
        return ips
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None


def is_ip(item):
    """
    Check if a string looks like an IP address

    :param item: String to check
    :return: True if item is an IP address
    """

    try:
        socket.inet_aton(item)
        return True
    except socket.error:
        return False


def is_cidr(item):
    """
    Check if a string looks like an CIDR range

    :param item: String to check
    :return: True if item is a CIDR range
    """

    import netaddr

    try:
        netaddr.IPNetwork(item)
        return True
    except netaddr.core.AddrFormatError:
        return False


def cidr_ips(cidr):
    """
    Get list of IP addresses for a CIDR

    :param cidr: CIDR to get IP addresses for
    :return: Generator producing IP addresses from the CIDR
    """

    import netaddr

    yield from (str(ip) for ip in netaddr.IPNetwork(cidr))


def find_cidr(cidrs, ip):
    """
    Find the CIDR for an IP address in a list of CIDRs. Returns the first CIDR
    if there are multiple.

    :param cidrs: List of CIDRs
    :param ip: IP address
    :return: CIDR or None
    """

    import netaddr

    for cidr in cidrs:
        if netaddr.IPAddress(ip) in netaddr.IPNetwork(cidr):
            return cidr

    return None


def resolve_to_ips(items, resolve_cidr=True, resolve_domains=True,
                   parse_ports=False, tcp=False):
    """
    Resolve an iterable of domain names, CIDR ranges, and IP addresses to IP
    addresses.

    :param items: Iterable of items
    :param resolve_cidr: Resolve CIDR ranges
    :param resolve_domains: Resolve domains
    :param parse_ports: Parse port ranges
    :param tcp: Use TCP for name resolution
    :return: Generator producing tuples containing: (ip, original_item,
             {ports}). If the IP returned is None resolution was not possible. If the IP
             returned is an Exception there was an error parsing or resolving the item.
    """

    for item in items:
        try:
            # parse out port ranges
            if parse_ports and ':' in item:
                item, *portranges = item.split(':')[0:]
                ports = set(parse_ranges(portranges))
            else:
                ports = None

            if is_ip(item):
                # it's an IP address
                yield (item, item, ports)
            elif is_cidr(item):
                # it's a CIDR range
                if resolve_cidr:
                    yield from ((ip, item, ports) for ip in cidr_ips(item))
                else:
                    exception = RuntimeError('CIDR range resolution is disabled. Could not resolve {}'.format(item))
                    yield (exception, item, ports)
            elif resolve_domains:
                # probably a domain name. resolve it
                debug('Resolving domain {}'.format(item))
                resolved_ips = resolve_domain(item, tcp=tcp)
                if resolved_ips:
                    yield from ((ip, item, ports) for ip in resolved_ips)
                else:
                    exception = RuntimeError('Failed to resolve domain')
                    yield (exception, item, ports)
            else:
                # resolve_domains is off and it wasn't an IP or CIDR
                exception = RuntimeError('Domain resolution is disabled. Could not resolve {}'.format(item))
                yield (exception, item, ports)
        except Exception as exception:
            yield (exception, item, None)


def port_pairs(pairs):
    """
    Produce (host, port) pairs for (host, ports) tuples.

    :param pairs: Iterable of tuples containing (host, ports) where ports is an iterable of ports.
    :return: Generator producing all possible (host, port) pairs
    """

    for pair in pairs:
        host, ports = pair
        for port in ports:
            yield host, port


def soup_up(response):
    """
    Get BeautifulSoup object for requests.get() response. Handles encoding
    correctly.

    :param response: Response to parse
    """

    if 'charset' in response.headers.get('content-type', '').lower():
        http_encoding = response.encoding
    else:
        http_encoding = None

    import bs4
    html_encoding = bs4.dammit.EncodingDetector.find_declared_encoding(response.content, is_html=True)
    encoding = html_encoding or http_encoding
    soup = bs4.BeautifulSoup(response.content, features='lxml', from_encoding=encoding)

    return soup


def rdns(ip, tcp=False):
    """
    Get PTR record for an IP address

    :param ip: IP to get PTR record for
    :param tcp: Use TCP to talk to the nameserver
    :return: PTR record or none
    """

    import dns.reversename
    import dns.resolver

    rev = dns.reversename.from_address(ip)
    try:
        record = str(dns.resolver.query(rev, 'PTR', tcp=tcp)[0]).rstrip('.')
        return record
    except dns.resolver.NXDOMAIN:
        return None


def threadify(function, items, max_threads=10, throw_exceptions=False,
        arg_items=False):
    """
    Threadpool helper. Automagically multi-threadifies a function with some items.
    Handles generators correctly by only submitting max_threads * 2 items to
    the threadpool at a time. Returns an iterator that produces (item, result)
    tuples in real-time.

    By default exceptions are returned in the results instead of thrown. See
    throw_exceptions.

    :param function: Function to execute on each item. Called like
                     function(item) by default. See arg_items for an
                     alternative.
    :param items: Iterable (or generator) of items to submit to the threadpool
    :param max_threads: Maximum number of threads to run at a time
    :param throw_exceptions: Throw exceptions instead of returning them.
                             Exception.item is set to the original item.
    :param arg_items: Each item is an iterable of positional arguments or a
                      dict of keyword arguments for the function. Function
                      calls become function(*item) or function(**item) if the
                      item is a dict.
    :return: Generator producing iter((item, result)...)
    """

    import concurrent.futures

    thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=max_threads)
    futures = set()

    # There are certain generators, like range() that are iterable but not
    # iterators and produce repeating, never-depleting lists of numbers for
    # some reason. This fixes that problem.
    items = iter(items)

    # since there's no way to get the original item from a future we have to
    # use this helper.
    #
    # this also handles exceptions. we can't use future.exception() since we'd
    # have no way to associate items with their exceptions. this makes handling
    # results from threadify a bit more annoying but meh... I can't really
    # think of a better option.
    def thread_helper(item):
        try:
            if arg_items:
                if isinstance(item, dict):
                    result = function(**item)
                elif is_iterable(item):
                    result = function(*item)
                else:
                    raise RuntimeError('arg_items is set but item is not an iterable or dict')
            else:
                result = function(item)

            return item, result
        except Exception as exception:
            return item, exception

    running = True
    while running or futures:
        # submit to threadpool
        # only submits max_threads * 2 at a time, in case items is a big generator
        for item in items:
            future = thread_pool.submit(thread_helper, item)
            futures.add(future)

            if len(futures) > max_threads * 2:
                break
        else:
            running = False

        # now we wait for some futures to complete
        # in order to provide results to the caller in realtime we use FIRST_COMPLETED
        done, futures = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
        for future in done:
            exception = future.exception()
            if exception:
                # we should hopefully never reach this
                raise exception
            
            item, result = future.result()
            if throw_exceptions and isinstance(result, Exception):
                result.item = item
                raise result
            else:
                yield item, result


def is_iterable(item):
    """
    Determine if an item is iterable.

    :param item: Item to check
    :return: True if 'item' is iterable
    """

    try:
        # sometimes python tries to optimize out native types that aren't used
        null = iter(item)
        return True
    except TypeError:
        return False


def check_iterator(iterator):
    """
    Determine if an iterator is empty. For some reason Python doesn't allow you
    to peak at the first element of an iterator so this is pretty hacky.

    :param iterator: Iterator to check
    :return: An iterator containing the original values or None if empty
    """

    try:
        first = next(iterator)
        return itertools.chain([first], iterator)
    except StopIteration:
        return None


def is_int(value, base=10):
    """
    Determine if a string value is an integer.

    :param value: String to check
    :param base: Numeric base to check with (default: 10)
    :return: True if 'value' is an integer
    """

    try:
        # sometimes python tries to optimize out native types that aren't used
        null = int(value, base=base)
        return True
    except ValueError:
        return False


def parse_ranges(ranges, allow_unbounded=False):
    """
    Parse a list of number ranges.

    A number range looks like this: 1,5-7,30-32.
    This turns into iter([1, 5, 6, 7, 30, 31, 32]).

    A generator is returned. A range with no end will produce an infinite
    amount of numbers. For example: '5-' produces all numbers from 5 to
    infinity.

    :param ranges: Iterable of ranges to parse
    :return: Generator producing values from the parsed range
    """

    for r in ranges:
        for r2 in r.split(','):
            if '-' in r2:
                start, finish = r2.split('-')
                start = int(start)
                if finish:
                    # bounded range (start-finish)
                    finish = int(finish)
                    yield from range(start, finish + 1)
                elif allow_unbounded:
                    # infinite/unbounded range (start-)
                    value = start
                    while True:
                        yield value
                        value += 1
                else:
                    raise RuntimeError('unbounded range: {}'.format(r2))
            else:
                yield int(r2)

# print helpers
_disabled_groups = {'debug'}
_log_file = None
_status_stream = sys.stderr


def disable_groups(*groups):
    """
    Disable message groups

    :param groups: Groups to disable
    """

    global _disabled_groups

    _disabled_groups |= set(groups)


def enable_groups(*groups):
    """
    Enable message groups

    :param groups: Groups to enable
    """

    global _disabled_groups

    _disabled_groups -= set(groups)


def enable_debug():
    """
    Enable debug messages from utils.debug()
    """

    enable_groups('debug')


def disable_debug():
    """
    Disable debug messages from utils.debug()
    """

    disable_groups('debug')


def disable_status():
    """
    Disable status messages from utils.info(), utils.good(), utils.bad(),
    utils.subline(), utils.debug(), and utils.die()
    """

    disable_groups('info', 'good', 'bad', 'subline', 'debug')


def enable_status():
    """
    Enable status messages from utils.info(), utils.good(), utils.bad(),
    utils.subline(), utils.debug(), and utils.die()
    """

    enable_groups('info', 'good', 'bad', 'subline', 'debug')


def enable_terminal(stream=sys.stderr):
    """
    Enable logging messages to terminal

    :param stream: Stream to write to (default: sys.stderr)
    """

    global _status_stream

    _status_stream = stream


def disable_terminal():
    """
    Disable logging messages to terminal
    """

    global _status_stream

    _status_stream = None


def set_log(fname):
    """
    Write log messages to a file
    """

    global _log_file

    _log_file = fname


def disable_log():
    """
    Disable log file
    """

    global _log_file

    _log_file = None


# log indent amount
_log_indent = 0

def indent(amount=4):
    """
    Increase indent amount for logs

    :param amount: Amount to indent
    """

    global _log_indent
    _log_indent +=4


def dedent(amount=4):
    """
    Decrease indent amount for logs

    :param amount: Amount to dedent
    """

    global _log_indent
    _log_indent -=4


def _indented(message):
    """
    Make indented message

    :param message: Message to indent
    :return: Indented message
    """

    global _log_indent
    return ' ' * _log_indent + message

def log(message='', group='other', color=None, status=False):
    """
    Log message to stderr and/or file, depending on settings

    :param message: Message to log
    :param group: Message group
    :param color: Message color. Passed directly to termcolor, if termcolor is installed
    :param status: Message is a status message. Print to stderr.
    """

    global _log_file
    global _status_stream
    global _disabled_groups

    if group in _disabled_groups:
        # messagr group is disabled
        return False
    
    message = _indented(message)

    if _status_stream:
        # print to terminal
        if color and _status_stream.isatty() and sys.platform.startswith('linux'):
            try:
                import termcolor
                terminal_message = termcolor.colored(message, color)
            except Exception as e:
                debug_exception(e)
                terminal_message = message
        else:
            terminal_message = message

        if status:
            print(terminal_message, file=_status_stream)
        else:
            print(terminal_message)

    if _log_file:
        # write to log file
        with open(_log_file, 'a+') as fp:
            fp.write(message + '\n')

    return True


def debug(message):
    """
    Log a debug message. Debug messages are disabled by default. Enable them
    with utils.enable_debug(). Disable them again with utils.disable_debug().

    :param message: Message to log
    """

    return log('[D] ' + message, group='debug', status=True)


def raw_debug(message):
    """
    Log a raw debug message. No prefix. See utils.debug().

    :param message: Message to log
    """

    return log(message, group='debug', status=True)


def info(message):
    """
    Log an info message.

    :param message: Message to log
    """

    return log('[.] ' + message, group='info', status=True)


def good(message, color=False):
    """
    Log a good message.

    :param message: Message to log
    """

    return log('[+] ' + message, group='good', color='green' if color else None, status=True)


def bad(message, color=False):
    """
    Log a bad message.

    :param message: Message to log
    """

    return log('[!] ' + message, group='bad', color='yellow' if color else None)


def die(message=None, code=1):
    """
    Log a bad message and exit.

    :param message: Message to log
    :param code: Process return code
    """

    if message:
        bad(message)
    sys.exit(code)


def subline(message):
    """
    Log an indented message.

    :param message: Message to log
    """

    return log(' ' * 4 + message, group='subline', status=True)


def exception_info(exception, limit=6):
    """
    Get multi-line info and stacktrace for an exception

    :param exception: Exception
    :param limit: Stackframe limit
    :return: Exception info from traceback
    """

    try:
        if isinstance(exception, Exception):
            raise exception
        else:
            # not an exception
            return None
    except:
        return traceback.format_exc(limit=limit)

    # weird exception. failed to raise
    return None


def debug_exception(exception, limit=6):
    """
    Print info for an exception if debug is enabled.

    :param exception: Exception
    :param limit: Stackframe limit
    """

    info = exception_info(exception, limit=limit)
    if info:
        raw_debug(info)


def check_args(func, args):
    """
    Check argument list length before calling a function

    For functions with *args there is no maximum argument length. The minimum
    argument length is the number of positional and keyword arguments a
    function has.

    :param func: Function to check
    :param args: Args to check
    :return: True if function arguments are valid
    """

    sig = inspect.signature(func)
    min_args = 0
    max_args = len(sig.parameters)
    for name, info in sig.parameters.items():
        if info.kind == inspect.Parameter.VAR_POSITIONAL:
            # no max arg
            max_args = 9999
        else:
            # positional, kwarg, etc
            if info.default == inspect._empty:
                min_args += 1

    return len(args) >= min_args and len(args) <= max_args


def signature(func, trim=0):
    """
    Get stringy function argument signature

    :param func: Function to get signature for
    :param trim: Trim N arguments from front
    :return: Stringified function argument signature
    """

    sig = inspect.signature(func)
    params = list(sig.parameters.values())[trim:]
    sig = sig.replace(parameters=params)
    return str(sig)


def signature_command(func, trim=0):
    """
    Get stringy function argument signature, in unix command form

    '(a, b, c=None, *d)' turns into 'a b [c=None] [d...]'

    :param func: Function to get signature for
    :param trim: Trim N arguments from front
    :return: Stringified function argument signature
    """

    sig = inspect.signature(func)
    params = list(sig.parameters.values())[trim:]

    parsed = []
    for param in params:
        if param.kind == inspect.Parameter.POSITIONAL_OR_KEYWORD:
            # arg or arg=None
            if param.default == param.empty:
                # no default
                parsed.append(param.name)
            else:
                # default
                parsed.append('[{}={}]'.format(param.name, str(param.default)))
        elif param.kind == inspect.Parameter.VAR_POSITIONAL:
            # *arg
            parsed.append('[{}...]'.format(param.name))

    return ' '.join(parsed)


def func():
    """
    Get function object of caller

    :return: Function object of calling function
    """

    tup = inspect.stack()[2]
    return tup[0].f_globals[tup[3]]


def yaml_basic_load(yaml):
    """
    Very rudimentary yaml to list-of-dict loader. It only supports a single
    list of dictionaries.

    :param yaml: Yaml to load
    :return: A list of dicts representing the items
    """

    items = []
    new_item = collections.OrderedDict()

    for line in yaml.splitlines():
        line = line.strip()

        # skip blank lines
        if not line:
            continue

        if line.startswith('- '):
            # start new item
            if new_item:
                items.append(new_item)
            line = line[2:]
            new_item = collections.OrderedDict()

        # key-value pair
        m = re.match('([^:]+):(.*)', line)
        if m:
            key = m.group(1).strip()
            value = m.group(2).strip()
            new_item[key] = value
        else:
            raise RuntimeError("yaml_basic_read: Could not parse yaml. It's probably too complex")

    if new_item:
        items.append(new_item)

    return items


def yaml_basic_dump(items):
    """
    Very rudimentary list-of-dict to yaml dumper. It only supports a single
    list of dictionaries.

    :param items: List of dictionaries to dump
    :return: Yaml representing the items
    """

    yaml = ''

    for item in items:
        first = True
        for key, value in item.items():
            # choose prefix
            if first:
                first = False
                prefix = '- '
            else:
                prefix = '  '

            yaml += '{}{}: {}\n'.format(prefix, key, value)

    return yaml


def is_iterable(var):
    """
    Determine if a variable is an Iterable.

    :param var: Variable to check
    :return: Boolean specifying whether 'var' is iterable
    """

    try:
        iterator = iter(var)
        return True
    except TypeError:
        return False


def is_int(string, base=10):
    """
    Check if a string is an integer.

    :param string: String to check
    :param base: Base to check with (default: 10)
    :return: True if the string is an integer
    """

    try:
        int(string, base=base)
        return True
    except ValueError:
        return False


def random_string(minsize=4, maxsize=8, choices=string.ascii_uppercase):
    """
    Generate a random ASCII string

    :param minsize: Minimum string size
    :param maxsize: Maximum string size
    :param choices: Character choices (default: ASCII uppercase letters)
    """

    size = random.randint(minsize, maxsize)
    return ''.join(random.choice(choices) for _ in range(size))


def random_number_string(length, no_zero_start=False):
    """
    Produce a random fixed-length number string

    :param length: Length of string
    :param no_zero_start: Do not allow the string to start with 0
    """

    if no_zero_start:
        number = str(random.randint(1, 9))
    else:
        number = str(random.randint(0, 9))

    number += ''.join([str(random.randint(0, 9)) for _ in range(length - 1)])

    return number


def capture(command, shell=True, stdin=None, stderr=subprocess.DEVNULL, triplet=False):
    """
    Run a command and capture output (blocking)

    :param command: Command to run
    :param shell: Run in shell?
    :param stdin: Data to pass to stdin
    :param stderr: Where to pipe stderr (DEVNULL, PIPE, STDOUT, etc)
    :param triplet: Return a tuple triplet of (return, stdout, stderr) instead of just stdout
    """

    if triplet and stderr == subprocess.DEVNULL:
        stderr = subprocess.PIPE

    proc = subprocess.Popen(command, shell=shell, stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=stderr)

    if triplet:
        stdout, stderr = proc.communicate(input=stdin)
        return proc.returncode, stdout, stderr
    else:
        return proc.communicate(input=stdin)[0]


def writelines(fname, lines, append=True):
    """
    Write iterable of lines to a file with linebreaks

    :param fname: File to write to
    :param lines: Iterable of lines
    :param append: Append instead of overwriting file?
    """

    mode = 'a+' if append else 'w+'

    with open(fname, mode) as fp:
        fp.write('\n'.join(lines) + '\n')


def parse_host(host):
    """
    Parse a host
    
    :param host: Host in [user@]host[:port] format 
    :return: (host, user, port)
    """
    
    user = None
    port = None
    
    # Split port
    if ':' in host:
        host, port = host.split(':')
        port = int(port)
    
    # Split user
    if '@' in host:
        user, host = host.split('@')
    
    return host, user, port


def print_exception(exception, limit=6):
    """
    Print info for an exception
    
    :param exception: Exception
    :param limit: Stackframe limit
    """
    
    info = exception_info(exception, limit=limit)
    if info:
        log(info)


def merge_iterators(*iters):
    """
    Merge iterators
    
    :param *iters: Iterators to merge
    :return: Values intertwined
    """
    
    empty = {}
    for values in itertools.izip_longest(*iters, fillvalue=empty):
        for value in values:
            if value is not empty:
                yield value


def select_files(*files):
    """
    Select read lines on multiple files
    
    :param *files: Files to select on
    :return: Generator of file lines
    """

    descriptors = {}
    for fp in files:
        descriptor = fp.fileno()
        descriptors[descriptor] = fp
    
    reads, _, _ = select.select(descriptors.keys(), [], [])
    
    for descriptor in reads:
        fp = descriptors[descriptor]
        yield fp.readline()


def lazy_json(fp):
    """
    Load a list of json dictionaries super slowly but lazily. Each JSON entry
    must end in } or }, then a newline.

    :param fp: File to read from
    :return: Generator of json objects
    """

    import json

    buf = ''
    for line in fp:
        line = line.rstrip()
        if line in ('[', ']'):
            continue
        if line.endswith('},'):
            line = line[:-2] + '}'
        buf += line

        try:
            obj = json.loads(buf)
            yield obj
            buf = ''
        except json.JSONDecodeError:
            pass


def lazy_json_strict(fp):
    """
    Load a list of json dictionaries lazily. Must be formatted as follows:

    [
    {
        "foo": "bar"
    },
    ...
    ]

    :param fp: File to read from
    :return: Generator of json objects
    """

    try:
        # ujson is a bit faster if we have it
        import ujson as json
    except ImportError:
        import json

    buf = ''
    for line in fp:
        line = line.rstrip()
        if line in ('[', ']'):
            continue
        if line == '},':
            buf += '}'

            obj = json.loads(buf)
            yield obj
            buf = ''
        else:
            buf += line


# From https://gist.github.com/babakness/3901174
class CaselessDictionary(dict):
    """
    Dictionary that enables case insensitive searching while preserving case
    sensitivity when keys are listed, ie, via keys() or items() methods. Works
    by storing a lowercase version of the key as the new key and stores the
    original key-value pair as the key's value (values become dictionaries).
    """

    def __init__(self, initval={}):
        if isinstance(initval, dict):
            for key, value in initval.items():
                self.__setitem__(key, value)
        elif isinstance(initval, list):
            for (key, value) in initval:
                self.__setitem__(key, value)
            
    def __contains__(self, key):
        return dict.__contains__(self, key.lower())
  
    def __getitem__(self, key):
        return dict.__getitem__(self, key.lower())['val'] 
  
    def __setitem__(self, key, value):
        return dict.__setitem__(self, key.lower(), {'key': key, 'val': value})

    def get(self, key, default=None):
        try:
            v = dict.__getitem__(self, key.lower())
        except KeyError:
            return default
        else:
            return v['val']

    def has_key(self,key):
        if self.get(key):
            return True
        else:
            return False    

    def items(self):
        return [(v['key'], v['val']) for v in dict.values(self)]
    
    def keys(self):
        return [v['key'] for v in dict.values(self)]
    
    def values(self):
        return [v['val'] for v in dict.values(self)]
    
    def items(self):
        for v in dict.values(self):
            yield v['key'], v['val']
        
    def keys(self):
        for v in dict.values(self):
            yield v['key']
        
    def values(self):
        for v in dict.values(self):
            yield v['val']


def ensure_type(item, type_):
    """
    Ensure item is of a type.

    If items is already of that type, return as-is. If converting a
    non-collection item to a list, make item an only item in the list.
    Otherwise cast it to the type.

    :param item: Item to ensure
    :param type_: Type to ensure against
    """

    if isinstance(item, type_) or type_ is None:
        return item
    elif type_ == list and not (isinstance(item, set) or isinstance(item, tuple)):
        return [item]
    else:
        return type_(item)


def insensitive_in(item, collection):
    """
    Run case-insensitve "item in collection".

    :param item: Item to check
    :param collection: Collection to check against
    :return: True if item is in collection
    """

    # ensure collection is a list
    collection = ensure_type(collection, list)

    return item.lower() in [c.lower() for c in collection]


def insensitive_equals(item1, item2):
    """
    Run case-insensitve "item1 == item2".

    :param item1: Item to compare
    :param item2: Item to compare
    :return: True if items are equal
    """

    return item1.lower() == item2.lower()


def remove_duplicates(iterable):
    """
    Slow duplicate remover that maintains order and does not require items to
    be sorted or grouped.

    From http://www.peterbe.com/plog/uniqifiers-benchmark

    :param iterable: Iterable to remove duplicates from
    :return: Generator with de-duplicated values
    """

    seen = set()
    seen_add = seen.add
    return (x for x in iterable if not (x in seen or seen_add(x)))


def remove_grouped_duplicates(iterable):
    """
    Remove duplicates in an iterable that are already grouped together

    :param iterable: Iterable to remove duplicates from
    :return: Generator for de-duplicated values
    """
    last_item = None
    for item in iterable:
        if item == last_item:
            continue
        else:
            yield item
            last_item = item


def sort_unique(iterable, key=None, reverse=False):
    """
    Sort and remove duplicates while maintaining order

    :param iterable: Iterable to sort
    :param key: Sort key
    :param reverse: Reverse sort?
    :return: Sorted and de-deplicated map object
    """

    return map(operator.itemgetter(0),
        itertools.groupby(sorted(iterable, key=key, reverse=reverse)))


def interact(var):
    """
    Interact with a Python REPL

    :param var: Local variables to expose (recommended locals() or globals() or a dict)
    """

    info('Local variables: {}'.format(var))
    import code
    code.InteractiveConsole(var).interact()


def jitter(middle, percent):
    """
    Generate a random jitter value. Value is centered around middle. Percent
    defines the relative upper and lower bounds.

    :param middle: Mid-point for random number
    :param percent: Percent for upper and lower bounds
    :return: A random value between upper and lower bounds
    """

    middle *= 1000
    variant = int(middle * (percent / 100.0))
    min = middle - variant
    max = middle + variant
    return random.randint(min, max) / 1000


def jitter_sleep(middle, percent):
    """
    Sleep for a random amount of time based on a jitter value.

    :param middle: Mid-point for random number
    :param percent: Percent for upper and lower bounds
    """

    length = jitter(middle, percent)
    time.sleep(length)

def round_to(value, to):
    """
    Round a value up to the nearest multiple of a number

    :param value: Value to round up
    :param to: Multiple
    :return: Rounded value
    """

    if value % to == 0:
        return value
    else:
        return value + to - value % to

def xor_encrypt(data, key):
    """
    Encrypt/decrypt data with an xor key

    :param data: Data to encrypt
    :param key: Variable length key to encrypt with
    :return: Encrypted data
    """

    encrypted = []
    for i, b in enumerate(data):
        encrypted.append(b ^ key[i % len(key)])
    return bytes(encrypted)


def randstr(minsize=4, maxsize=8, choices=string.ascii_lowercase):
    """
    Generate a random string token

    :param minsize: Minimum string size
    :param maxsize: Maximum string size
    :param choices: Characters to choose from
    :return: Random string
    """

    size = random.randint(minsize, maxsize + 1)
    return ''.join(random.choice(choices) for _ in range(size))


# wordlist for randhuman
wordlist = basedir('resources/wordlist.txt')
words = None

def randhuman(minnumber=1, maxnumber=3, title_case=True):
    """
    Generate random token made of real words
    
    :param minnumber: Minimum number of words
    :param maxnumber: Maximum number of words
    :param title_case: Use title case instead of the case in the wordlist
    :return: Random token
    """

    # read in wordlist
    global words
    if not words:
        with open(wordlist, 'r') as fp:
            words = [
                        ''.join(c for c in s if c.isalpha()) for s in fp.readlines()
                    ]

    # generate them
    num_choices = random.randint(minnumber, maxnumber + 1)
    choices = [random.choice(words) for _ in range(num_choices)]

    # make title case
    if title_case and len(choices) > 1:
        choices = [choices[0]] + [s.title() for s in choices[1:]]

    return ''.join(choices)


def chunkup(data, size=75):
    """
    Split data into chunks

    :param data: Data to chunk up
    :param size: Size of each chunk
    :return: List of chunks
    """

    chunks = [data[i:i + size] for i in range(0, len(data), size)]
    return chunks


def obfuscate_tokens(data, regex='%%[^%]+%%', human=False):
    """
    Obfuscate %%NAME%% tokens
    
    :param data: Data to obfuscate tokens in
    :param human: Use wordlist to generate tokens
    :return: Obfuscated data
    """

    # get tokens
    matches = re.finditer(regex, data)
    tokens = [m.group(0) for m in matches]
    unique = set(tokens)

    def gentokens(factor=5):
        while True:
            if human:
                yield randhuman(factor - 2, factor - 1)
            else:
                yield randstr(3 * factor, 5 * factor)

    token_iter = iter(unique)
    replace_iter = gentokens()
    for token, replace in zip(token_iter, replace_iter):
        debug('replacing {} with {}'.format(token, replace))
        while replace in data:
            replace = next(replace_iter)
        data = data.replace(token, replace)

    return data


def mask_string(string, mask):
    """
    Mask and hex encode a string

    :param string: String to mask
    :param mask: XOR mask
    :return: Hex-encoded masked string
    """

    masked = xor_encrypt(string.encode(), bytes(mask))
    return binascii.hexlify(masked).decode()


def command_exists(name):
    """
    Check if a command exists in PATH

    :param name: Name of command to check
    :return: True if command exists
    """

    return shutil.which(name) is not None

def run_msfvenom(input=None, encoder=None, iterations=1, payload='-', platform='windows', arch='x86', format='raw', remove_bytes=None):
    """
    Run msfvenom
    """

    # make sure msfvenom exists
    if not command_exists('msfvenom'):
        die('msfvenom not in PATH')

    command = ['msfvenom']
    # encoder
    if encoder is not None:
        command += ['-e', encoder]
    # iterations
    command += ['-i', str(iterations)]
    # payload
    command += ['-p', payload]
    # platform
    command += ['--platform', platform]
    # arch
    command += ['-a', arch]
    # format
    command += ['-f', format]
    # remove_bytes
    if remove_bytes is not None:
        command += ['-b', remove_bytes]

    debug('running {}'.format(' '.join(command)))
    code, stdout, stderr = capture(command, shell=False, stdin=input, triplet=True)

    if code != 0:
        bad('msfvenom failed:')
        log(' '.join(command))
        log(stderr.decode())
        die()

    return stdout


def run_mcs(*files, unsafe=True, target='exe', out=None, arch='anycpu', sdk=2, references=None):
    """
    Run mcs to compile C# code

    :param files: Files to compile
    :param unsafe: Add /unsafe flag
    :param target: Compilation target
    :param out: Output file
    :param arch: Architecture to target
    :param sdk: SDK version
    :param references: References to add
    """

    if not command_exists('mcs'):
        die('mcs not in PATH')

    command = ['mcs',
        '/target:{}'.format(target),
        '/platform:{}'.format(arch),
        '/sdk:{}'.format(sdk)]

    if references is not None:
        command.append('/reference:{}'.format(','.join(references)))

    if unsafe:
        command.append('/unsafe')

    if out is not None:
        command.append('/out:{}'.format(out))
    
    command += files

    debug('running {}'.format(' '.join(command)))
    code, stdout, stderr = capture(command, shell=False, triplet=True, stderr=subprocess.STDOUT)
    if code != 0:
        bad('mcs failed:')
        log(' '.join(command))
        log(stdout.decode())
        die()

    return stdout


def add_args(parser, arguments):
    """
    Add ArgumentParser options in dict format.
    
    The dict keys match the kwargs to the add_argument function. The flag/flags key is a single or list. The help key is extended with (default: foo)

    This is maybe less annoying than extending ArgumentParser because it covers both argument groups and the regular add_argument.

    :param parser: Parser to add to
    :param arguments: Arguments to add
    """

    for arg in arguments:
        if 'flags' in arg:
            flags = arg['flags']
            del arg['flags']
        elif 'flag' in arg:
            flags = arg['flag']
            del arg['flag']
        else:
            raise RuntimeError('arg must have flag or flags')

        # make it a list
        if not isinstance(flags, list) or isinstance(flags, tuple):
            flags = [flags]

        if 'default' in arg:
            arg['help'] += ' (default: {})'.format(arg['default'])

        parser.add_argument(*flags, **arg)


def yesno(value):
    """
    Turn a boolean into a yes/no value

    :param value: Boolean
    :return: 'yes' if value is True. otherwise 'no'
    """

    return 'yes' if value else 'no'

def csharp_array(values, split=50):
    """
    Turn an iterable of values into a csharp array literal

    :param values: Values to turn into literal
    """

    out = '{'
    for line in chunkup(values, size=split):
        out += ','.join([str(value) for value in line]) + ',\n'
    out += '}'
    return out

def binary_percent(data):
    textchars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})
    translated = bytes.translate(None, textchars)
    print(len(translated))
    print(len(data))

