#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import argparse
import os
import re
import string
import sys
from collections import defaultdict, namedtuple
from functools import partial  

CHARS_FOR_SHELL = set(string.ascii_letters + string.digits + '%+,-./:=@^_~')
REGEX_TIMESTAMP = re.compile(r'^\d+(?::\d+:\d+)?(?:\.\d+)?\s+')
RESUMED_PREFIX = re.compile(r'<... \w+ resumed> ')
TAG_FOR_UNFINISHED = ' <unfinished ...>'
IGNORE = re.compile(r'^$|^strace: Process \d+ attached$')
DURATION_SUFFIX = re.compile(r' <\d+(?:\.\d+)?>$')
QUOTES_FOR_SHELL = CHARS_FOR_SHELL | set("!#&'()*;<>?[]{|} \t\n")
PROCESSID = re.compile(r'^\[pid (\d+)\]')



Tree = namedtuple('Tree', 'trunk, fork, end, space')


class Theme(object):

    default_styles = dict(
        tree_style='normal',
        pid='red',
        process='green',
        time_range='blue',
    )

    tree_format = Tree(
        '  │ ',
        '  ├─',
        '  └─',
        '    ',
    )

    def __new__(cls, color=None, unicode=None):
        cls = color_set
        return object.__new__(cls)

    def __init__(self):
        unicode = getattr(sys.stdout, 'encoding', None) == 'UTF-8'
        self.tree = self.tree_format
        self.styles = dict(self.default_styles)

    def _format(self, prefix, suffix, text):
        if not text:
            return ''
        return '{}{}{}'.format(prefix, text, suffix)

    def _no_format(self, text):
        return text or ''

    def __getattr__(self, attr):
        if attr not in self.styles:
            raise AttributeError(attr)
        style = self.styles[attr]
        if style == 'normal':
            _format = self._no_format
        else:
            prefix = self.ctlseq[style]
            suffix = self.ctlseq['normal']
            _format = partial(self._format, prefix, suffix)
        setattr(self, attr, _format)
        return _format

class color_set(Theme):

    ctlseq = dict(
        normal='\033[m',
        red='\033[31m',
        green='\033[32m',
        blue='\033[34m',
    )


Event = namedtuple('Event', 'pid, timestamp, event')


def parse_timestamp(timestamp):
    if ':' in timestamp:
        h, m, s = timestamp.split(':')
        return (float(h) * 60 + float(m)) * 60 + float(s)
    else:
        return float(timestamp)



def events(stream):
    pending = {}
    for line in stream:
        line = line.strip()
        if line.startswith('[pid'):
            line = PROCESSID.sub(r'\1', line)
        pid, space, event = line.partition(' ')
        try:
            pid = int(pid)
        except ValueError:
            if IGNORE.match(line):
                continue
            raise SystemExit(
                "This does not look like a log file produced by strace -f:\n\n"
                "  %s\n\n"
                "There should've been a PID at the beginning of the line."
                % line)
        event = event.lstrip()
        timestamp = None
        if event[:1].isdigit():
            m = REGEX_TIMESTAMP.match(event)
            if m is not None:
                timestamp = parse_timestamp(m.group())
                event = event[m.end():]
        if event.endswith('>'):
            e, sp, d = event.rpartition(' <')
            if DURATION_SUFFIX.match(sp + d):
                event = e
        if event.startswith('<...'):
            m = RESUMED_PREFIX.match(event)
            if m is not None:
                pending_event, timestamp = pending.pop(pid)
                event = pending_event + event[m.end():]
        if event.endswith(TAG_FOR_UNFINISHED):
            pending[pid] = (event[:-len(TAG_FOR_UNFINISHED)], timestamp)
        else:
            yield Event(pid, timestamp, event)


Process = namedtuple('Process', 'pid, seq, name, parent')


class ChildMapping(object):
    def __init__(self):
	# dictionary for processes
        self.processes = {} 
	# dicitonary for the start time to seconds  
        self.start_time = {} 
	# dicitonary for the exit time to seconds 
        self.exit_time = {}  
	# mapping of child processes and every process will appear only once
        self.children = defaultdict(set)

    def add_child(self, ppid, pid, name, timestamp):
        parent = self.processes.get(ppid)
        if parent is None:
	    # for -p command .out file it's possible that the it can leave the initial call of the parent so initializing the parent.
            parent = Process(pid=ppid, seq=0, name=None, parent=None)
            self.children[None].add(parent)
	# To get the previous process id as it's possible that the child process was executed before the parent's clone() returned a value
        old_process = self.processes.get(pid)
        if old_process is not None:
            self.children[old_process.parent].remove(old_process)
            child = old_process._replace(parent=parent)
        else:
	    # It is possible that clone can happen before execve so condition for those cases
            child = Process(pid=pid, seq=0, name=name, parent=parent)
        self.processes[pid] = child
        self.children[parent].add(child)
	# Assigning the timestamp can be tricky because timestamp of execuve() will always be greater than clone()'s 
        self.start_time[child] = timestamp

    def handle_exec(self, pid, name, timestamp):
        old_process = self.processes.get(pid)
        if old_process:
            new_process = old_process._replace(seq=old_process.seq + 1,
                                               name=name)
            if old_process.seq == 0 and not self.children[old_process]:
		# removing the child process if there is nothing between the start of process and exec()
                self.children[old_process.parent].remove(old_process)
        else:
            new_process = Process(pid=pid, seq=1, name=name, parent=None)
        self.processes[pid] = new_process
        self.children[new_process.parent].add(new_process)
        self.start_time.setdefault(new_process, timestamp)

    def handle_exit(self, pid, timestamp):
        process = self.processes.get(pid)
        if process:
	    # checking for the exit time if the process is still running and its clone/execve calls
            self.exit_time[process] = timestamp

    def _format_time_range(self, start_time, exit_time):
        if start_time is not None and exit_time is not None:
            return '[{duration:.1f}s @{start_time:.1f}s]'.format(
                start_time=start_time,
                exit_time=exit_time,
                duration=exit_time - start_time
            )
	# condition for if start_time is None or 0 
        elif start_time:
            return '[@{start_time:.1f}s]'.format(
                start_time=start_time,
            )
        else:
            return ''

    def _format_process_name(self, theme, name, indent, cs, ccs, padding):
        lines = (name or '').split('\n')
        return '\n{indent}{tree}{padding}'.format(
            indent=indent,
            tree=theme.tree_style(cs + ccs),
            padding=padding,
        ).join(
            theme.process(line)
            for line in lines
        )

    def _format(self, theme, processes, indent='', level=0):
        r = []
        for n, process in enumerate(processes):
            if level == 0:
                s, cs = '', ''
            elif n < len(processes) - 1:
                s, cs = theme.tree.fork, theme.tree.trunk
            else:
                s, cs = theme.tree.end, theme.tree.space
            children = sorted(self.children[process])
            if children:
                ccs = theme.tree.trunk
            else:
                ccs = theme.tree.space
            time_range = self._format_time_range(
                self.start_time.get(process),
                self.exit_time.get(process),
            )
            title = '{pid} {name} {time_range}'.format(
                pid=theme.pid(process.pid or '<unknown>'),
                name=self._format_process_name(
                    theme, process.name, indent, cs, ccs, theme.tree.space),
                time_range=theme.time_range(time_range),
            ).rstrip()
            r.append(indent + (theme.tree_style(s) + title).rstrip() + '\n')
            r.append(self._format(theme, children, indent+cs, level+1))

        return ''.join(r)

    def format(self, theme):
        return self._format(theme, sorted(self.children[None]))

    def __str__(self):
        return self.format(PlainTheme(unicode=True))


def simplify_syscall(event):
    # checking for the events which start with clone and the flags present in it
    if event.startswith('clone('):
        event = re.sub('[(].*, flags=([^,]*), .*[)]', r'(\1)', event)
    return event.rstrip()

ESCAPES = {
    'n': '\n',
    'r': '\r',
    't': '\t',
    'b': '\b',
    '0': '\0',
    'a': '\a',
}


# parsing the event stream and creating the Tree
def stream_analyzer(event_stream):
    tree = ChildMapping()
    first_timestamp = None
    for e in event_stream:
        timestamp = e.timestamp
        if timestamp is not None:
            if first_timestamp is None:
                first_timestamp = e.timestamp
            timestamp -= first_timestamp
        if e.event.startswith('execve('):
            args, equal, result = e.event.rpartition(' = ')
            if result == '0':
                name = simplify_syscall(args)
		
                tree.handle_exec(e.pid, name, timestamp)
        if e.event.startswith(('clone(', 'fork(', 'vfork(')):
            args, equal, result = e.event.rpartition(' = ')
	    # checking the result.isdigit() to get not permitted operation 
            if result.isdigit():
                child_pid = int(result)
                name = simplify_syscall(args)
                tree.add_child(e.pid, child_pid, name, timestamp)
        if e.event.startswith('+++ exited with '):
            tree.handle_exit(e.pid, timestamp)
    return tree

def adding_quotes(arg):
    # Adding double quote in the command "--exec=yes" to --exec="yes"
    return re.sub('''^(['"])(--[a-zA-Z0-9_-]+)=''', r'\2=\1', arg)

def command_org(safe_command):
    return ' '.join(map(adding_quotes, (
        arg if all(c in CHARS_FOR_SHELL for c in arg) else
        '"%s"' % arg if all(c in QUOTES_FOR_SHELL for c in arg) else
        "'%s'" % arg.replace("'", "'\\''")
        for arg in safe_command
    )))

def main():
    tree = stream_analyzer(events(open(sys.argv[1], 'r')))
    theme = Theme()
    print(tree.format(theme).rstrip())


if __name__ == '__main__':
    main()
