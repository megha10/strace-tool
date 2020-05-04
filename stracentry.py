import re
import sys
from decimal import *


class RowInput:
	'''
	A strace entry
	'''

	def __init__(self, processid, timestamp, flag_process, elapsed_time,
                 sys_call, sys_args, extra):
		self.processid = processid
		self.timestamp = timestamp
		self.flag_process = flag_process
		self.elapsed_time = elapsed_time
		self.sys_call = sys_call
		self.sys_args = sys_args
		self.extra = extra




class FileInput:
    def __init__(self, input):
        self.input = input
        self.head = 0
        self.flag_sys = {}
        self.flag_pid = False

    def __iter__(self):
        return self

    def next(self):
        row = self.input.next()
        if row is None:
            raise StopIteration
        self.head += 1
        row = row.strip()
        tail = 0

        if row == "" or not row[0].isdigit() :
            if self.head == 1:
                raise Exception("Not a valid first line")
            else:
                return self.next()
	processid = None
        if self.head == 1:
            self.flag_pid = re.compile(r"(\d+) .*").match(row) is not None
        if re.compile(r"(\d+) .*").match(row) is not None:
            processid = int(re.compile(r"(\d+) .*").match(row).group(1))
            tail = len(re.compile(r"(\d+) .*").match(row).group(1)) + 1

        if row.endswith("+++"):
            temp = re.compile(r"\s*(\d+\.\d+) \+\+\+ exited with (-?[\d]+) \+\+\+$").match(row, tail)
            if temp is not None:
                return RowInput(processid, Decimal(temp.group(1)), False, 0, "EXIT", [], temp.group(2))

            temp = re.compile(r"\s*(\d+\.\d+) \+\+\+ killed by ([\w]+) \+\+\+$").match(row, tail)
            if temp is not None:
                return RowInput(processid, Decimal(r.group(1)), False, 0, "KILL", [temp.group(2)], 0)

        if row.endswith("---"):
            temp = re.compile(r"\s*(\d+\.\d+) --- (\w+) \{(.)*\} ---$").match(row, tail)
            if temp is not None:
                args = self.__output_args(temp.group(3))
                return RowInput(processid, Decimal(temp.group(1)), False, 0, temp.group(2), args, 0)
        if row.endswith("<unfinished ...>"):
            temp = re.compile(r"\s*(\d+\.\d+ .*) <unfinished \.\.\.>$").match(row, tail)
            if temp is None:
                raise Exception("Erron in row with pid %d"
                                % self.row)
            self.flag_sys[processid] = temp.group(1)
            return self.next()

        temp = re.compile(r"\s*(\d+\.\d+) <\.\.\. [\a-zA-Z\d]+ resumed>(.*)$").match(row, tail)
        if temp is not None:
            flag = True
            if processid not in self.flag_sys.keys() \
                    or self.flag_sys[processid] is None:
                raise Exception("No line to resume (line %d)" % self.head)
            row = self.flag_sys[processid] + temp.group(2)
            self.flag_sys[processid] = None
            tail = 0
        else:
            flag = False

        # Extract basic information

        temp = re.compile(r"\s*(\d+\.\d+) (\w+)(\(.*) <(.+)>$").match(row, tail)
        if temp is not None:
            timestamp = Decimal(temp.group(1))
            sys_call = temp.group(2)
            arguments_result = temp.group(3)
            elapsed_time = temp.group(4)
            if elapsed_time[0].isdigit():
                elapsed_time = Decimal(elapsed_time)
            elif elapsed_time == "unavailable" or elapsed_time == "detached ...":
                elapsed_time = None
            else:
                print(elapsed_time)
                raise Exception("Invalid elapsed time (line %d)" % self.head)
        else:
            temp = re.compile(r"\s*(\d+\.\d+) (\w+)(\(.*)$").match(row, tail)
            if temp is not None:
                timestamp = Decimal(temp.group(1))
                sys_call = temp.group(2)
                arguments_result = temp.group(3)
                elapsed_time = None
            else:
                raise Exception("Invalid line (line %d)" % self.head)


            # Extract the return value

        regex_match=  re.compile(r"\((.*)\)[ \t]*= (-?\d+)$").match(arguments_result)
        if regex_match != None:
            return_value = int(regex_match.group(2))
            result = regex_match.group(1)
        if regex_match == None:
            regex_match_1 = re.compile(r"\((.*)\)[ \t]*= (-?0[xX][a-fA-F\d]+)$").match(arguments_result)
            if regex_match_1 != None:
                return_value = regex_match_1.group(2)
                result = regex_match_1.group(1)
            regex_match_2 = re.compile(r"\((.*)\)[ \t]*= (-?\d+) (\w+) \([\w ]+\)$").match(arguments_result)
            if regex_match_2 != None:
                return_value = regex_match_2.group(2)
                result = regex_match_2.group(1)
            regex_match_3 = re.compile(r"\((.*)\)[ \t]*= (\?) (\w+) \([\w ]+\)$").match(arguments_result)
            if regex_match_3 != None:
                return_value = regex_match_3.group(2)
                result = regex_match_3.group(1)
            regex_match_4 = re.compile(r"\((.*)\)[ \t]*= (-?\d+) \(([^()]+)\)$").match(arguments_result)
            if regex_match_4 != None:
                return_value = regex_match_4.group(2)
                result = regex_match_4.group(1)
            regex_match_5 = re.compile(r"\((.*)\)[ \t]*= (-?0[xX][a-fA-F\d]+) \(([^()]+)\)$").match(arguments_result)
            if regex_match_5 != None:
                return_value = regex_match_5.group(2)
                result = regex_match_5.group(1)
            regex_match_6 = re.compile(r"\((.*)\)[ \t]*= (\?)$").match(arguments_result)
            if regex_match_6 != None:
                return_value = None
                result = regex_match_6.group(1)
        '''if regex_match == None or regex_match_1 == None or regex_match_2 == None\
                or regex_match_3 == None or regex_match_4 == None or regex_match_5 == None \
                or regex_match_6 == None:
            raise Exception("Invalid line (line %d)" % self.head)'''

        # Extract the arguments

        final_args = self.__output_args(result)

        # Finish

        return RowInput(processid, timestamp, flag, elapsed_time,
                           sys_call, final_args, return_value)

    def __output_args(self, arguments_str):
        # output the arguments with quote and return it as an array of strings
        arguments = []
        current_arg = ""
        quote_type = None
        escaped = False
        expect_comma = False
        between_arguments = False
        nest_stack = []

        for c in arguments_str:

            # Characters between arguments

            if between_arguments and c in [' ', '\t']:
                continue
            else:
                between_arguments = False
            if expect_comma:
                assert quote_type is None
                if c == '.':
                    current_arg += c
                elif c == ',':
                    expect_comma = False
                    between_arguments = True
                    arguments.append(current_arg)
                    current_arg = ""
                elif c in [' ', '\t']:
                    continue
                else:
                    print("C:" + current_arg)
                    print(arguments)
                    raise Exception(("'%s' found where comma expected; " \
                                     + "offending string: %s") % (c, arguments_str))
                continue

            # Arguments

            if escaped:
                current_arg += c
                escaped = False
            elif c == '\\':
                current_arg += c
                escaped = True
            elif c in ['"', '\'', '[', ']', '{', '}']:
                if quote_type in ['"', '\''] and c != quote_type:
                    current_arg += c
                elif c == quote_type:
                    if  len(nest_stack) > 0:
                        current_arg += c
                    if len(nest_stack) > 1:
                        nest_stack.pop()
                        quote_type = nest_stack[-1]
                    else:
                        nest_stack.pop()
                        quote_type = None
                        if not current_arg == '[?]':
                            expect_comma = True
                elif c in [']', '}']:
                    current_arg += c
                else:
                    if  len(nest_stack) > 0:
                        current_arg += c
                    if c == '[': c = ']'
                    if c == '{': c = '}'
                    quote_type = c
                    nest_stack.append(c)
            elif c == ',' and quote_type is None:
                arguments.append(current_arg)
                current_arg = ""
                between_arguments = True
            else:
                current_arg += c

        if quote_type is not None:
            raise Exception(("Expected '%s' but found end of the string; " \
                             + "offending string: %s") % (quote_type, arguments_str))

        if len(current_arg) > 0:
            arguments.append(current_arg)
        return arguments

    def close(self):
        self.input.close()

