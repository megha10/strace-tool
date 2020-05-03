import os
import sys
import getopt
import stracentry

def prRed(skk): print("\033[91m {}\033[00m" .format(skk)) 
def prPurple(skk): print("\033[95m {}\033[00m" .format(skk)) 
def prCyan(skk): print("\033[96m {}\033[00m" .format(skk))

def csv_argument(row_value):
	#adding double quotes to every value
	temp = ""
	if row_value is None or row_value == "":
		return ""
	if type(row_value) == float:
		return "%0.6f" % row_value
	if type(row_value) == int:
		return str(row_value)
	for c in str(row_value):
		if c == '"':
			temp += '"'
		temp += c
	return '"' + temp + '"'

def check_for_boundary(input, i):

	if i < 0 or i >= len(input) :
		return ""
	else:
		return input[i]


def row_input(output_stream, input_stream):
	row = ""
	for st in input_stream:
		if row is not "":
			row += ','
		row += csv_argument(st)
	output_stream.write(row + "\n")



def csv_converter(input_file, output_file=None):

	input_stream = open(input_file,"r")
	if output_file is not None:
		output = open(output_file, "w")
	else:
		output = sys.stdout
	file_stream = stracentry.FileInput(input_stream)
	heading = ["TIMESTAMP", "SYSCALL",  "SPLIT", "ARGC", "ARG1", "ARG2", "ARG3", "ARG4", "ARG5", "ARG6","RESULT", "ELAPSED"]
	row_input(output,heading)
	for input in file_stream:
		data = [input.timestamp, input.sys_call,
				1 if input.flag_process else 0,
				len(input.sys_args),
				check_for_boundary(input.sys_args, 0),
				check_for_boundary(input.sys_args, 1),
				check_for_boundary(input.sys_args, 2),
				check_for_boundary(input.sys_args, 3),
				check_for_boundary(input.sys_args, 4),
				check_for_boundary(input.sys_args, 5),
				input.extra,
				input.elapsed_time]
		if file_stream.flag_pid: data.insert(0, input.processid)
		row_input(output, data)


	# closing the output streaming after writing the output
	if output is not sys.stdout:
		output.close()
	file_stream.close()


def main(argv):
	input_file = None
	output_file = None
	try:
		options, remainder = getopt.gnu_getopt(argv, 'ho:',
			['help', 'output='])
		
		for opt, arg in options:
			if opt in ('-o', '--output'):
				output_file = arg
		
		if len(remainder) > 1:
			raise Exception("Too many options")
		elif len(remainder) == 1:
			input_file = remainder[0]
	except Exception as e:
		sys.stderr.write("%s: %s\n" % (os.path.basename(sys.argv[0]), e))
		sys.exit(1)
	csv_converter(input_file,output_file)
	os.system('python ' +  'strace_process.py ' + input_file  )
	if input_file is not None:
		input_stream = open(input_file, "r")

	# Read in the file
	entry = stracentry.FileInput(input_stream)
	if entry is None:
		print("No process available")
		return
	process_map = {}
	for e in entry:
		test1 = str(e.sys_call) + ' ' + str(e.elapsed_time)
		process_map.setdefault(e.processid, []).append(test1)

	order_pro = sorted(process_map.items())
	# Print the result
	for p in order_pro:
		prRed('process id : ' + "{}".format(p[0]))
		prPurple("\tsyscall \telapsed_time ")
		for sub_process in p[1]:
			prCyan('\t' + '\t'.join(map(str, sub_process.split())))

if __name__ == "__main__":
	main(sys.argv[1:])


