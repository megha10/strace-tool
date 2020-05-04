# strace-tool
tool for organizing the output of a stroke command

main.py takes the input file with timestamp and with -f for child process.
for example to generate strace log file -

strace -f -ttt -T -o test.out -p 3433

To run the tool - 
python main.py test.out -o test.csv

This tool produces a .csv file as well as list all the child process of a process and all the system call in that process and its elapsed time.




