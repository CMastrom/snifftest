from subprocess import check_output
from colors import Msg
from sys import argv
from sys import exit as sysexit
from signal import signal, SIGINT
import time

def print_sniffs(top = False, bottom = False):
    if top == False and bottom == False:
        # Print all
        print(Msg.fnote("ALL SNIFFS")+" :")
        print("COMMAND\t", "PID\t", "FILE PATH")
        for (command, pid, file_path) in zip(commands, pids, file_paths):
            print(command+"\t", pid+"\t", file_path)
    else:
        if top != False:
            if type(top) != int:
                print(Msg.ferror("TOP ERROR")+" Top parameter must be an integer.")
                return
            print(Msg.fnote("TOP "+Msg.yellow(str(top))+" SNIFFS")+" :")
            print("COMMAND\t", "PID\t", "FILE PATH")
            count = 0
            for (command, pid, file_path) in zip(commands, pids, file_paths):
                if count <= top:
                    print(command+"\t", pid+"\t", file_path)
                else:
                    break
                count += 1
        if bottom != False:
            if type(bottom) != int:
                print(Msg.ferror("BOTTOM ERROR")+" Bottom parameter must be an integer.")
                return
            print(Msg.fnote("BOTTOM "+Msg.yellow(str(bottom))+" SNIFFS")+" :")
            print("COMMAND\t", "PID\t", "FILE PATH")
            count = 0
            for (command, pid, file_path) in zip(reversed(commands), reversed(pids), reversed(file_paths)):
                if count <= bottom:
                    print(command+"\t", pid+"\t", file_path)
                else:
                    break
                count += 1

# Unique prints
def uprint_sniffs(top = False, bottom = False):
    pids_uniqu = list(value for value in pids_unique)
    if top == False and bottom == False:
        # Print all
        print(Msg.fnote("ALL UNIQUE SNIFFS")+" :")
        print("COMMAND\t", "PID\t", "FILE PATH")
        for (command, pid, file_path) in zip(commands_corr, pids_uniqu, file_paths_corr):
            print(command+"\t", pid+"\t", file_path)
    else:
        if top != False:
            if type(top) != int:
                print(Msg.ferror("TOP ERROR")+" Top parameter must be an integer.")
                return
            print(Msg.fnote("TOP "+Msg.yellow(str(top))+" UNIQUE SNIFFS")+" :")
            print("COMMAND\t", "PID\t", "FILE PATH")
            count = 0
            for (command, pid, file_path) in zip(commands_corr, pids_uniqu, file_paths_corr):
                if count <= top:
                    print(command+"\t", pid+"\t", file_path)
                else:
                    break
                count += 1
        if bottom != False:
            if type(bottom) != int:
                print(Msg.ferror("BOTTOM ERROR")+" Bottom parameter must be an integer.")
                return
            print(Msg.fnote("BOTTOM "+Msg.yellow(str(bottom))+" UNIQUE SNIFFS")+" :")
            print("COMMAND\t", "PID\t", "FILE PATH")
            count = 0
            for (command, pid, file_path) in zip(reversed(commands_corr), reversed(pids_uniqu), reversed(file_paths_corr)):
                if count <= bottom:
                    print(command+"\t", pid+"\t", file_path)
                else:
                    break
                count += 1

def find_pid(pid, unique=False):
    found = False
    if not unique:
        global commands, pids, file_paths
        for (command, _pid, file_path) in zip(commands, pids, file_paths):
            if str(pid) == _pid:
                if not found:
                    print("COMMAND\t", "PID\t", "FILE PATH")
                print(command+"\t", _pid+"\t", file_path)
                found = True
        if not found:
            print(Msg.red("NOT FOUND"))
    else:
        # Unique
        global commands_corr, pids_unique, file_paths_corr
        unique_pid_list = list(value for value in pids_unique)
        for (command, _pid, file_path) in zip(commands_corr, unique_pid_list, file_paths_corr):
            if str(pid) == _pid:
                if not found:
                    print("COMMAND\t", "PID\t", "FILE PATH")
                print(command+"\t", _pid+"\t", file_path)
                found = True
        if not found:
            print(Msg.red("NOT FOUND"))

def find_command(cmd, unique=False):
    found = False
    if not unique:
        global commands, pids, file_paths
        for (command, _pid, file_path) in zip(commands, pids, file_paths):
            if str(cmd) == command:
                if not found:
                    print("COMMAND\t", "PID\t", "FILE PATH")
                print(command+"\t", _pid+"\t", file_path)
                found = True
        if not found:
            print(Msg.red("NOT FOUND"))
    else:
        # Unique
        global commands_corr, pids_unique, file_paths_corr
        unique_pid_list = list(value for value in pids_unique)
        for (command, _pid, file_path) in zip(commands_corr, unique_pid_list, file_paths_corr):
            if str(cmd) == command:
                if not found:
                    print("COMMAND\t", "PID\t", "FILE PATH")
                print(command+"\t", _pid+"\t", file_path)
                found = True
        if not found:
            print(Msg.red("NOT FOUND"))

def find_fpath(fpath, unique=False):
    found = False
    if not unique:
        global commands, pids, file_paths
        for (command, _pid, file_path) in zip(commands, pids, file_paths):
            if str(fpath) in file_path:
                if not found:
                    print("COMMAND\t", "PID\t", "FILE PATH")
                print(command+"\t", _pid+"\t", file_path)
                found = True
        if not found:
            print(Msg.red("NOT FOUND"))
    else:
        # Unique
        global commands_corr, pids_unique, file_paths_corr
        unique_pid_list = list(value for value in pids_unique)
        for (command, _pid, file_path) in zip(commands_corr, unique_pid_list, file_paths_corr):
            if str(fpath) in file_path:
                if not found:
                    print("COMMAND\t", "PID\t", "FILE PATH")
                print(command+"\t", _pid+"\t", file_path)
                found = True
        if not found:
            print(Msg.red("NOT FOUND"))

def flagged_processes():
    global commands, pids, file_paths, _flagged_processes
    found = False
    for (command, pid, file_path) in zip(commands, pids, file_paths):
        for flg_proc in _flagged_processes:
            if flg_proc in command:
                if not found:
                    print("COMMAND\t", "PID\t", "FILE PATH")
                print(command+"\t", pid+"\t", file_path)
                found = True
                break
    if not found:
        print(Msg.red("NOT FOUND"))


def handler(signal_received, frame):
    # Handle any cleanup here
    print('Ctrl + C detected, leaving...')
    if LISTEN_MODE:
        while True:
            should_display = input("Display all '"+Msg.blue(str(len(commands)))+"' sniffs? (y/n): ")
            if should_display.strip().lower() == 'y':
                print_sniffs()
                return
            elif should_display.strip().lower() == 'n':
                return
signal(SIGINT, handler)

def popen(command):
    process = check_output(command.split(" "))
    try:
        process = process.decode('utf-8').split("\n")
    except Exception as e:
        print(Msg.ferror("POPEN ERROR")+":")
        print(e)
    return process

LISTEN_MODE = False
help = """
            Sniff Test Software -- Version 1.0.0
            Description:
                This software utilizes lsof to monitor all processes running on your computer. Upon termination, this script will defer to python interactive mode.
            
            Options:
                [ --help ] displays the current message
                [ --listen ] doesn't display any information in the terminal (except for errors), but rather silently continually listens to what is going on, then dumps it once CTRL + C is detected. NOTE: It will dump the full lists, not the unique sniffs!
            
            Notable Information:
                The following variables/lists/sets/etc are from this script and can be accessed once in python interactive mode:
                    pids_unique = [] -> Process ids (unique) for the sniffs
                    commands_corr = [] -> Corresponding commands (sniffs) for unique pids
                    file_paths_corr = [] -> Corresponding file_paths for unique pids
                    commands = [] -> Commands is the list of sniffs (full list wit duplicates)
                    pids = [] -> Process IDs
                    file_paths = [] -> File path of file that was ran
                    _flagged_processes = [] -> List of flagged processes

                    print_sniffs(top: int = False, bottom: int = False) = def -> Function that displays all sniffs (including duplicates) (Optional: You can specify how many to print from the top and bottom)
                    uprint_sniffs(top: int = False, bottom: int = False) = def -> Function that displays all sniffs (not including duplicates) (Optional: You can specify how many to print from the top and bottom)
                    find_pid(pid: int, unique: bool = False) = def -> Function that will print the corresponding value(s) for a given PID (unique or not unique, depending on if unique argument is passed)
                    find_command(cmd: str, unique: bool = False) = def -> Function that will print the corresponding value(s) for a given command name (unique or not unique, depending on if unique argument is passed) 
                    find_fpath(fpath: str, unique: bool = False) = def -> Function that will print the corresponding value(s) for the given file name/path (unique or not unique, depending on if unique argument is passed)(NOTE: fpath will search for LIKE not equal)
                    flagged_processes() = def -> Function that will print all flagged processes (flagged_processes)

                The default mode (where no arguments are passed) will dump commands_unique everytime a key is pressed.
        """
try:
    if argv[1] == "--help":
        print(help)
        sysexit(1)
    elif argv[1] == "--listen":
        print(Msg.fwarn("LISTEN MODE")+" ON")
        LISTEN_MODE = True
except Exception:
    pass

# Global declarations:
pids_unique = [] # Pid names (unique)
commands_corr = [] # Corresponding command names for pids_unique
file_paths_corr = [] # Corresponding file_path names for pids_unique
commands = [] # Command names
pids = [] # Process ids (not unique)
file_paths = [] # File paths
_flagged_processes = [
    "python",
    "cpp",
    "ssh",
    "sftp",
    "zsh",
    "userevent"
]

def remove_spaces(array):
    return [value for value in array if value != '']

def did_add(_list, value):
    if value not in _list:
        _list.append(value)
        return True
    else:
        return False

count_sniffs = 0
def parse_lsof(line):
    global count_sniffs

    l = line.split(" ")
    if line == "":
        return
    l = remove_spaces(l)
    try:
        commands.append(l[0])
        count_sniffs += 1
    except:
        print(Msg.ferror("PARSE FAILED")+ Msg.cyan("command") + line)
        return
    try:
        pids.append(l[1])
        if did_add(pids_unique, l[1]):
            try:
                commands_corr.append(l[0])
            except:
                commands_corr.append(Msg.red("NOT FOUND"))
            try:
                file_paths_corr.append(l[len(l)-1])
            except:
                file_paths_corr.append(Msg.red("NOT FOUND"))
    except:
        print(Msg.ferror("PARSE FAILED")+ Msg.blue("PID") + line)
        pids.append(Msg.red("NOT FOUND"))
    try:
        file_paths.append(l[len(l)-1])
    except:
        print(Msg.ferror("PARSE FAILED")+ Msg.yellow("file path") + line)
        file_paths.append(Msg.red("NOT FOUND"))

    if not LISTEN_MODE:
        print(Msg.fnote("ACTIVE SNIFFS")+" :", end="\n\t")
        print(commands_corr)
        input("")
    else:
        print(Msg.fnote("SNIFFS: ")+Msg.yellow(str(count_sniffs)), end="\r")

print("This script will keep running until Ctrl + C is executed...")

while True:
    lsof_lines = popen('lsof')
    for line in lsof_lines:
        parse_lsof(line)
