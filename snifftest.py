import sys
sys.path.append("packages")
import time
import logging
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler
from colors import Msg

try:
    if sys.argv[1] == "--parse":
        print(Msg.fnote("PARSING FILE")+" ...")
        try:
            FILE = sys.argv[2]
            f = open(FILE, "r")
            lines = f.readlines()
            f.close()
            dates, file_actions, file_paths, parse_errors = [], [], [], []
            for line in lines:
                l = line.split(" ")
                parse_error = False
                try:
                    dates.append(l[0]+" "+l[1])
                except:
                    dates.append(Msg.red("PARSE ERROR"))
                    parse_error = True
                try:
                    file_actions.append(l[3]+" "+l[4])
                except:
                    file_actions.append(Msg.red("PARSE ERROR"))
                    parse_error = True
                try:
                    file_path = ""
                    for (i,word) in enumerate(l):
                        if i >= 5:
                            file_path += " " + word
                    file_paths.append(file_path)
                except:
                    file_paths.append(Msg.red("PARSE ERROR"))
                    parse_error = True
                if parse_error:
                    parse_errors.append(line)

            del lines
            # Parse was a success:
            print(Msg.green("PARSE WAS SUCCESSFULL"))
            print("""
                                ,   .-'\"'=;_  ,
                                |\.'-~`-.`-`;/|
                                \.` '.'~-.` './
                                (\`,__=-'__,'/)
                             _.-'-.( d\_/b ).-'-._
                            /'.-'   ' .---. '   '-.`\\
                          /'  .' (=    (_)    =) '.  `\\
                         /'  .',  `-.__.-.__.-'  ,'.  `\\
                        (     .'.   V       V  ; '.     )
                        (    |::  `-,__.-.__,-'  ::|    )
                        |   /|`:.               .:'|\   |
                        |  / | `:.              :' |`\  |
                        | |  (  :.             .:  )  | |
                        | |   ( `:.            :' )   | |
                        | |    \ :.           .: /    | |
                        | |     \`:.         .:'/     | |
                        ) (      `\`:.     .:'/'      ) (
                        (  `)_     ) `:._.:' (     _(`  )
                        \  ' _)  .'           `.  (_ `  /
                        \  '_) /   .'\"```\"'.   \ (_`  /
                        `'"`  \  (         )  /  `"'`
                    ___        `.`.       .'.'        ___
                    .`   ``\"\"\"'''--`_)     (_'--'''\"\"\"``   `.
                    (_(_(___...--'\"'`         `'\"'--...___)_)_)
                     _____       _  __  __ _____         _     __   _____  _____ 
                    /  ___|     (_)/ _|/ _|_   _|       | |   /  | |  _  ||  _  |
                    \ `--. _ __  _| |_| |_  | | ___  ___| |_  `| | | |/' || |/' |
                    `--. \ '_ \| |  _|  _| | |/ _ \/ __| __|  | | |  /| ||  /| |
                    /\__/ / | | | | | | |   | |  __/\__ \ |_  _| |_\ |_/ /\ |_/ /
                    \____/|_| |_|_|_| |_|   \_/\___||___/\__| \___(_)___(_)\___/ 


            """)
            while True:
                print("\nOptions: ")
                print("""
                    [ * ] -> prints all sniffed content in human-readable format
                    [ find ] [ fpath | faction | fdate ] [ key_word ] -> searches file paths (fpath), file actions (faction), or file dates (fdate) and prints the results
                    [ q | exit ] -> exits program (NOTE: does not delete log file)
                    (NOTE: This builds off of python watchdog)
                """)
                response = input(">>> ")
                if response.strip().lower() == "*":
                    print("File Date\t", "File Action\t", "File Path")
                    for (fpath, faction, fdate) in zip(file_paths, file_actions, dates):
                        print(fdate+"\t", faction+"\t", fpath.rstrip())
                elif len(response.strip().lower().split(" ")) > 1:
                    if response.strip().lower().split(" ")[0] == "find":
                        if response.strip().lower().split(" ")[1] == "fpath":
                            if len(response.strip().lower().split(" ")) > 2:
                                found = False
                                for (fpath, faction, fdate) in zip(file_paths, file_actions, dates):
                                    if response.strip().lower().split(" ")[2] in fpath:
                                        if not found:
                                            print("File Date\t", "File Action\t", "File Path")
                                        found = True
                                        print(fdate+"\t", faction+"\t", fpath.rstrip())
                            else:
                                print(Msg.ferror("FIND FPATH ERROR")+" Must specify a keyword to search for.")
                        elif response.strip().lower().split(" ")[1] == "faction":
                            if len(response.strip().lower().split(" ")) > 2:
                                found = False
                                for (fpath, faction, fdate) in zip(file_paths, file_actions, dates):
                                    if response.strip().lower().split(" ")[2] in faction:
                                        if not found:
                                            print("File Date\t", "File Action\t", "File Path")
                                        found = True
                                        print(fdate+"\t", faction+"\t", fpath.rstrip())
                            else:
                                print(Msg.ferror("FIND FACTION ERROR")+" Must specify a keyword to search for.")
                        elif response.strip().lower().split(" ")[1] == "fdate":
                            if len(response.strip().lower().split(" ")) > 2:
                                found = False
                                for (fpath, faction, fdate) in zip(file_paths, file_actions, dates):
                                    if response.strip().lower().split(" ")[2] in fdate:
                                        if not found:
                                            print("File Date\t", "File Action\t", "File Path")
                                        found = True
                                        print(fdate+"\t", faction+"\t", fpath.rstrip())
                            else:
                                print(Msg.ferror("FIND FDATE ERROR")+" Must specify a keyword to search for.")
                        else:
                            print(Msg.ferror("FIND ERROR")+" Passed argument not recognized.")
                elif response.strip().lower() == "exit" or response.strip().lower() == "q":
                    sys.exit(0)
                else:
                    print(Msg.ferror("ERROR")+" Command not recognized.")
        except Exception:
            print(Msg.ferror("ERROR")+ " File not found")
            sys.exit(1)
except Exception:
    if __name__ == "__main__":
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s - %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')
        path = sys.argv[1] if len(sys.argv) > 1 else '/'
        event_handler = LoggingEventHandler()
        observer = Observer()
        observer.schedule(event_handler, path, recursive=True)
        observer.start()
        try:
            while True:
                time.sleep(1)
        finally:
            observer.stop()
            observer.join()