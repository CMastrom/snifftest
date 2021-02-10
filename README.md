## snifftest

This tool utilizes python watchdog to easily identify file/directory modification/creation/deletion.

## For best experience:

Will create an alias for snifftest: alias snifftest='/{path_to_snifftest_repo}/snifftest/snifftest.py'

Will dump sniffs to terminal and log into file: snifftest 2>&1 > log_file.log 2>&1

Will take that previously used log file and parse it for you: snifftest --parse log_file.log
