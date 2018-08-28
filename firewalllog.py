"""
receives bridge firewall log input from named pipe, extracts the relevant addresses, collates the info, and
  periodically writes to a database

the input has the format

2018-08-11T16:21:09.503819+09:30 garden kernel: [103105.328637] EBTABLESLOGINFO
  IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8
  MAC source = 38:2c:4a:64:d1:50 MAC dest = a4:91:b1:4f:6b:e8 proto = 0x0800
and optionally:
  IP SRC=192.168.1.200 IP DST=203.47.10.37, IP tos=0x00, IP proto=6 SPT=55028 DPT=8080

Note the use of multithreading.
log_database has its own internal lock to protect it

"""

import sys
from dbaccess import DBaccess
from logdatabase import LogDatabase
import argparse
import errorhandler
import logging
import threading


def process_pipe(log_database, inputpipepath):
    """
    process incoming information from the pipe and add to the log
    loops eternally until the pipe breaks
    :param db: LogDatabase to write to
    :param fip: pipe for incoming log information
    :return:
    """
    try:
        with open(inputpipepath, "r") as fip:
            while True:
                line = fip.readline()
                if len(line) == 0:  # I'm not sure - does it block or not?
                    errorhandler.logerror("readline from pipe {} had zero length.".format(args.inputpipe))
                    return
                try:
                    log_database.add_log_entry_string(line)
                except errorhandler.LogDatabaseError as exc:
                    errorhandler.loginfo(exc)

    except IOError as exc:
        errorhandler.logerror(exc)


def periodic_database_upload(log_database):
    """
    write the logs to the database, clear them ready for the next chunk
    :param log_database:
    :return:
    """
    log_database.write_to_database()


if __name__ == '__main__':
    #        EBTABLES_FILENAME = r"c:/junk/ebtabletemp"
    # EBTABLES_SCRIPT_PATH = r"c:/junk"
    # EBTABLES_FILENAME = r"/var/tap/ebtabletemp"
    # EBTABLES_SCRIPT_PATH = r"/var/tap"

    if sys.platform.startswith('linux'):  # defaults for CMD line:
        DEBUG_LOG_PATH = r"/var/tap/firewall.log"
        TESTPORT = "3306"
        INPUT_PIPE = r"/var/tap/firewalllogpipe"
    else:  # defaults for IDE:
        DEBUG_LOG_PATH = r"c:/junk/firewall.log"
        TESTPORT = "8889"
        INPUT_PIPE = r"c:/junk/firewalllogpipe.txt"

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", help="print debugging information", action="store_true")
    parser.add_argument("-db", "--databasename", help="name of the database to connect to", default="testfirewall")
    parser.add_argument("-dh", "--host", help="the database host to connect to (IP address)", default="localhost")
    parser.add_argument("-p", "--port", help="the database host port to connect to", default=TESTPORT)
    parser.add_argument("-pw", "--password", help="the database password", default="TESTADDROWS")
    parser.add_argument("-u", "--username", help="the database username", default="testaddrows")
    parser.add_argument("-i", "--inputpipe", help="the named pipe to read from", default=INPUT_PIPE)
    parser.add_argument("-c", "--chunktime", help="the chunk size (seconds) for logging", default=60 * 5)

    args = parser.parse_args()

    errorhandler.initialise("firewalllog", DEBUG_LOG_PATH, logging.DEBUG if args.debug else logging.INFO)

    with DBaccess(host=args.host, port=args.port, dbname=args.databasename,
                  username=args.username, dbpassword=args.password) as db:
        log_database = LogDatabase(db)

        # use multithreading as follows:
        # start a thread to process the pipe input into the log database
        # try to join it, with timeout
        # when the pipe thread terminates or the timeout expires, log the chunk.

        process_pipe_thread = threading.Thread(target=process_pipe, args=(log_database, args.inputpipe))
        process_pipe_thread.start()
        while process_pipe_thread.is_alive():
            process_pipe_thread.join(timeout=args.chunktime)
            periodic_database_upload(log_database)

# https://www.python-course.eu/pipes.php
# http://www.roman10.net/2011/04/21/named-pipe-in-linux-with-a-python-example/
#    http: // kodedevil.com / 2017 / 07 / 07 / linux - fifos - python /
