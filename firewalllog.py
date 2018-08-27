"""
receives bridge firewall log input from named pipe, extracts the relevant addresses, collates the info, and
  periodically writes to a database

the input has the format

2018-08-11T16:21:09.503819+09:30 garden kernel: [103105.328637] EBTABLESLOGINFO
  IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8
  MAC source = 38:2c:4a:64:d1:50 MAC dest = a4:91:b1:4f:6b:e8 proto = 0x0800
  IP SRC=192.168.1.200 IP DST=203.47.10.37, IP tos=0x00, IP proto=6 SPT=55028 DPT=8080

"""

"""
options I need:
database paraphernalia
named pipe

"""

import sys
from dbaccess import DBaccess
from logdatabase import LogDatabase
import argparse
import errorhandler
import logging

if __name__ == '__main__':
    # defaults for IDE:
    #        EBTABLES_FILENAME = r"c:/junk/ebtabletemp"
    #         testport = 8889
    # EBTABLES_SCRIPT_PATH = r"c:/junk"
    # defaults for CMD line:
    # testport = 3306
    # EBTABLES_FILENAME = r"/var/tap/ebtabletemp"
    # EBTABLES_SCRIPT_PATH = r"/var/tap"

    if sys.platform.startswith('linux'):
        DEBUG_LOG_PATH = r"/var/tap/firewall.log"
    else:
        DEBUG_LOG_PATH = r"c:/junk/firewall.log"

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", help="print debugging information", action="store_true")
    parser.add_argument("-db", "--databasename", help="name of the database to connect to", default="testfirewall")
    parser.add_argument("-dh", "--host", help="the database host to connect to (IP address)", default="localhost")
    parser.add_argument("-p", "--port", help="the database host port to connect to", default="3306")
    parser.add_argument("-pw", "--password", help="the database password", default="TESTADDROWS")
    parser.add_argument("-u", "--username", help="the database username", default="testaddrows")
    parser.add_argument("-i", "--inputpipe", help="the named pipe to read from", default="firewalllog")

    args = parser.parse_args()

    errorhandler.initialise("firewalllog", DEBUG_LOG_PATH, logging.DEBUG if args.debug else logging.INFO)

    with DBaccess(host=args.host, port=args.port, dbname=args.databasename,
                  username=args.username, dbpassword=args.password) as db:
        log_database = LogDatabase(db)

        try:
            with open(args.inputpipe, "r") as fip:
                while True:
                    line = fip.readline()
                    if len(line) == 0:  # I'm not sure - does it block or not?
                        errorhandler.logerror("readline from pipe {} had zero length.".format(args.inputpipe))
                        sys.exit(0)
                    try:
                        log_database.add_log_entry_string(line)
                    except errorhandler.LogDatabaseError as exc:
                        errorhandler.loginfo(exc)

        except IOError as exc:
            errorhandler.logerror(exc)
            sys.exit(-1)

    #     finally:
    #
    # if args.debug:
    #     print("wrote temp script to {}".format(DEBUG_LOG_PATH), file=sys.stderr)
    #     with open(DEBUG_LOG_PATH, "w+t") as f:
    #         for singleline in eblist:
    #             f.write(singleline)
    #             f.write("\n")
    #
    # for singleline in eblist:
    #     print(singleline)

#https://www.python-course.eu/pipes.php
#http://www.roman10.net/2011/04/21/named-pipe-in-linux-with-a-python-example/
#    http: // kodedevil.com / 2017 / 07 / 07 / linux - fifos - python /
