import ebtables
from ebtables import EbTables
import sys
from dbaccess import DBaccess
from errorhandler import DatabaseError
from ebtables import EbTables
import argparse
import datetime
import subprocess
import tempfile
import os

IDE = True

BASH_CMD = "bash"

debug = False

# if __name__ == '__main__':
#     print("arguments: ")
#     for arg in sys.argv[1:]:
#         if arg == "-debug":
#             debug = True
#         elif arg == "-cmd":
#             IDE = False
#         else:
#             print("usage: {} -debug -cmd".format(sys.argv[0]))
#
#     if IDE:
#         testport = 8889
#         EBTABLES_FILENAME = r"c:/junk/ebtabletemp"
#         EBTABLES_SCRIPT_PATH = r"c:/junk"
#     else:
#         testport = 3306
#         EBTABLES_FILENAME = r"/var/tap/ebtabletemp"
#         EBTABLES_SCRIPT_PATH = r"/var/tap"
#
#     with DBaccess(dbpassword="TESTREADONLY", port=testport) as db:
#         ebtables = EbTables(db)
# #        eblist = ebtables.compilerulesandcommit(EBTABLES_FILENAME)
# #        print("eblist: {}".format(eblist))
#         eblist = ebtables.completeupdate(EBTABLES_FILENAME)
# #        print("eblist: {}".format(eblist))
#
#     if debug:
#         tempscriptfilename = EBTABLES_SCRIPT_PATH + "/ebtables.sh"
#         print("wrote temp script to {}".format(tempscriptfilename))
#         with open(tempscriptfilename, "w+t") as f:
#             for singleline in eblist:
#                 f.write(singleline)
#                 f.write("\n")
#
#     # with tempfile.NamedTemporaryFile(mode="w+t", dir=EBTABLES_SCRIPT_PATH) as tmp:
#     #     for singleline in eblist:
#     #         tmp.write(singleline)
#     #         tmp.write("\n")
#     #     tmp.flush()
#     #     os.fsync(tmp.fileno())
#     #     cmd = subprocess.Popen([BASH_CMD, tmp.name])
#
#     tmpscriptfilename = EBTABLES_SCRIPT_PATH + "/junkus"
#     tmp = open(tmpscriptfilename, mode="wt")
#
#     try:
#         for singleline in eblist:
#             tmp.write(singleline)
#             tmp.write("\n")
#         tmp.flush()
#         os.fsync(tmp.fileno())
# #        cmd = subprocess.Popen([BASH_CMD, tmp.name])
#     finally:
#         tmpname = tmp.name
#         tmp.close()
#         os.remove(tmpname)

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
        DEBUG_LOG_PATH = r"/var/tap/test.txt"
    else:
        DEBUG_LOG_PATH = r"c:/junk/test.txt"

    parser = argparse.ArgumentParser()
    parser.add_argument("-acf", "--atomiccommitfilename",
                        help="if the action should be performed using atomic commit: the full path to the file")
    parser.add_argument("-d", "--debug", help="print debugging information", action="store_true")
    parser.add_argument("-db", "--databasename", help="name of the database to connect to", default="testfirewall")
    parser.add_argument("-host", help="the host to connect to (IP address)", default="localhost")
    parser.add_argument("-port", help="the host port to connect to", default="3306")
    parser.add_argument("-pw", "--password", help="the database password", default="TESTREADONLY")
    parser.add_argument("-user", "--username", help="the database username", default="testreadonly")
    args = parser.parse_args()

    with DBaccess(host=args.host, port=args.port, dbname=args.databasename,
                  username=args.username, dbpassword=args.password) as db:
        ebtables = EbTables(db)
        eblist = ebtables.completeupdate(args.atomiccommitfilename)

    if debug:
        print("wrote temp script to {}".format(DEBUG_LOG_PATH), file=sys.stderr)
        with open(DEBUG_LOG_PATH, "w+t") as f:
            for singleline in eblist:
                f.write(singleline)
                f.write("\n")

    for singleline in eblist:
        print(singleline)








