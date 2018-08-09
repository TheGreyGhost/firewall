import ebtables
from ebtables import EbTables
import sys
from dbaccess import DBaccess
from errorhandler import DatabaseError
from ebtables import EbTables
import datetime
import subprocess
import tempfile
import os

IDE = True

BASH_CMD = "bash"

debug = False

if __name__ == '__main__':
    print("arguments: ")
    for arg in sys.argv[1:]:
        if arg == "-debug":
            debug = True
        elif arg == "-cmd":
            IDE = False
        else:
            print("usage: {} -debug -cmd".format(sys.argv[0]))

    if IDE:
        testport = 8889
        EBTABLES_FILENAME = r"c:/junk/ebtabletemp"
        EBTABLES_SCRIPT_PATH = r"c:/junk"
    else:
        testport = 3306
        EBTABLES_FILENAME = r"/var/tap/ebtabletemp"
        EBTABLES_SCRIPT_PATH = r"/var/tap"

    with DBaccess(dbpassword="TESTREADONLY", port=testport) as db:
        ebtables = EbTables(db)
#        eblist = ebtables.compilerulesandcommit(EBTABLES_FILENAME)
#        print("eblist: {}".format(eblist))
        eblist = ebtables.completeupdate(EBTABLES_FILENAME)
#        print("eblist: {}".format(eblist))

    if debug:
        tempscriptfilename = EBTABLES_SCRIPT_PATH + "/ebtables.sh"
        print("wrote temp script to {}".format(tempscriptfilename))
        with open(tempscriptfilename, "w+t") as f:
            for singleline in eblist:
                f.write(singleline)
                f.write("\n")

    with tempfile.NamedTemporaryFile(mode="w+t", dir=EBTABLES_SCRIPT_PATH) as tmp:
        for singleline in eblist:
            tmp.write(singleline)
            tmp.write("\n")
        tmp.flush()
        os.fsync(tmp.fileno())
        cmd = subprocess.Popen([BASH_CMD, tmp.name])


