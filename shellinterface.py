import ebtables
from ebtables import EbTables
import sys
from dbaccess import DBaccess
from errorhandler import DatabaseError
from ebtables import EbTables
import datetime
import subprocess
import tempfile

testport = 3306
#testport = 8889

EBTABLES_FILENAME = r"/var/tap/ebtabletemp"
EBTABLES_SCRIPT_PATH = r"/var/tap"
BASH_CMD = "bash"

debug = False

if __name__ == '__main__':
    print("arguments: ")
    for arg in sys.argv[1:]:
        if arg == "-debug":
            debug = True
        else:
            print("usage: {} -debug".format(sys.argv[0]))

    with DBaccess(dbpassword="TESTREADONLY", port=testport) as db:
        ebtables = EbTables(db)
        eblist = ebtables.compilerulesandcommit(EBTABLES_FILENAME)
        print("eblist: {}".format(eblist))

        eblist = ebtables.completeupdate(EBTABLES_FILENAME)
        print("eblist: {}".format(eblist))

    if debug:
        tempscriptfilename = EBTABLES_SCRIPT_PATH + "ebtables.sh"
        print("wrote temp script to {}".format(tempscriptfilename))
        with open(EBTABLES_SCRIPT_PATH + "ebtables.sh", "r") as f:
            f.writelines(eblist)

    with tempfile.TemporaryFile(dir=EBTABLES_SCRIPT_PATH) as tmp:
        tmp.writelines(eblist)
        cmd = subprocess.Popen([BASH_CMD, EBTABLES_SCRIPT_PATH])


