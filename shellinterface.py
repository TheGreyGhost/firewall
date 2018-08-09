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
        cmd = subprocess.Popen([BASH_CMD, tmp.name])


