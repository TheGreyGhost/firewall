import ebtables
from ebtables import EbTables
import sys
from dbaccess import DBaccess
from errorhandler import DatabaseError
from ebtables import EbTables
import datetime
import subprocess

testport = 3306
#testport = 8889

EBTABLES_FILENAME = r"/var/tap/ebtabletemp"
BASH_CMD = "bash"

if __name__ == '__main__':
    print("arguments: ")
    for arg in sys.argv[1:]:
        print(arg)

    with DBaccess(dbpassword="TESTREADONLY", port=testport) as db:
        ebtables = EbTables(db)
        eblist = ebtables.compilerulesandcommit(EBTABLES_FILENAME)
        print("eblist: {}".format(eblist))

        eblist = ebtables.completeupdate(EBTABLES_FILENAME)
        print("eblist: {}".format(eblist))

    cmd = subprocess.Popen([BASH_CMD, EBTABLES_FILENAME])


