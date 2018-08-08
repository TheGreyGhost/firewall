import ebtables
from ebtables import EbTables
import sys
from dbaccess import DBaccess
from errorhandler import DatabaseError
from ebtables import EbTables
import datetime

testport = 3306

if __name__ == '__main__':
    print("arguments: ")
    for arg in sys.argv[1:]:
        print(arg)

    with DBaccess(dbpassword="TESTREADONLY", port=testport) as db:
        ebtables = EbTables(db)
        eblist = ebtables.compilerules()
        print("eblist: {}".format(eblist))

