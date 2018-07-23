# contains all the functions for interacting with the firewall database
import mysql.connector
from mysql.connector import errorcode
import errorhandler
from errorhandler import DatabaseError

class DBaccess:
    db = None
    cursor = None

    def __init__(self, username="testreadonly", dbpassword=None,
                 host="localhost", port="8889", dbname="testfirewall"):
        tryagain = True
        interactive = (dbpassword is None)
        while tryagain:
            try:
                if interactive:
                    dbpassword = input("Enter database password for " + username +  " (empty = abort):")
                    if len(dbpassword) == 0:
                        return

                self.db = mysql.connector.connect(host=host,  # your host, usually localhost
                                             port=port,
                                             user=username,  # your username
                                             passwd=dbpassword,  # your password
                                             db=dbname)
                # you must create a Cursor object. It will let
                #  you execute all the queries you need
                self.cursor = self.db.cursor()
            except mysql.connector.Error as err:
                if err.errno == errorcode.ER_ACCESS_DENIED_ERROR and interactive:
                    print("Something is wrong with your user name or password")
                else:
                    errorhandler.logerror(err)
                    tryagain = False
            else:
                tryagain = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # make sure the objects get closed
        if not self.cursor is None:
            self.cursor.close()
        if not self.db is None:
            self.db.close()

    def getaccess(self, macaddress):
        if self.db is None or self.cursor is None:
            raise DatabaseError("Not connected to a database")

        # Use all the SQL you like
        self.cursor.execute("SELECT * FROM clients")

        # print all the first cell of all the rows
        for row in self.cursor.fetchall():
            print(row[0])


    def testconnection(self, sqlstring="SELECT * FROM clients LIMIT 3"):
        if self.db is None or self.cursor is None:
            raise DatabaseError("Not connected to a database")

        # Use all the SQL you like
        self.cursor.execute(sqlstring)

        # print all the first cell of all the rows
        for row in self.cursor.fetchall():
            print(row[0:])


