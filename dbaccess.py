# contains all the functions for interacting with the firewall database
import mysql.connector
from mysql.connector import errorcode
import errorhandler
from errorhandler import DatabaseError
import time


class DBaccess:
    db = None
    cursor = None   # named tuple cursor into the db which holds access information
    UNKNOWN_MAC_OWNER_NAME = 'unknown'
    DEFAULT_ACCESS = False                  # if the access tables say "Default" then this is the access granted

    BLOCKING_PRIORITY_OWNER_EXPLICIT = 1
    BLOCKING_PRIORITY_CLIENT_EXPLICIT = 2
    BLOCKING_PRIORITY_OWNER_TIMETABLE = 3
    BLOCKING_PRIORITY_CLIENT_TIMETABLE = 4
    BLOCKING_PRIORITY_OWNER_DEFAULT = 5
    BLOCKING_PRIORITY_CLIENT_DEFAULT = 6

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
                self.cursor = self.db.cursor(named_tuple=True)
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

    def getaccess(self, macaddress, timenow):
        """  Returns the current access for the given MAC address at the given time

        :param macaddress: in the format 08:60:6e:42:f0:fb
        :param timenow: timestamp
        :return: true if the MAC currently has access, false otherwise
        :raises: DatabaseError
        """

#        Logic:
#            1) check owner: if blocked/unblocked, apply.  Else:
#            2) check client: if blocked/unblocked, apply.  Else:
#            3) check timetable - first for owner, if none then check device.  If neither:
#               TODO: If whitelist, check whitelist IPs.
#            4) use global default

        if self.db is None or self.cursor is None:
            raise DatabaseError("Not connected to a database")

        self.cursor.execute("SELECT * FROM qryClientAccess WHERE MAC='{}'".format(macaddress))

        # if we don't know this MAC, or the device has no owner, use reserved entry in owners table: unknown
        clientrow = self.cursor.fetchone()
        if clientrow is None or clientrow.owner is None:
            ownername = self.UNKNOWN_MAC_OWNER_NAME
            self.cursor.execute("SELECT * FROM owners WHERE name='{}'".format(ownername))
            ownerrow = self.cursor.fetchone()
            if ownerrow is None:
                raise DatabaseError("'unknown' owner {} not found in database".format(ownername))
            owneraccess = self.checkowner(ownerrow.status, ownerrow.endtime, time.time(), ownerrow.timetable)
            if clientrow is None:
                return owneraccess[0]
        else:
            owneraccess = self.checkclient(clientrow.ownerstatus, clientrow.ownerendtime, time.time(),
                                           clientrow.ownertimetable)

        clientaccess = self.checkclient(clientrow.clientstatus, clientrow.clientendtime, time.time(), clientrow.clienttimetable)
        return owneraccess[0] if owneraccess[1] < clientaccess[1] else clientaccess[0]

    def checkclient(self, clientstatus, clientendtime, timenow, timetable):
        """ Check if the named client has access or not.

        :param clientstatus: the status of the owner ('Default','BlockedUntil','UnblockedUntil','Timetable')
        :param clientendtime: for 'BlockedUntil' or 'UnblockedUntil', the end time of the status, in string format
                                2018-07-20 20:41:48
        :param timenow: the current time in Python time format
        :param timetable: the name of the timetable to be applied (Null = no timetable)
        :returns a tuple: (access, priority) where access==true if access is permitted, and blocking priority:
        :raises ValueError, DatabaseError
        """

        #        Logic:
        #            1) if blocked/unblocked and time hasn't expired, apply it, otherwise fall back to timetable or default
        if clientstatus == "BlockedUntil" or clientstatus == "UnblockedUntil":
            timevalid = False
            try:
                clientendtimestruct = time.strptime(clientendtime, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                errorhandler.logerror(
                    DatabaseError("endtime {} did not match expected format 2018-07-20 20:41:48".format(clientendtime)))
            else:
                timevalid = (timenow < clientendtimestruct)

            if timevalid:
                return (False, self.BLOCKING_PRIORITY_CLIENT_EXPLICIT) if clientstatus == "BlockedUntil" \
                    else (True, self.BLOCKING_PRIORITY_CLIENT_EXPLICIT)

            clientstatus2 = "Default" if timetable is None else "Timetable"
        else:
            clientstatus2 = clientstatus

        #   2) Use Default or timetable to find access
        if clientstatus2 == "Default":
            return (self.DEFAULT_ACCESS, self.BLOCKING_PRIORITY_CLIENT_DEFAULT)
        elif clientstatus2 == "Timetable":
            # TODO look up timetable
            return (False, self.BLOCKING_PRIORITY_CLIENT_TIMETABLE)
        else:
            raise (DatabaseError("Invalid clientstatus:{}".format(clientstatus)))


    def checkowner(self, ownerstatus, ownerendtime, timenow, timetable):
        """ Check if the named owner has access or not.

        :param ownerstatus: the status of the owner ('Default','BlockedUntil','UnblockedUntil','Timetable')
        :param ownerendtime: for 'BlockedUntil' or 'UnblockedUntil', the end time of the status, in string format
                                2018-07-20 20:41:48
        :param timenow: the current time in Python time format
        :param timetable: the name of the timetable to be applied (Null = no timetable)
        :returns a tuple: (access, priority) where access==true if access is permitted, and blocking priority:
        :raises ValueError, DatabaseError
        """

    #        Logic:
    #            1) if blocked/unblocked and time hasn't expired, apply it, otherwise fall back to timetable or default
        if ownerstatus == "BlockedUntil" or ownerstatus == "UnblockedUntil":
            timevalid = False
            try:
                ownerendtimestruct = time.strptime(ownerendtime, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                errorhandler.logerror(DatabaseError("endtime {} did not match expected format 2018-07-20 20:41:48".format(ownerendtime)))
            else:
                timevalid = (timenow < ownerendtimestruct)

            if timevalid:
                return (False, self.BLOCKING_PRIORITY_OWNER_EXPLICIT) if ownerstatus == "BlockedUntil" \
                                                                      else (True, self.BLOCKING_PRIORITY_OWNER_EXPLICIT)

            ownerstatus2 = "Default" if timetable is None else "Timetable"
        else:
            ownerstatus2 = ownerstatus

    #   2) Use Default or timetable to find access
        if ownerstatus2 == "Default":
            return (self.DEFAULT_ACCESS, self.BLOCKING_PRIORITY_OWNER_DEFAULT)
        elif ownerstatus2 == "Timetable":
            #TODO look up timetable
            return (False, self.BLOCKING_PRIORITY_OWNER_TIMETABLE)
        else:
            raise(DatabaseError("Invalid ownerstatus:{}".format(ownerstatus)))

    def testconnection(self, sqlstring="SELECT * FROM clients LIMIT 3"):
        if self.db is None or self.cursor is None:
            raise DatabaseError("Not connected to a database")

        # Use all the SQL you like
        self.cursor.execute(sqlstring)

        # print all the first cell of all the rows
        for row in self.cursor.fetchall():
            print(row[0:])


