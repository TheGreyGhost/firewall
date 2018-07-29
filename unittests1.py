import unittest
from dbaccess import DBaccess
from errorhandler import DatabaseError
import time

class MyTestCase(unittest.TestCase):
    def test_databaseconnections(self):
        pass
        # with DBaccess() as newdb:
        #     newdb.testconnection()
        #
        # with self.assertRaises(DatabaseError):
        #     with DBaccess(username="invalid", dbpassword="junk") as newdb:
        #         newdb.testconnection()

    def test_clientlogic(self):
        with DBaccess(dbpassword="TESTREADONLY") as db:
            # 1. BlockedUntil - still valid
            testtimestr = "2018-06-03 12:35:22"
            testtime_earlier = time.strptime("2018-06-03 11:35:22", "%Y-%m-%d %H:%M:%S")
            testtime_later = time.strptime("2018-06-03 13:35:22", "%Y-%m-%d %H:%M:%S")
            self.assertEqual(db.checkclient("BlockedUntil", testtimestr, testtime_earlier, None),
                             (False, DBaccess.BLOCKING_PRIORITY_CLIENT_EXPLICIT), "tcl1")

            # 2. BlockedUntil - expired
            self.assertEqual(db.checkclient("BlockedUntil", testtimestr, testtime_later, None)[1],
                              DBaccess.BLOCKING_PRIORITY_CLIENT_DEFAULT, "tcl2")

            # 3. UnblockedUntil - still valid
            self.assertEqual(db.checkclient("UnblockedUntil", testtimestr, testtime_earlier, None),
                             (True, DBaccess.BLOCKING_PRIORITY_CLIENT_EXPLICIT), "tcl3")

            # 4. UnblockedUntil - expired
            self.assertEqual(db.checkclient("UnblockedUntil", testtimestr, testtime_later, None)[1],
                             DBaccess.BLOCKING_PRIORITY_CLIENT_DEFAULT, "tcl4")

            # 5. Timetable
            self.assertEqual(db.checkclient("Timetable", testtimestr, testtime_later, None)[1],
                             DBaccess.BLOCKING_PRIORITY_CLIENT_TIMETABLE, "tcl5")

            # 6. Default
            self.assertEqual(db.checkclient("Default", testtimestr, testtime_later, None)[1],
                             DBaccess.BLOCKING_PRIORITY_CLIENT_DEFAULT, "tcl6")

    def test_ownerlogic(self):
        with DBaccess(dbpassword="TESTREADONLY") as db:
            # 1. BlockedUntil - still valid
            testtimestr = "2018-06-03 12:35:22"
            testtime_earlier = time.strptime("2018-06-03 11:35:22", "%Y-%m-%d %H:%M:%S")
            testtime_later = time.strptime("2018-06-03 13:35:22", "%Y-%m-%d %H:%M:%S")
            self.assertEqual(db.checkowner("BlockedUntil", testtimestr, testtime_earlier, None),
                             (False, DBaccess.BLOCKING_PRIORITY_OWNER_EXPLICIT), "tol1")

            # 2. BlockedUntil - expired
            self.assertEqual(db.checkowner("BlockedUntil", testtimestr, testtime_later, None)[1],
                             DBaccess.BLOCKING_PRIORITY_OWNER_DEFAULT, "tol2")

            # 3. UnblockedUntil - still valid
            self.assertEqual(db.checkowner("UnblockedUntil", testtimestr, testtime_earlier, None),
                             (True, DBaccess.BLOCKING_PRIORITY_OWNER_EXPLICIT), "tol3")

            # 4. UnblockedUntil - expired
            self.assertEqual(db.checkowner("UnblockedUntil", testtimestr, testtime_later, None)[1],
                             DBaccess.BLOCKING_PRIORITY_OWNER_DEFAULT, "tol4")

            # 5. Timetable
            self.assertEqual(db.checkowner("Timetable", testtimestr, testtime_later, None)[1],
                             DBaccess.BLOCKING_PRIORITY_OWNER_TIMETABLE, "tol5")

            # 6. Default
            self.assertEqual(db.checkowner("Default", testtimestr, testtime_later, None)[1],
                            DBaccess.BLOCKING_PRIORITY_OWNER_DEFAULT, "tol6")


if __name__ == '__main__':
    unittest.main()
