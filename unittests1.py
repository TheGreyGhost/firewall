import unittest
from dbaccess import DBaccess
from errorhandler import DatabaseError
from ebtables import EbTables
import datetime


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
            testtimedt = datetime.datetime.strptime(testtimestr, "%Y-%m-%d %H:%M:%S")
            testtime_earlier = testtimedt - datetime.timedelta(hours=1)
            testtime_later = testtimedt + datetime.timedelta(hours=1)
            self.assertEqual(db.checkclient("BlockedUntil", testtimedt, testtime_earlier, None),
                             (False, DBaccess.BLOCKING_PRIORITY_CLIENT_EXPLICIT), "tcl1")

            # 2. BlockedUntil - expired
            self.assertEqual(db.checkclient("BlockedUntil", testtimedt, testtime_later, None)[1],
                             DBaccess.BLOCKING_PRIORITY_CLIENT_DEFAULT, "tcl2")

            # 3. UnblockedUntil - still valid
            self.assertEqual(db.checkclient("UnblockedUntil", testtimedt, testtime_earlier, None),
                             (True, DBaccess.BLOCKING_PRIORITY_CLIENT_EXPLICIT), "tcl3")

            # 4. UnblockedUntil - expired
            self.assertEqual(db.checkclient("UnblockedUntil", testtimedt, testtime_later, None)[1],
                             DBaccess.BLOCKING_PRIORITY_CLIENT_DEFAULT, "tcl4")

            # 5. Timetable
            self.assertEqual(db.checkclient("Timetable", testtimedt, testtime_later, None)[1],
                             DBaccess.BLOCKING_PRIORITY_CLIENT_TIMETABLE, "tcl5")

            # 6. Default
            self.assertEqual(db.checkclient("Default", testtimedt, testtime_later, None)[1],
                             DBaccess.BLOCKING_PRIORITY_CLIENT_DEFAULT, "tcl6")

    def test_ownerlogic(self):
        with DBaccess(dbpassword="TESTREADONLY") as db:
            # 1. BlockedUntil - still valid
            testtimestr = "2018-06-03 12:35:22"
            testtimedt = datetime.datetime.strptime(testtimestr, "%Y-%m-%d %H:%M:%S")
            testtime_earlier = testtimedt - datetime.timedelta(hours=1)
            testtime_later = testtimedt + datetime.timedelta(hours=1)
            self.assertEqual(db.checkowner("BlockedUntil", testtimedt, testtime_earlier, None),
                             (False, DBaccess.BLOCKING_PRIORITY_OWNER_EXPLICIT), "tol1")

            # 2. BlockedUntil - expired
            self.assertEqual(db.checkowner("BlockedUntil", testtimedt, testtime_later, None)[1],
                             DBaccess.BLOCKING_PRIORITY_OWNER_DEFAULT, "tol2")

            # 3. UnblockedUntil - still valid
            self.assertEqual(db.checkowner("UnblockedUntil", testtimedt, testtime_earlier, None),
                             (True, DBaccess.BLOCKING_PRIORITY_OWNER_EXPLICIT), "tol3")

            # 4. UnblockedUntil - expired
            self.assertEqual(db.checkowner("UnblockedUntil", testtimedt, testtime_later, None)[1],
                             DBaccess.BLOCKING_PRIORITY_OWNER_DEFAULT, "tol4")

            # 5. Timetable
            self.assertEqual(db.checkowner("Timetable", testtimedt, testtime_later, None)[1],
                             DBaccess.BLOCKING_PRIORITY_OWNER_TIMETABLE, "tol5")

            # 6. Default
            self.assertEqual(db.checkowner("Default", testtimedt, testtime_later, None)[1],
                             DBaccess.BLOCKING_PRIORITY_OWNER_DEFAULT, "tol6")

    def test_getaccess(self):
        with DBaccess(dbpassword="TESTREADONLY") as db:
            # tests for getaccess:
            # 1) MAC with owner that is blocked and client that is unblocked.  Repeat for time elapsed
            # DB contains
            # 00:01:02:03:04:05 0.0.0.1 testMAC1 testOwner1 UnblockedUntil 2018-06-01 03:00:00 NULL
            # testOwner1 BlockedUntil 2018-05-01 03:00:00 NULL
            testMAC1 = "00:01:02:03:04:05"
            client1EndDate = datetime.datetime.strptime("2018-06-01 03:00:00", "%Y-%m-%d %H:%M:%S")
            owner1EndDate = datetime.datetime.strptime("2018-05-01 03:00:00", "%Y-%m-%d %H:%M:%S")
            self.assertEqual(db.getaccess(testMAC1, owner1EndDate - datetime.timedelta(hours=1)), False, "tga1")
            self.assertEqual(db.getaccess(testMAC1, owner1EndDate + datetime.timedelta(hours=1)), True, "tga2")

            # 2) MAC with owner that is unblocked, and client that is blocked.  Repeat for time elapsed.
            # DB contains
            # 00:01:02:03:04:06 0.0.0.2 testMAC2 testOwner2 BlockedUntil 2018-06-01 03:00:00 NULL
            # testOwner2 UnblockedUntil 2018-05-01 03:00:00 NULL
            testMAC2 = "00:01:02:03:04:06"
            client2EndDate = datetime.datetime.strptime("2018-06-01 03:00:00", "%Y-%m-%d %H:%M:%S")
            owner2EndDate = datetime.datetime.strptime("2018-05-01 03:00:00", "%Y-%m-%d %H:%M:%S")
            self.assertEqual(db.getaccess(testMAC2, owner2EndDate - datetime.timedelta(hours=1)), True, "tga3")
            self.assertEqual(db.getaccess(testMAC2, owner2EndDate + datetime.timedelta(hours=1)), False, "tga4")

            # 3) unknown MAC - 'unknown' is unblocked until xxx. Repeat for time elapsed
            # DB contains
            # unknown UnblockedUntil 2018-04-01 03:00:00 NULL
            self.assertFalse(db.DEFAULT_ACCESS)  # if not false, the test won't work
            testMACunknown = "ff:01:02:03:04:06"
            ownerunkEndDate = datetime.datetime.strptime("2018-04-01 03:00:00", "%Y-%m-%d %H:%M:%S")
            self.assertEqual(db.getaccess(testMACunknown, ownerunkEndDate - datetime.timedelta(hours=1)), True, "tga5")
            self.assertEqual(db.getaccess(testMACunknown, ownerunkEndDate + datetime.timedelta(hours=1)), False, "tga6")

            # 4) known client with NULL owner.  As per 3.
            # DB contains
            # 00:01:02:03:04:07 0.0.0.3 testMAC3 NULL BlockedUntil 2018-06-01 03:00:00 NULL
            # unknown UnblockedUntil 2018-04-01 03:00:00 NULL
            testMAC3 = "00:01:02:03:04:07"
            self.assertEqual(db.getaccess(testMAC3, ownerunkEndDate - datetime.timedelta(hours=1)), True, "tga7")
            self.assertEqual(db.getaccess(testMAC3, ownerunkEndDate + datetime.timedelta(hours=1)), False, "tga8")

    def test_getknown_macs(self):
        with DBaccess(dbpassword="TESTREADONLY") as db:
            maclist = db.getknown_macs()
            self.assertIsNotNone(maclist, "tgkm1")

    def test_ebtables(self):
        with DBaccess(dbpassword="TESTREADONLY") as db:
            ebtables = EbTables(db)
            eblist = ebtables.compilerules()
            self.assertIsNotNone(eblist, "tet1")

if __name__ == '__main__':
    unittest.main()
