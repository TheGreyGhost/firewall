import unittest
import datetime
from dbaccess import DBaccess
import logdatabase
from logdatabase import LogDatabase
from logdatabase import LogDataEntry

testport = 8889

class MyTestCase(unittest.TestCase):

    def test_log_parser(self):
        with DBaccess(dbname="testfirewall", username="testreadonly", dbpassword="TESTREADONLY", port=testport) as db:
            log_database = LogDatabase(db)

            testparse = {
                "2018-08-11T16:21:09.503819+09:30 garden kernel: [103105.328637] EBTABLESLOGUMAC "
                "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8"
                "MAC source = 38:2c:4a:64:d1:50 MAC dest = a4:91:b1:4f:6b:e8 proto = 0x0800"
                "IP SRC=192.168.1.200 IP DST=203.47.10.37, IP tos=0x00, IP proto=6 SPT=55028 DPT=8080" :
                LogDataEntry(logdatabase.LogEntryType.UNKNOWN_MAC,
                             datetime.datetime(2018, 8, 11, 16, 21, 9),
                             b"\x38\x2c\x4a\x64\xd1\x50",
                             b"\xa4\x91\xb1\x4f\x6b\xe8",
                             bytes([192, 168,   1, 200]), 55028,
                             bytes([203,  47,  10,  37]), 8080
                             ),
                "2019-08-11T18:21:09.503819+09:30 garden kernel: [103105.328637] EBTABLESLOGUIP "
                "IN=enxa0cec81d71e2    OUT=enxb827eb8cefb8"
                "MAC source = aa:2c:4a:64:d1:00 MAC dest = 00:91:35:4f:6b:e8 proto = 0x0800"
                "IP SRC=0.0.1.0 IP DST=1.255.3.4, IP tos=0x00, IP proto=6 SPT=0 DPT=65535":
                    LogDataEntry(logdatabase.LogEntryType.UNKNOWN_IP,
                                 datetime.datetime(2019, 8, 11, 18, 21, 9),
                                 b"\xaa\x2c\x4a\x64\xd1\x00",
                                 b"\x00\x91\x35\x4f\x6b\xe8",
                                 bytes([0, 0, 1, 0]), 0,
                                 bytes([1, 255, 3, 4]), 65535
                                 ),
                "2019-12-31T0:12:13.003819+09:30 garden kernel: [103105.328637] EBTABLESLOGIPOUT "
                "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8"
                "MAC source = 11:2c:4a:64:d1:00 MAC dest = ff:91:35:4f:6b:e8 proto = 0x0800"
                "IP SRC=255.255.255.255 IP DST=127.0.0.1, IP tos=0x00, IP proto=6 SPT=12345 DPT=541":
                    LogDataEntry(logdatabase.LogEntryType.IP_TRAFFIC_OUT,
                                 datetime.datetime(2019, 12, 31, 00, 12, 13),
                                 b"\x11\x2c\x4a\x64\xd1\x00",
                                 b"\xff\x91\x35\x4f\x6b\xe8",
                                 bytes([255, 255, 255, 255]), 12345,
                                 bytes([127, 0, 0, 1]), 541
                                 ),
                "2019-12-31T0:12:13.003819+09:30 garden kernel: [103105.328637] EBTABLESLOGIPIN "
                "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8"
                "MAC source = 11:2c:4a:64:d1:00 MAC dest = ff:91:35:4f:6b:e8 proto = 0x0800"
                "IP SRC=255.255.255.255 IP DST=127.0.0.1, IP tos=0x00, IP proto=6 SPT=12345 DPT=541":
                    LogDataEntry(logdatabase.LogEntryType.IP_TRAFFIC_IN,
                                 datetime.datetime(2019, 12, 31, 00, 12, 13),
                                 b"\x11\x2c\x4a\x64\xd1\x00",
                                 b"\xff\x91\x35\x4f\x6b\xe8",
                                 bytes([255, 255, 255, 255]), 12345,
                                 bytes([127, 0, 0, 1]), 541
                                 )
            }
        i = 0
        for k, v in testparse.items():
            reply = log_database.parse_log_entry(k)
            self.assertEqual(v, reply, "test_log_parser1 {}".format(i))
            i += 1

if __name__ == '__main__':
    unittest.main()
