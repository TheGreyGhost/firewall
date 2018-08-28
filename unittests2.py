import unittest
import datetime
from dbaccess import DBaccess
import logdatabase
from logdatabase import LogDatabase
from logdatabase import LogDataEntry

testport = 8889


class MyTestCase(unittest.TestCase):

    # def test_log_parser(self):
    #     with DBaccess(dbname="testfirewall", username="testreadonly", dbpassword="TESTREADONLY", port=testport) as db:
    #         log_database = LogDatabase(db)
    #
    #         testparse = {
    #             "2018-08-11T16:21:09.503819+09:30 garden kernel: [103105.328637] EBTABLESLOGUMAC "
    #             "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8"
    #             "MAC source = 38:2c:4a:64:d1:50 MAC dest = a4:91:b1:4f:6b:e8 proto = 0x0800"
    #             "IP SRC=192.168.1.200 IP DST=203.47.10.37, IP tos=0x00, IP proto=6 SPT=55028 DPT=8080" :
    #             LogDataEntry(logdatabase.LogEntryType.UNKNOWN_MAC,
    #                          datetime.datetime(2018, 8, 11, 16, 21, 9),
    #                          b"\x38\x2c\x4a\x64\xd1\x50",
    #                          b"\xa4\x91\xb1\x4f\x6b\xe8",
    #                          bytes([192, 168,   1, 200]), 55028,
    #                          bytes([203,  47,  10,  37]), 8080
    #                          ),
    #             "2019-08-11T18:21:09.503819+09:30 garden kernel: [103105.328637] EBTABLESLOGUIP "
    #             "IN=enxa0cec81d71e2    OUT=enxb827eb8cefb8"
    #             "MAC source = aa:2c:4a:64:d1:00 MAC dest = 00:91:35:4f:6b:e8 proto = 0x0800"
    #             "IP SRC=0.0.1.0 IP DST=1.255.3.4, IP tos=0x00, IP proto=6 SPT=0 DPT=65535":
    #                 LogDataEntry(logdatabase.LogEntryType.UNKNOWN_IP,
    #                              datetime.datetime(2019, 8, 11, 18, 21, 9),
    #                              b"\xaa\x2c\x4a\x64\xd1\x00",
    #                              b"\x00\x91\x35\x4f\x6b\xe8",
    #                              bytes([0, 0, 1, 0]), 0,
    #                              bytes([1, 255, 3, 4]), 65535
    #                              ),
    #             "2019-12-31T0:12:13.003819+09:30 garden kernel: [103105.328637] EBTABLESLOGIPOUT "
    #             "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8"
    #             "MAC source = 11:2c:4a:64:d1:00 MAC dest = ff:91:35:4f:6b:e8 proto = 0x0800"
    #             "IP SRC=255.255.255.255 IP DST=127.0.0.1, IP tos=0x00, IP proto=6 SPT=12345 DPT=541":
    #                 LogDataEntry(logdatabase.LogEntryType.IP_TRAFFIC_OUT,
    #                              datetime.datetime(2019, 12, 31, 00, 12, 13),
    #                              b"\x11\x2c\x4a\x64\xd1\x00",
    #                              b"\xff\x91\x35\x4f\x6b\xe8",
    #                              bytes([255, 255, 255, 255]), 12345,
    #                              bytes([127, 0, 0, 1]), 541
    #                              ),
    #             "2019-12-31T0:12:13.003819+09:30 garden kernel: [103105.328637] EBTABLESLOGIPIN "
    #             "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8"
    #             "MAC source = 11:2c:4a:64:d1:00 MAC dest = ff:91:35:4f:6b:e8 proto = 0x0800"
    #             "IP SRC=255.255.255.255 IP DST=127.0.0.1, IP tos=0x00, IP proto=6 SPT=12345 DPT=541":
    #                 LogDataEntry(logdatabase.LogEntryType.IP_TRAFFIC_IN,
    #                              datetime.datetime(2019, 12, 31, 00, 12, 13),
    #                              b"\x11\x2c\x4a\x64\xd1\x00",
    #                              b"\xff\x91\x35\x4f\x6b\xe8",
    #                              bytes([255, 255, 255, 255]), 12345,
    #                              bytes([127, 0, 0, 1]), 541
    #                              )
    #         }
    #     i = 0
    #     for k, v in testparse.items():
    #         reply = log_database.parse_log_entry(k)
    #         self.assertEqual(v, reply, "test_log_parser1 {}".format(i))
    #       i += 1

    def test_log_parser(self):
        with DBaccess(dbname="testfirewall", username="testreadonly", dbpassword="TESTREADONLY", port=testport) as db:
            log_database = LogDatabase(db)

            testparse = {
                "2018-08-11T16:21:09.503819+09:30 garden kernel: [103105.328637] EBTABLESLOGUMAC "
                "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8 "
                "MAC source = 38:2c:4a:64:d1:50 MAC dest = a4:91:b1:4f:6b:e8 proto = 0x0800 "
                "IP SRC=192.168.1.200 IP DST=203.47.10.37, IP tos=0x00, IP proto=6 SPT=55028 DPT=8080":
                    LogDataEntry(logdatabase.LogEntryType.UNKNOWN_MAC,
                                 datetime.datetime(2018, 8, 11, 16, 21, 9),
                                 "38:2c:4a:64:d1:50",
                                 "a4:91:b1:4f:6b:e8",
                                 "", "",
                                 "", ""
                                 ),
                "2019-08-11T18:21:09.503819+09:30 garden kernel: [103105.328637] EBTABLESLOGUIP "
                "IN=enxa0cec81d71e2    OUT=enxb827eb8cefb8 "
                "MAC source = aa:2c:4a:64:d1:00 MAC dest = 00:91:35:4f:6b:e8 proto = 0x0800 "
                "IP SRC=0.0.1.0 IP DST=1.255.3.4, IP tos=0x00, IP proto=6 SPT=0 DPT=65535":
                    LogDataEntry(logdatabase.LogEntryType.UNKNOWN_IP,
                                 datetime.datetime(2019, 8, 11, 18, 21, 9),
                                 "aa:2c:4a:64:d1:00",
                                 "00:91:35:4f:6b:e8",
                                 "0.0.1.0", "0",
                                 "1.255.3.4", "65535"
                                 ),
                "2019-12-31T0:12:13.003819+09:30 garden kernel: [103105.328637] EBTABLESLOGIPOUT "
                "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8 "
                "MAC source = 11:2c:4a:64:d1:00 MAC dest = ff:91:35:4f:6b:e8 proto = 0x0800 "
                "IP SRC=255.255.255.255 IP DST=127.0.0.1, IP tos=0x00, IP proto=6 SPT=12345 DPT=541":
                    LogDataEntry(logdatabase.LogEntryType.IP_TRAFFIC_OUT,
                                 datetime.datetime(2019, 12, 31, 00, 12, 13),
                                 "11:2c:4a:64:d1:00",
                                 "ff:91:35:4f:6b:e8",
                                 "255.255.255.255", "12345",
                                 "127.0.0.1", "541"
                                 ),
                "2019-12-31T0:12:13.003819+09:30 garden kernel: [103105.328637] EBTABLESLOGIPIN "
                "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8"
                "MAC source = 11:2c:4a:64:d1:00 MAC dest = ff:91:35:4f:6b:e8 proto = 0x0800 "
                "IP SRC=255.255.255.255 IP DST=127.0.0.1, IP tos=0x00, IP proto=6 SPT=12345 DPT=541":
                    LogDataEntry(logdatabase.LogEntryType.IP_TRAFFIC_IN,
                                 datetime.datetime(2019, 12, 31, 00, 12, 13),
                                 "11:2c:4a:64:d1:00",
                                 "ff:91:35:4f:6b:e8",
                                 "255.255.255.255", "12345",
                                 "127.0.0.1", "541"
                                 )
            }
        i = 0
        for k, v in testparse.items():
            reply = log_database.parse_log_entry(k)
            self.assertEqual(v, reply, "test_log_parser1 {}".format(i))
            i += 1

    def test_write_logs(self):
        with DBaccess(username="testaddrows", dbpassword="TESTADDROWS", port=testport) as db:
            log_database = LogDatabase(db)

            unk_mac_1 = "2019-12-31T0:12:13.003819+09:30 garden kernel: [103105.328637] EBTABLESLOGUMAC " \
                        "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8 " \
                        "MAC source = 11:2c:4a:64:d1:00 MAC dest = ff:91:35:4f:6b:e8 proto = 0x0800 " \
                        "IP SRC=255.255.255.255 IP DST=127.0.0.1, IP tos=0x00, IP proto=6 SPT=12345 DPT=541"

            unk_mac_2 = "2019-12-31T0:12:13.003819+09:30 garden kernel: [103105.328637] EBTABLESLOGUMAC " \
                        "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8 " \
                        "MAC source = ff:ee:dd:cc:bb:aa MAC dest = 00:11:22:33:44:55 proto = 0x0800 " \
                        "IP SRC=255.255.255.255 IP DST=127.0.0.1, IP tos=0x00, IP proto=6 SPT=12345 DPT=541"

            unk_mac_3 = "2019-12-31T0:15:13.003819+09:30 garden kernel: [103105.328637] EBTABLESLOGUMAC " \
                        "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8 " \
                        "MAC source = ff:ee:dd:cc:bb:aa MAC dest = 00:11:22:33:44:55" \
                        "IP SRC=255.255.255.255 IP DST=127.0.0.1, IP tos=0x00, IP proto=6 SPT=12345 DPT=541"

            log_database.add_log_entry_string(unk_mac_1)
            log_database.add_log_entry_string(unk_mac_2)
            log_database.add_log_entry_string(unk_mac_3)

            unk_ip_1 = "2019-12-31T0:12:13.003819+09:30 garden kernel: [103105.328637] EBTABLESLOGUIP " \
                       "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8 " \
                       "MAC source = 11:2c:4a:64:d1:00 MAC dest = ff:91:35:4f:6b:e8 proto = 0x0800 " \
                       "IP SRC=255.255.255.255 IP DST=127.0.0.1, IP tos=0x00, IP proto=6 SPT=12345 DPT=541"

            unk_ip_2 = "2019-12-31T0:12:13.003819+09:30 garden kernel: [103105.328637] EBTABLESLOGUIP " \
                       "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8 " \
                       "MAC source = ff:ee:dd:cc:bb:aa MAC dest = 00:11:22:33:44:55 proto = 0x0800 " \
                       "IP SRC=255.255.255.255 IP DST=127.0.0.1, IP tos=0x00, IP proto=6 SPT=12345 DPT=541"

            unk_ip_3 = "2019-12-31T0:15:13.003819+09:30 garden kernel: [103105.328637] EBTABLESLOGUIP " \
                       "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8 " \
                       "MAC source = ff:ee:dd:cc:bb:aa MAC dest = 00:11:22:33:44:55" \
                       "IP SRC=1.2.3.4 IP DST=127.0.0.1, IP tos=0x00, IP proto=6 SPT=12345 DPT=541"

            log_database.add_log_entry_string(unk_ip_1)
            log_database.add_log_entry_string(unk_ip_2)
            log_database.add_log_entry_string(unk_ip_3)

            ip_in_1 = "2019-12-31T0:12:13.003819+09:30 garden kernel: [103105.328637] EBTABLESLOGIPIN " \
                      "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8 " \
                      "MAC source = 11:2c:4a:64:d1:00 MAC dest = ff:91:35:4f:6b:e8 proto = 0x0800 " \
                      "IP SRC=255.255.255.255 IP DST=127.0.0.1, IP tos=0x00, IP proto=6 SPT=12345 DPT=541"

            ip_in_2 = "2019-12-31T0:12:13.003819+09:30 garden kernel: [103105.328637] EBTABLESLOGIPIN " \
                      "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8 " \
                      "MAC source = ff:ee:dd:cc:bb:aa MAC dest = 00:11:22:33:44:55 proto = 0x0800 " \
                      "IP SRC=255.255.255.255 IP DST=127.0.0.1, IP tos=0x00, IP proto=6 SPT=54321 DPT=541"

            ip_in_3 = "2019-12-31T0:15:13.003819+09:30 garden kernel: [103105.328637] EBTABLESLOGIPIN " \
                      "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8 " \
                      "MAC source = ff:ee:dd:cc:bb:aa MAC dest = 00:11:22:33:44:55" \
                      "IP SRC=1.2.3.4 IP DST=127.0.0.1, IP tos=0x00, IP proto=6 SPT=12345 DPT=541"

            log_database.add_log_entry_string(ip_in_1)
            log_database.add_log_entry_string(ip_in_2)
            log_database.add_log_entry_string(ip_in_3)

            ip_out_1 = "2019-12-31T0:12:13.003819+09:30 garden kernel: [103105.328637] EBTABLESLOGIPOUT " \
                      "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8 " \
                      "MAC source = 11:2c:4a:64:d1:00 MAC dest = ff:91:35:4f:6b:e8 proto = 0x0800 " \
                      "IP SRC=255.255.255.255 IP DST=127.0.0.1, IP tos=0x00, IP proto=6 SPT=12345 DPT=1"

            ip_out_2 = "2019-12-31T0:12:13.003819+09:30 garden kernel: [103105.328637] EBTABLESLOGIPOUT " \
                      "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8 " \
                      "MAC source = ff:ee:dd:cc:bb:aa MAC dest = 00:11:22:33:44:55 proto = 0x0800 " \
                      "IP SRC=255.255.255.255 IP DST=127.0.0.1, IP tos=0x00, IP proto=6 SPT=54321 DPT=2"

            ip_out_3 = "2019-12-31T0:21:1.003819+09:30 garden kernel: [103105.328637] EBTABLESLOGIPOUT " \
                      "IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8 " \
                      "MAC source = ff:ee:dd:cc:bb:aa MAC dest = 00:11:22:33:44:55 proto = 0x0800 " \
                      "IP SRC=255.255.255.255 IP DST=127.0.2.1, IP tos=0x00, IP proto=6 SPT=54321 DPT=2"

            log_database.add_log_entry_string(ip_out_1)
            log_database.add_log_entry_string(ip_out_2)
            log_database.add_log_entry_string(ip_out_3)

            log_database.write_to_database()

            # expect: two MAC rows, one with 11:2c etc count == 1 , one with ff:ee:dd etc count == 2
            print("inspect unknown_macs_log table to verify correct insertion")

            # expect: two IP rows, one with 1.2.3.4 count == 1 , one with 255.255.255.255 count == 2
            print("inspect unknown_ips_log table to verify correct insertion")

            # expect: three IP_in rows, all with count == 1
            print("inspect ip_traffic_in_log table to verify correct insertion")

            # expect: three IP_out rows, all with count == 1
            print("inspect ip_traffic_out_log table to verify correct insertion")

if __name__ == '__main__':
    unittest.main()
