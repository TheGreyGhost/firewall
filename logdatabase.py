"""
Maintains a database of the logged information

receives input, extracts the relevant addresses, collates the info, and
  periodically writes to a database

the input has the format

2018-08-11T16:21:09.503819+09:30 garden kernel: [103105.328637] EBTABLESLOGINFO
  IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8
  MAC source = 38:2c:4a:64:d1:50 MAC dest = a4:91:b1:4f:6b:e8 proto = 0x0800
  IP SRC=192.168.1.200 IP DST=203.47.10.37, IP tos=0x00, IP proto=6 SPT=55028 DPT=8080
"""

import errorhandler

class LogDatabase:
    dbAccess = None
    LOGFILE_PREFIX_UNKNOWN_MAC = "EBTABLESLOGUNK"
    LOGFILE_PREFIX_DNS_QUERY = "EBTABLESLOGDQ"
    LOGFILE_PREFIX_DNS_RESPONSE = "EBTABLESLOGDR"
    LOGFILE_PREFIX = "EBTABLESLOG"

    def __init__(self, database):
        """
        :param database: the DBaccess to use
        """
        self.dbAccess = database

    def add_log_entry(self, logstring):
        """
        Adds the given log string to the database
        :param logstring: the logged string
            expects the format:
                  2018-08-11T16:21:09.503819+09:30 garden kernel: [103105.328637] EBTABLESLOGINFO
                  IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8
                  MAC source = 38:2c:4a:64:d1:50 MAC dest = a4:91:b1:4f:6b:e8 proto = 0x0800
                  IP SRC=192.168.1.200 IP DST=203.47.10.37, IP tos=0x00, IP proto=6 SPT=55028 DPT=8080
        :return: none
        :raises: LogDatabaseError if the input is malformed
        """


    def parse_log_entry(self, logstring):
        """
        parses the given logstring into MAC source, MAC dest, IP source, IP dest, IP source, IP dest, timestamp
        :param logstring:
        :return: the parsed data
        """

        splitLogInfo = logstring.partition(self.LOGFILE_PREFIX)
        if len(splitLogInfo[1]) == 0:
            raise errorhandler.LogDatabaseError("separator {} not found".format(self.LOGFILE_PREFIX))
