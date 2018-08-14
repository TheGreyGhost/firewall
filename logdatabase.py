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
import datetime
import time
from collections import namedtuple
import binascii
import socket
import re
LogDataEntry = namedtuple("LogDataEntry", "timestamp srcMAC dstMAC srcIP srcPort dstIP dstPort")

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
            raise errorhandler.LogDatabaseError("separator {} not found in log entry".format(self.LOGFILE_PREFIX))
        str2 = splitLogInfo[2]

        try:
            timestamp = datetime.datetime(*time.strptime(splitLogInfo[0], "%Y-%m-%dT%H:%M:%S")[:6])
        except ValueError:
            raise errorhandler.LogDatabaseError("Value error parsing timestamp out of log entry")

        tokens = {
            "MAC source": "MAC source = ",
            "MAC dest": "MAC dest = ",
            "IP source": "IP SRC=",
            "IP dest": "IP DST=",
            "IP source port": "SPT=",
            "IP dest port": "DPT="
        }

        indices = []
        lastidx = 0
        for k, v in tokens.items():
            nextidx = str2.find(v, lastidx)
            if nextidx < 0:
                raise errorhandler.LogDatabaseError("{} not found in log entry".format(k))
            indices.append(nextidx + len(v))
            lastidx = nextidx

        srcMAC = mac_to_bytes(str2, indices[0])
        dstMAC = mac_to_bytes(str2, indices[1])
        srcIP = ip_to_bytes(str2, indices[2])
        dstIP = ip_to_bytes(str2, indices[3])
        srcPort = int(str2[indices[4]:])
        dstPort = int(str2[indices[5]:])

        logdataentry = LogDataEntry(timestamp=timestamp, srcMAC=srcMAC, dstMAC=dstMAC, srcIP=srcIP, dstIP=dstIP,
                                    srcPort=srcPort, dstPort=dstPort)
        return logdataentry

def mac_to_bytes(str, start):
    macbytes = binascii.unhexlify(str[start:start+17].replace(b':', b''))
    return macbytes

def ip_to_bytes(str, start):
    addressonly = re.search(r"[\d\.]+", str[start:])
    if not addressonly:
        return b'\x00\x00\x00\x00'
    ipbytes = socket.inet_aton(addressonly.group())
    return ipbytes
