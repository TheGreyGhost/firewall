"""
Maintains a database of the logged information

receives input, extracts the relevant addresses, collates the info, and
  periodically writes to a database

the input has the format

2018-08-11T16:21:09.503819+09:30 garden kernel: [103105.328637] EBTABLESLOG
  IN=enxa0cec81d71e2 OUT=enxb827eb8cefb8
  MAC source = 38:2c:4a:64:d1:50 MAC dest = a4:91:b1:4f:6b:e8 proto = 0x0800
  IP SRC=192.168.1.200 IP DST=203.47.10.37, IP tos=0x00, IP proto=6 SPT=55028 DPT=8080

valid log entry tags are
     EBTABLESLOGUMAC (unknown MAC address)
     EBTABLESLOGUIP (unknown IP address)
     EBTABLESLOGIPOUT (outgoing IP traffic)
     EBTABLESLOGIPIN (incoming IP traffid)

"""

import errorhandler
import datetime
import time
from collections import namedtuple
import binascii
import socket
import re
from enum import Enum, auto
import collections

class LogEntryType(Enum):
    UNKNOWN_MAC = auto()
    UNKNOWN_IP = auto()
    IP_TRAFFIC_IN = auto()
    IP_TRAFFIC_OUT = auto()

LogDataEntry = namedtuple("LogDataEntry", "entry_type timestamp srcMAC dstMAC srcIP srcPort dstIP dstPort")

class LogDatabase:
    dbAccess = None
    validpostfixes = {"UMAC " : LogEntryType.UNKNOWN_MAC,
                      "UIP " : LogEntryType.UNKNOWN_IP,
                      "IPOUT" : LogEntryType.IP_TRAFFIC_OUT,
                      "IPIN" : LogEntryType.IP_TRAFFIC_IN
                      }
    LOGFILE_PREFIX = "EBTABLESLOG"

    def __init__(self, database):
        """
        :param database: the DBaccess to use
        """
        self.dbAccess = database

    def add_log_entry_string(self, logstring):
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

        entrytype = None
        for k, v in self.validpostfixes.items():
            if splitLogInfo[2][0:len(k)] == k:
                entrytype = v
                break
        if entrytype is None:
            raise errorhandler.LogDatabaseError("Invalid log type: {}".format(splitLogInfo[2][0:10]))

        try:
            timestringtrimmed = logstring.partition(".")[0]
            timestamp = datetime.datetime(*time.strptime(timestringtrimmed, "%Y-%m-%dT%H:%M:%S")[:6])
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
        srcPort = int(str2[indices[4]:].partition(" ")[0])
        dstPort = int(str2[indices[5]:])

        logdataentry = LogDataEntry(entry_type=entrytype, timestamp=timestamp, srcMAC=srcMAC, dstMAC=dstMAC, srcIP=srcIP, dstIP=dstIP,
                                    srcPort=srcPort, dstPort=dstPort)
        return logdataentry

    unknown_macs = collections.Counter()
    unknown_ips = collections.Counter()
    ip_traffic_in = collections.Counter()
    ip_traffic_out = collections.Counter()
    firsttimestamp = None
    lasttimestamp = None

    def add_log_entry(self, logdataentry):
        if self.firsttimestamp is None:
            self.firsttimestamp = logdataentry.timestamp
        self.lasttimestamp = logdataentry.timestamp

        if logdataentry.entry_type == LogEntryType.UNKNOWN_MAC:
            self.unknown_macs[logdataentry.srcMAC] += 1
        elif logdataentry.entry_type == LogEntryType.UNKNOWN_IP:
            self.unknown_ips[logdataentry.srcIP] += 1
        elif logdataentry.entry_type == LogEntryType.IP_TRAFFIC_IN:
            self.ip_traffic_in[b"".join(logdataentry.srcIP, logdataentry.srcPort,
                                        logdataentry.destIP, logdataentry.dstPort)] += 1
        elif logdataentry.entry_type == LogEntryType.IP_TRAFFIC_OUT:
            self.ip_traffic_in[b"".join(logdataentry.srcIP, logdataentry.srcPort,
                                        logdataentry.destIP, logdataentry.dstPort)] += 1

    def write_to_database(self):
        need locks



def mac_to_bytes(str, start):
    macbytes = binascii.unhexlify(str[start:start+17].replace(':', ''))
    return macbytes

def ip_to_bytes(str, start):
    addressonly = re.search(r"[\d\.]+", str[start:])
    if not addressonly:
        return b'\x00\x00\x00\x00'
    ipbytes = socket.inet_aton(addressonly.group())
    return ipbytes
