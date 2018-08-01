"""
Generate an ebtables configuration file from the access database

#$EBTABLES  -A FORWARD --log-level info --log-ip --log-prefix EBTABLESLOG -j CONTINUE

#log all dns -for troubleshooting at this time
$EBTABLES -A FORWARD -i $INSIDE_IF_NAME  -p IP --ip-protocol UDP --ip-destination-port 53 --log-level info --log-ip --log-prefix EBTABLESLOGDQ -j CONTINUE
$EBTABLES -A FORWARD -i $OUTSIDE_IF_NAME -p ip --ip-protocol UDP --ip-source-port 53      --log-level info --log-ip --log-prefix EBTABLESLOGDR -j CONTINUE
$EBTABLES -A FORWARD -i $INSIDE_IF_NAME  -p IP --ip-protocol TCP --ip-destination-port 53 --log-level info --log-ip --log-prefix EBTABLESLOGDQ -j CONTINUE
$EBTABLES -A FORWARD -i $OUTSIDE_IF_NAME -p IP --ip-protocol TCP --ip-source-port 53      --log-level info --log-ip --log-prefix EBTABLESLOGDR -j CONTINUE

$EBTABLES  -A FORWARD -p IPv4 -j ACCEPT
$EBTABLES  -A FORWARD -p ARP -j ACCEPT
$EBTABLES  -A FORWARD -p IPv6 -j DROP
#$EBTABLES  -A FORWARD -p LENGTH -j ACCEPT
#log dropped
$EBTABLES  -A FORWARD --log-level info --log-ip --log-prefix EBTABLESLOG

$EBTABLES - A FORWARD --among-src ! MAC1, MAC2
$EBTABLES - A FORWARD --among-dst ! MAC1, MAC2 -j

################################################################
# END
################################################################

Functions I want:
 OPTIONAL 1) Check for MAC/IP spoofs - DROP
2) Check for unknown MACs - log
3) Let all ARP through
4) log all DNS packets
5) debug: log all?
6) for defined MACs (Call, Alycia): depending on the time of day
  a) drop all
  b) accept all
  c) accept white list only

So in order of priority:
1) search for all known macs.  if unknown, log it
2) accept all ARP
3) log all DNS IP4
4) make a list of accept macs
5) log all dropped macs

"""

#TODO: later - convert to transaction / commit

class EbTables:
    dbAccess = None
    LOGFILE_PREFIX_UNKNOWN_MAC = "EBTABLESLOGUNK"
    LOGFILE_PREFIX_DNS_QUERY = "EBTABLESLOGDQ"
    LOGFILE_PREFIX_DNS_RESPONSE = "EBTABLESLOGDR"

    def __init__(self, database):
        """
        :param database: the DBaccess to use
        """
        self.dbAccess = database

    def compilerules(self):
        """
        compile the ebtables script for the access rules in the database
        :return: list of rules in order
        """
        eblines = []
    # first check for all known macs
        allknownmacs = self.dbAccess.getknown_macs()
        ebline = "$EBTABLES - A FORWARD -p IP --among-src ! " + ",".join(allknownmacs)
        ebline += "--log-level info --log-ip --log-prefix {} -j CONTINUE".format(self.LOGFILE_PREFIX_UNKNOWN_MAC)
        eblines.append(ebline)

    # pass all ARP
        eblines.append("$EBTABLES -A FORWARD -p ARP -j ACCEPT")

#log all dns -for troubleshooting at this time
        eblines.append("$EBTABLES -A FORWARD -i $INSIDE_IF_NAME  -p IP --ip-protocol UDP --ip-destination-port 53" 
                       " --log-level info --log-ip --log-prefix {} -j CONTINUE".format(self.LOGFILE_PREFIX_DNS_QUERY))
        eblines.append("$EBTABLES -A FORWARD -i $INSIDE_IF_NAME  -p IP --ip-protocol TDP --ip-destination-port 53"
                       " --log-level info --log-ip --log-prefix {} -j CONTINUE".format(self.LOGFILE_PREFIX_DNS_QUERY))
        eblines.append("$EBTABLES -A FORWARD -i $OUTSIDE_IF_NAME  -p IP --ip-protocol UDP --ip-source-port 53" 
                       " --log-level info --log-ip --log-prefix {}"
                       " -j CONTINUE".format(self.LOGFILE_PREFIX_DNS_RESPONSE))
        eblines.append("$EBTABLES -A FORWARD -i $OUTSIDE_IF_NAME  -p IP --ip-protocol TDP --ip-source-port 53"
                       " --log-level info --log-ip --log-prefix {}"
                       " -j CONTINUE".format(self.LOGFILE_PREFIX_DNS_RESPONSE))

    # for now: pass all IP4
        eblines.append("$EBTABLES -A FORWARD -p IPv4 -j ACCEPT")
        return eblines


