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

$EBTABLES is added by the caller

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

    HEADER_CONFIG_FILE = "configs/ebtablesprefix.txt"

    def __init__(self, database):
        """
        :param database: the DBaccess to use
        """
        self.dbAccess = database

    def compilerules(self, lineprefix="$EBTABLES", atomicfilename=None):
        """
        compile the ebtables script for the access rules in the database
        :lineprefix: the prefix to add to the start of each line
        :atomicfilename: if the rules are to be used for atomic commit: the filename to use
        :return: list of rules in order
        """
        eblines = []

        atomicoptions = {"atomicfile": ""}

        if not atomicfilename is None:
            atomicoptions = {"atomicfile": " --atomic-file " + atomicfilename}

        # first check for all known macs
        allknownmacs = self.dbAccess.getknown_macs()
        ebline = "{0} -A FORWARD -p IP --among-src ! ".format(lineprefix) + ",".join(allknownmacs)
        ebline += " --log-level info --log-ip --log-prefix {1} -j CONTINUE"\
            .format(lineprefix, self.LOGFILE_PREFIX_UNKNOWN_MAC, **atomicoptions)
        eblines.append(ebline)

    # pass all ARP
        eblines.append("{0} -A FORWARD -p ARP -j ACCEPT".format(lineprefix))

#log all dns -for troubleshooting at this time
        eblines.append("{0} -A FORWARD -i $INSIDE_IF_NAME  -p IP --ip-protocol UDP --ip-destination-port 53" 
                       " --log-level info --log-ip --log-prefix {1} -j CONTINUE"
                       .format(lineprefix, self.LOGFILE_PREFIX_DNS_QUERY, **atomicoptions))
        eblines.append("{0} -A FORWARD -i $INSIDE_IF_NAME  -p IP --ip-protocol TDP --ip-destination-port 53"
                       " --log-level info --log-ip --log-prefix {1} -j CONTINUE"
                       .format(lineprefix, self.LOGFILE_PREFIX_DNS_QUERY, **atomicoptions))
        eblines.append("{0} -A FORWARD -i $OUTSIDE_IF_NAME  -p IP --ip-protocol UDP --ip-source-port 53" 
                       " --log-level info --log-ip --log-prefix {1}"
                       " -j CONTINUE".format(lineprefix, self.LOGFILE_PREFIX_DNS_RESPONSE, **atomicoptions))
        eblines.append("{0} -A FORWARD -i $OUTSIDE_IF_NAME  -p IP --ip-protocol TDP --ip-source-port 53"
                       " --log-level info --log-ip --log-prefix {1}"
                       " -j CONTINUE".format(lineprefix, self.LOGFILE_PREFIX_DNS_RESPONSE, **atomicoptions))

    # for now: pass all IP4
        eblines.append("{0} -A FORWARD -p IPv4 -j ACCEPT".format(lineprefix))
        return eblines

    def compilerulesandcommit(self, atomiccommitfilename, lineprefix="$EBTABLES"):
        """
        compile the ebtables script for the access rules in the database, wrap it in commit
        :lineprefix: the prefix to add to the start of each line
        :atomicfilename: the filename to use for the commit
        :return: list of rules in order
        """
        eblines = []
        eblines.append("{0} --atomic-file {1} --atomic-init ".format(lineprefix, atomiccommitfilename))
        eblines += self.compilerules(lineprefix, atomiccommitfilename)
        eblines.append("{0} --atomic-file {1} --atomic-commit".format(lineprefix, atomiccommitfilename))
        return eblines

    def completeupdate(self, atomiccommitfilename=None):
        """
        perform a complete update of the table
        :param atomicfilename: the atomic commit filename to use, if any.  If none, don't use atomic commit
        :return: the script ready for execution
        """

        with open(self.HEADER_CONFIG_FILE, 'r') as f:
            header = f.readlines()
        if atomiccommitfilename is None:
            eblines = header + self.compilerules()
        else:
            eblines = header + self.compilerulesandcommit(atomiccommitfilename)

        return eblines

