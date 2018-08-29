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


# TODO: later - convert to transaction / commit

class EbTables:
    dbAccess = None
    LOGFILE_PREFIX_UNKNOWN_MAC = "EBTABLESLOGUMAC"
    LOGFILE_PREFIX_UNKNOWN_IP4 = "EBTABLESLOGUIP"
    LOGFILE_PREFIX_IP4_OUT = "EBTABLESLOGIPOUT"
    LOGFILE_PREFIX_IP4_IN = "EBTABLESLOGIPIN"
    LOGFILE_PREFIX_DROP = "EBTABLESLOGDROP"
    # LOGFILE_PREFIX_DNS_QUERY = "EBTABLESLOGDQ"
    # LOGFILE_PREFIX_DNS_RESPONSE = "EBTABLESLOGDR"

    HEADER_CONFIG_FILE = "configs/ebtablesprefix.txt"

    def __init__(self, database):
        """
        :param database: the DBaccess to use
        """
        self.dbAccess = database

    def compilerules(self, datetimenow, lineprefix="$EBTABLES", atomicfilename=None):
        """
        compile the ebtables script for the access rules in the database
        :timenow: current date+time (datetime object)
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
        ebline = "{0} {atomicfile} -A FORWARD -p IP --among-src ! ".format(lineprefix, **atomicoptions)
        ebline += ",".join(allknownmacs)
        ebline += " --log-level info --log-ip --log-prefix {1} -j CONTINUE" \
            .format(lineprefix, self.LOGFILE_PREFIX_UNKNOWN_MAC)
        eblines.append(ebline)

        # pass all ARP
        eblines.append("{0} -A FORWARD -p ARP -j ACCEPT".format(lineprefix))

        # then check for all known MAC+IP outgoings (detect IP spoofs)
        allknownmacips = self.dbAccess.getknown_mac_ips()
        ebline = "{0} {atomicfile} -A FORWARD -p IP --among-src ! ".format(lineprefix, **atomicoptions)
        ebline += ",".join(allknownmacips)
        ebline += " --log-level info --log-ip --log-prefix {1} -j CONTINUE" \
            .format(lineprefix, self.LOGFILE_PREFIX_UNKNOWN_IP4)
        eblines.append(ebline)

        # log all outbound traffic
        ebline = "{0} {atomicfile} -A FORWARD -i $INSIDE_IF_NAME -p IP " \
                 "--log-level info --log-ip --log-prefix {1} -j CONTINUE" \
            .format(lineprefix, self.LOGFILE_PREFIX_IP4_OUT, **atomicoptions)
        eblines.append(ebline)

        # log all inbound traffic
        ebline = "{0} {atomicfile} -A FORWARD -i $OUTSIDE_IF_NAME -p IP " \
                 "--log-level info --log-ip --log-prefix {1} -j CONTINUE" \
            .format(lineprefix, self.LOGFILE_PREFIX_IP4_IN, **atomicoptions)
        eblines.append(ebline)

        # #log all dns -for troubleshooting at this time
        #         eblines.append("{0} -A FORWARD -i $INSIDE_IF_NAME  -p IP --ip-protocol UDP --ip-destination-port 53"
        #                        " --log-level info --log-ip --log-prefix {1} -j CONTINUE"
        #                        .format(lineprefix, self.LOGFILE_PREFIX_DNS_QUERY, **atomicoptions))
        #         eblines.append("{0} -A FORWARD -i $INSIDE_IF_NAME  -p IP --ip-protocol TCP --ip-destination-port 53"
        #                        " --log-level info --log-ip --log-prefix {1} -j CONTINUE"
        #                        .format(lineprefix, self.LOGFILE_PREFIX_DNS_QUERY, **atomicoptions))
        #         eblines.append("{0} -A FORWARD -i $OUTSIDE_IF_NAME  -p IP --ip-protocol UDP --ip-source-port 53"
        #                        " --log-level info --log-ip --log-prefix {1}"
        #                        " -j CONTINUE".format(lineprefix, self.LOGFILE_PREFIX_DNS_RESPONSE, **atomicoptions))
        #         eblines.append("{0} -A FORWARD -i $OUTSIDE_IF_NAME  -p IP --ip-protocol TCP --ip-source-port 53"
        #                        " --log-level info --log-ip --log-prefix {1}"
        #                        " -j CONTINUE".format(lineprefix, self.LOGFILE_PREFIX_DNS_RESPONSE, **atomicoptions))

        # for now: pass all IP4
        #        eblines.append("{0} -A FORWARD -p IPv4 -j ACCEPT".format(lineprefix))

        # pass all IP4 clients which have access
        permittedmacs = []
        for mac in allknownmacs:
            if self.dbAccess.getaccess(mac, datetimenow):
                permittedmacs.append(mac)
        ebline = "{0} {atomicfile} -A FORWARD -p IP --among-src ".format(lineprefix, **atomicoptions)
        ebline += ",".join(permittedmacs)
        ebline += " -j ACCEPT"
        eblines.append(ebline)

        # log all dropped traffic
        ebline = "{0} {atomicfile} --log-level info --log-ip --log-prefix {1} -j DROP" \
            .format(lineprefix, self.LOGFILE_PREFIX_DROP, **atomicoptions)
        eblines.append(ebline)

        return eblines

    def compilerulesandcommit(self, datetimenow, atomiccommitfilename, lineprefix="$EBTABLES"):
        """
        compile the ebtables script for the access rules in the database, wrap it in commit
        :datetimenow: current date+time (datetime object)
        :lineprefix: the prefix to add to the start of each line
        :atomicfilename: the filename to use for the commit
        :return: list of rules in order
        """
        eblines = []
        eblines.append("{0} --atomic-file {1} --atomic-init ".format(lineprefix, atomiccommitfilename))
        eblines += self.compilerules(datetimenow, lineprefix, atomiccommitfilename)
        eblines.append("{0} --atomic-file {1} --atomic-commit".format(lineprefix, atomiccommitfilename))
        return eblines

    def completeupdate(self, datetimenow, atomiccommitfilename=None):
        """
        perform a complete update of the table
        :datetimenow: current date+time (datetime object)
        :param atomicfilename: the atomic commit filename to use, if any.  If none, don't use atomic commit
        :return: the script ready for execution
        """

        with open(self.HEADER_CONFIG_FILE, 'r') as f:
            header = f.readlines()
        if atomiccommitfilename is None:
            eblines = header + self.compilerules(datetimenow)
        else:
            eblines = header + self.compilerulesandcommit(datetimenow, atomiccommitfilename)

        return eblines
