#! /usr/bin/env python2
#
# This is a multi-threaded RBL lookup check for Icinga / Nagios.
# Copyright (C) 2012 Frode Egeland <egeland[at]gmail.com>
#
# Modified by Kumina bv in 2013. We only added an option to use an
# address instead of a hostname.
#
# Modified by Guillaume Subiron (Sysnove) in 2015 : mainly PEP8.
#
# Modified by Steve Jenkins (SteveJenkins.com) in 2017. Added a number
# of additional DNSRBLs and made 100% PEP8 compliant.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

# Import Modules
import sys
import os
import getopt
import socket
import string
if sys.version_info[0] == 3:
    import queue as Queue
else:
    import Queue
import threading
import ipaddress
import timeit

# Python version check
rv = (2, 6)
if rv >= sys.version_info:
    print("ERROR: Requires Python 2.6 or greater")
    sys.exit(3)

# List of DNS blacklists
serverlist = [
  "0spam-killlist.fusionzero.com",
  "0spam.fusionzero.com",
  "0spamtrust.fusionzero.com",
  "0spamurl.fusionzero.com",
  "_vouch.dwl.spamhaus.org",
  "abuse.rfc-clueless.org",
  "access.redhawk.org",
  "accredit.habeas.com",
  "all.dnsbl.bit.nl",
  "all.rbl.jp",
  "all.rbl.webiron.net",
  "all.s5h.net",
  "all.spamrats.com",
  "aspews.ext.sorbs.net",
  "b.barracudacentral.org",
  "babl.rbl.webiron.net",
  "backscatter.spameatingmonkey.net",
  "bad.psky.me",
  "badconf.rhsbl.sorbs.net",
  "badnets.spameatingmonkey.net",
  "bb.barracudacentral.org",
  "bhnc.njabl.org",
  "bitonly.dnsbl.bit.nl",
  "bl.blocklist.de",
  "bl.deadbeef.com",
  "bl.drmx.org",
  "bl.emailbasura.org",
  "bl.fmb.la",
  "bl.konstant.no",
  "bl.mailspike.net",
  "bl.mailspike.org",
  "bl.mav.com.br",
  "bl.nszones.com",
  "bl.scientificspam.net",
  "bl.score.senderscore.com",
  "bl.spamcannibal.org",
  "bl.spamcop.net",
  "bl.spameatingmonkey.net",
  "bl.spamstinks.com",
  "bl.suomispam.net",
  "bl.technovision.dk",
  "black.uribl.com",
  "blackholes.five-ten-sg.com",
  "blackholes.mail-abuse.org",
  "blacklist.sci.kun.nl",
  "blacklist.woody.ch",
  "block.ascams.com",
  "block.dnsbl.sorbs.net",
  "bogons.cymru.com",
  "bogusmx.rfc-clueless.org",
  "bsb.empty.us",
  "bsb.spamlookup.net",
  "cabl.rbl.webiron.net",
  "cbl.abuseat.org",
  "cbl.anti-spam.org.cn",
  "cblless.anti-spam.org.cn",
  "cblplus.anti-spam.org.cn",
  "cdl.anti-spam.org.cn",
  "cidr.bl.mcafee.com",
  "cml.anti-spam.org.cn",
  "combined.abuse.ch",
  "combined.rbl.msrbl.net",
  "combined.njabl.org",
  "communicado.fmb.la",
  "contacts.abuse.net",
  "crawler.rbl.webiron.net",
  "db.wpbl.info",
  "dbl.spamhaus.org",
  "dbl.suomispam.net",
  "dnsbl-0.uceprotect.net",
  "dnsbl-1.uceprotect.net",
  "dnsbl-2.uceprotect.net",
  "dnsbl-3.uceprotect.net",
  "dnsbl.anticaptcha.net",
  "dnsbl.beetjevreemd.nl",
  "dnsbl.burnt-tech.com",
  "dnsbl.calivent.com.pe",
  "dnsbl.cobion.com",
  "dnsbl.cyberlogic.net",
  "dnsbl.dronebl.org",
  "dnsbl.inps.de",
  "dnsbl.justspam.org",
  "dnsbl.kempt.net",
  "dnsbl.madavi.de",
  "dnsbl.net.ua",
  "dnsbl.njabl.org",
  "dnsbl.openresolvers.org",
  "dnsbl.rizon.net",
  "dnsbl.rv-soft.info",
  "dnsbl.rymsho.ru",
  "dnsbl.solid.net",
  "dnsbl.sorbs.net",
  "dnsbl.spfbl.net",
  "dnsbl.tornevall.org",
  "dnsbl.webequipped.com",
  "dnsbl.zapbl.net",
  "dnsblchile.org",
  "dnsrbl.org",
  "dnsrbl.swinog.ch",
  "dnswl.inps.de",
  "dnswl.spfbl.net",
  "dob.sibl.support-intelligence.net",
  "drone.abuse.ch",
  "dsn.rfc-clueless.org",
  "duinv.aupads.org",
  "dul.dnsbl.sorbs.net",
  "dul.pacifier.net",
  "dul.ru",
  "dyn.nszones.com",
  "dyna.spamrats.com",
  "dyndns.rbl.jp",
  "dynip.rothen.com",
  "elitist.rfc-clueless.org",
  "escalations.dnsbl.sorbs.net",
  "eswlrev.dnsbl.rediris.es",
  "ex.dnsbl.org",
  "exitnodes.tor.dnsbl.sectoor.de",
  "feb.spamlab.com",
  "fnrbl.fast.net",
  "forbidden.icm.edu.pl",
  "free.v4bl.org",
  "fresh.spameatingmonkey.net",
  "fresh10.spameatingmonkey.net",
  "fresh15.spameatingmonkey.net",
  "fulldom.rfc-clueless.org",
  "geobl.spameatingmonkey.net",
  "gl.suomispam.net",
  "grey.uribl.com",
  "hil.habeas.com",
  "hostkarma.junkemailfilter.com",
  "http.dnsbl.sorbs.net",
  "hul.habeas.com",
  "iadb.isipp.com",
  "iadb2.isipp.com",
  "iddb.isipp.com",
  "images.rbl.msrbl.net",
  "in.dnsbl.org",
  "ip.v4bl.org",
  "ipbl.zeustracker.abuse.ch",
  "ips.backscatterer.org",
  "ips.whitelisted.org",
  "ispmx.pofon.foobar.hu",
  "ix.dnsbl.manitu.net",
  "korea.services.net",
  "l1.bbfh.ext.sorbs.net",
  "l2.bbfh.ext.sorbs.net",
  "l3.bbfh.ext.sorbs.net",
  "l4.bbfh.ext.sorbs.net",
  "list.bbfh.org",
  "list.blogspambl.com",
  "list.dnswl.org",
  "mail-abuse.blacklist.jippg.org",
  "mailsl.dnsbl.rjek.com",
  "misc.dnsbl.sorbs.net",
  "mtawlrev.dnsbl.rediris.es",
  "multi.surbl.org",
  "multi.uribl.com",
  "netbl.spameatingmonkey.net",
  "netblockbl.spamgrouper.to",
  "netscan.rbl.blockedservers.com",
  "new.spam.dnsbl.sorbs.net",
  "no-more-funn.moensted.dk",
  "nobl.junkemailfilter.com",
  "nomail.rhsbl.sorbs.net",
  "noptr.spamrats.com",
  "nsbl.fmb.la",
  "ohps.dnsbl.net.au",
  "old.spam.dnsbl.sorbs.net",
  "omrs.dnsbl.net.au",
  "orvedb.aupads.org",
  "osps.dnsbl.net.au",
  "osrs.dnsbl.net.au",
  "owfs.dnsbl.net.au",
  "owps.dnsbl.net.au",
  "pbl.spamhaus.org",
  "phishing.rbl.msrbl.net",
  "plus.bondedsender.org",
  "pofon.foobar.hu",
  "postmaster.rfc-clueless.org",
  "probes.dnsbl.net.au",
  "problems.dnsbl.sorbs.net",
  "proxies.dnsbl.sorbs.net",
  "proxy.bl.gweep.ca",
  "proxy.block.transip.nl",
  "psbl.surriel.com",
  "public.sarbl.org",
  "query.bondedsender.org",
  "rbl.abuse.ro",
  "rbl.blockedservers.com",
  "rbl.choon.net",
  "rbl.dns-servicios.com",
  "rbl.efnet.org",
  "rbl.efnetrbl.org",
  "rbl.fasthosts.co.uk",
  "rbl.interserver.net",
  "rbl.iprange.net",
  "rbl.lugh.ch",
  "rbl.megarbl.net",
  "rbl.orbitrbl.com",
  "rbl.polarcomm.net",
  "rbl.rbldns.ru",
  "rbl.realtimeblacklist.com",
  "rbl.schulte.org",
  "rbl.spamlab.com",
  "rbl.talkactive.net",
  "rbl2.triumf.ca",
  "rdts.dnsbl.net.au",
  "recent.spam.dnsbl.sorbs.net",
  "red.uribl.com",
  "relays.bl.gweep.ca",
  "relays.bl.kundenserver.de",
  "relays.dnsbl.sorbs.net",
  "relays.nether.net",
  "rep.mailspike.net",
  "reputation-domain.rbl.scrolloutf1.com",
  "reputation-ip.rbl.scrolloutf1.com",
  "reputation-ns.rbl.scrolloutf1.com",
  "residential.block.transip.nl",
  "rf.senderbase.org",
  "rhsbl.rymsho.ru",
  "rhsbl.scientificspam.net",
  "rhsbl.sorbs.net",
  "rhsbl.zapbl.net",
  "ricn.dnsbl.net.au",
  "rmst.dnsbl.net.au",
  "rsbl.aupads.org",
  "sa-accredit.habeas.com",
  "safe.dnsbl.sorbs.net",
  "sbl-xbl.spamhaus.org",
  "sbl.nszones.com",
  "sbl.spamhaus.org",
  "short.fmb.la",
  "short.rbl.jp",
  "singlebl.spamgrouper.com",
  "singular.ttk.pte.hu",
  "smtp.dnsbl.sorbs.net",
  "socks.dnsbl.sorbs.net",
  "sohul.habeas.com",
  "spam.abuse.ch",
  "spam.dnsbl.anonmails.de",
  "spam.dnsbl.sorbs.net",
  "spam.pedantic.org",
  "spam.rbl.blockedservers.com",
  "spam.rbl.msrbl.net",
  "spam.spamrats.com",
  "spamguard.leadmon.net",
  "spamlist.or.kr",
  "spamrbl.imp.ch",
  "spamsources.fabel.dk",
  "spamtrap.drbl.drand.net",
  "srn.surgate.net",
  "srnblack.surgate.net",
  "st.technovision.dk",
  "stabl.rbl.webiron.net",
  "superblock.ascams.com",
  "swl.spamhaus.org",
  "t3direct.dnsbl.net.au",
  "tor.dan.me.uk",
  "tor.dnsbl.sectoor.de",
  "tor.efnet.org",
  "torexit.dan.me.uk",
  "torserver.tor.dnsbl.sectoor.de",
  "truncate.gbudb.net",
  "trusted.nether.net",
  "ubl.lashback.com",
  "ubl.nszones.com",
  "ubl.unsubscore.com",
  "unsure.nether.net",
  "uri.blacklist.woody.ch",
  "uribl.abuse.ro",
  "uribl.pofon.foobar.hu",
  "uribl.spameatingmonkey.net",
  "uribl.swinog.ch",
  "uribl.zeustracker.abuse.ch",
  "urired.spameatingmonkey.net",
  "url.rbl.jp",
  "urlsl.dnsbl.rjek.com",
  "v4.fullbogons.cymru.com",
  "virbl.dnsbl.bit.nl",
  "virus.rbl.jp",
  "virus.rbl.msrbl.net",
  "vote.drbl.caravan.ru",
  "vote.drbl.gremlin.ru",
  "vote.drbldf.dsbl.ru",
  "wadb.isipp.com",
  "wbl.triumf.ca",
  "web.dnsbl.sorbs.net",
  "web.rbl.msrbl.net",
  "white.uribl.com",
  "whitelist.sci.kun.nl",
  "whitelist.surriel.com",
  "whois.rfc-clueless.org",
  "wl.mailspike.net",
  "wl.nszones.com",
  "work.drbl.caravan.ru",
  "work.drbl.gremlin.ru",
  "work.drbldf.dsbl.ru",
  "wormrbl.imp.ch",
  "xbl.spamhaus.org",
  "z.mailspike.net",
  "zen.spamhaus.org",
  "zombie.dnsbl.sorbs.net"
]

####

queue = Queue.Queue()
debug = False
global on_blacklist
on_blacklist = []


class ThreadRBL(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            # Grab hosts from queue
            hostname, root_name = self.queue.get()
            check_host = "%s.%s" % (hostname, root_name)
            start_time = timeit.default_timer()
            try:
                check_addr = socket.gethostbyname(check_host)
            except socket.error:
                check_addr = None
            if check_addr is not None and "127.0.0." in check_addr:
                on_blacklist.append(root_name)

            elapsed = timeit.default_timer() - start_time
            # If debug option is set it prints the time it took to get an answer from each RBL
            if debug: print("It took %s seconds to get a response from the DNSBL %s" % (elapsed,root_name))

            # Signal queue that job is done
            self.queue.task_done()


def usage(argv0):
    print("%s -w <WARN level> -c <CRIT level> -h <hostname> [-d|--debug]" % argv0)
    print(" or")
    print("%s -w <WARN level> -c <CRIT level> -a <ip address> [-d|--debug]" % argv0)


def main(argv, environ):
    options, remainder = getopt.getopt(argv[1:],
                                       "w:c:h:a:d",
                                       ["warn=", "crit=", "host=", "address=","debug"])
    status = {'OK': 0, 'WARNING': 1, 'CRITICAL': 2, 'UNKNOWN': 3}
    host = None
    addr = None

    if len(options) > 4 or len(options) < 3:
        usage(argv[0])
        sys.exit(status['UNKNOWN'])

    for field, val in options:
        if field in ('-w', '--warn'):
            warn_limit = int(val)
        elif field in ('-c', '--crit'):
            crit_limit = int(val)
        elif field in ('-h', '--host'):
            host = val
        elif field in ('-a', '--address'):
            addr = val
        elif field in ('-d', '--debug'):
            global debug
            debug = True
        else:
            usage(argv[0])
            sys.exit(status['UNKNOWN'])

    if host and addr:
        print("ERROR: Cannot use both host and address. Please choose one.")
        sys.exit(status['UNKNOWN'])

    if host:
        try:
            addr = socket.gethostbyname(host)
        except:
            print("ERROR: Host '%s' not found - maybe try a FQDN?" % host)
            sys.exit(status['UNKNOWN'])

    if sys.version_info[0] >= 3:
        ip = ipaddress.ip_address(addr)
    else:
        ip = ipaddress.ip_address(unicode(addr))
    if (ip.version == 6):
        addr_exploded = ip.exploded
        check_name = '.'.join([c for c in addr_exploded if c != ':'])[::-1]
    else:
        addr_parts = addr.split('.')
        addr_parts.reverse()
        check_name = '.'.join(addr_parts)
    # Make host and addr the same thing to simplify output functions below
    host = addr

# ##### Start thread stuff

    # Spawn a pool of threads then pass them the queue
    for i in range(10):
        t = ThreadRBL(queue)
        t.setDaemon(True)
        t.start()

    # Populate the queue
    for blhost in serverlist:
        queue.put((check_name, blhost))

    # Wait for everything in the queue to be processed
    queue.join()

# ##### End thread stuff

# Create output
    if on_blacklist:
        output = '%s on %s blacklist(s): %s' % (
            host, len(on_blacklist), ', '.join(on_blacklist))
        # Status is CRITICAL
        if len(on_blacklist) >= crit_limit:
            print('CRITICAL: %s' % output)
            sys.exit(status['CRITICAL'])
        # Status is WARNING
        if len(on_blacklist) >= warn_limit:
            print('WARNING: %s' % output)
            sys.exit(status['WARNING'])
        else:
            # Status is OK and host is blacklisted
            print('OK: %s' % output)
            sys.exit(status['OK'])
    else:
        # Status is OK and host is not blacklisted
        print('OK: %s not on any known blacklists' % host)
        sys.exit(status['OK'])

if __name__ == "__main__":
    main(sys.argv, os.environ)
