#!/usr/bin/python
# Copyright(C) 2013 Open Information Security Foundation

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.


import argparse
import glob

from process_pcap import *


SOCKET_PATH = "/var/run/suricata/suricata-command.socket"
sc = ProcessPcap(SOCKET_PATH)
try:
    sc.connect()
except SuricataNetException, err:
    print "Unable to connect to socket %s: %s" % (SOCKET_PATH, err)
    sys.exit(1)
except SuricataReturnException, err:
    print "Unable to negotiate version with server: %s" % (err)
    sys.exit(1)
try:
    pcap_files=glob.glob(sys.argv[1]+'*.pcap')
    for f in pcap_files:
        sc.send_pcap(f, sys.argv[2])
except SuricataNetException, err:
    print "Communication error: %s" % (err)
    sys.exit(1)
except SuricataReturnException, err:
    print "Invalid return from server: %s" % (err)
    sys.exit(1)

print "[+] Quit command client"

sc.close()
