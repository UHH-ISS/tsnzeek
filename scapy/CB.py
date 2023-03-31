#!/usr/bin/env python3

# -----------------------------------------------------------
#
#  cb.py --- IEEE 802.1CB Frame Replication and Elimination for Reliability (FRER) support for Scapy
#
# (C) 2022 Robin Schenderlein, Hamburg, Germany
# Released under GNU Public License (GPL)
# email robin.schenderlein@studium.uni-hamburg.de
# -----------------------------------------------------------

# scapy.contrib.description = IEEE 802.1CB
# scapy.contrib.status = loads

import logging

from scapy.fields import ShortField
from scapy.layers.l2 import Dot1Q
from scapy.main import interact
from scapy.packet import Packet, bind_layers

logger = logging.getLogger("scapy")
logger.setLevel(logging.INFO)


class CB(Packet):
    name = "FRER"
    fields_desc = [ShortField("reserved", 0),
                   ShortField("sequence_nr", 0)]


bind_layers(Dot1Q, CB, type=0xf1c1)

if __name__ == "__main__":
    interact(mydict=globals(), mybanner="Test add-on TSN")
