# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
# -----------------------------------------------------------
#
#  topo.py
#
# The test network of TSNZeek:
#
#        h1 (talker, ptp4l master) --+
#   attacker -------------------------+-- s1 --+-- h2 (receiver, ptp4l client)
#                                     |
#                                     +-- mon  (Zeek and the IDS; sees every frame once)
#
# The MAC addresses match those of tests/gen_pcaps.py (h1 = ...:01, h2 = ...:02), so the frames of the
# offline tests can be sent unchanged.
#
# Why s1 can be a user-space hub (userhub.py) instead of OVS: real ptp4l does not survive a kernel switch.
# It asks for a software TX time stamp, and every further virtual-interface hop of the same buffer (a switch's last
# output, or a flood) adds another stamp to ptp4l's socket. ptp4l reads that leftover as an error ("error on fda[0]:
# Success"), the port goes FAULTY every ~2 s and no Announce or Sync is ever sent. A hub in user space sends each frame
# again as a new buffer, so ptp4l sees one stamp; it also needs no mirror, and link-local gPTP frames just work.
# OVS (mirror to mon, forward-bpdu) stays the default for crafted traffic, which has no time stamps to lose.
#
# Mininet needs root and the system Python: `sudo python3 tests/live/topo.py [--hub]` opens the Mininet CLI.
# -----------------------------------------------------------

import os
import subprocess
import sys

from mininet.net import Mininet
from mininet.node import OVSBridge, Switch

HUB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "userhub.py")

HOSTS = {
    # name: (MAC, IP)
    "h1": ("00:00:00:00:00:01", "10.0.0.1/24"),
    "attacker": ("00:00:00:00:00:66", "10.0.0.66/24"),
    "h2": ("00:00:00:00:00:02", "10.0.0.2/24"),
    "mon": ("00:00:00:00:00:99", "10.0.0.99/24"),
}

class UserHub(Switch):
    """The switch as a hub process in user space; see the top of this file for why ptp4l needs it."""

    def __init__(self, name, **params):
        super().__init__(name, **params)
        self.proc = None

    def start(self, controllers):
        ports = [intf.name for intf in self.intfList() if intf.name != "lo"]
        for port in ports:
            self.cmd(f"ip link set {port} up")
        self.proc = self.popen([sys.executable, HUB] + ports)

    def stop(self, deleteIntfs=True):
        if self.proc:
            self.proc.terminate()
            self.proc.wait()
        super().stop(deleteIntfs)

    def connected(self):
        return True


def build_net(hub=False):
    """Create (not start) the network. With hub=True the switch is a user-space hub instead of OVS."""
    net = Mininet(controller=None, switch=UserHub if hub else OVSBridge, autoSetMacs=False, waitConnected=True)
    s1 = net.addSwitch("s1")
    for name, (mac, ip) in HOSTS.items():
        net.addLink(net.addHost(name, mac=mac, ip=ip), s1)
    return net


def switch_port(net, host):
    """Name of the s1 interface that the link to `host` ends in."""
    link = net.linksBetween(net["s1"], net[host])[0]
    return link.intf1.name if link.intf1.node.name == "s1" else link.intf2.name


def ovs(*args):
    subprocess.run(["ovs-vsctl", *args], check=True)


def start_monitoring(net):
    """Mirror every port of s1 to mon-eth0, and let s1 forward link-local multicast.

    gPTP (802.1AS) sends to the link-local address 01:80:c2:00:00:0e. A bridge does not forward these frames, and
    OVS drops them in its NORMAL processing unless forward-bpdu is set; with it, ptp4l on h1 and h2 can talk to each
    other and the mirror copies the frames to mon like any other.
    """
    if isinstance(net["s1"], UserHub):
        return                          # the hub sends every frame to mon like to any other port
    port = switch_port(net, "mon")
    ovs("--", "--id=@p", "get", "Port", port, "--", "--id=@m", "create", "Mirror", "name=mon",
        "select-all=true", "output-port=@p", "--", "set", "Bridge", "s1", "mirrors=@m")
    ovs("set", "Bridge", "s1", "other_config:forward-bpdu=true")


if __name__ == "__main__":
    from mininet.cli import CLI
    from mininet.log import setLogLevel

    setLogLevel("info")
    network = build_net(hub="--hub" in sys.argv)
    network.start()
    start_monitoring(network)
    CLI(network)
    network.stop()
