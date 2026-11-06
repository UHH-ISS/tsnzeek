# Frames

Scapy layers to forge and send SRP and FRER frames.

## Layout

| Folder | Content |
| --- | --- |
| `layers/` | the protocol definitions: `frer.py` (FRER redundancy tag, class `FRER`), `srp.py` (enhanced SRP) and `ptp.py` (the PTP / gPTP header, and the helpers for Announce bodies and TLVs); started directly they open an interactive Scapy shell |
| `samples/` | example captures: `frer.pcap`, `ptp.pcap`, `srp_talker.pcap`, `srp_listener.pcap` (made by `scripts/make_samples.py`) and a gPTP capture, `ptpv2_vlan.pcap` |
| `scripts/` | `pcap_sender.py <pcap> [interface]` sends the frames of a capture, one per Enter (`pcap_sender.py frer`, `srp_talker`, `ptpv2_vlan`, ...); `make_samples.py` rewrites the sample captures; `attacks.py` is the attack script (needs numpy), not updated for the new IDS, whose functions now carry the names of the rules that detect them (`frer_excess_copies()`, `srp_oversized_request()`, ...). The `tsn` commands of the [live demo](../tests/live/README.md) replace it |

The tests and the demo build their frames with `tests/gen_pcaps.py`, which uses the layers.

## Usage

Scapy needs root to send. Install it in the project's venv (`python3 -m venv .venv && .venv/bin/pip install scapy`) and start a layer, on the machine or Mininet host that should send the frames (`xterm h1` in the Mininet CLI):

```sh
sudo .venv/bin/python frames/layers/srp.py
```

This will start up a Scapy interactive shell. In this shell, you can create frames and send them to other hosts in your network. Scapy can be used to create malformed frames. Therefore there is no mechanism to check if created frames are of valid form.

Build the frames in this shell, or send the sample captures with `pcap_sender.py` (`scripts/make_samples.py` shows how they are built: `Ether / Dot1Q / SRP` or `Ether / Dot1Q / FRER`; `srp_talker.pcap` and `srp_listener.pcap` each hold a minimal frame without the optional fields and a complete one). This structure is required to form valid packets. For more on packet structure, refer to the Scapy documentation.

Type `pkt.show()` to inspect one of the created packets. Replace `pkt` with the name of the packet you want to inspect. This will show the structure and the values stored inside the packet. Some of the displayed fields will be uninitialized. To show the final assembled packet use `pkt.show2()`. To get a hex view on the packet use `hexdump(pkt)` and for a raw byte view `raw(pkt)`.

To send a frame, only the definition of a packet is required. Send the packet with `sendp(pkt, iface="h1-eth0")`.

To create your own SRP frame, fill the `tlvlist` parameter of `SRP()` with a list of Type Length Value (tlv) groups. The data does not have to be structured like in the samples.
