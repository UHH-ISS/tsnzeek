# Scapy

Scapy layers to forge and send SRP and FRER frames.

## Layout

| Folder | Content |
| --- | --- |
| `layers/` | the protocol definitions: `cb.py` (FRER redundancy tag, class `CB`) and `srp.py` (enhanced SRP); started directly they open an interactive Scapy shell |
| `samples/` | frames to paste into that shell (`frer_sample`, `srp_sample`) and a gPTP capture (`ptpv2_vlan.pcap`) |
| `scripts/` | runnable senders: `gptp_sender.py` sends the frames of the capture, one per Enter; `attacks.py` is the original attack script (needs numpy), not updated for the new IDS, whose functions now carry the names of the rules that detect them (`frer_excess_copies()`, `srp_oversized_request()`, ...). The `tsn` commands of the [live demo](../tests/live/README.md) replace it |

The tests and the demo build their frames with `tests/gen_pcaps.py`, which uses the layers.

## Usage

Scapy needs root to send. Install it in the project's venv (`python3 -m venv .venv && .venv/bin/pip install scapy`) and start a layer, on the machine or Mininet host that should send the frames (`xterm h1` in the Mininet CLI):

```sh
sudo .venv/bin/python scapy/layers/srp.py
```

This will start up a Scapy interactive shell. In this shell, you can create frames and send them to other hosts in your network. Scapy can be used to create malformed frames. Therefore there is no mechanism to check if created frames are of valid form.

Copy and paste the content of one of the `sample` files into the Scapy shell. There seems to be a limit of 50 lines that can be inserted at once. So copy the contents in steps. With the `srp_sample`, you defined four ethernet packets. Two of them include the SRP TalkerEnhancedFirstValue message. The other two include the SRP ListenerEnhancedFirstValue. Each SRP frame comes as a minimal version without all optional fields and a version that includes all fields.
All packets are of the structure: `Ether \ Dot1Q \ SRP`. This structure is required to form valid packets. For more on packet structure, refer to the Scapy documentation.

Type `pkt.show()` to inspect one of the created packets. Replace `pkt` with the name of the packet you want to inspect. This will show the structure and the values stored inside the packet. Some of the displayed fields will be uninitialized. To show the final assembled packet use `pkt.show2()`. To get a hex view on the packet use `hexdump(pkt)` and for a raw byte view `raw(pkt)`.

To send a frame, only the definition of a packet is required. Send the packet with `sendp(pkt, iface="h1-eth0")`.

To create your own SRP frame, fill the `tlvlist` parameter of `SRP()` with a list of Type Length Value (tlv) groups. The data does not have to be structured like in the sample.
