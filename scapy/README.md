# Scapy

Scapy is used in this project to forge and send SRP and FRER frames.

# Startup

Scapy sends the frames from the machine it runs on. Ensure that you are on the device that should originate the frames. Start the Scapy scripts like any other python script or start it directly with:
```sh
source $HOME/env/bin/activate
esudo python3 $HOME/scapy/CB.py
```

# Usage example

Ensure that mininet is up and running. SSH into one of the hosts, load the environment and start Scapy:
```sh
ssh 10.0.0.2
source $HOME/env/bin/activate
esudo python3 $HOME/scapy/SRP.py
```

This will start up a Scapy interactive shell. In this shell, you can create frames and send them to other hosts in your network. Scapy can be used to create malformed frames. Therefore there is no mechanism to check if created frames are of valid form.

Copy and paste the content of one of the `sample` files into the Scapy shell. There seems to be a limit of 50 lines that can be inserted at once. So copy the contents in steps. With the `srp_sample`, you defined four ethernet packets. Two of them include the SRP TalkerEnhancedFirstValue message. The other two include the SRP ListenerEnhancedFirstValue. Each SRP frame comes as a minimal version without all optional fields and a version that includes all fields.
All packets are of the structure: `Ether \ Dot1Q \ SRP`. This structure is required to form valid packets. For more on packet structure, refer to the Scapy documentation.

Type `pkt.show()` to inspect one of the created packets. Replace `pkt` with the name of the packet you want to inspect. This will show the structure and the values stored inside the packet. Some of the displayed fields will be uninitialized. To show the final assembled packet use `pkt.show2()`. To get a hex view on the packet use `hexdump(pkt)` and for a raw byte view `raw(pkt)`.

To send a frame, only the definition of a packet is required. Send the packet with `sendp(pkt, iface="h2-eth0")`.

To create your own SRP frame, fill the `tlvlist` parameter of `SRP()` with a list of Type Length Value (tlv) groups. The data does not have to be structured like in the sample.
