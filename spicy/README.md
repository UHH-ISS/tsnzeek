# Spicy

Spicy is used in this project to parse SRP and FRER frames and make the packet data available to Zeek. To run Spicy with Zeek, install the Spicy Plugin first.

# File functionality

`FRER.spicy`, `SRP.spicy`, and `PTP.spicy` hold the grammar for FRER, SRP, and PTP frames, respectively. The public types are the entry points to the grammar.

`Zeek_TSN.spicy` prepares the type conversion from Spicy data types to Zeek data types. It might also include other functionality addressing information exchange between Spicy and Zeek.

`TSN.evt` adds the packet analyzer and hooks on the spicy entry points that execute Zeek events. The hooks get triggered on successful completion of the grammar. 

`TSN.hlto` is the compiled grammar from the files listed above.

`TSN.zeek` registers the packet analyzer in Zeek.

`main.zeek` adds Zeek events and their data structure. It also activates the Zeek Broker.

# Startup

For spicy as standalone software, there is nothing other than installation required to use Spice. To use Spicy with Zeek, the Spicy Plugin for Zeek must be installed.

# Usage example

To test a grammar, create a frame with Scapy and then analyze its raw byte representation with Spicy:

```sh
printf '\x0f\n\x02\x08\x00\x00\x00\x00\x00\x00\x00\x00\x10\x05\x11\x03\x00\x00\x00' | HILTI_DEBUG=spicy spicy-driver -d $HOME/spicy/spicy-analyzer/SRP.spicy
```
Here we created a frame without the Ether and VLAN layer using `listenerEnhancedFirstValueMinimal` from the `srp_sample`. `spicy-driver` will compile the grammar and then parse the frame. If it does not throw any error messages, then the frame got successfully parsed. Output like the following is expected:

```sh
SRPFrame recieved
no endStationInterfaces
no userToNetworkRequirements
no interfaceCapabilities
Done
```

To show the actual values Spicy extracted from the frame, add a hook to `SRPFrame` in the grammar:
```sh
on %done { print "Done";  print self; }
```

This will add something like the following depending on the input of the parser:
```sh
[$tlvType=SrpTlvTypeCode::Listener, $talkerEnhanced_FirstValue=(not set), $listenerEnhanced_FirstValue=[$listener=[$talkerLen=10, $streamID=[$macAddress=b"\x00\x00\x00\x00\x00\x00", $uniqueID=0], $endStationInterfaces=(not set), $userToNetworkRequirements=(not set), $interfaceCapabilities=(not set)], $status=[$code=SrpTlvTypeCode::Status, $statusLen=5, $statusInfo=[$talkerStatus=EnumTalkerStatus::NONE, $listenerStatus=EnumListenerStatus::NONE, $failureCode=0], $accumulatedLatency=(not set), $tlvT1=b"", $failedInterfaces=(not set), $interfaceConfigurations=(not set), $tlvT2=(not set)]]]
```

Spicy can be used on its own. However, for Zeek to use Spicy, compiled grammar is required. Compile a grammar with:

```sh
source $HOME/env/bin/activate
spicyz Zeek_TSN.spicy FRER.spicy SRP.spicy PTP.spicy TSN.evt -o TSN.hlto
```
This creates `TSN.hlto` which can be used by Zeek.
