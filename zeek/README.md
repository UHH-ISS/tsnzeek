# Zeek

Zeek is used in this project to analyze frames and to flag them if they seem to be malicious.

# Startup

Start up Zeek by:

```sh
source $HOME/env/bin/activate
esudo zeek -C $HOME/spicy/spicy-analyzer/TSN.hlto $HOME/spicy/spicy-analyzer/TSN.zeek $HOME/spicy/scripts -i s1-eth1 LogAscii::use_json=T Spicy::enable_print=T
```
`Spicy::enable_print=T` allows print statements in Spicy files to be executed. `LogAscii::use_json=T` writes all created logs in a `.json` format. These logs can be read with `jq`. Both options are not required.

# Usage example

Ensure that a mininet instance is running and that one of the created host runs a Scapy instance. Start up Zeek. To see Zeek in action create a packet in Scapy and send it to another host in  the network. Make sure that Zeek listens to an interface thats on the path the frame takes through the network. When Zeek is ready it will print something like `Zeek init 1 fired`. When a frame gets processed, Information about that frame will be written to the console. See the example output below:

```sh
Zeek init 1 fired
SRPFrame recieved
no iface config ieee802MacAddresses
no iface config ieee802VlanTag
no iface config ipv4Tuple
no iface config ipv6Tuple
Done
[talker=[streamID=[macAddress=\x00\x00\x00\x00\x00\x00, uniqueID=0], streamRank=1, endStationInterfaces=[[macAddress=\x00\x00\x00\x00\x00\x00, interfaceName=thisIsAnInterfaceName], [macAddress=\x00\x00\x00\x00\x00\x00, interfaceName=thisIsAnotherInterfaceName]], dataFrameSpecification=[ieee802MacAddresses=[destinationMacAddress=\x00\x00\x00\x00\x00\x00, sourceMacAddress=\x00\x00\x00\x00\x00\x00], ieee802VlanTag=[priorityCodePoint=0, vlanId=0], ipv4Tuple=[sourceIpAddress=0.0.0.0, destinationIpAddress=0.0.0.0, dscp=0, protocol=0, sourcePort=0, destinationPort=0], ipv4Tuple=[sourceIpAddress=::, destinationIpAddress=::, dscp=0, protocol=0, sourcePort=0, destinationPort=0]], trafficSpecification=[intervalNumerator=0, intervalDenominator=1, maxFramesPerInterval=0, maxFrameSize=0, transmissionSelection=0], tSpecTimeAware=[earliestTransmitOffset=0, latestTransmitOffset=0, jitter=0], userToNetworkRequirements=[numSeamlessTrees=12, maxLatency=13], interfaceCapabilities=[vlanTagCapable=1, numITL=2, numSTL=2, cbStreamIdenTypeList=[1, 2], cbSequenceTypeList=[3, 4]]], status=[statusInfo=[talkerStatus=SRP::EnumTalkerStatus_NONE, listenerStatus=SRP::EnumListenerStatus_NONE, failureCode=0], accumulatedLatency=0, interfaceConfigurations=[[interfaceID=[macAddress=\x00\x00\x00\x00\x00\x00, interfaceName=thisIsAnInterfaceName], ieee802MacAddresses=<uninitialized>, ieee802VlanTag=<uninitialized>, ipv4Tuple=<uninitialized>, ipv6Tuple=<uninitialized>, timeAwareOffset=55]], failedInterfaces=[[macAddress=\x00\x00\x00\x00\x00\x00, interfaceName=thisIsAnInterfaceName], [macAddress=\x00\x00\x00\x00\x00\x00, interfaceName=thisIsAnotherInterfaceName]]]]
```

The data extracted from the frame will then be published by the Zeek Broker.