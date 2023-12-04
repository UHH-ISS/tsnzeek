# TSNZeek: An Open-source Intrusion Detection System for IEEE 802.1 Time-sensitive Networking

This repository includes files, instructions, and examples to recognize attacks against IEEE 802.1Qcc and IEEE 802.1CB. Samples and further instructions for testing can be found under individual subfolders. 

You can follow this guideline to install the required versions of Zeek-related components to eventually run TSNZeek.

## Project Overview

(Under construction)

### Data Plane

Under `spicy` folder, you can find the grammar definition files for each protocol, i.e., .1Qcc SRP and .1CB FRER.

### Control Plane

Under `zeek` folder, you can find the attack detection script for each attack defined under scapy-attack.py script.

### Management Plane

To be implemented to configure the existing intrusion detection function.

## Prerequisites and Environment

### Dependencies

TSNZeek requires installing the core components (i) Zeek (v4.1.1), (ii) spicy (v1.4.0), (iii) spicy-plugin (v1.3.1), and (iv) Zeek broker (commit 8493e17). Besides, for testing and simulating a TSN environment, you can also install (v) mininet and (vi) scapy. To install the dependencies of the core components, you can run (in a Debian-based system):
```sh
sudo apt-get install cmake libpcap-dev libssl-dev swig
pip install numpy BitVector
```
Besides, the broker (iv) requires Python 3.9 (instead of a later version). You can compile it from the source code following [this guideline](https://linuxize.com/post/how-to-install-python-3-9-on-debian-10/). Note that this compilation requires to enable linking by setting the flag `--enable-shared` on the configuration script. Then, you can whether set your default Python version to 3.9 or use the Python 3.9 binary explicitly during the installationg of the broker (iv).

### Environment

Several components in the TSNZeek environment (e.g., mininet and scapy) requires root permissions, and they should access to the installed Zeek components within `sudo` environment. The following command helps you to import the necessary environment variable `PATH` into the  `sudo` environment:
```sh
alias esudo='sudo -E env PATH=$PATH:$(sudo printenv PATH)'
```
You can also set another environmental varible to indicate the full path of this project following the command:
```sh
export TSNZEEK_PATH=<the-full-path-of-this-project>
```
It is recommended to fetch and install all core components (i-iv) under the same folder, e.g., `/usr/local/src`, for an easier installation.

## Installation

### Zeek

Zeek (i) is an open-source security monitoring and intrusion detection tool. TSNZeek extends the Zeek v4.1.1 with further packet processing and intrusion detection functions for IEEE TSN protocols. Next, you will install the respective version of Zeek. Note that, depending on the installation path you select, it may require root privileges (e.g., `/usr/local/src` folder below). Accordingly, you can run the following commands with `sudo` or `esudo`, or simply switch to `su` environment:
```sh
cd /usr/local/src
git clone --recursive https://github.com/zeek/zeek
cd zeek
git checkout v4.1.1
git submodule update --recursive
./configure --disable-python
make -j
make install -j
```

Lastly, Zeek binary should be added to the environment variable `PATH` with the following command:
```sh
export PATH="$PATH:/usr/local/zeek/bin"
```

### spicy

spicy enables developing a new parser grammar for Zeek. This grammer then helps to parse the extended Ethernet frames for IEEE TSN protocols. You should install (a) the main parser and (b) the Zeek plugin, separately.

#### Grammmar

The following commands help to install the main parser spicy v1.4.0, which TSNZeek particularly requires:
```sh
git clone --recursive https://github.com/zeek/spicy
git checkout v1.4.0
git submodule update --recursive
./configure
make -j
sudo make install
```
#### Plugin

Zeek requires a plugin to use spicy parsers. The following commands help to install the plugin v1.3.7, which TSNZeek particularly requires. Note that you should set the path prefix for the spicy below, depending on where you cloned and installed the spicy project (e.g., `/usr/local/src/` in the command below).

```sh
git clone https://github.com/zeek/spicy-plugin.git
cd spicy-plugin/
git checkout v1.3.7
git submodule update --recursive
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local/src/spicy/ ..
make -j
cd ../
make -C tests
make -C build install
```

Lastly, spicy binary should be added to the environment variable `PATH` with the following command (depending on where you install it):
```sh
export PATH="$PATH:/usr/local/src/spicy/bin"
```
### Broker

The broker helps to export the parsed network packets (i.e., Ethernet frames) to any external modules (e.g., an intrusion detection module) for further processing. To install the broker version that TSNZeek requires, you can follow the commands below:

```sh
git clone --recursive https://github.com/zeek/broker.git
cd broker
git checkout 8493e17
git submodule update --recursive
./configure --prefix=$TSNZEEK_PATH/broker --python-prefix=$(python -c 'import sys; print(sys.exec_prefix)')
make install
```
Note that if Python 3.9 is not the main Python version on your system, you need to set the flag `--with-python=<full-path-to-python3.9-binary>` while running the configuration script.

Lastly, you can test the broker installation via:
```sh
python -c 'import broker; print(broker.__file__)'
```

### Other Components

#### Scapy

Scapy is a Python-based networking framework to create packets for several network protocols. You can use it to forge FRER and SRP frames to test TSNZeek via the scripts in this project. The following command simply installs it:

```sh
pip install --pre scapy[basic]
```

#### Mininet

Mininet is a network emulator and the native test environment for Zeek. You can install it via:
```sh
cd /usr/local/src/
git clone git://github.com/mininet/mininet
cd mininet
git checkout 2.3.0
PYTHON=$HOME/env/bin/python3 ./util/install.sh -s <installation-path>/mininet -n
```
For further configuration and examples of Mininet, please refer to [its original webpage](https://mininet.org/).

## (Test) Configuration

1. **Testing the grammer** files via `spicy` using the following command:
```sh
echo '\x0f\n\x02\x08\x00\x00\x00\x00\x00\x00\x00\x00\x10\x05\x11\x03\x00\x00\x00' | HILTI_DEBUG=spicy spicy-driver -d $TSNZEEK_PATH/spicy/spicy-analyzer/SRP.spicy
```
This should not give any errors.

2. **Compiling the new TSN grammer** using spicy(-plugin) using the following command:
```sh
cd $TSNZEEK_PATH/spicy/spicy-analyzer
spicyz Zeek_TSN.spicy FRER.spicy SRP.spicy TSN.evt -o TSN.hlto
```

3. **Initiating data plane** by attaching TSNZeek instance (equipped with the generated grammer) to one of your network interfaces using the following command:
```sh
esudo zeek -C $TSNZEEK_PATH/spicy/spicy-analyzer/TSN.hlto $TSNZEEK_PATH/spicy/spicy-analyzer/TSN.zeek $TSNZEEK_PATH/spicy/scripts -i <your-eth-interface> LogAscii::use_json=T Spicy::enable_print=T
```
TSNZeek is now able to monitor inbound traffic on the respective interface.

4. **Testing data plane** by sending packets to the interface that TSNZeek is attached via `scapy`:
```sh
esudo python3 $TSNZEEK_PATH/scapy/CB.py
>> frer_packet = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / Dot1Q(vlan=150) / CB(sequence_nr=1)
>> sendp(frer_packet, iface="<your-eth-interface>")
```
After this, you should be able to see a log file named `cb.log` that contains the content of the processed p802.1CB frames. 

5. **Initiating control plane** via the following command:
```sh
esudo python3 $TSNZEEK_PATH/zeek/attack-detection.py
```
This connects the IDS to the broker by subscribing to FRER and SRP packets so that data plane can forward the processed frames to the IDS module. 

