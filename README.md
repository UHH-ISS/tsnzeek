### TSNZeek: An Open-source Intrusion Detection System for IEEE 802.1 Time-sensitive Networking

This repository includes files, instructions, and examples to recognize attacks against IEEE 802.1Qcc and IEEE 802.1CB. Samples and further instructions for testing can be found in each software folder.

note: The versions mentioned below are updated and should be changed in this guideline as well.

# Environment

Scapy and Mininet need root to run. To avoid problems with `PATH`, create an alias for `sudo` that combines the users `PATH` and the path used by `root`. Use the alias to run Scapy and Mininet later.

```sh
alias esudo='sudo -E env PATH=$PATH:$(sudo printenv PATH)'
```

# Zeek

Zeek is used as the IDS to analyze frames and to detect attacks.

## Installation

Install Zeek 4.1.1 by following [these](https://docs.zeek.org/en/master/install.html) instructions or copy the lines below to build Zeek manually. If you run multiple instances of Zeek, change the install path with `./configure  --prefix=/usr/local/zeek-4.1.1`. If you do not constantly hop between versions of Zeek, you can also change the prefix to '/usr/local'. This will put the Zeek binaries under `/usr/local/bin`, making changes to `PATH` unnecessary.
Writing and modifying files in `/usr/local` requires root privileges. Consider using `su` during the installation process.

```sh
cd /usr/local/src
git clone --recursive https://github.com/zeek/zeek
cd zeek
git checkout v4.1.1
git submodule update --recursive
./configure
make
make install
```

Depending on the way chosen to install Zeek, it needs to be added to `PATH`.
```sh
export PATH="$PATH:/usr/local/zeek/bin"
```
Other solutions to run Zeek with root could include adding Zeeks installation path to `secure_path`:
Type `sudo visudo`, enable `secure_path` and add `:/usr/local/zeek/bin/` to `secure_path`.

Zeek version 4.2.0 introduces some braking changes. The Zeek extension has not been tested with Zeek 4.2.0. 

## Zeek Plugin

This plugin is not required anymore. It can be compiled to add a Zeek Plugin. It does not include much functionality.
The documentation for this plugin is in its own [repositiory](https://git.informatik.uni-hamburg.de/5schende/zeek-tsn-plugin).


## Spicy

Spicy is a parser for grammar. It is used to develop and test the created grammar.

### Installation
```sh
git clone --recursive https://github.com/zeek/spicy
git checkout v1.3.0
git submodule update --recursive
./configure && make
sudo make install
```

### Spicy Plugin Installation

The Spicy plugin for Zeek makes Spicy parsers accessible to Zeek.

### Installation

```sh
git clone https://github.com/zeek/spicy-plugin.git
cd spicy-plugin/
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local/spicy .. && make -j
make -C tests
esudo make -C build install
```

Add `/usr/local/spicy/bin` to `PATH`.

## Zeek Broker

The Zeek Broker is used to transfer data to a python script that handles some logic for detecting attacks.

### Installation

Python can not import the broker for some reason, which the Zeek install script should install. Therefore install the broker into the python virtual environment. Ensure the virtual environment is loaded.

```sh
git clone --recursive https://github.com/zeek/broker.git
cd broker
git checkout 8493e17
git submodule update --recursive
./configure --prefix=$THESIS/broker --python-prefix=$(python -c 'import sys; print(sys.exec_prefix)')
make install
```

`8493e17` is the commit id used for the broker repository by Zeek 4.1.1.
Test successful install with the following command and see if the path fits your requirements.
```sh
python -c 'import broker; print(broker.__file__)'
```

# Scapy

Scapy is used in this project to forge and send SRP and FRER frames.

## Installation

Install scapy with the following lines:

```sh
source $HOME/env/bin/activate
pip install --pre scapy[basic]
```
Optionally make the script executable by executing `chmod u+x CB.py`.

# Mininet

Mininet creates the network over which the frames get sent by emulating network components.

## Installation

Install mininet into the previously created python virtual environment.
```sh
source $HOME/env/bin/activate
cd /usr/local/src/
git clone git://github.com/mininet/mininet
cd mininet
git checkout 2.3.0
```
For debian sytems using python3 the install scipt is wonky. For a quick fix change line 176 of `mininet/util/install.sh` to `pf=pyflakes3`.
Continue installation with:
```sh
sudo PYTHON=$HOME/env/bin/python3 ./util/install.sh -s $HOME/mininet -n
```

You can start mininet with `esudo mn`. 

To connect to the created hosts, you can use ssh. For convenience add your public ssh key to `authorized_keys`
```sh
cat .ssh/id_rsa.pub >> .ssh/authorized_keys
```
