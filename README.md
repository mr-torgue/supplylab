# SupplyLab
SupplyLab is an effort to show the (lack of) security in RFID-based traceability systems in physical supply chains.
Traceability is known under many names, one which is called path authentication.
We noticed that path authentication solutions always remain theoretical and never include a physical implementation.
This gives rise to several questions. 
The main question is to determine the feasibility of such solutions.
The solutions might assume capabilities that current state-of-the-art components don't have.

Oar goals are threefold:
1. Provide a traceability solution from tag to back-end, so that everybody sees what happens
2. Show the impact of path authentication solutions
3. Show attacks (if there are any) in those path authentication solutions

# Hardware Requirements
Since we target traceability solutions that use UHF RFID technology, we do require the user to have at least 1 programmable RFID reader available.
We require the following components:
1. Arduino Uno R4 Wifi Board
2. SparkFun m6e nano RFID Shield
3. Raspberry pi (optional)
4. IoT sensor (optional)
5. UHF RFID tags
Raspberry pi can be replaced by any PC/laptop.
The IoT sensors are optional, they merely show the integration of heterogenous sources.
It is advised to have multiple RFID readers.

# Hardware Assembling
Follow the guides.

# Installation Scipts
install.sh sets everything up.
It installs Mosquitto mqtt broker and MQTTX.
It flushes firmware to the reader and installs arduino-cli.
Todo:
* automatically configure mqtt
* check for already installed dependencies
* IoT device installation script


# RFID Reader
Consists of the Reader firmware and Serial to MQTT python script.
The following still needs to be done for the python script:
* add multi-threading, 1 thread per RFID reader
* add logging, so that events get written to log files
* better parsing

For the reader firmware, the following needs to be done:
* add write to tag functionality
* read all fields instead of timestamp + EPC
