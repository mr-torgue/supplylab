# supplylab
Contains all the code and installation scripts to set up a traceability system.

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