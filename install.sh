# Installs the following:
# 1. 
#
#=============== READER ===============#
# install arduino-cli
curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh | sh
# install the library for RFID
arduino-cli install SparkFun Simultaneous RFID Tag Reader Library@1.1.1
# list boards
arduino-cli board list
if no boards detected
# compile and install for all boards
for i in ();
do
	arduino-cli compile --fqbn arduino:samd:mkr1000 MyFirstSketch
	arduino-cli upload -p /dev/ttyACM0 --fqbn arduino:samd:mkr1000 MyFirstSketch
done

#============= IoT DEVICE =============#
# configure wifi
# configure mqtt topics

#============== BACK-END ==============#
# install MQTT
# 
