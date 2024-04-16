# install arduino-cli
curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh | BINDIR=. sh
sudo mv arduino-cli /usr/local/bin/arduino-cli
arduino-cli core update-index
# install the library for RFID
arduino-cli lib install "SparkFun Simultaneous RFID Tag Reader Library"@1.1.1
# list boards
boards=$(arduino-cli board list)
if [$boards -eq "No boards found."]
then
	echo "No RFID readers connected"
else
	{
		read # skips headers
		while IFS=" " read -r Port Protocol Type BoardName
		do
    			echo "Installing Reader $Port"
			arduino-cli compile --fqbn arduino:avr:uno RFID_reader/firmware
			arduino-cli upload -p $Port --fqbn arduino:avr:uno RFID_reader/firmware
		done
	} <<< $boards
fi
