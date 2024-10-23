# assumes that arduino-cli and all relevant libraries have been installed

while getopts d:s: flag
do
    case "${flag}" in
        s) scheme=${OPTARG};;
        d) data_dir=${OPTARG};;
    esac
done

# check if a valid scheme has been selected
case $scheme in
	scanner)
	    firmware_dir=reader/firmware/scheme_0_scanner
		;;
	stepauth)
	    firmware_dir=reader/firmware/scheme_1_stepauth
	    ;;
	baseline)
	    firmware_dir=reader/firmware/scheme_2_baseline
	    ;;
	tracker)
	    firmware_dir=reader/firmware/scheme_3_tracker
	    firmware_dir_2=reader/firmware/scheme_3_tracker_verify
	    ;;
	rfchain)
	    firmware_dir=reader/firmware/scheme_4_rfchain
	    ;;
	*)
	    echo "Unknown scheme!"
	    exit 1
	    ;;
esac

echo "Scheme: $scheme";
echo "Data dir: $data_dir"
echo "Firmware dir: $firmware_dir"

# start at reader 0
i=0
while true; do
	read -p "Setup next reader? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || break;
	# list boards
	boards=$(arduino-cli board list)
	if [ "$boards" = "No boards found." ]; then
		echo "No RFID readers connected"
	else
		{
			read # skips headers
			while IFS=" " read -r Port Protocol Type BoardName
			do
				echo "Copying $data_dir/reader_$i/scheme_settings.h to $firmware_dir"
				if cp $data_dir/reader_$i/scheme_settings.h $firmware_dir; then
					echo "Installing Reader $Port with Scheme $scheme and ID $i"
					arduino-cli compile --build-property  "build.extra_flags=\"-DuECC_ENABLE_VLI_API\"" --fqbn arduino:renesas_uno:unor4wifi $firmware_dir
					arduino-cli upload -p $Port --fqbn arduino:renesas_uno:unor4wifi $firmware_dir
					((i++))
				fi
			done
		} <<< $boards
	fi
done
# upload a manager in the case of tracker
if [ "$scheme" = tracker ]; then
	echo "Firmware dir for verification: $firmware_dir_2"
	read -p "Install tracker verifier? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1;
# list boards
	boards=$(arduino-cli board list)
	if [ "$boards" = "No boards found." ]; then
		echo "No RFID readers connected"
	else
		{
			read # skips headers
			while IFS=" " read -r Port Protocol Type BoardName
			do
				echo "Copying $data_dir/manager_*/scheme_settings.h to $firmware_dir_2"
				if cp $data_dir/manager_*/scheme_settings.h $firmware_dir_2; then
					echo "Installing Reader $Port with Scheme $scheme and ID $i"
					arduino-cli compile --build-property  "build.extra_flags=\"-DuECC_ENABLE_VLI_API\"" --fqbn arduino:renesas_uno:unor4wifi $firmware_dir_2
					arduino-cli upload -p $Port --fqbn arduino:renesas_uno:unor4wifi $firmware_dir_2
					((i++))
				fi
			done
		} <<< $boards
	fi
fi