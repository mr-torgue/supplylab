Contains the firmware and scripts for the readers.
There are four scripts, one for each step of a path authentication solution: reader setup, tag initialization, tag update, and tag verification.
Reader setup and tag initialization are always done by executing the scipt.
It generates a tag object which we can use to verify if our scheme is working.
This means that the executioner of the scripts is the manager/issuer.
The tag update and verification schemes are there for debugging purposes.
In practice, the reader firmware takes care of updating and verifying tag secrets.
The supported schemes are stored in the schems directory.

# Generic Setup
Assume we have 11 readers.
We need one reader to act as a generic reader write.
This means that this reader is responsible for writing the tag secret into the tag.
The other 10 readers are running 


# generate_reader_configs.py [-h] -n NR_READERS -m MODE -d DIR [-p PATHFILE]
Requires the iser to pick a scheme using '-m', the number of readers '-n', and an output directory '-d'.
Generates the initial key material according to the selected scheme.
It generates a json file called 'keyfile.json'. 
This file contains all sensitive information and should not be shared!
For every reader a header file 'settings.h' is generated.
This header file is used by the firmware.

# generate_tag_secret.py [-h] -f KEYFILE -m MODE -p PATH [PATH ...] -t TAG
Generates the tag secret and writes it to a virtual tag specified by 't'.
It needs keyfile.json to generate a proper secret.
Make sure that you use the same mode for both generation scripts!
Some files encode the path into the tag secret, so you might need to specify a path.

# update_tag.py [-h] -f KEYFILE -m MODE -r READER -t TAG
Takes as input a keyfile, mode, and a tag.
Updates the tag secret according to the mode and writes the new secret to the virtual tag.

# verify_tag.py [-h] -f KEYFILE -m MODE -t TAG
Verifies the tag secret of tag '-t' according to the specified mode.

# firmware
The firmware is responsible for the tag update and tag verification.
