'''
Usage : python3 rfid2mqtt.py [MQTT broker] [topic]

Finds all connected boards using arduino-cli
Spawns a new process for each board
'''

import sys
import serial 
import re
import threading
import json
import time
import subprocess
import paho.mqtt.publish as publish

from os.path import exists

'''
will keep polling the device and log output to a file
'''
def poll_RFID_reader(device, hostname, topic):
	with serial.Serial(device, 115200, timeout=0.5) as ser:
		ser.flushInput()
		ser.flushOutput()
		time.sleep(3)
		print(ser.readline())
		# input a first character to start reading		
		ser.write(b'y')		
		time.sleep(0.5)
		while True:
			# efficient and fast but not needed (https://stackoverflow.com/questions/676172/full-examples-of-using-pyserial-package)
			#bytesToRead = ser.inWaiting()
			#data = ser.read(bytesToRead).decode('UTF-8').strip()
			#if data != "":
			#	print("%s, %d" % (data, bytesToRead))

			# depends on timeout
			EPC = {}
			lines = ser.readlines()
			print("reading %d lines" % len(lines))
			for line in lines:
				line = line.decode('UTF-8')
				#matches = re.findall("rssi\[(\-\d*)\] freq\[(\d*)\] time\[(\d*)\] epc\[((?:[A-F0-9]{2} )*)\]\r\nSize of msg: (\d*)\r\n((?:[A-F0-9]{2} )*)\r\n(Bad CRC\r\n)?" , data)
				matches = re.findall("rssi\[(\-\d*)\] freq\[(\d*)\] time\[(\d*)\] epc\[((?:[A-F0-9]{2} )*)\]?" , line)
				for match in matches:
					if len(match) == 4 and match[3] not in EPC:
						EPC[match[3]] = {"EPC": match[3], "rssi": match[0], "freq": match[1], "time": match[2]}
					if len(match) < 6:
						print("not enough groups: corrupted data")
					elif len(match[5].replace(" ", "")) != int(match[4]) * 2:
						print("data and length mismatch: ignored")
					elif len(match) == 7 and match[6] == "Bad CRC\r\n":
						print("bad crc: ignored") 
					elif match[3] not in EPC:
						EPC[match[3]] = {"EPC": match[3], "rssi": match[0], "freq": match[1], "time": match[2], "size": match[4], "content": match[5]}

			print("found %d EPC's" % len(EPC))
			for epc in EPC:
				publish.single(topic, json.dumps(EPC[epc]), hostname=hostname)


if len(sys.argv) != 3:
	print("Usage : python3 rfid2mqtt.py [MQTT broker] [topic]")
else:
	hostname = sys.argv[1]
	topic = sys.argv[2]
	command_output = subprocess.run(["arduino-cli", "board", "list"], capture_output=True)
	output_lines = command_output.stdout.decode('UTF-8').strip().split("\n")
	if len(output_lines) > 1:
		# assumes there are no spaces in the device name
		devices = [output_lines[i].split(" ")[0] for i in range(1, len(output_lines))]
		for device in devices:
			if exists(device):
				# spawn a new daemon thread
				#t1 = threading.Thread(poll_RFID_reader, device, hostname, topic)
				#t1.daemon = True
				#t1.start()
				poll_RFID_reader(device, hostname, topic)
			else:
				print("Not a valid device")
	else:
		print("No RFID readers connected")
