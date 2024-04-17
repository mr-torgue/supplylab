'''
Install dependencies:
1. apt install python3-serial python3-paho-mqtt
'''


import serial 
import re
import json
import paho.mqtt.publish as publish

def poll_RFID_reader():
	with serial.Serial(device, 115200, timeout=0.8) as ser:
		# read 10000 bytes and split
		data = ser.read(10000).decode("utf-8") 
		print(data)
		EPC = {}
		#matches = re.findall("rssi\[(\-\d*)\] freq\[(\d*)\] time\[(\d*)\] epc\[((?:[A-F0-9]{2} )*)\]\r\nSize of msg: (\d*)\r\n((?:[A-F0-9]{2} )*)\r\n(Bad CRC\r\n)?" , data)
		matches = re.findall("rssi\[(\-\d*)\] freq\[(\d*)\] time\[(\d*)\] epc\[((?:[A-F0-9]{2} )*)\]?" , data)
		for match in matches:
			print(match)
			print(match[1])
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

		print(len(EPC))
		for epc in EPC:
			publish.single("test", json.dumps(EPC[epc]), hostname="localhost")

device = input('Specify serial device(/dev/ttyUSB0) (use arduino-cli board list)')
x = input('Press any key to read (q to quit)')
while x != 'q':
	poll_RFID_reader()
	x = input('Press any key to read (q to quit)') 
