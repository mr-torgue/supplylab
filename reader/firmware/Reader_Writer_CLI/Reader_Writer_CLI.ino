/*
Date: 25-04-2024
Author: Folmer Heikamp
Board: Arduino Uno R4 Wifi
Requires:  UHF m6e nano shield

The GENERIC UHF RFID READER AND WRITER is an RFID reader and writer for UHF Gen2 tags.
It uses the SparkFun Simultaneous RFID Tag Reader Library, modified with support for filters.
It tries to mimick the functionalities offered by the Universal Reader Assistant.
Currently, the GENERIC UHF RFID READER AND WRITER offers the following functionality:
1. Reading a single random tag
2. Reading multiple tags with or withour a EPC filter
3. Inspecting the tag content for a given EPC
4. Writing to tag (EPC and Data) with or without EPC filter
Note that not all capabilities of the MercuryAPI are implemented in the SparkFun library.
So, functionality like locking a tag requires changes to the library.
*/

#include <types.h>
#include <SparkFun_UHF_RFID_Reader.h>

RFID nano;

void setup()
{
  Serial.begin(115200);

  while (!Serial);
  Serial.println();
  Serial.println("Initializing...");

  if (setupNano(115200) == false) //Configure nano to run at 38400bps
  {
    Serial.println("Module failed to respond. Please check wiring.");
    while (1); //Freeze!
  }
  Serial.println(F("----------------------------------------"));
  Serial.println(F("|  GENERIC UHF READER AND WRITER V1.0  |"));
  Serial.println(F("----------------------------------------"));
  Serial.println(F("Select one of the following options:"));
  Serial.println(F(" (1) Read Random Tag EPC"));
  Serial.println(F(" (2) Read Tag EPCs"));
  Serial.println(F(" (3) Continuous Read With Timeout"));
  Serial.println(F(" (4) Inspect Tag"));
  Serial.println(F(" (5) Write New Tag EPC"));
  Serial.println(F(" (6) Write New Tag Data"));
  Serial.println(F(" (7) Enable Continuous Read Filter"));
  Serial.println(F(" (8) Disable Continuous Read Filter"));
  Serial.println(F(" (9) Set Timeout Continuous Read Filter"));

  nano.setRegion(REGION_AUSTRALIA); //Set to North America

  nano.setReadPower(2200); //5.00 dBm. Higher values may cause USB port to brown out
  //Max Read TX Power is 27.00 dBm and may cause temperature-limit throttling

  nano.setWritePower(2200); //5.00 dBm. Higher values may cause USB port to brown out
  //Max Write TX Power is 27.00 dBm and may cause temperature-limit throttling
  nano.enableReadFilterWithTimeout(1000);
  nano.sendMessage(TMR_SR_OPCODE_CLEAR_TAG_ID_BUFFER, NULL, 0);

}


// ------------------------------------------------------------------
// HELPER FUNCTIONS (could be moved to library)
// ------------------------------------------------------------------

bool isHex(String input) {
  // test if string is hexadecimal
  for(int i=0; i < input.length(); i++) {
    if(!isHexadecimalDigit(input[i])) {
      return false;
    }
  }
  return true;  
}

// Tests if the string is a valid EPC.
// Valid EPCs are in hex format and should be byte aligned
bool isEPC(String EPC) {
  // if uneven, it is not an EPC
  if(EPC.length() % 4 != 0) {
    return false;
  }
  return isHex(EPC);
}

// For converting a hex string into a byte array
uint16_t hexStringToByteArray(String s, byte *arr, uint16_t arrSize) {
  int length = s.length() / 2;
  length = length > arrSize ? arrSize : length;
  for(int i=0; i < length * 2; i += 2) {
    // include 0-byte
    char tmp[3];
    s.substring(i, i + 2).toCharArray(tmp, 3);
    arr[i/2] = (byte) strtoul(tmp, NULL, 16);
  } 
  return length;
}

// Gets an EPC from the user
String getUserEPC() {
  String EPC;
  do {
    Serial.println(F("Enter a valid EPC: "));
    while (!Serial.available());
    EPC = Serial.readString();
    EPC.trim();
  } while(!isEPC(EPC) && EPC != "");  
  return EPC;
}

// ------------------------------------------------------------------
// CLI FUNCTIONS
// ------------------------------------------------------------------
 
// Scans a single random tag using the readTagEPC function
void readRandomTagId() {
  uint16_t myEPClength = 16;
  byte myEPC[myEPClength]; 
  while (nano.response.status != RESPONSE_SUCCESS && nano.response.status != ALL_GOOD)
  {
    myEPClength = sizeof(myEPC);
    nano.readTagEPC(1500); 
    Serial.println(F("Searching for tag"));
  }
  if(nano.response.nrTags > 0)
  {
    nano.response.getData(0, myEPC, myEPClength, 4);
    Serial.print(F("EPC: "));
    printBytes(myEPC, myEPClength);
  }
}

// Scans for all tags once
// Supports simple EPC filters
void readMultipleTagIds() {
  Serial.println(F("Provide EPC Filter (\"\" to leave empty):"));
  String EPCFilter = getUserEPC();
  uint16_t EPCSize = 16;
  byte EPC[EPCSize];
  int metadataSize = 128;
  char metadata[metadataSize];
  // apply an EPC filter
  if(EPCFilter != "") {
    uint16_t EPCFilterSize = EPCFilter.length() / 2;
    byte EPCFilterBytes[EPCFilterSize];
    uint16_t EPCFilterLength = hexStringToByteArray(EPCFilter, EPCFilterBytes, EPCFilterSize);
    ReadConfig config = nano.initStandardReadMultipleTagsOnceConfig();
    TagFilter filter = nano.initEPCReadFilter(EPCFilterBytes, EPCFilterLength);
    nano.readMultipleTagsWithFilterConfig(config, filter);
  }
  else {
    nano.readMultipleTags();
  }
  Serial.print("Found: ");
  Serial.print(nano.response.nrTags);
  Serial.println(" tags!");
  for(uint8_t i = 0; i < nano.response.nrTags; i++) {
    uint16_t EPCLength = nano.response.getEPCdata(i, EPC, EPCSize);
    uint16_t metadataLength = nano.response.metadataToJsonString(i, metadata, metadataSize);
    Serial.print(F("EPC: "));
    printBytes(EPC, EPCLength);
    Serial.print("Metadata: ");
    Serial.println(metadata);
  }
}

void pollTags(uint8_t time) {
  TagFilter filter;
  ReadConfig readConfig = nano.initStandardContinuousReadConfig();
  uint16_t EPCLength = 12;
  byte EPC[EPCLength];
  nano.startReadingWithFilterConfig(readConfig, filter);
  unsigned long end;
  unsigned long start = millis();
  do {
    if (nano.check() == true) //Check to see if any new data has come in from module
    {
      if (nano.response.status == RESPONSE_IS_KEEPALIVE)
      {
        Serial.println(F("Scanning"));
      }
      else if (nano.response.status == RESPONSE_IS_TAGFOUND && nano.response.nrTags > 0)
      {
        int metadataLength = 256;
        char metadata[metadataLength];
        nano.response.getEPCdata(0, EPC, EPCLength);
        nano.response.metadataToJsonString(0, metadata, metadataLength);
        Serial.print(F("EPC: "));
        printBytes(EPC, EPCLength);
        Serial.print("Metadata: ");
        Serial.println(metadata);
      }
      else if (nano.response.status == ERROR_CORRUPT_RESPONSE)
      {
        Serial.println("Bad CRC");
      }
    }
    end = millis();
  } while((end - start) / 1000 < time); // there is an overflow issue in that case the loop will also terminate
  nano.stopReading();
}

// Inspects a tag, if no EPC is provided, a random tag is inspected
void inspectTag() {
  String EPCFilter = getUserEPC();
  TagFilter filter;
  ReadConfig config;
  // enable the filter
  uint16_t EPCFilterSize = EPCFilter.length() / 2;
  byte EPCFilterBytes[EPCFilterSize];
  if(EPCFilter != "") {
    uint16_t EPCFilterLength = hexStringToByteArray(EPCFilter, EPCFilterBytes, EPCFilterSize);
    config = nano.initStandardReadTagDataOnce();
    filter = nano.initEPCSingleReadFilter(EPCFilterBytes, EPCFilterLength);
  } 
  uint16_t bufSize = 512;
  uint16_t bufLength;
  byte buffer[bufSize];
  nano.readDataWithFilterConfig(0x00, 0x00, config, filter);
  if(nano.response.nrTags > 0)
  {
    Serial.print(F("Reserved Bank: "));
    bufLength = nano.response.getBankdata(0, buffer, bufSize);
    printBytes(buffer, bufLength);
  }
  nano.readDataWithFilterConfig(0x01, 0x00, config, filter);
  if(nano.response.nrTags > 0)
  {
    Serial.print(F("EPC Bank: "));
    bufLength = nano.response.getBankdata(0, buffer, bufSize);
    printBytes(buffer, bufLength);
  }
  nano.readDataWithFilterConfig(0x02, 0x00, config, filter);
  if(nano.response.nrTags > 0)
  {
    Serial.print(F("TID Bank: "));
    bufLength = nano.response.getBankdata(0, buffer, bufSize);
    printBytes(buffer, bufLength);
  }
  nano.readDataWithFilterConfig(0x03, 0x00, config, filter, 10000);
  if(nano.response.nrTags > 0)
  {
    Serial.print(F("User Bank: "));
    bufLength = nano.response.getBankdata(0, buffer, bufSize);
    printBytes(buffer, bufLength);
  }
}

// Takes care of writing a new EPC to the tag
// Handles the user input, conversion and writing
void writeTagEPC() {
  // gets user input and tests if it is hexadecimal
  String oldEPC = getUserEPC();
  String newEPC = getUserEPC();
  TagFilter filter;
  if(newEPC != "") {
    // with filter
    if(oldEPC != "") {
      Serial.println("Old Tag EPC: " + oldEPC);
    }
    Serial.println("New Tag EPC: " + newEPC);

    uint16_t oldEPCSize = oldEPC.length() / 2;
    uint16_t newEPCSize = newEPC.length() / 2;
    byte oldBytes[oldEPCSize];
    byte newBytes[newEPCSize];
    uint16_t oldEPCLength = hexStringToByteArray(oldEPC, oldBytes, oldEPCSize);
    uint16_t newEPCLength = hexStringToByteArray(newEPC, newBytes, newEPCSize);
    if(oldEPC != "") {
      printBytes(oldBytes, oldEPCLength);
    }
    printBytes(newBytes, newEPCLength);
    if(oldEPC != "") {  
      filter = nano.initEPCWriteFilter(oldBytes, oldEPCLength);
      nano.writeTagEPCWithFilter(newBytes, newEPCLength, filter);
    }
    else {  
      nano.writeTagEPC(newBytes, newEPCLength);
    }

    if (nano.response.status == RESPONSE_SUCCESS || nano.response.status == ALL_GOOD) {
      Serial.println("New EPC Written!");
    }
    else {
      Serial.println("Failed write");
    }
  }
  else {
    Serial.println(F("New EPC cannot be empty"));
  }
}

void writeTagData() {
  // get user input and convert to bytes
  Serial.println(F("Provide input(ASCII or HEX):"));
  String input;
  while (!Serial.available());
  input = Serial.readString();
  input.trim();
  uint16_t inputBytesSize = input.length() + 1;
  uint16_t inputBytesLength = inputBytesSize;
  byte inputBytes[inputBytesSize];
  // check if we should interpret it as a hex string
  if(isHex(input) && input.length() % 2 == 0) {
    inputBytesLength = hexStringToByteArray(input, inputBytes, inputBytesSize);
  }
  else {
    input.getBytes(inputBytes, inputBytesSize);
  }

  // get EPC filter
  Serial.println(F("Provide EPC Filter (\"\" to leave empty):"));
  String EPCFilter = getUserEPC();

  // if there is a filter
  if(EPCFilter != "") {
    Serial.println("writing " + input + " to " + EPCFilter);
    // prepare filter
    uint16_t EPCFilterSize = EPCFilter.length() / 2;
    byte EPCFilterBytes[EPCFilterSize];
    uint16_t EPCFilterLength = hexStringToByteArray(EPCFilter, EPCFilterBytes, EPCFilterSize);
    TagFilter filter = nano.initEPCWriteFilter(EPCFilterBytes, EPCFilterLength);
    //nano.writeUserData(inputBytes, sizeof(inputBytes) - 1);
    nano.writeDataWithFilter(0x03, 0x00, inputBytes, inputBytesLength, filter);
  }
  // if there is no filter
  else {
    Serial.println("writing " + input + " to random tag");
    nano.writeUserData(inputBytes, inputBytesLength - 1);
  }

  // check response
  if (nano.response.status == RESPONSE_SUCCESS || nano.response.status == ALL_GOOD) {
    Serial.println("New Data Written!");
  }
  else {
    Serial.println("Failed write");
  }
}

void enableReadFilterWithTimeout(uint32_t timeout)
{
  nano.enableReadFilter();
  uint8_t data[6] = {0x01, 0x0D, timeout >> 24, timeout >> 16, timeout >> 8, timeout};
  nano.sendMessage(TMR_SR_OPCODE_SET_READER_OPTIONAL_PARAMS, data, sizeof(data));
}

void loop()
{
  Serial.println(F("Select an option"));
  while (!Serial.available());
  int option = Serial.parseInt();
  // empty buffer
  while(Serial.available() > 0) Serial.read(); 
  switch(option) {
    case 1:
      readRandomTagId();
      break;
    case 2:
      readMultipleTagIds();
      break;
    case 3: {
      Serial.println("Specify Polling Time(s):");
      while (!Serial.available());
      uint32_t polltime = Serial.parseInt();
      while(Serial.available() > 0) Serial.read(); 
      pollTags(polltime);
      break;
    }
    case 4:
      inspectTag();
      break;
    case 5:
      writeTagEPC();
      break;
    case 6:
      writeTagData();
      break;
    case 7:
      nano.enableReadFilter();
      break;
    case 8:
      nano.disableReadFilter();
      break;
    case 9: {
      Serial.println("Specify Read Filter Timeout(s):");
      while (!Serial.available());
      uint32_t timeout = Serial.parseInt() * 1000;
      while(Serial.available() > 0) Serial.read(); 
      nano.enableReadFilterWithTimeout(timeout);
      break;
    }
    default:
      Serial.println(F("Invalid option"));
      break; 
  }
}

//Gracefully handles a reader that is already configured and already reading continuously
//Because Stream does not have a .begin() we have to do this outside the library
boolean setupNano(long baudRate)
{
  //nano.enableDebugging(Serial); 
  nano.begin(Serial1); //Tell the library to communicate over software serial port

  //Test to see if we are already connected to a module
  //This would be the case if the Arduino has been reprogrammed and the module has stayed powered
  Serial1.begin(baudRate); //For this test, assume module is already at our desired baud rate
  while (!Serial1); //Wait for port to open

  //About 200ms from power on the module will send its firmware version at 115200. We need to ignore this.
  while (Serial1.available()) Serial1.read();

  nano.getVersion();

  if (nano.msg[0] == ERROR_WRONG_OPCODE_RESPONSE)
  {
    //This happens if the baud rate is correct but the module is doing a ccontinuous read
    nano.stopReading();

    Serial.println(F("Module continuously reading. Asking it to stop..."));

    delay(1500);
  }
  else
  {
    //The module did not respond so assume it's just been powered on and communicating at 115200bps
    Serial1.begin(115200); //Start software serial at 115200

    nano.setBaud(baudRate); //Tell the module to go to the chosen baud rate. Ignore the response msg

    Serial1.begin(baudRate); //Start the software serial port, this time at user's chosen baud rate
    delay(250);
  }

  //Test the connection
  nano.getVersion();
  //Serial.println(nano.msg);
  if (nano.msg[0] != ALL_GOOD) return (false); //Something is not right

  //The M6E has these settings no matter what
  nano.setTagProtocol(); //Set protocol to GEN2

  nano.setAntennaPort(); //Set TX/RX antenna ports to 1

  return (true); //We are ready to rock
}
