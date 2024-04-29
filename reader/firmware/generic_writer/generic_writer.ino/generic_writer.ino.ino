/*
Date: 25-04-2024
Author: Folmer Heikamp
Board: Arduino Uno R4 Wifi
Requires:  UHF m6e nano shield

Flow:
1. Waits for user input
2. Scans EPC tags for a few seconds
3. Reports unique tags found
4. User selects one of the EPC's
5. User selects (1) write EPC, (2) write user data, (3) write passwords, or(4) check
6. Nano reports success or failure and waits for user input again

*/


//Used for transmitting to the device
//If you run into compilation errors regarding this include, see the README
#include <SoftwareSerial.h>

SoftwareSerial softSerial(2, 3); //RX, TX

#include "SparkFun_UHF_RFID_Reader.h" //Library for controlling the M6E Nano module
RFID nano; //Create instance

void setup()
{
  Serial.begin(115200);

  while (!Serial);
  Serial.println();
  Serial.println("Initializing...");

  if (setupNano(38400) == false) //Configure nano to run at 38400bps
  {
    Serial.println("Module failed to respond. Please check wiring.");
    while (1); //Freeze!
  }

  nano.setRegion(REGION_NORTHAMERICA); //Set to North America

  nano.setReadPower(500); //5.00 dBm. Higher values may cause USB port to brown out
  //Max Read TX Power is 27.00 dBm and may cause temperature-limit throttling

  nano.setWritePower(500); //5.00 dBm. Higher values may cause USB port to brown out
  //Max Write TX Power is 27.00 dBm and may cause temperature-limit throttling
}

void writeNewEPC(EPC) {

}

/*
Asks the user to select an option.
Blocks until it receives input terminated by a newline.
Makes sure that a valid option is returned
*/
int pickMenuItem() {
  int option = 0;
  do {
    String str = "";
    char chr = '';
    Serial.println(F("Select one of the following options:\n
    (1) Read tags\n
    (2) Show tag content\n
    (3) Write new EPC to tag\n
    (4) Write user data to tag\n
    (5) Write passwords to tag\n"));
    // wait until a new line
    while(chr != '\n') {
      // wait for user input
      while(!Serial.available());
      chr = Serial.read();
      str += chr;
    }
    // will be 0 if there is no integer in the string
    option = str.toInt();
  } while(option <= 0 || option > 5);
  return option;
}

/*
Tests if the string is a valid EPC.
Valid EPCs are in hex format and have a length of 8 (could be more)
*/
bool isValidEPC(String EPC) {
  // if uneven, it is not an EPC
  if(EPC.length() % 2 != 0) {
    return false;
  }
  // test if string is hexadecimal
  for(int i=0; i < EPC.length(); i++) {
    if(!isHexadecimalDigit(ECP[i]) {
      return false;
    }
  }
  return true;
}

String readUserEPC() {
  String EPC;
  char chr;
  do {
    Serial.println("Specify EPC (hex format, example: ff2d3311");
    while(chr != '\n') {
      // wait for user input
      while(!Serial.available());
      chr = Serial.read();
      EPC += chr;
    }
  } while(!isValidEPC);
  return EPC;
}

String readUserData() {
  String data;
  char chr;
  Serial.println("Specify data (any string terminated by newline)");
  while(chr != '\n') {
    // wait for user input
    while(!Serial.available());
    chr = Serial.read();
    data += chr;
  }
  return data;
}

/*
Scans for tags and prints the EPCodes
*/
void scanTags() {
  byte myEPC[12]; //Most EPCs are 12 bytes
  byte myEPClength;
  byte responseType = 0;
  while (responseType != RESPONSE_SUCCESS)
  {
    myEPClength = sizeof(myEPC);
    responseType = nano.readTagEPC(myEPC, myEPClength, 500); 
    Serial.println(F("Searching for tag"));
  }
  Serial.print(F(" epc["));
  for (byte x = 0 ; x < myEPClength ; x++)
  {
    if (myEPC[x] < 0x10) Serial.print(F("0"));
    Serial.print(myEPC[x], HEX);
    Serial.print(F(" "));
  }
  Serial.println(F("]"));
}

/*
W
*/
void writeEPCToTag(String EPC) {
  byte responseType = nano.writeTagEPC(hexEPC, sizeof(hexEPC));

  if (responseType == RESPONSE_SUCCESS) {
    Serial.println("New EPC Written!");
  }
  else {
    Serial.println("Failed write");
  }
}

void writeDataToTag(String EPC) {
  byte responseType = nano.writeTagEPC(hexEPC, sizeof(hexEPC));

  if (responseType == RESPONSE_SUCCESS) {
    Serial.println("New EPC Written!");
  }
  else {
    Serial.println("Failed write");
  }
}

void loop()
{
  int option = pickMenuItem();
  switch(option) {
    case 1:
      scanTags();
      break;
    case 2:
      EPC = readUserEPC();
    break;
    case 3:
      EPC = readUserEPC();
      writeEPCToTag()
    break;
    case 4:
      data = readUserData();
      writeDataToTag();
    break;
    case 5:
      // TODO
    break;
  } 

  // print menu 
  Serial.println(F("Get all tags out of the area. Press a key to write EPC to first detected tag."));
  if (Serial.available()) Serial.read(); //Clear any chars in the incoming buffer (like a newline char)
  while (!Serial.available()); //Wait for user to send a character
  Serial.read(); //Throw away the user's character

  //"Hello" Does not work. "Hell" will be recorded. You can only write even number of bytes
  //char stringEPC[] = "Hello!"; //You can only write even number of bytes
  //byte responseType = nano.writeTagEPC(stringEPC, sizeof(stringEPC) - 1); //The -1 shaves off the \0 found at the end of string
  char testData[] = "ACBD"; //You can only write even number of bytes
  byte responseType = nano.writeUserData(testData, sizeof(testData) - 1); //The -1 shaves off the \0 found at the end of string
  char hexEPC[] = {0xFF, 0x2D, 0x03, 0x54}; //You can only write even number of bytes

}

//Gracefully handles a reader that is already configured and already reading continuously
//Because Stream does not have a .begin() we have to do this outside the library
boolean setupNano(long baudRate)
{
  nano.begin(softSerial); //Tell the library to communicate over software serial port

  //Test to see if we are already connected to a module
  //This would be the case if the Arduino has been reprogrammed and the module has stayed powered
  softSerial.begin(baudRate); //For this test, assume module is already at our desired baud rate
  while (!softSerial); //Wait for port to open

  //About 200ms from power on the module will send its firmware version at 115200. We need to ignore this.
  while (softSerial.available()) softSerial.read();

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
    softSerial.begin(115200); //Start software serial at 115200

    nano.setBaud(baudRate); //Tell the module to go to the chosen baud rate. Ignore the response msg

    softSerial.begin(baudRate); //Start the software serial port, this time at user's chosen baud rate
  }

  //Test the connection
  nano.getVersion();
  if (nano.msg[0] != ALL_GOOD) return (false); //Something is not right

  //The M6E has these settings no matter what
  nano.setTagProtocol(); //Set protocol to GEN2

  nano.setAntennaPort(); //Set TX/RX antenna ports to 1

  return (true); //We are ready to rock
}
