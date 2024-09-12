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
  Serial.println(F(" (3) Continuous read for 5 seconds"));
  Serial.println(F(" (4) Inspect Tag"));
  Serial.println(F(" (5) Write New Tag EPC"));
  Serial.println(F(" (6) Write New Tag Data"));

  nano.setRegion(REGION_AUSTRALIA); //Set to North America

  nano.setReadPower(1500); //5.00 dBm. Higher values may cause USB port to brown out
  //Max Read TX Power is 27.00 dBm and may cause temperature-limit throttling

  nano.setWritePower(1500); //5.00 dBm. Higher values may cause USB port to brown out
  //Max Write TX Power is 27.00 dBm and may cause temperature-limit throttling

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

    uint8_t oldEPCLength = oldEPC.length() / 2;
    uint8_t newEPCLength = newEPC.length() / 2;
    byte oldBytes[oldEPCLength];
    byte newBytes[newEPCLength];
    hexStringToByteArray(oldEPC, oldBytes);
    hexStringToByteArray(newEPC, newBytes);
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

    if (nano.response.status == RESPONSE_SUCCESS) {
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
  Serial.println(F("Provide input(ASCII):"));
  String input;
  while (!Serial.available());
  input = Serial.readString();
  byte inputBytes[input.length() + 1]; 
  input.getBytes(inputBytes, input.length() + 1);

  // get EPC filter
  Serial.println(F("Provide EPC Filter (\"\" to leave empty):"));
  String EPCFilter = getUserEPC();

  // if there is a filter
  if(EPCFilter != "") {
    Serial.println("writing " + input + " to " + EPCFilter);
    // prepare filter
    uint8_t EPCFilterLength = EPCFilter.length() / 2;
    byte EPCFilterBytes[EPCFilterLength];
    hexStringToByteArray(EPCFilter, EPCFilterBytes);
    TagFilter filter = nano.initEPCWriteFilter(EPCFilterBytes, EPCFilterLength);
    nano.writeUserData(inputBytes, sizeof(inputBytes) - 1);
  }
  // if there is no filter
  else {
    Serial.println("writing " + input + " to random tag");
    nano.writeUserData(inputBytes, sizeof(inputBytes) - 1);
  }

  // check response
  if (nano.response.status == RESPONSE_SUCCESS) {
    Serial.println("New Data Written!");
  }
  else {
    Serial.println("Failed write");
  }
}

void mode_2_plain() {
  uint16_t EPCSize = 12;
  byte EPC[EPCSize];
  int metadataSize = 512;
  char metadata[metadataSize];
  // read embedded data as well
  ReadConfig config = initStandardReadMultipleTagsOnceConfig();
  config.metadataFlag |= TMR_TRD_METADATA_FLAG_DATA;
  TagFilter filter = initEmptyFilterWithMetadata();
  nano.readMultipleTagsWithFilterConfig(config, filter);
  for(uint8_t i = 0; i < nano.response.nrTags; i++) {
    uint16_t EPCLength = nano.response.getEPCdata(i, EPC, EPCSize);
    int metadataLength = nano.response.metadataToJsonString(i, metadata, metadataSize);
    Serial.print(F("EPC: "));
    printBytes(EPC, EPCLength);
    Serial.print("Metadata: ");
    Serial.println(metadata);
  }
}

void loop()
{
  uint8_t mode = 2;
  switch(mode) {
    case 1:
      break;
    case 2:
      mode_2_plain();
      break;
    case 3:
      break;
    default:
      break;
  }
}




//Gracefully handles a reader that is already configured and already reading continuously
//Because Stream does not have a .begin() we have to do this outside the library
boolean setupNano(long baudRate)
{
  nano.enableDebugging(Serial); 
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
