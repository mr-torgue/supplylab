#include <SparkFun_UHF_RFID_Reader.h>
#include <AES.h>
#include <GCM.h>
#include <RNG.h>

// include the settings for this mode
#include "settings.h"

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
  Serial.println(F("Running in plain mode"));

  nano.setRegion(REGION_AUSTRALIA); //Set to North America

  nano.setReadPower(1500); //5.00 dBm. Higher values may cause USB port to brown out
  //Max Read TX Power is 27.00 dBm and may cause temperature-limit throttling

  nano.setWritePower(1500); //5.00 dBm. Higher values may cause USB port to brown out
  //Max Write TX Power is 27.00 dBm and may cause temperature-limit throttling

}
/*
For this mode to work:
(1) the settings header should have a shared secret key of 16 bytes in hexadecimal format
(2) the tag secret should be encrypted with this key in GCM mode, 16 bytes IV, 16 bytes tag, rest is ciphertext
The tag secret is the same as modes 2 and 3: path length | path | reader index (all a byte long)
*/
void loop()
{
  // setup cipher in gcm mode
  GCM<AES128> gcm;
  gcm.setKey(sharedKey, sizeof(sharedKey));
  
  // variables for storing data
  uint16_t EPCSize = 16;
  byte EPC[EPCSize];
  uint16_t metadataRawSize = 512;
  uint8_t metadataRaw[metadataRawSize];
  int metadataSize = 512;
  char metadata[metadataSize];

  // read for tags
  ReadConfig config = nano.initStandardReadMultipleTagsOnceConfig();
  config.metadataFlag |= TMR_TRD_METADATA_FLAG_DATA;
  config.searchFlag = 0x17; // included embedded data
  TagFilter filter = nano.initEmptyFilterWithMetadata();
  nano.readMultipleTagsWithFilterConfig(config, filter);

  // only if tags were found
  for(uint8_t i = 0; i < nano.response.nrTags; i++) {
    uint16_t EPCLength = nano.response.getEPCdata(i, EPC, EPCSize);
    int metadataLength = nano.response.metadataToJsonString(i, metadata, metadataSize);
    Serial.print(F("Found Tag: "));
    printBytes(EPC, EPCLength);
    Serial.print("Metadata: ");
    Serial.println(metadata);
    uint16_t metadataRawLength = nano.response.getMetadata(0, metadataRaw, metadataRawSize);
    uint16_t offset = nano.response.metadataOffsets[DATA];
    uint16_t embeddedDataLength = (metadataRaw[offset] << 8 | metadataRaw[offset + 1]) >> 3;
    uint8_t embeddedData[embeddedDataLength];
    // hard copy
    memcpy(embeddedData, metadataRaw + offset + 2, embeddedDataLength);
    //for(uint16_t k = 0; k < embeddedDataLength; k++) {
    //  embeddedData[k] = metadataRaw[k + offset + 2];
    //}
    Serial.print("Raw Embedded Data(encrypted): ");
    printBytes(embeddedData, embeddedDataLength);
    
    // only if there is at least 32 bytes
    if(embeddedDataLength >= 32) {
      // decrypt the tag content
      uint16_t plaintextLength = embeddedDataLength - 32;
      uint8_t plaintext[plaintextLength];
      gcm.setIV(embeddedData, 16);
      gcm.decrypt(plaintext, embeddedData + 32, plaintextLength);
      
      // check if the tag matches the message
      if(gcm.checkTag(plaintext + 16, 16)) {
        // path length is the first byte
        uint8_t pathLength = plaintext[0];
        Serial.println(pathLength);
        // if x bytes are returned, path can only be x - 2
        if(pathLength < plaintextLength - 2) {
          uint8_t readerIndex = plaintext[1 + pathLength];
          Serial.println(readerIndex);
          if(readerIndex < pathLength - 1) {
            uint8_t currentReader = plaintext[1 + readerIndex];
            if(currentReader == readerId) {
              Serial.println("Tag needs to be updated by this reader!");
              // increase the reader index by 1
              plaintext[1 + pathLength] = readerIndex + 1;

              // encrypt with a new IV (not entirely random)
              uint8_t ciphertext[plaintextLength + 32];
              RNG.begin("GENERATOR...");
              RNG.rand(ciphertext, 16);
              gcm.setIV(ciphertext, 16);
              gcm.encrypt(ciphertext + 32, plaintext, plaintextLength); 
              gcm.computeTag(ciphertext + 16, 16);
              
              // write to tag
              TagFilter filter = nano.initEPCWriteFilter(EPC, EPCLength);
              nano.writeDataWithFilter(0x03, 0x00, ciphertext, sizeof(ciphertext), filter);
            }
          }
          else if(readerIndex == pathLength - 1) {
            Serial.println(F("Tag is at the last reader!"));
          }
          else {
            Serial.println(F("Reader index is not within path length"));
          }
        }
        else {
          Serial.println(F("Path length too large, either tag secret is malformed or not enough bytes are retrieved from the tag."));
        }
      }
      else {
        Serial.println(F("Could not verify tag!"));
      }
    }
  }
  delay(1000);
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
