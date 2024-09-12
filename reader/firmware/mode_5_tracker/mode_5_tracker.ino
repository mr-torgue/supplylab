#include <SparkFun_UHF_RFID_Reader.h>
#include <uECC_vli.h>

// include the settings for this mode
#include "settings.h"

RFID nano;

/* 
very simple number generator
*/
static int RNG(uint8_t *dest, unsigned size) {
  randomSeed(analogRead(0));
  for(unsigned i = 0; i < size; i++)
  {
    dest[i] = random(256);
  }
  return 1;
}


void setup()
{
  Serial.begin(115200);

  while (!Serial)
    ;
  Serial.println(F("----------------------------------------------------------------------------------------"));
  Serial.println(F("| Title       : Tracker Update Firmware                                                |"));
  Serial.println(F("| Scheme      : Tracker                                                                |"));
  Serial.println(F("| Mode        : Standard                                                               |"));
  Serial.println(F("| Version     : 1.0                                                                    |"));
  Serial.println(F("| Hardware    : Arduino uno R4 Wifi and RFID UHF M6E nano shield                       |"));
  Serial.println(F("| Description : Scans for available tags. If tags are available, it reads the content. |"));
  Serial.println(F("|               If content is encoded using tracker protocol, it gets updated by using |"));
  Serial.println(F("|               the homomorphic properties of ECC el-gamal.                            |"));
  Serial.println(F("----------------------------------------------------------------------------------------"));
  if (setupNano(115200) == false) // Configure nano to run at 38400bps
  {
    Serial.println("Module failed to respond. Please check wiring.");
    while (1)
      ; // Freeze!
  }

  nano.setRegion(REGION_AUSTRALIA); // Set to North America

  nano.setReadPower(1800); // 5.00 dBm. Higher values may cause USB port to brown out
  // Max Read TX Power is 27.00 dBm and may cause temperature-limit throttling

  nano.setWritePower(1800); // 5.00 dBm. Higher values may cause USB port to brown out
  // Max Write TX Power is 27.00 dBm and may cause temperature-limit throttling
  uECC_set_rng(&RNG);
}

/*
Reencrypts using el-gamal (homomorphic)
Given c = (c1, c2): c1' = r * P + c1 and c2' = r * Y + c2, where r is random and Y is the public key 
@cNew: output buffer of size 2 * num_words (Point)
@c: input buffer of size 2 * num_words (Point)
@j: specifies first of second point
@r: random number, assumed to be nrNBytes long
@curve: curve being used
*/
void reencrypt(uint8_t *cNew, uint8_t *c, uint8_t j, uint8_t *r, const uECC_Curve_t *curve)
{
  // setup variables
  const uint8_t nrNBytes = uECC_curve_num_n_bytes(curve);
  const uint8_t nrBytes = uECC_curve_num_bytes(curve);
  uint8_t tmp[2 * nrBytes];

  // calculate 
  if(j == 0)
    uECC_point_mult_bytes(tmp, P, r, nrNBytes, curve);
  else
    uECC_point_mult_bytes(tmp, pubKey, r, nrNBytes, curve);
  uECC_add_points_bytes(cNew, tmp, c, curve);
}

/*
Tracker update firmware:
Tracker expects the input of the tag (C1_ID, C2_ID), (C1_HMAC_ID, C2_HMAC_ID), (C1_poly, C2_poly)
It calculates an updated (C1_poly', C2_poly') = (x0 * C1_poly + ai * C1_HMAC_ID, x0 * C2_poly + ai * C2_HMAC_ID)
Tracker updates are 'dumb' they do it regardless of input
Only if the inputs are not points on the curve will it fail
*/
void loop()
{
  // variables for storing data
  const uint16_t EPCSize = 16;
  byte EPC[EPCSize];

  // specify curve and set dataSize
  const struct uECC_Curve_t *curve = uECC_secp160r1();
  const uint8_t nrBytes = uECC_curve_num_bytes(curve);
  const uint8_t nrNBytes = uECC_curve_num_n_bytes(curve);
  const uint8_t nrWords = uECC_curve_num_words(curve); // for example if wordsize is 4B and curve is 20B, we have 20 / 4 = 5 
  const uint8_t pointSize = uECC_curve_num_bytes(curve) * 2; // uncrompressed size of a point

  // data should be 240 bytes (not compressed)
  const uint8_t dataSize = 6 * pointSize;
  byte data[dataSize];

  // variables for storing tag data
  uint8_t cId[pointSize], cHash[pointSize], cPoly[pointSize], tmp1[pointSize], tmp2[pointSize]; 
  uint8_t cIdNew[pointSize], cHashNew[pointSize], cPolyNew[pointSize];

  // declare configuration and filter for reading tag content
  ReadConfig dataReadConfig = nano.initStandardReadTagDataOnce();
  TagFilter dataReadFilter;

  // read for tags
  nano.readMultipleTags();
  
  // only if tags were found
  for (uint8_t i = 0; i < nano.response.nrTags; i++)
  {
    // obtain EPCLength and print EPC
    uint16_t EPCLength = nano.response.getEPCdata(i, EPC, EPCSize);
    Serial.print(F("Found Tag: "));
    printBytes(EPC, EPCLength);

    // read tag data into data
    dataReadFilter = nano.initEPCSingleReadFilter(EPC, EPCLength);
    nano.readDataWithFilterConfig(0x03, 0x00, dataReadConfig, dataReadFilter, true, 1000);
    if (nano.response.nrTags > 0)
    {
      Serial.print(F("User Bank: "));
      uint16_t dataLength = nano.response.getBankdata(0, data, dataSize);
      if(dataLength == dataSize)
      {
        uint8_t j;
        printBytes(data, dataLength);

        // generate random numbers (NOTE: reduces security)
        // better is to do it modulo n, but this is a quick fix
        uint8_t rID[nrNBytes], rHash[nrNBytes], rPoly[nrNBytes];
        rID[0] = 0;
        rHash[0] = 0;
        rPoly[0] = 0;
        RNG(rID + 1, nrNBytes - 1);
        RNG(rHash + 1, nrNBytes - 1);
        RNG(rPoly + 1, nrNBytes - 1);

        // every encryption has two messages
        for(j = 0; j < 2; j++)
        {
          // copy into right buffers, not strictly necessary but enhances readability
          memcpy(cId, data + j * pointSize, pointSize);
          memcpy(cHash, data + (2 + j) * pointSize, pointSize);
          memcpy(cPoly, data + (4 + j) * pointSize, pointSize);

          // check if it is a valid point
          if (uECC_valid_public_key(cId, curve) && uECC_valid_public_key(cHash, curve) && uECC_valid_public_key(cPoly, curve))
          {
            // update: x0 * cPolyNative + ai * cHashNative
            uECC_point_mult_bytes(tmp1, cPoly, x0, sizeof(x0), curve);
            uECC_point_mult_bytes(tmp2, cHash, a, sizeof(a), curve);
            uECC_add_points_bytes(cPoly, tmp1, tmp2, curve);

            // reencryption
            reencrypt(cIdNew, cId, j, rID, curve);
            reencrypt(cHashNew, cHash, j, rHash, curve);
            reencrypt(cPolyNew, cPoly, j, rPoly, curve);

            // add all messages together again
            memcpy(data + j * pointSize, cIdNew, pointSize);
            memcpy(data + (j + 2) * pointSize, cHashNew, pointSize);
            memcpy(data + (j + 4) * pointSize, cPolyNew, pointSize);
          }
          else 
          {
            Serial.println(F("Point could not be decoded!"));
            break;
          }
        }
        if(j == 2)
        {
          // write to tag
          TagFilter filter = nano.initEPCWriteFilter(EPC, EPCLength);
          if(nano.writeDataWithFilter(0x03, 0x00, data, sizeof(data), filter))
          {
            Serial.print(F("Succesfully updated tag content to: "));
            printBytes(data, dataLength);
          }
          else
          {
            Serial.println(F("Writing data failed!"));
          }
        }
      }
      else 
      {
        Serial.println(F("Not enough bytes retrieved!"));
      }
    }
    else
    {
      Serial.println(F("Could not find tag!"));
    }
  }
  while (!Serial.available());
  Serial.readString();
  while(Serial.available() > 0) Serial.read(); 
  delay(1000);
}

// Gracefully handles a reader that is already configured and already reading continuously
// Because Stream does not have a .begin() we have to do this outside the library
boolean setupNano(long baudRate)
{
  nano.enableDebugging(Serial);
  nano.begin(Serial1); // Tell the library to communicate over software serial port

  // Test to see if we are already connected to a module
  // This would be the case if the Arduino has been reprogrammed and the module has stayed powered
  Serial1.begin(baudRate); // For this test, assume module is already at our desired baud rate
  while (!Serial1)
    ; // Wait for port to open

  // About 200ms from power on the module will send its firmware version at 115200. We need to ignore this.
  while (Serial1.available())
    Serial1.read();

  nano.getVersion();

  if (nano.msg[0] == ERROR_WRONG_OPCODE_RESPONSE)
  {
    // This happens if the baud rate is correct but the module is doing a ccontinuous read
    nano.stopReading();

    Serial.println(F("Module continuously reading. Asking it to stop..."));

    delay(1500);
  }
  else
  {
    // The module did not respond so assume it's just been powered on and communicating at 115200bps
    Serial1.begin(115200); // Start software serial at 115200

    nano.setBaud(baudRate); // Tell the module to go to the chosen baud rate. Ignore the response msg

    Serial1.begin(baudRate); // Start the software serial port, this time at user's chosen baud rate
    delay(250);
  }

  // Test the connection
  nano.getVersion();
  // Serial.println(nano.msg);
  if (nano.msg[0] != ALL_GOOD)
    return (false); // Something is not right

  // The M6E has these settings no matter what
  nano.setTagProtocol(); // Set protocol to GEN2

  nano.setAntennaPort(); // Set TX/RX antenna ports to 1

  return (true); // We are ready to rock
}
