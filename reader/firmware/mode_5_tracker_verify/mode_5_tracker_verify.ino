#include <SparkFun_UHF_RFID_Reader.h>
#include <uECC_vli.h>
#include <SHA256.h>

// include the settings for this mode
#include "settings.h"

RFID nano;

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
  Serial.println(F("| Title       : Tracker Verification Firmware                                          |"));
  Serial.println(F("| Scheme      : Tracker                                                                |"));
  Serial.println(F("| Mode        : Standard                                                               |"));
  Serial.println(F("| Version     : 1.0                                                                    |"));
  Serial.println(F("| Hardware    : Arduino uno R4 Wifi and RFID UHF M6E nano shield                       |"));
  Serial.println(F("| Description : Scans for available tags. If tags are available, it reads the content. |"));
  Serial.println(F("|               If content is encoded using tracker protocol, it tries to verify the   |"));
  Serial.println(F("|               tag by decrypting the tag with ECC el-gamal, verifying the HMAC, and   |"));
  Serial.println(F("|               checking if tag followed a valid path. Tag database not implemented.   |"));
  Serial.println(F("----------------------------------------------------------------------------------------"));

  if (setupNano(115200) == false) // Configure nano to run at 38400bps
  {
    Serial.println("Module failed to respond. Please check wiring.");
    while (1)
      ; // Freeze!
  }

  nano.setRegion(REGION_AUSTRALIA); 

  nano.setReadPower(1800); // 5.00 dBm. Higher values may cause USB port to brown out
  // Max Read TX Power is 27.00 dBm and may cause temperature-limit throttling

  nano.setWritePower(1800); // 5.00 dBm. Higher values may cause USB port to brown out
  // Max Write TX Power is 27.00 dBm and may cause temperature-limit throttling
  uECC_set_rng(&RNG);
}

/*
Given a ciphertext C = (C1, C2), it decrypts using elgamal in ecc
Calculation: M = C2 - pk * C1
@C1: first ciphertext message in bytes (size: uECC_curve_num_bytes(curve) * 2)
@C2: second ciphertext message in bytes (size: uECC_curve_num_bytes(curve) * 2)
@M: plaintext byffer in bytes (size: uECC_curve_num_bytes(curve) * 2)
@curve: curve to be used
*/
void elgamalDecrypt(uint8_t *C1, uint8_t *C2, uint8_t *M, const uECC_Curve_t *curve)
{ 
  const uint8_t nrBytes = uECC_curve_num_bytes(curve);
  uint8_t tmp1[2 * nrBytes];
  uECC_point_mult_bytes(tmp1, C1, privKey, sizeof(privKey), curve);
  uECC_sub_points_bytes(M, C2, tmp1, curve);
}

/*
Tracker verify firmware
*/
void loop()
{
  // variables for storing data
  const uint16_t EPCSize = 16;
  byte EPC[EPCSize];

  // some strings for printing
  char str[256];
  char byteStr[128];
  char epcStr[32];

  // specify curve and set dataSize
  const struct uECC_Curve_t *curve = uECC_secp160r1();
  const uint8_t nrBytes = uECC_curve_num_bytes(curve);
  const uint8_t nrWords = uECC_curve_num_words(curve); // for example if wordsize is 4B and curve is 20B, we have 20 / 4 = 5 
  const uint8_t pointSize = uECC_curve_num_bytes(curve) * 2; // uncrompressed size of a point

  // data should be 240 bytes (not compressed)
  const uint8_t dataSize = 6 * pointSize;
  byte data[dataSize];

  // variables for storing tag data
  uint8_t cId[2][pointSize], cHash[2][pointSize], cPoly[2][pointSize]; 
  // variables for plaintext
  uint8_t ID[pointSize], hmacPlain[pointSize], poly[pointSize];
  // variables for storing the hash
  SHA256 hash = SHA256();
  uint8_t hmac[32];
  uint8_t hmacPoint[pointSize];


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
    nano.readDataWithFilterConfig(0x03, 0x00, dataReadConfig, dataReadFilter, true, 500);
    if (nano.response.nrTags > 0)
    {
      uint16_t dataLength = nano.response.getBankdata(0, data, dataSize);
      if(dataLength == dataSize)
      {
        Serial.print(F("User Bank: "));
        printBytes(data, dataLength);
        // every encryption has two messages
        for(uint8_t j = 0; j < 2; j++)
        {
          // copy into right buffers, not strictly necessary but enhances readability
          memcpy(cId[j], data + j * pointSize, pointSize);
          memcpy(cHash[j], data + (2 + j) * pointSize, pointSize);
          memcpy(cPoly[j], data + (4 + j) * pointSize, pointSize);
        }

        // check if it is a valid point
        if (uECC_valid_public_key(cId[0], curve) && uECC_valid_public_key(cHash[0], curve) && uECC_valid_public_key(cPoly[0], curve) && 
            uECC_valid_public_key(cId[1], curve) && uECC_valid_public_key(cHash[1], curve) && uECC_valid_public_key(cPoly[1], curve))
        {
          // decrypt ID
          elgamalDecrypt(cId[0], cId[1], ID, curve);
          bytesToHexString(ID, sizeof(ID), byteStr, sizeof(byteStr));
          snprintf(str, sizeof(str), "Decrypted ID: %s", byteStr);
          Serial.println(str);

          // place holder for DB identifier check
          if(true)
          {
            // decrypt hmac
            elgamalDecrypt(cHash[0], cHash[1], hmacPlain, curve);
            bytesToHexString(hmacPlain, sizeof(hmacPlain), byteStr, sizeof(byteStr));
            snprintf(str, sizeof(str), "Decrypted hash: %s", byteStr);
            Serial.println(str);

            // calculate HMAC
            hash.resetHMAC(k, strlen(k));
            hash.update(ID, nrBytes);
            hash.update(ID + nrBytes, nrBytes);
            hash.finalizeHMAC(k, strlen(k), hmac, sizeof(hmac));
            bytesToHexString(hmac, sizeof(hmac), byteStr, sizeof(byteStr));
            snprintf(str, sizeof(str), "Using key %s for HMAC-SHA256: %s", k, byteStr);
            Serial.println(str);

            // calculate digest(hmac) point
            uECC_point_mult_bytes(hmacPoint, P, hmac, sizeof(hmac), curve);

            // hmac check
            if(memcmp(hmacPlain, hmacPoint, pointSize) == 0)
            {
              // decrypt polynomial
              elgamalDecrypt(cPoly[0], cPoly[1], poly, curve);
              bytesToHexString(poly, sizeof(poly), byteStr, sizeof(byteStr));
              snprintf(str, sizeof(str), "Decrypted polynomial: %s", byteStr);
              Serial.println(str);

              // declare some memory for the product of valid_path with hmac
              uint8_t valid_path_hmac[pointSize];

              // check if path is valid
              uint16_t j;
              for(j = 0; j < nrPaths; j++) 
              {
                uECC_point_mult_bytes(valid_path_hmac, valid_paths[j], hmac, sizeof(hmac), curve);
                if(memcmp(valid_path_hmac, poly, pointSize) == 0)
                {
                  snprintf(str, sizeof(str), "Match found!\nTag followed path %s", valid_path_labels[j]);
                  Serial.println(str);
                  break;
                }
              }
              if(j == nrPaths)
              {
                Serial.println(F("No match found!"));
              }
            }
            else
            {
              Serial.println(F("HMAC could not be verified!"));
            }
          }
        }
        else 
        {
          Serial.println(F("Point could not be decoded!"));
        }
      }
      else 
      {
        Serial.println(F("Not enough bytes retrieved! Please make sure the tag is properly encoded according to the Tracker protocol."));
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
