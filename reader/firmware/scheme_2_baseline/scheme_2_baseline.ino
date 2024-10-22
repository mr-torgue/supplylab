/*
Date: 11-09-2024
Author: Folmer Heikamp
Board: Arduino Uno R4 Wifi
Requires:  UHF m6e nano shield

For this mode to work:
(1) the settings header should have a shared secret key of 16 bytes in hexadecimal format
(2) the tag secret should be encrypted with this key in GCM mode, 16 bytes IV, 16 bytes tag, rest is ciphertext
The tag secret is defined as follows: IV (16 bytes) || tag (16 bytes) || Enc(k, t || r1 || ... || rn) (variable length)
We assume each ID (t/r) is 4 bytes.
The reader verifies and updates the tag.
*/

#include <AES.h>
#include <GCM.h>
#include <RNG.h>
#include <TransistorNoiseSource.h>

// include the settings for this mode
#include "helpers.h"

TransistorNoiseSource noise(A1);

void setup()
{
    setupClockPrintersReaders();
    RNG.begin("Baseline Random Number Generator");
    RNG.addNoiseSource(noise);
}
/*
main loop
*/
void loop()
{
    // setup cipher in gcm mode
    GCM<AES256> gcm;
    gcm.setKey(sharedKey, sizeof(sharedKey));

    // variables for storing data
    uint16_t EPCSize = 16;
    byte EPC[EPCSize];
    const uint16_t dataSize = 2048;
    byte data[dataSize];
    uint16_t metadataRawSize = 512;
    uint8_t metadataRaw[metadataRawSize];
    int metadataSize = 512;
    char metadata[metadataSize];

    // declare configuration and filter for reading tag content
    ReadConfig dataReadConfig = nano.initStandardReadTagDataOnce();
    TagFilter dataReadFilter;

    // read for tags
    nano.readMultipleTags();

    // only if tags were found
    for (uint8_t i = 0; i < nano.response.nrTags; i++)
    {
        uint16_t EPCLength = nano.response.getEPCdata(i, EPC, EPCSize);
        int metadataLength = nano.response.metadataToJsonString(i, metadata, metadataSize);
        bufLen = snprintf(buf, sizeof(buf), "Found Tag: ");
        bufLen += bytesToHexString(EPC, EPCLength, buf + bufLen, sizeof(buf) - bufLen);
        print(buf);

        // read tag data into data
        dataReadFilter = nano.initEPCSingleReadFilter(EPC, EPCLength);
        nano.readDataWithFilterConfig(0x03, 0x00, dataReadConfig, dataReadFilter, true, 1000);
        if (nano.response.nrTags > 0)
        {
            uint16_t dataLength = nano.response.getBankdata(0, data, dataSize);
            if (dataLength >= 2)
            {
                uint16_t msgLength = data[0] << 8 | data[1];
                if(msgLength + 2 <= dataLength)
                {
                    // print the buffer to mqtt and serial
                    bufLen = snprintf(buf, sizeof(buf), "Raw Embedded Data(encrypted): ");
                    bufLen += bytesToHexString(data, msgLength + 2, buf + bufLen, sizeof(buf) - bufLen);
                    sendToMQTT(buf);
                    printSerial(buf);

                    // decrypt the tag content
                    uint16_t plaintextLength = msgLength - 32;
                    uint8_t plaintext[plaintextLength];
                    gcm.setIV(data + 2, 16);
                    gcm.decrypt(plaintext, data + 34, plaintextLength);

                     // check if the tag matches the message
                    if (gcm.checkTag(data + 18, 16))
                    {
                        uint32_t tagId = plaintext[0] << 24 | plaintext[1] << 16 | plaintext[2] << 8 | plaintext[3];
                        bufLen = snprintf(buf, sizeof(buf), "Found new tag %d with content ", tagId);
                        bufLen += bytesToHexString(plaintext, plaintextLength, buf + bufLen, sizeof(buf) - bufLen);
                        print(buf);

                        // create new plaintext
                        uint16_t plaintextNewLength = plaintextLength + 4;
                        uint8_t plaintextNew[plaintextLength + 4];
                        memcpy(plaintextNew, plaintext, plaintextLength);
                        memcpy(plaintextNew + plaintextLength, readerIdBytes, 4);

                        // encrypt with a new IV (not entirely random)
                        uint8_t ciphertext[plaintextNewLength + 34];
                        RNG.rand(ciphertext + 2, 16);
                        gcm.setIV(ciphertext + 2, 16);
                        gcm.encrypt(ciphertext + 34, plaintextNew, plaintextNewLength);
                        gcm.computeTag(ciphertext + 18, 16);

                        // set new length
                        ciphertext[0] = (plaintextNewLength + 32) >> 8;
                        ciphertext[1] = plaintextNewLength + 32;

                        // write to tag
                        TagFilter filter = nano.initEPCWriteFilter(EPC, EPCLength);
                        if(nano.writeDataWithFilter(0x03, 0x00, ciphertext, sizeof(ciphertext), filter))
                        {
                            bufLen = snprintf(buf, sizeof(buf), "Succesfully updated tag content!");
                            printScreen(buf);
                            bufLen = snprintf(buf, sizeof(buf), "Succesfully updated tag content to: ");
                            bufLen += bytesToHexString(ciphertext, sizeof(ciphertext), buf + bufLen, sizeof(buf) - bufLen);
                            printSerial(buf);
                            sendToMQTT(buf);
                        }
                        else
                        {
                            print("Writing data failed!");
                        }
                    }
                    else
                    {
                        print("Could not verify tag!");
                    }
                }
                else
                {
                    print("Message length too large!");
                }
            }
            else
            {
                print("Not enough data!");
            }
        }
    }    
    // important, makes sure it stays random
    RNG.loop();
    delay(1000);
}
