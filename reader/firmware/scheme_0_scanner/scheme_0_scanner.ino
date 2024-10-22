/*
Date: 11-09-2024
Author: Folmer Heikamp
Board: Arduino Uno R4 Wifi
Requires:  UHF m6e nano shield

Scanner simply scans for tags and then reads tag contents.
Uses the SSD1306/SSD1327 screen module, WiFi, and MQTT.
*/

#include "helpers.h"

/*
setup the whole system
*/
void setup()
{
    setupClockPrintersReaders();
}

/*
Keeps searching for tags and sends message if found
*/
void loop()
{
    // variables for storing epc data
    const uint16_t EPCSize = 16;
    byte EPC[EPCSize];
    char strEPC[2 * EPCSize];

    // create some space for the memory bank
    const uint16_t dataSize = 2048;
    byte data[dataSize];

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
        bufLen = snprintf(buf, sizeof(buf), "Found Tag: ");
        bufLen += bytesToHexString(EPC, EPCLength, buf + bufLen, sizeof(buf) - bufLen);
        print(buf);
    }
    delay(1000);
}