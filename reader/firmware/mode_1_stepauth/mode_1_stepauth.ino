#include <SparkFun_UHF_RFID_Reader.h>
#include <uECC_vli.h>
#include <AES.h>
#include <HKDF.h>
#include <SHA256.h>

// include the settings for this mode
#include "settings.h"

RFID nano;

/*
very simple number generator
*/
static int RNG(uint8_t *dest, unsigned size)
{
    randomSeed(analogRead(0));
    for (unsigned i = 0; i < size; i++)
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
    Serial.println(F("| Title       : StepAuth Firmware                                                      |"));
    Serial.println(F("| Scheme      : StepAuth                                                               |"));
    Serial.println(F("| Mode        : Standard                                                               |"));
    Serial.println(F("| Version     : 1.0                                                                    |"));
    Serial.println(F("| Hardware    : Arduino uno R4 Wifi and RFID UHF M6E nano shield                       |"));
    Serial.println(F("| Description : Scans for available tags. If tags are available, it reads the content. |"));
    Serial.println(F("|               It tries to verify a DSA signature. If successful, it decrypts the     |"));
    Serial.println(F("|               message and checks if the first bytes match the reader's ID. If so,    |"));
    Serial.println(F("|               the tag is updated by removing the first bytes (reader and nextReader).|"));
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
Checks if byte array contains only zeros
*/
bool isZero(const uint8_t *buf, const uint16_t bufLen)
{
    for(uint16_t i = 0; i < bufLen; i++)
    {
        if(buf[i] != 0)
        {
            return false;
        }
    }
    return true;
}

/*
PKCS7 unpad function (for 16 bytes)
If encoded, buf should end with the amount of padding in bytes
Each byte of padding should have the same value
*/
bool unpad(const uint8_t * const buf, uint16_t &bufLen)
{
    // get amount of byte
    uint8_t paddingLen = buf[bufLen - 1];

    // should be between 0x01 and 0x10
    if(paddingLen >= 0x01 && paddingLen <= 0x10)
    {   
        // check if other padding bytes have the same  value
        for(uint16_t i = 1; i < paddingLen; i++)
        {
            if(buf[bufLen - i - 1] != paddingLen)
            {
                return false;
            }
        }
        bufLen -= paddingLen;
        return true;
    }
    return false;
}

/*
AES decrypt:
ECB mode is not supported by default, so created a function that decrypt all blocks
Notice, blocksize is always 16 bytes, even with AES256
Also notice, we assume input is block aligned
*/
 void decryptAES(uint8_t *output, const uint8_t *input, const uint16_t len, AESCommon &cipher)
 {
     uint16_t posn = 0;
     while (posn < len) 
     {
         cipher.decryptBlock(output + posn, input + posn);
         posn += 16;
     }
 }


/*
ecies decryption consists of two steps:
1. obtaining the shared key 
2. decrypt ciphertext with AES256-ECB

c should be {R, ciphertext} (NO AUTH MSG!)
R is used for deriving the symmetric key k (point on curve)
ciphertext is encrypted with AES256-ECB using key k

Shared point is S = R + P where R = r * G(enerator) and P = r * pk 
*/
void eciesDecrypt(uint8_t * const m, uint16_t &mLen, const uint8_t *c, const uint16_t cLen, const uECC_Curve_t *curve)
{
    // get number of bytes for curve and set up some variables
    const uint8_t nrBytes = uECC_curve_num_bytes(curve);
    uint8_t S[4 * nrBytes + 2], P[2 * nrBytes], key[32];

    // make sure they point to the right address
    const uint8_t *R = c;
    const uint8_t *ciphertext = c + 2 * nrBytes;
    
    // calculate S = [R, P] (concat)
    uECC_point_mult_bytes(P, R, privKey, sizeof(privKey), curve);
    S[0] = 0x04;
    S[2 * nrBytes + 1] = 0x04;
    memcpy(S + 1, R, 2 * nrBytes);
    memcpy(S + 2 * nrBytes + 2, P, 2 * nrBytes);
    if(!isZero(P, sizeof(P)))
    {
        // derive key
        HKDF<SHA256> hkdf;
        hkdf.setKey(S, sizeof(S));
        hkdf.extract(key, sizeof(key));
        printBytes(key, sizeof(key));

        // decrypt using key
        AES256 cipher = AES256();
        cipher.setKey(key, sizeof(key));
        decryptAES(m, c + 2 * nrBytes, cLen - 2 * nrBytes, cipher);   
        unpad(m, mLen);
    }
    else 
    {
        Serial.println(F("Point P is at infinity!"));
    }
}

/*

*/
void loop()
{
    // variables for storing data
    const uint16_t EPCSize = 16;
    byte EPC[EPCSize];
    char str[256];

    // specify curve and set dataSize (NOTE: sizes should be the same!)
    const struct uECC_Curve_t *curveEnc = uECC_secp256k1(); 
    const struct uECC_Curve_t *curveSig = uECC_secp256r1();
    const uint8_t nrBytes = uECC_curve_num_bytes(curveSig);
    const uint8_t nrNBytes = uECC_curve_num_n_bytes(curveSig);

    // check key sizes
    if(sizeof(privKey) != nrNBytes || sizeof(pubKeyIssuer) != 2 * nrBytes)
    {   
        Serial.println(F("Make sure that privkey and public key are the right size!"));
        exit(0);
    }

    // create some space for the data
    const uint16_t dataSize = 2048;
    byte data[dataSize];

    // variables for storing tag data
    const uint16_t sigSize = 2 * nrBytes;
    uint8_t sig[sigSize];

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
            uint16_t dataLength = nano.response.getBankdata(0, data, dataSize);
            if(dataLength >= 2)
            {
                Serial.print(F("User Bank: "));
                printBytes(data, dataLength);
                uint16_t cLen = data[0] << 8 | data[1];

                // if size is to small, assume it has already finished
                if(cLen <= dataSize && cLen <= 16) 
                {
                    Serial.println(F("Not enough data, assuming it finished!"));
                }
                // assume that it is encrypted
                else if(cLen <= dataSize)
                {
                    // everything except signature is used for ecies
                    uint16_t eciesLen = cLen - sigSize;

                    // print some info
                    snprintf(str, sizeof(str), "Total message length: %d\ECIES length: %d\nSignature length: %d", cLen, eciesLen, sigSize);
                    Serial.println(str);

                    // get signature in buffer
                    memcpy(sig, data + 2 + eciesLen, sigSize);

                    // calculate hash of the message
                    SHA256 hash = SHA256();
                    uint8_t digest[32];
                    hash.reset();
                    hash.update(data + 2, eciesLen);
                    hash.finalize(digest, sizeof(digest));
                    Serial.print(F("Hash: "));
                    printBytes(digest, sizeof(digest));

                    Serial.print(F("Public key: "));
                    printBytes(pubKeyIssuer, sizeof(pubKeyIssuer));

                    Serial.print(F("Signature: "));
                    printBytes(sig, sizeof(sig));

                    // check signature
                    if(uECC_verify(pubKeyIssuer, digest, sizeof(digest), sig, curveSig))
                    {
                        // decrypt using ECIES
                        uint16_t msgLen = eciesLen;
                        uint8_t m[msgLen];
                        eciesDecrypt(m, msgLen, data + 2, msgLen, curveEnc);
                        snprintf(str, sizeof(str), "Message length: %d\nMessage: ", msgLen);
                        Serial.print(str);
                        printBytes(m, msgLen);

                        // check if encryption was valid
                        if(memcmp(m, readerId, readerIdSize) == 0)
                        {
                            if(memcmp(m + readerIdSize, readerId, readerIdSize) == 0)
                            {
                                Serial.println(F("Tag has finished its path!"));
                            }
                            else
                            {
                                Serial.println(F("Updating tag"));
                            }
                            // write new message to tag by removing first 2 * readerIdSize bytes from m (include length)
                            TagFilter filter = nano.initEPCWriteFilter(EPC, EPCLength);
                            uint8_t *newC = m + 2 * readerIdSize - 2;
                            uint16_t newCLen = msgLen - 2 * readerIdSize;
                            newC[0] = newCLen >> 8;
                            newC[1] = newCLen;
                            if(nano.writeDataWithFilter(0x03, 0x00, newC, newCLen + 2, filter))
                            {
                                Serial.print(F("Succesfully updated tag content to: "));
                                printBytes(newC, newCLen + 2);
                            }
                            else
                            {
                                Serial.println(F("Writing data failed!"));
                            }
                        }
                        else
                        {
                            Serial.println(F("Could not decrypt tag content. Make sure you have the right reader!"));
                        }
                    }
                    else
                    {
                        Serial.println(F("Signature could not be verified!"));
                    }
                }
                else
                {
                    Serial.println(F("Specified message size is to large for buffer!"));
                }
            }
            else 
            {
                Serial.println(F("Tag does not have enough memory!"));
            }
        }
        else
        {
            Serial.println(F("Could not find tag!"));
        }
    }
    while (!Serial.available())
        ;
    Serial.readString();
    while (Serial.available() > 0)
        Serial.read();
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
