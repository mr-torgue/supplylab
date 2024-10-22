#include <uECC_vli.h>
#include <AES.h>
#include <HKDF.h>
#include <SHA256.h>

// include the settings for this mode
#include "helpers.h"

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
    setupClockPrintersReaders();
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
        print("Point P is at infinity!");
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
        print("Make sure that privkey and public key are the right size!");
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
        bufLen = snprintf(buf, sizeof(buf), "Found Tag: ");
        bufLen += bytesToHexString(EPC, EPCLength, buf + bufLen, sizeof(buf) - bufLen);
        print(buf);

        // read tag data into data
        dataReadFilter = nano.initEPCSingleReadFilter(EPC, EPCLength);
        nano.readDataWithFilterConfig(0x03, 0x00, dataReadConfig, dataReadFilter, true, 1000);
        if (nano.response.nrTags > 0)
        {
            uint16_t dataLength = nano.response.getBankdata(0, data, dataSize);
            if(dataLength >= 2)
            {
                // print user bank
                bufLen = snprintf(buf, sizeof(buf), "User Bank: ");
                bufLen += bytesToHexString(data, dataLength, buf + bufLen, sizeof(buf) - bufLen);
                sendToMQTT(buf);
                printSerial(buf);

                uint16_t cLen = data[0] << 8 | data[1];

                // if size is to small, assume it has already finished
                if(cLen <= dataSize && cLen <= 16) 
                {
                    print("Not enough data, assuming it finished!");
                }
                // assume that it is encrypted
                else if(cLen <= dataSize)
                {
                    // everything except signature is used for ecies
                    uint16_t eciesLen = cLen - sigSize;

                    // print some info
                    //snprintf(str, sizeof(str), "Total message length: %d\ECIES length: %d\nSignature length: %d", cLen, eciesLen, sigSize);
                    //Serial.println(str);

                    // get signature in buffer
                    memcpy(sig, data + 2 + eciesLen, sigSize);

                    // calculate hash of the message
                    SHA256 hash = SHA256();
                    uint8_t digest[32];
                    hash.reset();
                    hash.update(data + 2, eciesLen);
                    hash.finalize(digest, sizeof(digest));

                    // check signature
                    if(uECC_verify(pubKeyIssuer, digest, sizeof(digest), sig, curveSig))
                    {
                        // decrypt using ECIES
                        uint16_t msgLen = eciesLen;
                        uint8_t m[msgLen];
                        eciesDecrypt(m, msgLen, data + 2, msgLen, curveEnc);
                        // print message
                        bufLen = snprintf(buf, sizeof(buf), "Message length: %d\nMessage: ", msgLen);
                        bufLen += bytesToHexString(m, msgLen, buf + bufLen, sizeof(buf) - bufLen);
                        printSerial(buf);
                        sendToMQTT(buf);


                        // check if encryption was valid
                        if(memcmp(m, readerIdBytes, readerIdSize) == 0)
                        {
                            if(memcmp(m + readerIdSize, readerIdBytes, readerIdSize) == 0)
                            {
                                print("Tag has finished its path!");
                            }
                            else
                            {
                                print("Updating tag");
                            }
                            // write new message to tag by removing first 2 * readerIdSize bytes from m (include length)
                            TagFilter filter = nano.initEPCWriteFilter(EPC, EPCLength);
                            uint8_t *newC = m + 2 * readerIdSize - 2;
                            uint16_t newCLen = msgLen - 2 * readerIdSize;
                            newC[0] = newCLen >> 8;
                            newC[1] = newCLen;
                            if(nano.writeDataWithFilter(0x03, 0x00, newC, newCLen + 2, filter))
                            {
                                bufLen = snprintf(buf, sizeof(buf), "Succesfully updated tag content!");
                                printScreen(buf);
                                bufLen = snprintf(buf, sizeof(buf), "Succesfully updated tag content to: ");
                                bufLen += bytesToHexString(newC, newCLen + 2, buf + bufLen, sizeof(buf) - bufLen);
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
                            print("Could not decrypt tag content. Make sure you have the right reader!");
                        }
                    }
                    else
                    {
                        print("Signature could not be verified!");
                    }
                }
                else
                {
                    print("Specified message size is to large for buffer!");
                }
            }
            else 
            {
                print("Tag does not have enough memory!");
            }
        }
        else
        {
            print("Could not find tag!");
        }
    }
    delay(1000);
}