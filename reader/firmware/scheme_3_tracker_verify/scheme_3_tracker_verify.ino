#include <uECC_vli.h>
#include <SHA256.h>

#include "helpers.h"

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

    // specify curve and set dataSize
    const struct uECC_Curve_t *curve = uECC_secp160r1();
    const uint8_t nrBytes = uECC_curve_num_bytes(curve);
    const uint8_t nrWords = uECC_curve_num_words(curve);       // for example if wordsize is 4B and curve is 20B, we have 20 / 4 = 5
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
        bufLen = snprintf(buf, sizeof(buf), "Found Tag: ");
        bufLen += bytesToHexString(EPC, EPCLength, buf + bufLen, sizeof(buf) - bufLen);
        print(buf);

        // read tag data into data
        dataReadFilter = nano.initEPCSingleReadFilter(EPC, EPCLength);
        nano.readDataWithFilterConfig(0x03, 0x00, dataReadConfig, dataReadFilter, true, 500);
        if (nano.response.nrTags > 0)
        {
            uint16_t dataLength = nano.response.getBankdata(0, data, dataSize);
            if (dataLength == dataSize)
            {
                // print content
                bufLen = snprintf(buf, sizeof(buf), "User Bank: ");
                bufLen += bytesToHexString(data, dataLength, buf + bufLen, sizeof(buf) - bufLen);
                //print(buf);
                sendToMQTT(buf);
                printSerial(buf);

                // every encryption has two messages
                for (uint8_t j = 0; j < 2; j++)
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
                    bufLen = snprintf(buf, sizeof(buf), "Decrypted ID: ");
                    bufLen += bytesToHexString(ID, sizeof(ID), buf + bufLen, sizeof(buf) - bufLen);
                    printSerial(buf);

                    // place holder for DB identifier check
                    if (true)
                    {
                        // decrypt hmac
                        elgamalDecrypt(cHash[0], cHash[1], hmacPlain, curve);
                        bufLen = snprintf(buf, sizeof(buf), "Decrypted hash: ");
                        bufLen += bytesToHexString(hmacPlain, sizeof(hmacPlain), buf + bufLen, sizeof(buf) - bufLen);
                        printSerial(buf);

                        // calculate HMAC
                        hash.resetHMAC(k, strlen(k));
                        hash.update(ID, nrBytes);
                        hash.update(ID + nrBytes, nrBytes);
                        hash.finalizeHMAC(k, strlen(k), hmac, sizeof(hmac));
                        bufLen = snprintf(buf, sizeof(buf), "Using key %s for HMAC-SHA256: ", k);
                        bufLen += bytesToHexString(hmac, sizeof(hmac), buf + bufLen, sizeof(buf) - bufLen);
                        printSerial(buf);

                        // calculate digest(hmac) point
                        uECC_point_mult_bytes(hmacPoint, P, hmac, sizeof(hmac), curve);

                        // hmac check
                        if (memcmp(hmacPlain, hmacPoint, pointSize) == 0)
                        {
                            // decrypt polynomial
                            elgamalDecrypt(cPoly[0], cPoly[1], poly, curve);
                            bufLen = snprintf(buf, sizeof(buf), "Decrypted polynomial: ");
                            bufLen += bytesToHexString(poly, sizeof(poly), buf + bufLen, sizeof(buf) - bufLen);
                            printSerial(buf);

                            // declare some memory for the product of valid_path with hmac
                            uint8_t valid_path_hmac[pointSize];

                            // check if path is valid
                            uint16_t j;
                            for (j = 0; j < nrPaths; j++)
                            {
                                uECC_point_mult_bytes(valid_path_hmac, valid_paths[j], hmac, sizeof(hmac), curve);
                                if (memcmp(valid_path_hmac, poly, pointSize) == 0)
                                {
                                    snprintf(buf, sizeof(buf), "Match found!\nTag followed path %s", valid_path_labels[j]);
                                    print(buf);
                                    break;
                                }
                            }
                            if (j == nrPaths)
                            {
                                print("No match found!");
                            }
                        }
                        else
                        {
                            print("HMAC could not be verified!");
                        }
                    }
                }
                else
                {
                   print("Point could not be decoded!");
                }
            }
            else
            {
                print("Not enough bytes retrieved! Please make sure the tag is properly encoded according to the Tracker protocol.");
            }
        }
        else
        {
            print("Could not find tag!");
        }
    }
    delay(1000);
}