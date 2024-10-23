/*
Date: 01-10-2024
Author: Folmer Heikamp
Board: Arduino Uno R4 Wifi
Requires:  UHF m6e nano shield

Implements RF-Chain
*/

#include <SHA256.h>
#include <uECC_vli.h>
#include <AES.h>
#include <GCM.h>
#include <MySQL_Connection.h>
#include <MySQL_Cursor.h>

#include "helpers.h"

// mysql server settings
IPAddress server_addr(192,168,0,100);  // IP of the MySQL *server* here
char user[] = "user";              // MySQL user login username
char password[] = "password";        // MySQL user login password
MySQL_Connection conn((Client *)&wifiClient);
const struct uECC_Curve_t *curve = uECC_secp256r1();

static int RNG(uint8_t *dest, unsigned size)
{
    randomSeed(analogRead(0));
    for (unsigned i = 0; i < size; i++)
    {
        dest[i] = random(256);
    }
    return 1;
}

/*
setup the whole system
*/
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
PKCS7 pad function (16 bytes)
We assume output has enough space for an extra block
*/
bool pad(const uint8_t * const input, uint16_t inputLen, uint8_t *output, uint16_t &outputLen) 
{
    uint8_t padValue = 16 - (inputLen % 16);
    
    // check if it fits in the output buffer
    if(inputLen + padValue > outputLen)
        return false;

    // add padding and change outputLen
    memcpy(output, input, inputLen);
    memset(output + inputLen, padValue, padValue);
    outputLen = inputLen + padValue;
    return true;
}

/*
Calculates the xor for two byte arrays of length len
*/
void xorBytes(const uint8_t * const a, const uint16_t aLen, const uint8_t * const b, const uint16_t bLen, uint8_t *output, const uint16_t len)
{
    if(len >= bLen && len >=aLen)
    {
        uint16_t diff = 0;
        uint16_t offsetA = 0;
        uint16_t offsetB = 0;
        // if b is larger, first bytes will be copied from b
        if(bLen > aLen)
        {
            diff = bLen - aLen;
            offsetA = diff;
            for(uint16_t i = 0; i < diff; i++)
            {
                output[i] = b[i];
            }
        }   
        
        // idem for a
        if(aLen > bLen)
        {
            diff = aLen - bLen;
            offsetB = diff;
            for(uint16_t i = 0; i < diff; i++)
            {
                output[i] = a[i];
            }
        }   

        // xor the rest
        for(uint16_t i = diff; i < len; i++)
        {
            output[i] = a[i - offsetA] ^ b[i- offsetB];
        }
    }
}

/*
AES decrypt:
ECB mode is not supported by default, so created a function that decrypt all blocks
Notice, blocksize is always 16 bytes, even with AES256
Also notice, we assume input is block aligned
*/
void decryptAES(uint8_t *output, const uint8_t *input, const uint16_t len, const uint8_t * const key, const uint16_t keyLen)
{
    AES256 cipher = AES256();
    cipher.setKey(key, keyLen);
    uint16_t posn = 0;
    while (posn < len) 
    {
        cipher.decryptBlock(output + posn, input + posn);
        posn += 16;
    }
}

/*
 AES encrypt using ECB mode.
 Automatically pads using PCKS7
 Assumes output buffer is large enough
 */
void encryptAES(uint8_t *output, uint16_t &outputLen, const uint8_t * const input, const uint16_t len, const uint8_t * const key, const uint16_t keyLen)
{
    AES256 cipher = AES256();
    cipher.setKey(key, keyLen);
    uint16_t paddedInputLen = len + 16;
    uint8_t paddedInput[paddedInputLen];
    // only encrypt when padding is successfull
    if(pad(input, len, paddedInput, paddedInputLen) && outputLen >= paddedInputLen)
    {
        uint16_t posn = 0;
        while (posn < paddedInputLen) 
        {
            cipher.encryptBlock(output + posn, paddedInput + posn);
            posn += 16;
        }
        outputLen = paddedInputLen;
    }
}

/*
Converts a hex string into a byte array
b needs to be at least half the length of hex
*/
bool hexStringToBytes(const char * const hex, uint8_t *b, uint16_t &bLen)
{
    uint16_t len = strlen(hex);
    // check if b has enough space
    if(bLen >= len / 2)
    {
        char hexbyte[2];
        for(uint16_t i = 0; i < len; i+=2)
        {
            memcpy(hexbyte, hex + i, 2);
            b[i/2] = strtol(hexbyte, NULL, 16);
        }
        bLen = len / 2;
        return true;
    }
    else
    {
        return false;
    }
}

/*
Updates according to the RF-Chain scheme
Both data and plaintext will be changed
*/
bool update(uint8_t *data, const uint16_t dataLen, uint8_t *EPC, uint16_t EPCLength, uint8_t *plaintext, const uint16_t plaintextLen)
{
    uint16_t IDLen = 4, nonceLen = 16, tagLen = 16, aLen = 2 * curveSizeBytes;
    uint8_t *ID = data;
    uint8_t *nonce = data + IDLen;
    uint8_t *tag = data + IDLen + nonceLen;
    uint8_t *ciphertext = data + IDLen + nonceLen + tagLen;
    uint8_t *a = data + IDLen + nonceLen + tagLen + plaintextLen;
    uint8_t *h = plaintext;

    bufLen = snprintf(buf, sizeof(buf), "plaintext(%d): ", plaintextLen);
    bufLen += bytesToHexString(plaintext, plaintextLen, buf + bufLen, sizeof(buf) - bufLen);
    printSerial(buf);

    bufLen = snprintf(buf, sizeof(buf), "h: ");
    bufLen += bytesToHexString(h, 22, buf + bufLen, sizeof(buf) - bufLen);
    printSerial(buf);

    // create new hi by changing index
    uint16_t index = h[20] << 8 | h[21];
    index++;
    h[20] = index >> 8;
    h[21] = index;

    bufLen = snprintf(buf, sizeof(buf), "h: ");
    bufLen += bytesToHexString(h, 22, buf + bufLen, sizeof(buf) - bufLen);
    printSerial(buf);

    // create a new ki         
    uint8_t ki[32];
    SHA256 hash = SHA256();
    hash.reset();
    hash.update(h, 22);
    hash.finalize(ki, sizeof(ki));

    bufLen = snprintf(buf, sizeof(buf), "ki(%d): ", sizeof(ki));
    bufLen += bytesToHexString(ki, 32, buf + bufLen, sizeof(buf) - bufLen);
    printSerial(buf);

    bufLen = snprintf(buf, sizeof(buf), "a(%d): ", aLen);
    bufLen += bytesToHexString(a, aLen, buf + bufLen, sizeof(buf) - bufLen);
    printSerial(buf);

    // create new IDi
    uint16_t IDiLen = 16;
    char IDiHex[2 * IDiLen + 1];
    uint8_t IDi[IDiLen];
    encryptAES(IDi, IDiLen, ID, IDLen, ki, sizeof(ki));
    bytesToHexString(IDi, IDiLen, IDiHex, sizeof(IDiHex));

    // create new value for b                
    uint16_t bLen = 2 * curveSizeBytes;
    char bHex[bLen * 2 + 1];
    uint8_t b[bLen];
    xorBytes(a, aLen, ki, sizeof(ki), b, aLen);
    bytesToHexString(b, bLen, bHex, sizeof(bHex));

    bufLen = snprintf(buf, sizeof(buf), "Going to sign a(%d): ", aLen);
    bufLen += bytesToHexString(a, aLen, buf + bufLen, sizeof(buf) - bufLen);
    printSerial(buf);

    // hash ai and sign it
    uint8_t digest[32];
    hash.reset();
    hash.update(a, aLen);
    hash.finalize(digest, sizeof(digest));

    bufLen = snprintf(buf, sizeof(buf), "hash(a): ");
    bufLen += bytesToHexString(digest, sizeof(digest), buf + bufLen, sizeof(buf) - bufLen);
    printSerial(buf);

    if(!uECC_sign(privKey, digest, sizeof(digest), a, curve))
    {
        print("Could not create new a!");
        return false;
    }
    bufLen = snprintf(buf, sizeof(buf), "new a: ");
    bufLen += bytesToHexString(a, aLen, buf + bufLen, sizeof(buf) - bufLen);
    printSerial(buf);

    // create new data to be written to tag
    RNG(nonce, nonceLen);
    GCM<AES256> gcm;
    gcm.setKey(k, sizeof(k));
    gcm.setIV(nonce, nonceLen);
    gcm.encrypt(ciphertext, plaintext, plaintextLen); 
    gcm.computeTag(tag, tagLen);                   


    bufLen = snprintf(buf, sizeof(buf), "ciphertext: ");
    bufLen += bytesToHexString(ciphertext, plaintextLen, buf + bufLen, sizeof(buf) - bufLen);
    printSerial(buf);

    bool success = true;
    // write new secret to mysql
    char query[256];
    snprintf(query, sizeof(query), "INSERT INTO RFChain.TagDB (tagID, b, reader) VALUES ('%s', '%s', %d)", IDiHex, bHex, readerId);
    printSerial(query);
    sendToMQTT(query);
    if(conn.connect(server_addr, 3306, user, password))
    {
        MySQL_Cursor *cur_mem = new MySQL_Cursor(&conn);
        cur_mem->execute(query);
        delete cur_mem;

        // write new secret to tag
        // we do it here because an extra online secret does not matter too much
        TagFilter filter = nano.initEPCWriteFilter(EPC, EPCLength);
        if (nano.writeDataWithFilter(0x03, 0x00, data, dataLen, filter))
        {
            bufLen = snprintf(buf, sizeof(buf), "Succesfully updated tag content!");
            printScreen(buf);
            bufLen = snprintf(buf, sizeof(buf), "Succesfully updated tag content to: ");
            bufLen += bytesToHexString(data, dataLen, buf + bufLen, sizeof(buf) - bufLen);
            printSerial(buf);
            sendToMQTT(buf);
        }
        else
        {
            print("Writing data failed!");
            success = false;
        }
    }
    else 
    {
        print("Could not connect to database!");
        success = false;        
    }
    conn.close();
    return success;
}

/*
Verifies if the data on the tag is encoded according to the RF-Chain specs
Assuming AES256, SHA256, and P256, the format should be:
  ID(4) || nonce(16) || tag(16) || c(96) || a(64)
  c = E(k, h(22) || m(10) || S(64))
*/
bool verify(const uint8_t *data, const uint16_t dataLen, uint8_t *plaintext, uint16_t plaintextLen)
{
    if(dataLen == 196 && plaintextLen == 96)
    {
        // we use new pointers for convenience
        uint16_t IDLen = 4, nonceLen = 16, tagLen = 16, ciphertextLen = 96, aLen = 64;
        const uint8_t *ID = data;
        const uint8_t *nonce = data + IDLen;
        const uint8_t *tag = data + IDLen + nonceLen;
        const uint8_t *ciphertext = data + IDLen + nonceLen + tagLen;
        const uint8_t *a = data + IDLen + nonceLen + tagLen + ciphertextLen;

        // set up crypto objects
        GCM<AES256> gcm;
        SHA256 hash = SHA256();

        // decrypt shared reader message
        gcm.setKey(k, sizeof(k));
        gcm.setIV(nonce, nonceLen);
        gcm.decrypt(plaintext, ciphertext, ciphertextLen);
        if (gcm.checkTag(tag, tagLen)) 
        {
            // Plaintext should be in the following format:
            // h  : 0-22 (22 bytes)
            // m  : 22-32 (10 bytes)
            // S  : 32-96 (64 bytes) (ECDSA signature)
            uint16_t hLen = 22, mLen = 10, SLen = 2 * curveSizeBytes;   
            uint8_t *h = plaintext;
            uint8_t *m = plaintext + hLen;
            uint8_t *S = plaintext + hLen + mLen;
            uint16_t index = h[hLen - 2] << 8 | h[hLen - 1];
            uint16_t producer = m[0] << 8 | m[1];

            // check message signature
            uint8_t digest[32];
            hash.reset();
            hash.update(m, mLen);
            hash.finalize(digest, sizeof(digest));

            if(producer < nrReaders && uECC_verify(pubKeys[producer], digest, sizeof(digest), S, curve))
            {
                char query[128];
                char bHex[4 * curveSizeBytes]; // x4 because hex
                uint16_t bLen = 2 * curveSizeBytes;
                uint8_t b[bLen];
                uint8_t ai[aLen];
                memcpy(ai, a, aLen);

                // verify all the way to index 1
                for(uint8_t i = index; i > 0; i--)
                {   
                    bufLen = sprintf(buf, "Verifying i=%d", i);
                    printSerial(buf);
                    // create new hi
                    uint8_t hi[hLen];
                    memcpy(hi, h, hLen);
                    hi[hLen - 2] = i << 8;
                    hi[hLen - 1] = i;

                    // generate ki from hi               
                    uint8_t ki[32];
                    hash.reset();
                    hash.update(hi, sizeof(hi));
                    hash.finalize(ki, sizeof(ki));


                    // get IDi value
                    uint16_t IDiLen = 16;
                    char IDiHex[2 * IDiLen + 1];
                    uint8_t IDi[IDiLen];
                    encryptAES(IDi, IDiLen, ID, IDLen, ki, sizeof(ki));
                    bytesToHexString(IDi, IDiLen, IDiHex, 64);
                    uint16_t lastReader;

                    // use the hex value
                    snprintf(query, sizeof(query), "SELECT reader, b FROM RFChain.TagDB WHERE tagID = '%s' LIMIT 1", IDiHex);
                    printSerial(query);
                    sendToMQTT(query);
                    if(conn.connect(server_addr, 3306, user, password))
                    {
                        MySQL_Cursor *cur_mem = new MySQL_Cursor(&conn);
                        cur_mem->execute(query);
                        // get row
                        column_names *columns = cur_mem->get_columns();
                        row_values *row = cur_mem->get_next_row();
                        conn.close();
                        if (row != NULL) 
                        {
                            // get lastreader and b value
                            lastReader = strtol(row->values[0], NULL, 10);
                            strcpy(bHex, row->values[1]);   
                            hexStringToBytes(bHex, b, bLen);
                            bufLen = snprintf(buf, sizeof(buf), "bHex: %s", bHex);
                            printSerial(buf);

                            // calculate a[i-1]
                            uint8_t ai_1[2 * curveSizeBytes];

                            // signature over a 32 bytes hash (SHA256)
                            if(index == 1)
                            {
                                xorBytes(b, bLen, ki, sizeof(ki), ai_1, curveSizeBytes);
                                hash.update(ai_1, curveSizeBytes);
                                hash.finalize(digest, sizeof(digest));
                                // ai_1 should be SHA256(ID||f||pwd||r)
                                // ID is already given
                                // f   : bytes 4-8 of hi
                                // pwd : bytes 8-16 of hi
                                // r   : bytes 16-20 of hi
                                // so, it is the first 20 bytes of hi
                                uint8_t *a0digest[32];
                                hash.reset();
                                hash.update(hi, 20);
                                hash.finalize(a0digest, sizeof(a0digest));
                                if(memcmp(ai_1, a0digest, 32) != 0)
                                {
                                    print("Could not verify a0 hash!");
                                    return false;
                                }

                            }
                            // signature over a 64 bytes signature
                            else 
                            {
                                xorBytes(b, bLen, ki, sizeof(ki), ai_1, 2 * curveSizeBytes);
                                // prepare hash
                                hash.reset();
                                hash.update(ai_1, 2 * curveSizeBytes);
                                hash.finalize(digest, sizeof(digest));
                            }

                            bufLen = snprintf(buf, sizeof(buf), "a-1 Hex(%d): ", sizeof(ai_1));
                            bufLen += bytesToHexString(ai_1, sizeof(ai_1), buf + bufLen, sizeof(buf) - bufLen);
                            printSerial(buf);

                            bufLen = snprintf(buf, sizeof(buf), "ai (%d): ", aLen);
                            bufLen += bytesToHexString(ai, sizeof(ai), buf + bufLen, sizeof(buf) - bufLen);
                            printSerial(buf);

                            bufLen = snprintf(buf, sizeof(buf), "digest of ai: ");
                            bufLen += bytesToHexString(digest, sizeof(digest), buf + bufLen, sizeof(buf) - bufLen);
                            printSerial(buf);

                            // check signature
                            if(!uECC_verify(pubKeys[lastReader], digest, sizeof(digest), ai, curve))
                            {
                                print("a[i] is not a signature of a[i-1]!");
                                return false;
                            }
                            memcpy(ai, ai_1, sizeof(ai_1));
                        }
                        else 
                        {
                            print("Could not find online secret!");
                            return false;
                        }
                    }
                    else
                    {
                        print("Could not connect to database!");
                        return false;
                    }
                }
            }
            else
            {
                print("Message M does not match signature S!");
                return false;
            }
        }
        else 
        {
            print("Could not decrypt shared secret!");
            return false;
        }
        return true;
    }
    return false;
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
    const uint16_t dataSize = 196;
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

        // read tag data into data
        dataReadFilter = nano.initEPCSingleReadFilter(EPC, EPCLength);
        nano.readDataWithFilterConfig(0x03, 0x00, dataReadConfig, dataReadFilter, true, 500);
        if (nano.response.nrTags > 0)
        {
            // Memory content should be:
            // ID         : 0-4     (4 bytes)
            // Nonce      : 4-20    (16 bytes)
            // Tag        : 20-36   (16 bytes)
            // Ciphertext : 36-132  (96 bytes) (AES GCM)
            // Tag secret : 132-196 (64 bytes) (ECDSA signature)
            // Total length: 196 bytes
            uint8_t plaintext[96];
            uint16_t dataLength = nano.response.getBankdata(0, data, dataSize);
            if(verify(data, dataLength, plaintext, sizeof(plaintext)))
            {
                if(update(data, dataLength, EPC, EPCLength, plaintext, sizeof(plaintext)))
                {
                    print("Update successfull!");
                }
                else
                {
                    print("Could not update tag!");
                }
            }
            else
            {
                print("Tag could not be verified!");
            }

        }
    }
    delay(1000);
}