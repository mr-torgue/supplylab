#include "helpers.h"

/*
prints text to screen if available
how this works is as follows:
1. we have a screen buffer that fills the screen exactly
2. we keep track of the next empty row
3. given a buf and the row pointer, we get the width and height of the resulting print
4. if h > max height, shift the rows up until it fits (or screen is full)
screenbuf 
*/
void printScreen(const char *buf) 
{
    // check if screen is available
    if(hasScreen)
    {  
        display.clearDisplay();
        // print banner
        display.setTextSize(2); 
        //display.setTextColor(SSD1306_WHITE);        // Draw white text
        display.setTextColor(SSD1327_WHITE);        // Draw white text
        display.setCursor(0, 0);         
        display.setTextWrap(false);  
        // print banner
        display.println(screenBanner);
        // print reader ID
        display.setTextSize(1);  
        display.print("reader: ");
        display.println(readerId);
        display.setTextWrap(true);  
        

        // first 4 rows are for title
        uint8_t startRow = CHAR_HEIGHT * 4;
        // copy buffer
        screenBufLen += snprintf(screenBuf + screenBufLen, sizeof(screenBuf) - screenBufLen, "# %s\n", buf);
        // calculate the number of rows buf would take
        int16_t x, y; 
        uint16_t w, h, nrRows;
        display.getTextBounds(screenBuf, 0, startRow, &x, &y, &w, &h);
        
        // logic: keep looking for our terminal char (#) and remove until it fits
        uint16_t i = 0;
        while(h > SCREEN_HEIGHT && i != screenBufLen) 
        {
            i++;
            for(i; i < screenBufLen; i++)
            {
                if(screenBuf[i] == '#')
                {
                    break;
                }
            }
            display.getTextBounds(screenBuf + i, 0, startRow, &x, &y, &w, &h);
        }
        // move string if it was too large
        if(i != 0)
        {
            memmove(screenBuf, screenBuf + i, sizeof(screenBuf) - i);
            screenBufLen -= i;
        }

        //display.setTextColor(SSD1306_WHITE);        // Draw white text
        display.setTextColor(SSD1327_WHITE);        // Draw white text
        display.setCursor(0, startRow);           
        display.println(screenBuf);
        display.display();
    }
}

/*
prints text to serial if available
*/
void printSerial(const char *buf)
{
    if(hasSerial)
    {
        Serial.println(buf);
    }
}

/*
Sends to MQTT in JSON format:
make sure readerId and readerLabel are specified
*/
void sendToMQTT(const char *buf)
{
    if(hasMQTT)
    {
        // get current time
        RTCTime currentTime;
        RTC.getTime(currentTime);
        long utime = currentTime.getUnixTime();

        // we format it in json format, with some other metadata
        char jsonMsg[1024];
        snprintf(jsonMsg, sizeof(jsonMsg), "{"
                                                "\"reader id\": \"%d\"," 
                                                "\"reader label\": \"%s\"," 
                                                "\"timestamp\": %ld,"
                                                "\"IP address\": \"%s\","
                                                "\"msg\": \"%s\""
                                           "}", readerId, readerLabel, utime, ipAddr, buf);
                                           
                                           
        mqttClient.beginMessage(PUBLISH_TOPIC);
        mqttClient.print(jsonMsg);
        mqttClient.endMessage();       
    }
}

/*
prints the message to all possible outputs:
1. Serial
2. Display
3. MQTT
*/
void print(const char *buf) 
{
    printScreen(buf);
    printSerial(buf);
    sendToMQTT(buf);
}


/*
does the setup for the real-time clock, printers(serial, display, mqtt) and RFID reader
*/
void setupClockPrintersReaders()
{
    // real time clock (only for arduino r4)
    RTC.begin();
    RTCTime startTime(30, Month::JUNE, 2023, 13, 37, 00, DayOfWeek::WEDNESDAY, SaveLight::SAVING_TIME_ACTIVE);
    RTC.setTime(startTime);

    // try to set up Serial
    uint8_t retries = 3;
    Serial.begin(115200);
    while (!Serial && retries > 0)
    {
        delay(1000);
        retries--;
    }
    hasSerial = retries != 0;
    if(hasSerial)
    {
        printSerial(banner);
    }

    // try to set up screen
    hasScreen = true;
    //if(!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS)) // for SSD1306
    if(!display.begin(SCREEN_ADDRESS)) // for SSD1327
    {
        snprintf(buf, sizeof(buf), "SSD1306/SSD1327 allocation failed");
        print(buf);
        hasScreen = false;
    }

    // connect to WiFi
    retries = 3;
    snprintf(buf, sizeof(buf), "Attempting to connect to SSID: %s", WIFI_SSID);
    print(buf);
    while (WiFi.begin(WIFI_SSID, WIFI_PASSWORD) != WL_CONNECTED && retries > 0) 
    {    
        delay(2000);
        retries--;
    }  
    hasWifi = retries != 0;

    // only try mqtt if there is wifi
    if(hasWifi)
    {
        // print ip info
        WiFi.localIP().toString().toCharArray(ipAddr, sizeof(ipAddr));
        snprintf(buf, sizeof(buf), "IP Address: %s", ipAddr);
        print(buf);

        // set up MQTT
        retries = 3;
        mqttClient.setId(MQTT_CLIENT_ID);
        // make sure it does not disconnect
        mqttClient.setKeepAliveInterval(0);
        mqttClient.setTxPayloadSize(1024);
        //mqttClient.setUsernamePassword(MQTT_USERNAME, MQTT_PASSWORD)
        snprintf(buf, sizeof(buf), "Connecting to MQTT broker");
        print(buf);
        while (!mqttClient.connect(MQTT_BROKER_ADRRESS, MQTT_PORT) && retries > 0) 
        {    
            delay(1000);
            retries--;
        }    
        hasMQTT = retries != 0;
        // only print if mqtt was successful
        if(hasMQTT)
        {
            snprintf(buf, sizeof(buf), "MQTT broker Connected!");
            print(buf);
        }
    }
    // set up RFID nano
    if (setupNano(115200) == false) // Configure nano to run at 38400bps
    {
        snprintf(buf, sizeof(buf), "Module failed to respond. Please check wiring. Freezing...");
        print(buf);       
        while (1); // Freeze!
    }
    nano.setRegion(REGION_AUSTRALIA); // Set to North America
    nano.setReadPower(2200); 
    nano.setWritePower(2200); 
    
    // make sure that each tag can only be read once every 10 seconds
    nano.enableReadFilterWithTimeout(10000);
}

// Gracefully handles a reader that is already configured and already reading continuously
// Because Stream does not have a .begin() we have to do this outside the library
boolean setupNano(long baudRate)
{
    //nano.enableDebugging(Serial);
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

        bufLen = snprintf(buf, sizeof(buf), "Module continuously reading. Asking it to stop...");
        print(buf);

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
