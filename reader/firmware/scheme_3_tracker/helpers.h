/*
Contains all the settings needed for printing.
Unclutters the main firmware.
All firmware uses the same helpers.
*/

#ifndef _HELPERS_H_
#define _HELPERS_H_

#include <WiFiS3.h>
#include <ArduinoMqttClient.h>
#include <RTC.h>
#include <SparkFun_UHF_RFID_Reader.h> // my library, not the standard
// includes for display
//#include <Adafruit_SSD1306.h> 
#include <Adafruit_SSD1327.h>

#include "settings.h"
#include "scheme_settings.h"


// used for determining where to output
bool hasSerial = false;
bool hasScreen = false;
bool hasWifi = false;
bool hasMQTT = false;

RFID nano;

// create clients
WiFiClient wifiClient;
MqttClient mqttClient(wifiClient);

// display object
//Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire1, OLED_RESET);
Adafruit_SSD1327 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire1, OLED_RESET); //, 1000000);

// some string buffers for printing
char buf[600];
int bufLen = 0;
char screenBuf[1024];
int screenBufLen = 0;


// function declarations
void printScreen(const char *buf);
void printSerial(const char *buf);
void sendToMQTT(const char *buf);
void print(const char *buf); 
void setupClockPrintersReaders();


#endif /* _HELPERS_H_ */