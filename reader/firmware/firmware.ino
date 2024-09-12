/*
Reads for tags in continuous mode at 15db (1000 on, 500 off to prevent overheating)
Checks if it should update the tag and updates the tag if so
Actions are send to an MQTT broker. We log the following actions:
1. Reader read n tags, if n > 0, where n is the number of tags
  a) number n
  b) tag ids
  c) timestamp
2. Reader updated tag i, where i is one of the n tags
  a) tag id + user content
We could also consider sending the complete tag lay out all the time
*/

#include <WiFiS3.h>
#include <ArduinoMqttClient.h>
#include <ArduinoJson.h>
#include <SparkFun_UHF_RFID_Reader.h>

// includes the secrets it needs to know
#include "secrets.h"

#define WAIT_TIME_TEMP 10

// WiFi credentials
const char WIFI_SSID[] = "SupplyLab";   
const char WIFI_PASSWORD[] = "73833925"; 

// MQTT settings
const char MQTT_BROKER_ADRRESS[] = "192.168.0.100";  
const int MQTT_PORT = 1883;
const char MQTT_CLIENT_ID[] = "UHF RFID Reader 1"; 
const char MQTT_USERNAME[] = "";                       
const char MQTT_PASSWORD[] = "";                    

// only publish
const char PUBLISH_TOPIC[] = "READER-1";    
const int PUBLISH_INTERVAL = 5000; 

WiFiClient wifiClient;
MqttClient mqttClient(wifiClient);

// rfid reader object
RFID nano;
unsigned long end;
unsigned long start = millis();


void setup() {
  Serial.begin(115200);
  while (!Serial);

  // connect to WiFi
  Serial.print("Arduino - Attempting to connect to SSID: ");
  Serial.println(WIFI_SSID);
  while (WiFi.begin(WIFI_SSID, WIFI_PASSWORD) != WL_CONNECTED) {    
    Serial.print(".");
    delay(5000);
  }  
  Serial.println();
  Serial.print("IP Address: ");
  Serial.println(WiFi.localIP());

  connectToMQTT();

  // setup RFID reader
  if (setupNano(115200) == false) //Configure nano to run at 115200
  {
    Serial.println(F("Module failed to respond. Please check wiring."));
    while (1); //Freeze!
  }

  nano.setRegion(REGION_AUSTRALIA); // Set to North America
  nano.setReadPower(1500); // 15.00 dBm. Higher values may caues USB port to brown out
  //Max Read TX Power is 27.00 dBm and may cause temperature-limit throttling

  // set offtime to 500, so we have a 66.67% utilization
  ReadConfig config = nano.initStandardContinuousReadConfig();
  TagFilter filter;
  config.offtime = 0;
  nano.startReadingWithFilterConfig(config, filter); //Begin scanning for tags
}

// Tag format should be: path length (1 byte) | path (length bytes) | current step (1 byte)
// Each step in the path is a reader ID (limited to 256 readers)
// Checks if the path at current step is our reader ID, if so, we update the step by 1
void simple() {
  if(reader)
}

void pathAuthentication() {
  switch(mode)
  {
    // does not do anything
    case 0:
      break;
    // bu and li
    case 1:
      break;
    // simple
    case 2:
      break;
    // simple with encryption
    case 3:
      break;
    default:
      break;
  }
}

void loop() {
  // check if new messages came in
  if (nano.check() == true) //Check to see if any new data has come in from module
  {
    // succesful
    if (nano.response.status == RESPONSE_IS_TAGFOUND)
    {
      if(nano.response.nrTags > 0)
      {
        StaticJsonDocument<200> message;
        StaticJsonDocument<150> metadata;
        Serial.println("Found some tags!");
        // send EPC, Metadataflag, and raw metadata
        uint16_t EPCLength = 12;
        byte EPC[EPCLength];

        uint16_t metadataFlag = nano.response.metadataFlag;
        nano.response.getData(0, EPC, EPCLength, 4);

        // construct message
        int msgLength = 128;
        char msg[msgLength];
        bytesToHexString(EPC, EPCLength, msg, msgLength); 
        message["EPC"] = msg;
        message["Metadata Flag"] = nano.response.metadataFlag;
        nano.response.metadataToJsonString(0, msg, msgLength);
        deserializeJson(metadata, msg);
        message["Metadata"] = metadata;
        sendJSONToMQTT(message);


      }
    }
    else if(nano.response.status == RESPONSE_IS_TEMPERATURE)
    {
      end = millis();
      if((end - start) / 1000 > WAIT_TIME_TEMP)
      {
        StaticJsonDocument<200> message;
        message["type"] = 1;
        message["temperature"] = nano.response.temperature;
        sendJSONToMQTT(message);
        start = end;
      }
    }
    else if (nano.response.status == ERROR_CORRUPT_RESPONSE)
    {
      Serial.println("Corrupt response!");
      sendToMQTT(2, "CORRUPT RESPONSE");
    }
    else if (nano.response.status == RESPONSE_IS_HIGHRETURNLOSS)
    {
      Serial.println("Reader loses data!");
      sendToMQTT(3, "HIGH RETURN LOSS");
    }
    // 
    else if(nano.response.status != RESPONSE_IS_KEEPALIVE && nano.response.status != ALL_GOOD)
    {
      Serial.println("?!???!?!");
      sendToMQTT(4, "UNKNOWN");
    }
  }
}

void sendToMQTT(uint8_t type, char *msg)
{
  StaticJsonDocument<200> data;
  data["type"] = type;
  data["message"] = msg;
  sendJSONToMQTT(data);
}

void sendJSONToMQTT(StaticJsonDocument<200> data) {
  StaticJsonDocument<300> message;
  message["timestamp"] = millis();
  message["data"] = data;
  char messageBuffer[512];
  serializeJson(message, messageBuffer);

  mqttClient.beginMessage(PUBLISH_TOPIC);
  mqttClient.print(messageBuffer);
  mqttClient.endMessage();

  Serial.println("Arduino - sent to MQTT:");
  Serial.print("- topic: ");
  Serial.println(PUBLISH_TOPIC);
  Serial.print("- payload:");
  Serial.println(messageBuffer);
}

void connectToMQTT() {
  mqttClient.setId(MQTT_CLIENT_ID);
  //mqttClient.setUsernamePassword(MQTT_USERNAME, MQTT_PASSWORD)

  Serial.print("Arduino - Connecting to MQTT broker");

  while (!mqttClient.connect(MQTT_BROKER_ADRRESS, MQTT_PORT)) {
    Serial.print(".");
    delay(100);
  }
  Serial.println();
  Serial.println("Arduino - MQTT broker Connected!");
}

//Gracefully handles a reader that is already configured and already reading continuously
//Because Stream does not have a .begin() we have to do this outside the library
boolean setupNano(long baudRate)
{
  //nano.enableDebugging(Serial); 
  nano.begin(Serial1); //Tell the library to communicate over software serial port

  //Test to see if we are already connected to a module
  //This would be the case if the Arduino has been reprogrammed and the module has stayed powered
  Serial1.begin(baudRate); //For this test, assume module is already at our desired baud rate
  while (!Serial1); //Wait for port to open

  //About 200ms from power on the module will send its firmware version at 115200. We need to ignore this.
  while (Serial1.available()) Serial1.read();
  nano.getVersion();

  if (nano.msg[0] == ERROR_WRONG_OPCODE_RESPONSE)
  {
    //This happens if the baud rate is correct but the module is doing a ccontinuous read
    nano.stopReading();
    Serial.println(F("Module continuously reading. Asking it to stop..."));
    delay(1500);
  }
  else
  {
    //The module did not respond so assume it's just been powered on and communicating at 115200bps
    Serial1.begin(115200); //Start software serial at 115200
    nano.setBaud(baudRate); //Tell the module to go to the chosen baud rate. Ignore the response msg
    Serial1.begin(baudRate); //Start the software serial port, this time at user's chosen baud rate
    delay(250);
  }

  //Test the connection
  nano.getVersion();
  //Serial.println(nano.msg);
  if (nano.msg[0] != ALL_GOOD) return (false); //Something is not right

  //The M6E has these settings no matter what
  nano.setTagProtocol(); //Set protocol to GEN2
  nano.setAntennaPort(); //Set TX/RX antenna ports to 1

  return (true); //We are ready to rock
}