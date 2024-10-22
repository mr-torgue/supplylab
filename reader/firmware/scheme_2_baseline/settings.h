// Settings that are the same for all readers

// for the display (change for different displays)
#define SCREEN_WIDTH 128 // OLED display width, in pixels
#define SCREEN_HEIGHT 128 // OLED display height, in pixels
#define CHAR_WIDTH 6
#define CHAR_HEIGHT 8
#define SCREEN_WIDTH_CHAR (SCREEN_WIDTH / CHAR_WIDTH)
#define SCREEN_HEIGHT_CHAR (SCREEN_HEIGHT / CHAR_HEIGHT)
#define OLED_RESET     -1 // Reset pin # (or -1 if sharing Arduino reset pin)
#define SCREEN_ADDRESS 0x3C ///< See datasheet for Address; 0x3D for 128x64, 0x3C for 128x32

// WiFi credentials
char ipAddr[16] = "0"; 
const char WIFI_SSID[] = "SupplyLab";   
const char WIFI_PASSWORD[] = "73833925"; 

// MQTT settings
const char MQTT_BROKER_ADRRESS[] = "192.168.0.100";  
const int MQTT_PORT = 1883;
const char MQTT_USERNAME[] = "";                       
const char MQTT_PASSWORD[] = "";               
const char PUBLISH_TOPIC[] = "RFID";    
const int PUBLISH_INTERVAL = 5000; 

// printable banners
const char banner[] = 
    "----------------------------------------------------------------------------------------\n"
    "| Title       : Baseline                                                               |\n"
    "| Version     : 1.0                                                                    |\n"
    "| Hardware    : Arduino uno R4 Wifi, SSD1327 display, and RFID UHF M6E nano shield     |\n"
    "| Description : Scans for available tags. If tags are available, it reads the content. |\n"
    "|               Content is sent to screen, serial, or mqtt (whatever is available) and |\n"
    "|               Updated according to the baseline scheme.                              |\n"
    "----------------------------------------------------------------------------------------\n";
// same but smaller
const char screenBanner[] = "Baseline";