MeshCore Dual SX1262 Bridge

ESP32-S3 Dual-Modem MeshCore Packet Bridge with Web UI, OLED Display, Packet Logging, OTA Updates, and Public Channel Message Detection

This project implements a dual-radio SX1262 LoRa bridge using an ESP32-S3-N16R8, designed to extend MeshCore RF networks by forwarding packets between two independent radios.
It also includes a modern web interface, JSON configuration, packet viewing tools, OLED status display, and partial MeshCore packet awareness.

This device does not yet decrypt public text messages, but it automatically detects and classifies MeshCore GroupText packets and exposes them in the UI.

Features
Dual SX1262 Radio Bridge

Two independent Wio SX1262 LoRa radios are connected to the ESP32-S3.

Both radios remain in continuous RX mode until one receives a packet.

When one radio transmits, the other is automatically inhibited.

Full anti-loop protection prevents packet ping-pong.

All packets received on one modem are forwarded to the other.

MeshCore Packet Awareness

Recognizes MeshCore GroupText packets (payload type 0x05).

Identifies Public channel messages using the known public channel key hash.

Displays:

Message metadata

Ciphertext

Channel hash

Version field

This lays groundwork for full on-device decryption later.

Full Web Interface

Accessible at the device's IP address:

Status Dashboard

WiFi state and IP addresses

Modem states, frequencies, bandwidth, SF/CR, TX power

RSSI/SNR of last packets

Recently detected GroupText messages

Live Packet Monitor

Two columns (Modem 1 and Modem 2)

Auto-refreshing packet stream (hex + metadata)

Shows decoded public text when implemented later

Modem Settings

Frequency (MHz)

Bandwidth (kHz, 0.1 resolution)

Spreading Factor

Coding Rate

TX power

Enable/disable each modem

WiFi Configuration

Change SSID/password

Auto-save to flash

Settings JSON

Get or update the entire config as JSON

OTA Update

Upload new firmware directly through the browser

OLED Display

A 0.96" SSD1306 I2C OLED shows:

IP address

Modem RX/FWD counts

RSSI & SNR

Overall system status

Updates every 500 ms.

RX/TX LEDs

Each modem has two LEDs:

RX LED pulses when receiving a packet

TX LED lights while transmitting

Config & Logging

JSON configuration stored in SPIFFS

Persistent packet log with JSON entries

No reset of logs on reboot

Public Channel Key

The known MeshCore public channel key is included:

8b3387e9c5cdea6ac9e5edbaa115cd72


Used for detecting encrypted GroupText packets.

Hardware Used
ESP32-S3

ESP32-S3-N16R8 module

Shared SPI bus for both radios

Wio SX1262 LoRa Modules (x2)

Using the documented pinout from the official Seeed datasheet.

Shared SPI:
SCK  → 36  
MISO → 37  
MOSI → 35  

Modem 1:
NSS   → 10  
NRST  → 11  
BUSY  → 12  
DIO1  → 13  
RF_SW → 14  

Modem 2:
NSS   → 20  
NRST  → 21  
BUSY  → 47  
DIO1  → 48  
RF_SW → 38  

OLED (SSD1306)
SDA → GPIO 8  
SCL → GPIO 9  
Addr = 0x3C  

LED Indicators
Modem1 RX LED → GPIO 3  
Modem1 TX LED → GPIO 4  
Modem2 RX LED → GPIO 5  
Modem2 TX LED → GPIO 6  

How It Works
1. Normal State: Both Radios in RX

Both SX1262 modules continuously listen.

2. Packet Received

Interrupt fires

Packet is read, logged, and optionally classified

RX LED pulses

Loop prevention performed (FNV hash)

3. Forwarding

Receiving modem is placed into standby

Other modem transmits the packet

TX LED lights

Both radios return to RX mode

4. Public Channel Detection

If the packet is GroupText (payload type 0x05), the system extracts:

channelHash

version

ciphertext

This is added to the log and UI.

Roadmap
Implement Full MeshCore Public Text Decryption

We need:

AES-128 ECB

HMAC-SHA256 validation

Correct payload slicing (header, meta, MAC, body)

Show Decrypted Public Messages in:

Web UI

JSON feed

OLED

Optional Future Feature:

Appear as a MeshCore Repeater Node

Building the Firmware
Requirements

Arduino IDE or PlatformIO

ESP32 board support (esp32s3)

Libraries:

RadioLib

Adafruit SSD1306

Adafruit GFX

mbedtls (included with ESP32 core)

Building

Clone the repository

Open the project in Arduino or PlatformIO

Select ESP32-S3 Dev Module

Compile and flash

Web Interface Screenshots

(You can add your own screenshots here later)

License

MIT License
