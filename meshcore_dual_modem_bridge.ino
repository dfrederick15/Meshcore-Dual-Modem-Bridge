#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <Update.h>
#include <FS.h>
#include <SPIFFS.h>
#include <SPI.h>
#include <Wire.h>
#include <RadioLib.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <mbedtls/aes.h>

// =========================
// Firmware Info
// =========================
const char *FW_VERSION = "MeshcoreDualSX1262Bridge v0.3.4";

// =========================
// Hardware: Wio-SX1262 modules
// =========================
// Shared SPI bus pins on ESP32-S3
#define LORA_SCK_PIN     36
#define LORA_MISO_PIN    37
#define LORA_MOSI_PIN    35

// Modem 1 pins
#define MODEM1_NSS_PIN   10
#define MODEM1_NRST_PIN  11
#define MODEM1_BUSY_PIN  12
#define MODEM1_DIO1_PIN  13
#define MODEM1_RF_SW_PIN 14

// Modem 2 pins
#define MODEM2_NSS_PIN   20
#define MODEM2_NRST_PIN  21
#define MODEM2_BUSY_PIN  47
#define MODEM2_DIO1_PIN  48
#define MODEM2_RF_SW_PIN 38

// =========================
// Status LEDs
// =========================
// Adjust these to your actual LED pins
#define MODEM1_RX_LED_PIN   3
#define MODEM1_TX_LED_PIN   4
#define MODEM2_RX_LED_PIN   5
#define MODEM2_TX_LED_PIN   6

// =========================
// OLED 0.96" 128x64 I2C
// =========================
#define OLED_SDA_PIN     8
#define OLED_SCL_PIN     9
#define OLED_ADDR        0x3C
#define OLED_WIDTH       128
#define OLED_HEIGHT      64

Adafruit_SSD1306 display(OLED_WIDTH, OLED_HEIGHT, &Wire, -1);

// =========================
// LoRa / MeshCore radio defaults
// =========================

#define LORA_FREQ_MHZ_DEFAULT     910.525f   // MHz
#define LORA_BW_KHZ_DEFAULT       250.0f     // kHz
#define LORA_SF_DEFAULT           10         // spreading factor
#define LORA_CR_DEFAULT           5          // coding rate denominator (4/x)
#define LORA_TX_POWER_DBM_DEFAULT 20         // dBm
#define LORA_SYNC_WORD_DEFAULT    RADIOLIB_SX126X_SYNC_WORD_PRIVATE
#define LORA_PREAMBLE_LEN         8          // symbols
#define LORA_TCXO_VOLTAGE         1.8f       // V for TCXO

#define LORA_MAX_PACKET_LEN       256
#define BRIDGE_BUF_SIZE           LORA_MAX_PACKET_LEN

// =========================
// MeshCore public channel AES key
// =========================
// Public channel secret key from meshcore.ch (16 bytes AES-128)
const uint8_t PUBLIC_CH_KEY[16] = {
  0x8b, 0x33, 0x87, 0xe9,
  0xc5, 0xcd, 0xea, 0x6a,
  0xc9, 0xe5, 0xed, 0xba,
  0xa1, 0x15, 0xcd, 0x72
};

// =========================
// Packet log and config
// =========================
#define PACKET_LOG_MAX_ENTRIES    50     // in RAM per modem
#define PACKET_LOG_DATA_PREVIEW   32     // bytes
#define PACKET_LOG_FILE           "/packets.log"
#define CONFIG_FILE               "/config.json"

// Anti-loop cache
#define LOOP_CACHE_SIZE           64
#define LOOP_CACHE_TTL_MS         5000UL  // 5 seconds

// Max decrypted text bytes we will try to handle
#define PUBLIC_TEXT_MAX_LEN       192

// =========================
// WiFi configuration
// =========================
const char *WIFI_SSID_DEFAULT = "MeshcoreBridge";
const char *WIFI_PASS_DEFAULT = "meshcore123";

const char *AP_SSID = "MeshcoreBridge-AP";
const char *AP_PASS = "meshcoreap";

// =========================
// Types and Globals
// =========================

struct ModemConfig {
  uint32_t baud;      // legacy (unused for SX1262, kept for compatibility)
  bool enabled;

  float freqMHz;
  float bwKhz;
  uint8_t sf;
  uint8_t cr;
  int8_t txPower;
};

struct SystemConfig {
  char wifiSsid[32];
  char wifiPass[64];
  ModemConfig modem[2];
};

SystemConfig gConfig;

// RadioLib objects
SPIClass loraSPI = SPI;
SPISettings loraSPISettings(2000000, MSBFIRST, SPI_MODE0);

Module modem1Module(MODEM1_NSS_PIN, MODEM1_DIO1_PIN, MODEM1_NRST_PIN, MODEM1_BUSY_PIN, loraSPI, loraSPISettings);
Module modem2Module(MODEM2_NSS_PIN, MODEM2_DIO1_PIN, MODEM2_NRST_PIN, MODEM2_BUSY_PIN, loraSPI, loraSPISettings);

SX1262 modem1Radio(&modem1Module);
SX1262 modem2Radio(&modem2Module);

WebServer server(80);

// Packet log entry
struct PacketLogEntry {
  unsigned long ms;
  size_t length;
  bool fromOther;          // true if forwarded from other modem
  uint8_t preview[PACKET_LOG_DATA_PREVIEW];
  size_t previewLen;
  float rssi;
  float snr;
  String text;             // decoded public text for this packet (if any)
};

PacketLogEntry modemLogs[2][PACKET_LOG_MAX_ENTRIES];
uint8_t modemLogHead[2] = {0, 0};
bool modemLogFilled[2] = {false, false};

// Radio interrupt flags
volatile bool modem1ReceivedFlag = false;
volatile bool modem2ReceivedFlag = false;

// Shared bridge buffer
uint8_t bridgeBuf[BRIDGE_BUF_SIZE];

// Stats
unsigned long totalPacketsRx[2] = {0, 0};
unsigned long totalPacketsFwd[2] = {0, 0};
float lastRssi[2] = {0.0f, 0.0f};
float lastSnr[2] = {0.0f, 0.0f};

// Anti-loop cache
struct LoopCacheEntry {
  uint32_t hash;
  unsigned long timeMs;
};

LoopCacheEntry loopCache[LOOP_CACHE_SIZE];
uint8_t loopCacheHead = 0;

// Last decoded public text per modem
String lastPublicText[2];
uint32_t lastPublicTextTimeMs[2] = {0, 0};

// =========================
// Helpers: JSON parsing utils
// =========================

float parseJsonFloat(const String &json, const char *key, float defaultVal) {
  int idx = json.indexOf(key);
  if (idx < 0) return defaultVal;
  int colon = json.indexOf(':', idx);
  if (colon < 0) return defaultVal;
  int start = colon + 1;
  while (start < (int)json.length() && (json[start] == ' ')) start++;
  int end = start;
  while (end < (int)json.length()) {
    char c = json[end];
    if ((c >= '0' && c <= '9') || c == '.' || c == '-' || c == '+') {
      end++;
    } else {
      break;
    }
  }
  String s = json.substring(start, end);
  return s.toFloat();
}

int parseJsonInt(const String &json, const char *key, int defaultVal) {
  float f = parseJsonFloat(json, key, (float)defaultVal);
  return (int)f;
}

bool parseJsonBool(const String &json, const char *key, bool defaultVal) {
  int idx = json.indexOf(key);
  if (idx < 0) return defaultVal;
  int colon = json.indexOf(':', idx);
  if (colon < 0) return defaultVal;
  int start = colon + 1;
  while (start < (int)json.length() && (json[start] == ' ')) start++;
  if (json.startsWith("true", start)) return true;
  if (json.startsWith("false", start)) return false;
  return defaultVal;
}

// =========================
// Helper: Config
// =========================

void setDefaultModemConfig(ModemConfig &mc) {
  mc.baud = 57600;
  mc.enabled = true;
  mc.freqMHz = LORA_FREQ_MHZ_DEFAULT;
  mc.bwKhz = LORA_BW_KHZ_DEFAULT;
  mc.sf = LORA_SF_DEFAULT;
  mc.cr = LORA_CR_DEFAULT;
  mc.txPower = LORA_TX_POWER_DBM_DEFAULT;
}

void setDefaultConfig() {
  memset(&gConfig, 0, sizeof(gConfig));
  strncpy(gConfig.wifiSsid, WIFI_SSID_DEFAULT, sizeof(gConfig.wifiSsid) - 1);
  strncpy(gConfig.wifiPass, WIFI_PASS_DEFAULT, sizeof(gConfig.wifiPass) - 1);

  setDefaultModemConfig(gConfig.modem[0]);
  setDefaultModemConfig(gConfig.modem[1]);
}

String buildConfigJson() {
  String json;
  json.reserve(512);
  json += "{\"wifiSsid\":\"";
  json += gConfig.wifiSsid;
  json += "\",\"wifiPass\":\"";
  json += gConfig.wifiPass;
  json += "\",\"modem\":[";
  for (int i = 0; i < 2; i++) {
    if (i > 0) json += ",";
    ModemConfig &mc = gConfig.modem[i];
    json += "{";
    json += "\"baud\":";
    json += String(mc.baud);
    json += ",\"enabled\":";
    json += (mc.enabled ? "true" : "false");
    json += ",\"freq\":";
    json += String(mc.freqMHz, 3);
    json += ",\"bw\":";
    json += String(mc.bwKhz, 1);
    json += ",\"sf\":";
    json += String((int)mc.sf);
    json += ",\"cr\":";
    json += String((int)mc.cr);
    json += ",\"tx\":";
    json += String((int)mc.txPower);
    json += "}";
  }
  json += "]}";
  return json;
}

bool loadConfig() {
  if (!SPIFFS.exists(CONFIG_FILE)) {
    Serial.println("Config file not found. Using defaults.");
    setDefaultConfig();
    return false;
  }

  File f = SPIFFS.open(CONFIG_FILE, "r");
  if (!f) {
    Serial.println("Failed to open config file. Using defaults.");
    setDefaultConfig();
    return false;
  }

  String json = f.readString();
  f.close();

  setDefaultConfig();

  int idx;

  idx = json.indexOf("\"wifiSsid\"");
  if (idx >= 0) {
    int q1 = json.indexOf('"', idx + 10);
    int q2 = json.indexOf('"', q1 + 1);
    if (q1 >= 0 && q2 > q1) {
      String s = json.substring(q1 + 1, q2);
      strncpy(gConfig.wifiSsid, s.c_str(), sizeof(gConfig.wifiSsid) - 1);
    }
  }

  idx = json.indexOf("\"wifiPass\"");
  if (idx >= 0) {
    int q1 = json.indexOf('"', idx + 10);
    int q2 = json.indexOf('"', q1 + 1);
    if (q1 >= 0 && q2 > q1) {
      String s = json.substring(q1 + 1, q2);
      strncpy(gConfig.wifiPass, s.c_str(), sizeof(gConfig.wifiPass) - 1);
    }
  }

  int modemIdx = json.indexOf("\"modem\"");
  if (modemIdx >= 0) {
    int aStart = json.indexOf('[', modemIdx);
    int m0Start = json.indexOf('{', aStart);
    int m0End = json.indexOf('}', m0Start);
    int m1Start = json.indexOf('{', m0End);
    int m1End = json.indexOf('}', m1Start);

    if (m0Start > 0 && m0End > m0Start) {
      String m0 = json.substring(m0Start, m0End + 1);
      gConfig.modem[0].baud = parseJsonInt(m0, "\"baud\"", gConfig.modem[0].baud);
      gConfig.modem[0].enabled = parseJsonBool(m0, "\"enabled\"", gConfig.modem[0].enabled);
      gConfig.modem[0].freqMHz = parseJsonFloat(m0, "\"freq\"", gConfig.modem[0].freqMHz);
      gConfig.modem[0].bwKhz = parseJsonFloat(m0, "\"bw\"", gConfig.modem[0].bwKhz);
      gConfig.modem[0].sf = (uint8_t)parseJsonInt(m0, "\"sf\"", gConfig.modem[0].sf);
      gConfig.modem[0].cr = (uint8_t)parseJsonInt(m0, "\"cr\"", gConfig.modem[0].cr);
      gConfig.modem[0].txPower = (int8_t)parseJsonInt(m0, "\"tx\"", gConfig.modem[0].txPower);
    }

    if (m1Start > 0 && m1End > m1Start) {
      String m1 = json.substring(m1Start, m1End + 1);
      gConfig.modem[1].baud = parseJsonInt(m1, "\"baud\"", gConfig.modem[1].baud);
      gConfig.modem[1].enabled = parseJsonBool(m1, "\"enabled\"", gConfig.modem[1].enabled);
      gConfig.modem[1].freqMHz = parseJsonFloat(m1, "\"freq\"", gConfig.modem[1].freqMHz);
      gConfig.modem[1].bwKhz = parseJsonFloat(m1, "\"bw\"", gConfig.modem[1].bwKhz);
      gConfig.modem[1].sf = (uint8_t)parseJsonInt(m1, "\"sf\"", gConfig.modem[1].sf);
      gConfig.modem[1].cr = (uint8_t)parseJsonInt(m1, "\"cr\"", gConfig.modem[1].cr);
      gConfig.modem[1].txPower = (int8_t)parseJsonInt(m1, "\"tx\"", gConfig.modem[1].txPower);
    }
  }

  Serial.println("Config loaded.");
  return true;
}

bool saveConfig() {
  File f = SPIFFS.open(CONFIG_FILE, "w");
  if (!f) {
    Serial.println("Failed to open config file for writing.");
    return false;
  }

  String json = buildConfigJson();
  f.print(json);
  f.close();
  Serial.println("Config saved.");
  return true;
}

// =========================
// Helper: Packet Logging / JSON
// =========================

String hexPreview(const uint8_t *data, size_t len) {
  String out;
  char buf[4];
  for (size_t i = 0; i < len; i++) {
    snprintf(buf, sizeof(buf), "%02X", data[i]);
    out += buf;
    if (i != len - 1) out += " ";
  }
  return out;
}

// AES-128-CTR decrypt helper for MeshCore public channel.
// Assumptions (can be adjusted if needed):
// - 16 byte AES-128 key (PUBLIC_CH_KEY).
// - 16 byte IV constructed from first 8 bytes of payload (nonce) and 8 zero bytes.
// - Data is decrypted in-place.
bool aes128CtrDecrypt(const uint8_t *key,
                      const uint8_t *nonce8,
                      uint8_t *data,
                      size_t len) {
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);

  unsigned char iv[16];
  unsigned char stream_block[16];
  size_t nc_off = 0;

  memset(iv, 0, sizeof(iv));
  memcpy(iv, nonce8, 8);

  if (mbedtls_aes_setkey_enc(&ctx, key, 128) != 0) {
    mbedtls_aes_free(&ctx);
    return false;
  }

  int ret = mbedtls_aes_crypt_ctr(&ctx, len, &nc_off, iv, stream_block, data, data);

  mbedtls_aes_free(&ctx);
  return (ret == 0);
}

// MeshCore public text decoder
// Layout assumptions (same as before, but now with optional encrypted payload):
// [0..3]  packet id (uint32)
// [4..5]  source address (uint16)
// [6..7]  destination address (uint16)
// [8]     hop count (uint8)
// [9]     flags (uint8)
// [10]    message type (uint8) 0x01 for text
// [11..]  payload:
//         For encrypted public channel:
//            [11..18] 8 byte nonce
//            [19..len-3] ciphertext (AES-128-CTR)
//         For plain text fallback:
//            [11..len-3] text
// [len-2..len-1] CRC16
bool decodePublicTextMessage(const uint8_t *data, size_t len, String &outText) {
  outText = "";

  if (!data || len < 14) {
    return false;
  }

  uint8_t msgType = data[10];
  if (msgType != 0x01) {
    return false;
  }

  // Try encrypted format first
  const size_t headerOffset = 11;
  if (len > headerOffset + 8 + 2) {
    size_t payloadLen = len - headerOffset - 2;
    if (payloadLen > 8 && payloadLen <= PUBLIC_TEXT_MAX_LEN + 8) {
      const uint8_t *nonce = data + headerOffset;
      size_t cipherLen = payloadLen - 8;

      uint8_t decBuf[PUBLIC_TEXT_MAX_LEN];
      memset(decBuf, 0, sizeof(decBuf));
      memcpy(decBuf, data + headerOffset + 8, cipherLen);

      if (aes128CtrDecrypt(PUBLIC_CH_KEY, nonce, decBuf, cipherLen)) {
        // Check for printable text after decrypt
        size_t printableCount = 0;
        for (size_t i = 0; i < cipherLen; i++) {
          uint8_t c = decBuf[i];
          bool ok =
            (c == 0x09) ||
            (c == 0x0A) ||
            (c == 0x0D) ||
            (c >= 0x20 && c <= 0x7E) ||
            (c >= 0xC2);
          if (ok) {
            printableCount++;
          }
        }

        if (cipherLen >= 3 && printableCount >= (cipherLen * 7) / 10) {
          outText.reserve(cipherLen);
          for (size_t i = 0; i < cipherLen; i++) {
            char c = (char)decBuf[i];
            outText += c;
          }
          // Trim trailing zero and whitespace
          while (outText.length() > 0) {
            char c = outText[outText.length() - 1];
            if (c == '\0' || c == '\r' || c == '\n') {
              outText.remove(outText.length() - 1);
            } else {
              break;
            }
          }
          if (outText.length() > 0) {
            return true;
          }
        }
      }
    }
  }

  // Fallback: treat payload as plain text as before
  size_t textOffset = 11;
  size_t textLen = 0;
  if (len > textOffset + 2) {
    textLen = len - textOffset - 2;
  }
  if (textLen == 0 || textLen > PUBLIC_TEXT_MAX_LEN) {
    return false;
  }

  size_t printableCount = 0;
  for (size_t i = 0; i < textLen; i++) {
    uint8_t c = data[textOffset + i];
    bool ok =
      (c == 0x09) ||
      (c == 0x0A) ||
      (c == 0x0D) ||
      (c >= 0x20 && c <= 0x7E) ||
      (c >= 0xC2);
    if (ok) {
      printableCount++;
    }
  }

  if (printableCount < (textLen * 7) / 10 || textLen < 3) {
    return false;
  }

  outText = "";
  outText.reserve(textLen);
  for (size_t i = 0; i < textLen; i++) {
    outText += (char)data[textOffset + i];
  }

  while (outText.length() > 0) {
    char c = outText[outText.length() - 1];
    if (c == '\0' || c == '\r' || c == '\n') {
      outText.remove(outText.length() - 1);
    } else {
      break;
    }
  }

  return outText.length() > 0;
}

// Convert a packet to a JSON object string for file logging
String packetToJson(uint8_t modemIndex,
                    bool fromOther,
                    unsigned long ms,
                    const uint8_t *data,
                    size_t len,
                    float rssi,
                    float snr,
                    const String &text) {
  String j;
  j.reserve(256);
  j += "{";
  j += "\"timeMs\":";
  j += String(ms);
  j += ",\"modem\":";
  j += String((int)modemIndex + 1);
  j += ",\"dir\":\"";
  j += (fromOther ? "from-other" : "local");
  j += "\",\"len\":";
  j += String((unsigned)len);
  j += ",\"rssi\":";
  j += String(rssi, 1);
  j += ",\"snr\":";
  j += String(snr, 1);
  j += ",\"raw\":\"";
  j += hexPreview(data, (len > PACKET_LOG_DATA_PREVIEW) ? PACKET_LOG_DATA_PREVIEW : len);
  j += "\"";
  if (text.length() > 0) {
    j += ",\"text\":\"";
    for (size_t i = 0; i < (size_t)text.length(); i++) {
      char c = text[i];
      if (c == '\\' || c == '\"') {
        j += '\\';
      }
      if (c == '\r' || c == '\n') {
        j += ' ';
      } else {
        j += c;
      }
    }
    j += "\"";
  }
  j += "}";
  return j;
}

void appendPacketLogJson(uint8_t modemIndex,
                         bool fromOther,
                         unsigned long ms,
                         const uint8_t *data,
                         size_t len,
                         float rssi,
                         float snr,
                         const String &text) {
  File f = SPIFFS.open(PACKET_LOG_FILE, "a");
  if (!f) {
    Serial.println("Could not open packet log file for append.");
    return;
  }
  String line = packetToJson(modemIndex, fromOther, ms, data, len, rssi, snr, text);
  f.println(line);
  f.close();
}

void logPacket(uint8_t modemIndex,
               bool fromOther,
               const uint8_t *data,
               size_t len,
               float rssi,
               float snr) {
  if (modemIndex > 1) return;

  unsigned long now = millis();

  // Try to decode public text on RX (fromOther == false)
  String text;
  if (!fromOther) {
    if (decodePublicTextMessage(data, len, text)) {
      lastPublicText[modemIndex] = text;
      lastPublicTextTimeMs[modemIndex] = now;
    }
  }

  uint8_t idx = modemLogHead[modemIndex];
  PacketLogEntry *e = &modemLogs[modemIndex][idx];
  e->ms = now;
  e->length = len;
  e->fromOther = fromOther;
  e->previewLen = (len > PACKET_LOG_DATA_PREVIEW) ? PACKET_LOG_DATA_PREVIEW : len;
  memcpy(e->preview, data, e->previewLen);
  e->rssi = rssi;
  e->snr = snr;
  e->text = text;

  modemLogHead[modemIndex] = (idx + 1) % PACKET_LOG_MAX_ENTRIES;
  if (modemLogHead[modemIndex] == 0) {
    modemLogFilled[modemIndex] = true;
  }

  if (!fromOther) {
    totalPacketsRx[modemIndex]++;
  } else {
    totalPacketsFwd[modemIndex]++;
  }

  lastRssi[modemIndex] = rssi;
  lastSnr[modemIndex] = snr;

  appendPacketLogJson(modemIndex, fromOther, now, data, len, rssi, snr, text);
}

// =========================
// Anti-loop helper
// =========================

uint32_t fnv1a32(const uint8_t *data, size_t len) {
  uint32_t hash = 2166136261UL;
  for (size_t i = 0; i < len; i++) {
    hash ^= data[i];
    hash *= 16777619UL;
  }
  return hash;
}

bool seenRecently(uint32_t hash) {
  unsigned long now = millis();
  for (int i = 0; i < LOOP_CACHE_SIZE; i++) {
    if (loopCache[i].hash == hash) {
      if (now - loopCache[i].timeMs < LOOP_CACHE_TTL_MS) {
        return true;
      }
    }
  }
  loopCache[loopCacheHead].hash = hash;
  loopCache[loopCacheHead].timeMs = now;
  loopCacheHead = (loopCacheHead + 1) % LOOP_CACHE_SIZE;
  return false;
}

// =========================
// LED helpers
// =========================

void pulseRxLed(uint8_t modem) {
  const uint16_t pulseMs = 50;
  if (modem == 0) {
    digitalWrite(MODEM1_RX_LED_PIN, HIGH);
    delay(pulseMs);
    digitalWrite(MODEM1_RX_LED_PIN, LOW);
  } else {
    digitalWrite(MODEM2_RX_LED_PIN, HIGH);
    delay(pulseMs);
    digitalWrite(MODEM2_RX_LED_PIN, LOW);
  }
}

// =========================
// Web UI
// =========================

String htmlHeader(const char *title) {
  String h;
  h.reserve(512);
  h += "<!DOCTYPE html><html><head><meta charset='utf-8'>";
  h += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
  h += "<title>";
  h += title;
  h += "</title>";
  h += "<style>";
  h += "body{font-family:Arial,Helvetica,sans-serif;background:#111;color:#eee;margin:0;padding:0;}";
  h += "header{background:#222;padding:10px 16px;font-size:18px;}";
  h += "a{color:#4fc3f7;text-decoration:none;}";
  h += "a:hover{text-decoration:underline;}";
  h += ".container{padding:16px;}";
  h += "table{border-collapse:collapse;width:100%;max-width:900px;}";
  h += "th,td{border:1px solid #444;padding:6px 8px;font-size:13px;}";
  h += "th{background:#333;}";
  h += ".columns{display:flex;gap:16px;flex-wrap:wrap;}";
  h += ".column{flex:1 1 300px;}";
  h += ".badge{display:inline-block;padding:2px 6px;border-radius:4px;font-size:11px;}";
  h += ".badge-ok{background:#2e7d32;color:#fff;}";
  h += ".badge-bad{background:#c62828;color:#fff;}";
  h += "input[type=text],input[type=password],input[type=number],select{width:100%;padding:6px;margin:4px 0;background:#222;border:1px solid #555;color:#eee;border-radius:4px;box-sizing:border-box;}";
  h += "button,input[type=submit]{background:#1976d2;color:#fff;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;font-size:13px;margin-top:4px;}";
  h += "button:hover,input[type=submit]:hover{background:#0d47a1;}";
  h += "code{font-family:monospace;font-size:11px;}";
  h += "</style>";
  h += "</head><body>";
  h += "<header>";
  h += "MeshCore Dual SX1262 Bridge - ";
  h += FW_VERSION;
  h += "</header><div class='container'>";
  return h;
}

String htmlFooter() {
  return String("</div></body></html>");
}

void handleRoot() {
  String ip = WiFi.localIP().toString();
  String modeStr = (WiFi.getMode() & WIFI_AP) ? "STA+AP" : "STA";

  String html = htmlHeader("Status");
  html += "<h2>Status</h2>";
  html += "<p>WiFi Mode: ";
  html += modeStr;
  html += "<br>STA IP: ";
  html += ip;
  html += "<br>SSID: ";
  html += gConfig.wifiSsid;
  html += "</p>";

  html += "<h3>Modems</h3>";
  html += "<table><tr><th>Modem</th><th>Enabled</th><th>Freq (MHz)</th><th>BW (kHz)</th><th>SF</th><th>CR</th><th>Pwr (dBm)</th></tr>";
  for (int i = 0; i < 2; i++) {
    ModemConfig &mc = gConfig.modem[i];
    html += "<tr><td>Modem ";
    html += String(i + 1);
    html += "</td><td>";
    html += mc.enabled ? "<span class='badge badge-ok'>ON</span>" : "<span class='badge badge-bad'>OFF</span>";
    html += "</td><td>";
    html += String(mc.freqMHz, 3);
    html += "</td><td>";
    html += String(mc.bwKhz, 1);
    html += "</td><td>";
    html += String((int)mc.sf);
    html += "</td><td>";
    html += String((int)mc.cr);
    html += "</td><td>";
    html += String((int)mc.txPower);
    html += "</td></tr>";
  }
  html += "</table>";

  html += "<h3>Stats</h3>";
  html += "<table><tr><th>Modem</th><th>RX Packets</th><th>Forwarded Packets</th><th>Last RSSI</th><th>Last SNR</th></tr>";
  for (int i = 0; i < 2; i++) {
    html += "<tr><td>";
    html += String(i + 1);
    html += "</td><td>";
    html += String(totalPacketsRx[i]);
    html += "</td><td>";
    html += String(totalPacketsFwd[i]);
    html += "</td><td>";
    html += String(lastRssi[i], 1);
    html += " dBm</td><td>";
    html += String(lastSnr[i], 1);
    html += " dB</td></tr>";
  }
  html += "</table>";

  html += "<h3>Latest public text</h3><table><tr><th>Modem</th><th>Last text</th></tr>";
  for (int i = 0; i < 2; i++) {
    html += "<tr><td>";
    html += String(i + 1);
    html += "</td><td>";
    if (lastPublicText[i].length() > 0) {
      String t = lastPublicText[i];
      if (t.length() > 60) {
        t = t.substring(0, 57) + "...";
      }
      html += t;
    } else {
      html += "(none)";
    }
    html += "</td></tr>";
  }
  html += "</table>";

  html += "<h3>Navigation</h3><ul>";
  html += "<li><a href='/modem1'>Modem 1 Settings</a></li>";
  html += "<li><a href='/modem2'>Modem 2 Settings</a></li>";
  html += "<li><a href='/wifi'>WiFi Settings</a></li>";
  html += "<li><a href='/packets'>Live Packets + Public Text</a></li>";
  html += "<li><a href='/settings.json'>Settings JSON</a></li>";
  html += "<li><a href='/update'>OTA Update</a></li>";
  html += "</ul>";

  html += htmlFooter();
  server.send(200, "text/html", html);
}

void renderModemConfigPage(uint8_t index, const String &message) {
  if (index > 1) {
    server.send(404, "text/plain", "Invalid modem index");
    return;
  }
  ModemConfig &mc = gConfig.modem[index];

  String html = htmlHeader("Modem settings");
  html += "<h2>Modem ";
  html += String(index + 1);
  html += " Settings</h2>";

  if (message.length()) {
    html += "<p><strong>";
    html += message;
    html += "</strong></p>";
  }

  html += "<form method='POST'>";
  html += "<label>Enabled:</label><br>";
  html += "<select name='enabled'>";
  html += "<option value='1'";
  if (mc.enabled) html += " selected";
  html += ">ON</option>";
  html += "<option value='0'";
  if (!mc.enabled) html += " selected";
  html += ">OFF</option>";
  html += "</select><br>";

  html += "<label>Frequency (MHz):</label><br>";
  html += "<input type='number' step='0.001' name='freq' value='";
  html += String(mc.freqMHz, 3);
  html += "'><br>";

  html += "<label>Bandwidth (kHz):</label><br>";
  html += "<input type='number' step='0.1' name='bw' value='";
  html += String(mc.bwKhz, 1);
  html += "'><br>";

  html += "<label>Spreading Factor (7-12):</label><br>";
  html += "<input type='number' name='sf' value='";
  html += String((int)mc.sf);
  html += "'><br>";

  html += "<label>Coding Rate denominator (4/x, 5-8):</label><br>";
  html += "<input type='number' name='cr' value='";
  html += String((int)mc.cr);
  html += "'><br>";

  html += "<label>TX Power (dBm):</label><br>";
  html += "<input type='number' name='tx' value='";
  html += String((int)mc.txPower);
  html += "'><br>";

  html += "<input type='submit' value='Save and Reinit Radios'>";
  html += "</form>";

  html += "<p><a href='/'>Back to Status</a></p>";
  html += htmlFooter();
  server.send(200, "text/html", html);
}

void handleModemPost(uint8_t index);

void handleModem1Get() { renderModemConfigPage(0, ""); }
void handleModem2Get() { renderModemConfigPage(1, ""); }

void handleModem1Post() { handleModemPost(0); }
void handleModem2Post() { handleModemPost(1); }

void handleWifiGet() {
  String html = htmlHeader("WiFi settings");
  html += "<h2>WiFi Settings</h2>";
  html += "<form method='POST'>";
  html += "<label>SSID:</label><br>";
  html += "<input type='text' name='ssid' value='";
  html += gConfig.wifiSsid;
  html += "'><br>";
  html += "<label>Password:</label><br>";
  html += "<input type='password' name='pass' value='";
  html += gConfig.wifiPass;
  html += "'><br>";
  html += "<input type='submit' value='Save and Reconnect'>";
  html += "</form>";
  html += "<p><a href='/'>Back to Status</a></p>";
  html += htmlFooter();
  server.send(200, "text/html", html);
}

void handleWifiPost() {
  if (server.hasArg("ssid")) {
    String s = server.arg("ssid");
    strncpy(gConfig.wifiSsid, s.c_str(), sizeof(gConfig.wifiSsid) - 1);
  }
  if (server.hasArg("pass")) {
    String s = server.arg("pass");
    strncpy(gConfig.wifiPass, s.c_str(), sizeof(gConfig.wifiPass) - 1);
  }
  saveConfig();

  String html = htmlHeader("WiFi settings");
  html += "<h2>WiFi Settings</h2>";
  html += "<p>Settings saved. Reboot the device to apply, or it will reconnect automatically on next restart.</p>";
  html += "<p><a href='/'>Back to Status</a></p>";
  html += htmlFooter();
  server.send(200, "text/html", html);
}

// Live packet HTML page
void handlePacketsPage() {
  String html = htmlHeader("Live Packets");
  html += "<h2>Live Packets and Public Text</h2>";
  html += "<p>Last ";
  html += String(PACKET_LOG_MAX_ENTRIES);
  html += " packets per modem. Refreshes every second. If a packet decodes as a MeshCore public text message, the text will be shown.</p>";
  html += "<div class='columns'>";
  html += "<div class='column'><h3>Modem 1</h3><div id='modem1'></div></div>";
  html += "<div class='column'><h3>Modem 2</h3><div id='modem2'></div></div>";
  html += "</div>";
  html += "<p><a href='/'>Back to Status</a></p>";
  html += "<script>";
  html += "function updatePackets(){";
  html += "fetch('/packets.json').then(r=>r.json()).then(j=>{";
  html += "let m1='',m2='';";
  html += "for(let e of j.modem1){";
  html += "m1 += `<div><strong>${e.time}</strong> [${e.dir}] len=${e.len} rssi=${e.rssi} snr=${e.snr}`;";
  html += "if(e.text && e.text.length){m1 += `<br><strong>TXT:</strong> ${e.text}`;}";
  html += "m1 += `<br><code>${e.data}</code></div>`;";
  html += "}";
  html += "for(let e of j.modem2){";
  html += "m2 += `<div><strong>${e.time}</strong> [${e.dir}] len=${e.len} rssi=${e.rssi} snr=${e.snr}`;";
  html += "if(e.text && e.text.length){m2 += `<br><strong>TXT:</strong> ${e.text}`;}";
  html += "m2 += `<br><code>${e.data}</code></div>`;";
  html += "}";
  html += "document.getElementById('modem1').innerHTML=m1;";
  html += "document.getElementById('modem2').innerHTML=m2;";
  html += "}).catch(e=>{});";
  html += "}";
  html += "updatePackets();setInterval(updatePackets,1000);";
  html += "</script>";
  html += htmlFooter();
  server.send(200, "text/html", html);
}

// Live packet JSON feed for browser
void handlePacketsJson() {
  String out;
  out.reserve(4096);
  out += "{\"modem1\":[";
  int count1 = modemLogFilled[0] ? PACKET_LOG_MAX_ENTRIES : modemLogHead[0];
  for (int i = 0; i < count1; i++) {
    int idx = modemLogFilled[0]
                ? (modemLogHead[0] + i) % PACKET_LOG_MAX_ENTRIES
                : i;
    PacketLogEntry &e = modemLogs[0][idx];
    if (i > 0) out += ",";
    out += "{";
    out += "\"time\":\"";
    out += String(e.ms);
    out += " ms\",\"dir\":\"";
    out += (e.fromOther ? "from-other" : "local");
    out += "\",\"len\":";
    out += String((unsigned)e.length);
    out += ",\"rssi\":";
    out += String(e.rssi, 1);
    out += ",\"snr\":";
    out += String(e.snr, 1);
    out += ",\"data\":\"";
    out += hexPreview(e.preview, e.previewLen);
    out += "\"";
    if (e.text.length() > 0) {
      out += ",\"text\":\"";
      for (size_t k = 0; k < (size_t)e.text.length(); k++) {
        char c = e.text[k];
        if (c == '\\' || c == '\"') out += '\\';
        if (c == '\r' || c == '\n') {
          out += ' ';
        } else {
          out += c;
        }
      }
      out += "\"";
    }
    out += "}";
  }
  out += "],\"modem2\":[";
  int count2 = modemLogFilled[1] ? PACKET_LOG_MAX_ENTRIES : modemLogHead[1];
  for (int i = 0; i < count2; i++) {
    int idx = modemLogFilled[1]
                ? (modemLogHead[1] + i) % PACKET_LOG_MAX_ENTRIES
                : i;
    PacketLogEntry &e = modemLogs[1][idx];
    if (i > 0) out += ",";
    out += "{";
    out += "\"time\":\"";
    out += String(e.ms);
    out += " ms\",\"dir\":\"";
    out += (e.fromOther ? "from-other" : "local");
    out += "\",\"len\":";
    out += String((unsigned)e.length);
    out += ",\"rssi\":";
    out += String(e.rssi, 1);
    out += ",\"snr\":";
    out += String(e.snr, 1);
    out += ",\"data\":\"";
    out += hexPreview(e.preview, e.previewLen);
    out += "\"";
    if (e.text.length() > 0) {
      out += ",\"text\":\"";
      for (size_t k = 0; k < (size_t)e.text.length(); k++) {
        char c = e.text[k];
        if (c == '\\' || c == '\"') out += '\\';
        if (c == '\r' || c == '\n') {
          out += ' ';
        } else {
          out += c;
        }
      }
      out += "\"";
    }
    out += "}";
  }
  out += "]}";

  server.send(200, "application/json", out);
}

// Config JSON endpoint
void handleSettingsJson() {
  String json = buildConfigJson();
  server.send(200, "application/json", json);
}

// OTA update page
void handleUpdateGet() {
  String html = htmlHeader("OTA Update");
  html += "<h2>OTA Firmware Update</h2>";
  html += "<form method='POST' action='/update' enctype='multipart/form-data'>";
  html += "<input type='file' name='firmware'><br>";
  html += "<input type='submit' value='Upload and Flash'>";
  html += "</form>";
  html += "<p><a href='/'>Back to Status</a></p>";
  html += htmlFooter();
  server.send(200, "text/html", html);
}

void handleUpdatePost() {
  HTTPUpload &upload = server.upload();

  if (upload.status == UPLOAD_FILE_START) {
    Serial.printf("Update start: %s\n", upload.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) {
      Update.printError(Serial);
    }
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    if (Update.write(upload.buf, upload.currentSize) != upload.currentSize) {
      Update.printError(Serial);
    }
  } else if (upload.status == UPLOAD_FILE_END) {
    if (Update.end(true)) {
      Serial.printf("Update success: %u bytes\n", upload.totalSize);
    } else {
      Update.printError(Serial);
    }
  } else if (upload.status == UPLOAD_FILE_ABORTED) {
    Update.end();
    Serial.println("Update aborted");
  }

  if (upload.status == UPLOAD_FILE_END) {
    server.sendHeader("Connection", "close");
    server.send(200, "text/plain", "Update complete. Rebooting...");
    delay(1000);
    ESP.restart();
  }
}

// =========================
// WiFi and Server setup
// =========================

void setupWifi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(gConfig.wifiSsid, gConfig.wifiPass);
  Serial.print("Connecting to WiFi SSID ");
  Serial.println(gConfig.wifiSsid);

  unsigned long start = millis();
  bool connected = false;
  while (millis() - start < 10000) {
    if (WiFi.status() == WL_CONNECTED) {
      connected = true;
      break;
    }
    delay(500);
    Serial.print(".");
  }
  Serial.println();

  if (connected) {
    Serial.print("Connected. IP: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("WiFi STA connect failed. Starting AP fallback.");
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAP(AP_SSID, AP_PASS);
    Serial.print("AP SSID: ");
    Serial.print(AP_SSID);
    Serial.print(" pass: ");
    Serial.println(AP_PASS);
    Serial.print("AP IP: ");
    Serial.println(WiFi.softAPIP());
  }
}

void setupWebServer() {
  server.on("/", HTTP_GET, handleRoot);

  server.on("/modem1", HTTP_GET, handleModem1Get);
  server.on("/modem1", HTTP_POST, handleModem1Post);

  server.on("/modem2", HTTP_GET, handleModem2Get);
  server.on("/modem2", HTTP_POST, handleModem2Post);

  server.on("/wifi", HTTP_GET, handleWifiGet);
  server.on("/wifi", HTTP_POST, handleWifiPost);

  server.on("/packets", HTTP_GET, handlePacketsPage);
  server.on("/packets.json", HTTP_GET, handlePacketsJson);

  server.on("/settings.json", HTTP_GET, handleSettingsJson);

  server.on("/update", HTTP_GET, handleUpdateGet);
  server.on(
    "/update",
    HTTP_POST,
    []() {},
    handleUpdatePost
  );

  server.onNotFound([]() {
    server.send(404, "text/plain", "Not found");
  });

  server.begin();
  Serial.println("HTTP server started on port 80");
}

// =========================
// Radio setup and bridging
// =========================

#if defined(ESP32)
  #define ISR_ATTR IRAM_ATTR
#else
  #define ISR_ATTR
#endif

void ISR_ATTR onModem1Dio1() {
  modem1ReceivedFlag = true;
}

void ISR_ATTR onModem2Dio1() {
  modem2ReceivedFlag = true;
}

bool initSingleModem(SX1262 &radio, uint8_t rfSwPin, const ModemConfig &mc) {
  pinMode(rfSwPin, OUTPUT);
  digitalWrite(rfSwPin, HIGH);  // RX default

  float freqMHz = mc.freqMHz;
  float bwKhz = mc.bwKhz;
  uint8_t sf = mc.sf;
  uint8_t cr = mc.cr;
  int8_t power = mc.txPower;

  if (freqMHz < 800.0f) freqMHz = 800.0f;
  if (freqMHz > 1000.0f) freqMHz = 1000.0f;
  if (bwKhz < 7.8f) bwKhz = 7.8f;
  if (bwKhz > 500.0f) bwKhz = 500.0f;
  if (sf < 5) sf = 5;
  if (sf > 12) sf = 12;
  if (cr < 5) cr = 5;
  if (cr > 8) cr = 8;
  if (power < -9) power = -9;
  if (power > 22) power = 22;

  Serial.print("[SX1262] begin freq=");
  Serial.print(freqMHz, 3);
  Serial.print(" MHz, BW=");
  Serial.print(bwKhz, 1);
  Serial.print(" kHz, SF=");
  Serial.print(sf);
  Serial.print(" CR=");
  Serial.print(cr);
  Serial.print(" P=");
  Serial.print(power);
  Serial.println(" dBm");

  int16_t state = radio.begin(
    freqMHz,
    bwKhz,
    sf,
    cr,
    LORA_SYNC_WORD_DEFAULT,
    power,
    LORA_PREAMBLE_LEN,
    LORA_TCXO_VOLTAGE,
    false
  );

  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("[SX1262] begin failed, code ");
    Serial.println(state);
    return false;
  }

  radio.setRegulatorDCDC();
  radio.setDio2AsRfSwitch(true);

  return true;
}

bool initRadios() {
  loraSPI.begin(LORA_SCK_PIN, LORA_MISO_PIN, LORA_MOSI_PIN);

  bool ok1 = initSingleModem(modem1Radio, MODEM1_RF_SW_PIN, gConfig.modem[0]);
  bool ok2 = initSingleModem(modem2Radio, MODEM2_RF_SW_PIN, gConfig.modem[1]);

  modem1Radio.setDio1Action(onModem1Dio1);
  modem2Radio.setDio1Action(onModem2Dio1);

  modem1Radio.startReceive();
  modem2Radio.startReceive();

  return ok1 && ok2;
}

// Helper: ensure both radios are back in RX mode after any TX
void resumeReceiveBoth() {
  modem1Radio.startReceive();
  modem2Radio.startReceive();
}

// Bridge logic with RX inhibit and LEDs

void bridgeFrom1To2(const uint8_t *data, size_t len, float rssi, float snr) {
  uint32_t h = fnv1a32(data, len);
  if (seenRecently(h)) {
    Serial.println("[Bridge] Dropping looped packet from modem1.");
    logPacket(0, false, data, len, rssi, snr);
    resumeReceiveBoth();
    return;
  }

  if (!gConfig.modem[1].enabled) {
    logPacket(0, false, data, len, rssi, snr);
    resumeReceiveBoth();
    return;
  }

  // Log RX on modem1 and decode public text
  logPacket(0, false, data, len, rssi, snr);

  // RX LED pulse for modem1
  pulseRxLed(0);

  // Inhibit RX on modem1 while modem2 is transmitting
  modem1Radio.standby();

  // TX on modem2 with TX LED
  digitalWrite(MODEM2_TX_LED_PIN, HIGH);
  digitalWrite(MODEM2_RF_SW_PIN, LOW);
  int16_t txState = modem2Radio.transmit(data, len);
  digitalWrite(MODEM2_RF_SW_PIN, HIGH);
  digitalWrite(MODEM2_TX_LED_PIN, LOW);

  if (txState == RADIOLIB_ERR_NONE) {
    logPacket(1, true, data, len, rssi, snr);
  } else {
    Serial.print("[Bridge] TX modem2 failed, code ");
    Serial.println(txState);
  }

  // Back to RX on both
  resumeReceiveBoth();
}

void bridgeFrom2To1(const uint8_t *data, size_t len, float rssi, float snr) {
  uint32_t h = fnv1a32(data, len);
  if (seenRecently(h)) {
    Serial.println("[Bridge] Dropping looped packet from modem2.");
    logPacket(1, false, data, len, rssi, snr);
    resumeReceiveBoth();
    return;
  }

  if (!gConfig.modem[0].enabled) {
    logPacket(1, false, data, len, rssi, snr);
    resumeReceiveBoth();
    return;
  }

  // Log RX on modem2 and decode public text
  logPacket(1, false, data, len, rssi, snr);

  // RX LED pulse for modem2
  pulseRxLed(1);

  // Inhibit RX on modem2 while modem1 is transmitting
  modem2Radio.standby();

  // TX on modem1 with TX LED
  digitalWrite(MODEM1_TX_LED_PIN, HIGH);
  digitalWrite(MODEM1_RF_SW_PIN, LOW);
  int16_t txState = modem1Radio.transmit(data, len);
  digitalWrite(MODEM1_RF_SW_PIN, HIGH);
  digitalWrite(MODEM1_TX_LED_PIN, LOW);

  if (txState == RADIOLIB_ERR_NONE) {
    logPacket(0, true, data, len, rssi, snr);
  } else {
    Serial.print("[Bridge] TX modem1 failed, code ");
    Serial.println(txState);
  }

  // Back to RX on both
  resumeReceiveBoth();
}

void handleRadioTraffic() {
  if (modem1ReceivedFlag) {
    modem1ReceivedFlag = false;

    size_t len = modem1Radio.getPacketLength(true);
    if (len > BRIDGE_BUF_SIZE) len = BRIDGE_BUF_SIZE;

    int16_t state = modem1Radio.readData(bridgeBuf, len);
    float rssi = modem1Radio.getRSSI();
    float snr = modem1Radio.getSNR();

    if (state != RADIOLIB_ERR_NONE) {
      Serial.print("[RX1] readData failed, code ");
      Serial.println(state);
      modem1Radio.startReceive();
    } else {
      bridgeFrom1To2(bridgeBuf, len, rssi, snr);
    }
  }

  if (modem2ReceivedFlag) {
    modem2ReceivedFlag = false;

    size_t len = modem2Radio.getPacketLength(true);
    if (len > BRIDGE_BUF_SIZE) len = BRIDGE_BUF_SIZE;

    int16_t state = modem2Radio.readData(bridgeBuf, len);
    float rssi = modem2Radio.getRSSI();
    float snr = modem2Radio.getSNR();

    if (state != RADIOLIB_ERR_NONE) {
      Serial.print("[RX2] readData failed, code ");
      Serial.println(state);
      modem2Radio.startReceive();
    } else {
      bridgeFrom2To1(bridgeBuf, len, rssi, snr);
    }
  }
}

// =========================
// OLED update
// =========================

void updateOled() {
  static unsigned long lastUpdate = 0;
  unsigned long now = millis();
  if (now - lastUpdate < 500) return;
  lastUpdate = now;

  static bool oledOk = true;
  if (!oledOk) return;

  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.print("MeshCore Bridge");

  display.setCursor(0, 10);
  if (WiFi.status() == WL_CONNECTED) {
    display.print("STA ");
    display.print(WiFi.localIP());
  } else {
    display.print("AP  ");
    display.print(WiFi.softAPIP());
  }

  display.setCursor(0, 22);
  display.print("M1:");
  display.print(gConfig.modem[0].enabled ? "ON " : "OFF");
  display.print(" RX:");
  display.print(totalPacketsRx[0]);
  display.print(" F:");
  display.print(totalPacketsFwd[0]);

  display.setCursor(0, 32);
  display.print("M2:");
  display.print(gConfig.modem[1].enabled ? "ON " : "OFF");
  display.print(" RX:");
  display.print(totalPacketsRx[1]);
  display.print(" F:");
  display.print(totalPacketsFwd[1]);

  display.setCursor(0, 44);
  display.print("RSSI1:");
  display.print(lastRssi[0], 0);
  display.print(" SNR1:");
  display.print(lastSnr[0], 0);

  display.setCursor(0, 54);
  display.print("RSSI2:");
  display.print(lastRssi[1], 0);
  display.print(" SNR2:");
  display.print(lastSnr[1], 0);

  display.display();
}

// =========================
// Modem config POST handler
// =========================

void handleModemPost(uint8_t index) {
  if (index > 1) {
    server.send(404, "text/plain", "Invalid modem index");
    return;
  }
  ModemConfig &mc = gConfig.modem[index];

  if (server.hasArg("enabled")) {
    mc.enabled = (server.arg("enabled") == "1");
  }
  if (server.hasArg("freq")) {
    mc.freqMHz = server.arg("freq").toFloat();
  }
  if (server.hasArg("bw")) {
    mc.bwKhz = server.arg("bw").toFloat();
  }
  if (server.hasArg("sf")) {
    int v = server.arg("sf").toInt();
    if (v < 5) v = 5;
    if (v > 12) v = 12;
    mc.sf = (uint8_t)v;
  }
  if (server.hasArg("cr")) {
    int v = server.arg("cr").toInt();
    if (v < 5) v = 5;
    if (v > 8) v = 8;
    mc.cr = (uint8_t)v;
  }
  if (server.hasArg("tx")) {
    int v = server.arg("tx").toInt();
    if (v < -9) v = -9;
    if (v > 22) v = 22;
    mc.txPower = (int8_t)v;
  }

  saveConfig();

  initRadios();

  renderModemConfigPage(index, "Settings saved and radios reinitialized.");
}

// =========================
// Arduino setup / loop
// =========================

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println();
  Serial.println("MeshCore Dual SX1262 Bridge starting...");
  Serial.println(FW_VERSION);

  if (!SPIFFS.begin(true)) {
    Serial.println("SPIFFS mount failed.");
  }

  loadConfig();

  // LED pins init
  pinMode(MODEM1_RX_LED_PIN, OUTPUT);
  pinMode(MODEM1_TX_LED_PIN, OUTPUT);
  pinMode(MODEM2_RX_LED_PIN, OUTPUT);
  pinMode(MODEM2_TX_LED_PIN, OUTPUT);
  digitalWrite(MODEM1_RX_LED_PIN, LOW);
  digitalWrite(MODEM1_TX_LED_PIN, LOW);
  digitalWrite(MODEM2_RX_LED_PIN, LOW);
  digitalWrite(MODEM2_TX_LED_PIN, LOW);

  Wire.begin(OLED_SDA_PIN, OLED_SCL_PIN);
  if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) {
    Serial.println("SSD1306 allocation failed");
  } else {
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0, 0);
    display.print("MeshCore Bridge");
    display.setCursor(0, 10);
    display.print("Booting...");
    display.display();
  }

  if (!initRadios()) {
    Serial.println("Radio init failed. Check wiring and power for Wio-SX1262 modules.");
  }

  setupWifi();
  setupWebServer();
}

void loop() {
  handleRadioTraffic();
  server.handleClient();
  updateOled();
}
