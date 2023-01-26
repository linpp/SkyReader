/*
   Serial interface to a RFID-RC522 for use with Skyreader instead of a real Portal.
   Implements a serial protocol to read and write blocks, detecting and authenticating
   Skylander toys and/or standard NFC cards.

   Requires the MFRC522 Library by miguelbalboa.

   ----------------------------------------------------------------------------
   Example sketch/program which will try the most used default keys listed in
   https://code.google.com/p/mfcuk/wiki/MifareClassicDefaultKeys to dump the
   block 0 of a MIFARE RFID card using a RFID-RC522 reader.

   Typical pin layout used:
   -----------------------------------------------------------------------------------------
               MFRC522      Arduino       Arduino   Arduino    Arduino          Arduino
               Reader/PCD   Uno/101       Mega      Nano v3    Leonardo/Micro   Pro Micro
   Signal      Pin          Pin           Pin       Pin        Pin              Pin
   -----------------------------------------------------------------------------------------
   RST/Reset   RST          9             5         D9         RESET/ICSP-5     RST
   SPI SS      SDA(SS)      10            53        D10        10               10
   SPI MOSI    MOSI         11 / ICSP-4   51        D11        ICSP-4           16
   SPI MISO    MISO         12 / ICSP-1   50        D12        ICSP-1           14
   SPI SCK     SCK          13 / ICSP-3   52        D13        ICSP-3           15

   More pin layouts for other boards can be found here: https://github.com/miguelbalboa/rfid#pin-layout

   1/15/23 Peter Lin
*/

#include <AES.h>
#include <SPI.h>
#include <MFRC522.h>
#include "md5.h"

#define RST_PIN         9           // Configurable, see typical pin layout above
#define SS_PIN          10          // Configurable, see typical pin layout above
#define RESTORE_KEYS    0

#define USE_BLOCK0_BACKDOOR 1       // Use backdoor to write to block 0
#define SAFE_ACCESS_TRAILER 0       // write safe access conditions on all sector trailers

#define NUM_SECTORS         16
#define BLOCKS_PER_SECTOR   4
#define BLOCK_SIZE          16
#define NUM_BLOCKS          (NUM_SECTORS * BLOCKS_PER_SECTOR)

byte atqa[2];
byte atqa_size;

byte dataBuf[3][BLOCK_SIZE];        // [0] = block0, [1] = block1, [2] = general buffer
byte secKeys[NUM_SECTORS][MFRC522::MF_KEY_SIZE];

MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance.
MFRC522::StatusCode status;

bool debug = false;
uint16_t toyType = 0xFFFF;
uint32_t newUid = 0;

AES aes;

typedef enum : byte {
  wm_test = 0,
  wm_normal,
  wm_force,
} WRITE_MODE;

typedef enum : byte {
  am_default = 0,
  am_safe,
  am_locked,
} ACCESS_MODE;

// Number of known default keys (hard-coded)
// NOTE: Synchronize the NR_KNOWN_KEYS define with the defaultKeys[] array
#define NR_KNOWN_KEYS   9
// Known keys, see: https://code.google.com/p/mfcuk/wiki/MifareClassicDefaultKeys
const byte knownKeys[NR_KNOWN_KEYS][MFRC522::MF_KEY_SIZE] =  {
  {0x4b, 0x0b, 0x20, 0x10, 0x7c, 0xcb}, // Skylander tag
  {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // FF FF FF FF FF FF = factory default
  {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}, // A0 A1 A2 A3 A4 A5
  {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5}, // B0 B1 B2 B3 B4 B5
  {0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd}, // 4D 3A 99 C3 51 DD
  {0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a}, // 1A 98 2C 7E 45 9A
  {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7}, // D3 F7 D3 F7 D3 F7
  {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, // AA BB CC DD EE FF
  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}  // 00 00 00 00 00 00
};

const byte safe[4] = { 0xFF, 0x07, 0x80, 0x69 };
const char* _PASS = "O";
const char* _FAIL = "X";


/*
   Wake the card and select the old uid.  When an operation fails, the card will
   halt and stop responding until it is woken again.
*/
bool wake_card() {
  atqa_size = 2;
  memset(atqa, 0, atqa_size);
  mfrc522.PICC_WakeupA(atqa, &atqa_size);
  if (!atqa[0] && !atqa[1]) return false;
  mfrc522.PICC_Select(&mfrc522.uid, mfrc522.uid.size * 8);
  return true;
}

/*
   Bitwise shift of a byte array in LE MSB. Returns the last carry bit.
*/
inline byte shift_crc(byte* crc, byte bytes) {
  byte carry = 0;     // shift in
  while (bytes--) {
    byte c = *crc >> 7;
    *crc = ((*crc << 1) | carry);
    crc++;
    carry = c;
  }
  return carry;       // shift out
}

/*
   Psuedo crc of a byte array in LE MSB. The byte array defines the scope
   of operation avoiding extra shifts and masks.
*/
void pseudo_crc(byte bytes, const byte* poly, byte* crc, byte *data, byte len) {
  while (len--) {
    crc[bytes - 1] ^= *data++;
    for (byte k = 0; k < 8; k++) {
      if (shift_crc(crc, bytes)) {
        for (byte j = 0; j < bytes; j++) {
          crc[j] ^= poly[j];
        }
      }
    }
  }
}

/*
   ECMA-182 crc48 with 0x42f0e1eba9ea3693 polynomial (last 48 bits)
*/
void pseudo_crc48(byte *crc, byte* data, byte len) {
  const byte poly[MFRC522::MF_KEY_SIZE] = {0x93, 0x36, 0xea, 0xa9, 0xeb, 0xe1};
  pseudo_crc(sizeof(poly), poly, crc, data, len);
}

/*
   CCITT crc16 with 0x1021 polynomial
*/
void pseudo_crc16(byte *crc, byte* data, byte len) {
  const byte poly[2] = {0x21, 0x10};
  pseudo_crc(sizeof(poly), poly, crc, data, len);
}

/*
   Calculate access key (KeyA) for Skylander toys using pre-calculated primes:
    magic = 2 * 2 * 3 * 1103 * 12868356821
*/
void calc_keya(byte* uid, byte sector, byte* key) {
  const byte magic[MFRC522::MF_KEY_SIZE] = {0xc4, 0x0c, 0x26, 0x03, 0xe9, 0x9a};
  const byte *pre = (sector) ? magic : knownKeys[0];
  memcpy(key, pre, MFRC522::MF_KEY_SIZE);
  if (sector > 0 && sector < NUM_SECTORS) {
    byte data[5];
    memcpy(data, uid, 4);
    data[4] = sector;
    pseudo_crc48(key, data, 5);
  }
}

void dump_byte_array_int(byte *buf, byte bufSize, byte sep = 0) {
  while (bufSize--) {
    if (*buf < 0x10) Serial.print("0");
    Serial.print(*buf++, HEX);
    if (sep) Serial.print(" ");
  }
}

void dump_byte_array(byte *buf, byte bufSize, byte sep = 0) {
  dump_byte_array_int(buf, bufSize, sep);
  Serial.println();
}

void dump_byte_array1(byte *buf, byte bufSize) {
  while (bufSize--) {
    byte c = *buf++;
    c = (c < 0x20 || c > 0x7E) ? '.' : c;
    Serial.write(c);
  }
}
inline bool isHexadecimal(char c) {
  return isdigit(c) || (c >= 'A' && c <= 'F');
}

bool hex2array(byte *buf, byte bufSize, byte *string) {
  for (byte u, l, i = 0; i < bufSize * 2; i++) {
    l = *string++;
    if (l & 0x40) l &= 0xDF;
    if (isHexadecimal(l)) {
      l -= (l > '9') ? '7' : '0';
      if (i & 1) {
        *buf++ = u | l;
      } else {
        u = l << 4;
      }
    } else return false;    // bad char in input
  }
  return true;
}

byte getSerialBytes(byte *buf, byte len) {
  byte *b = buf;
  while (Serial.available() && len--) {
    *b = Serial.read();
    if (*b == 0x0d)
      break;
    b++;
  }
  //  dump_byte_array1(buf, b - buf);
  return b - buf;
}

/*
   update sector 0 checksum, buf points to sector 0 & sector 1
*/
void update_checksum(byte buf[][BLOCK_SIZE]) {
  byte cs[2] = { 0xFF, 0xFF };
  pseudo_crc16(cs, buf[0], 30);
  memcpy(&buf[1][14], cs, 2);
}

/*
   Generate all Skylander access keys for a given UID
*/
void key_gen(byte keys[][MFRC522::MF_KEY_SIZE], byte *uid, byte uidSize) {
  if (debug) {
    Serial.print(F("Generating keys for UID:"));
    dump_byte_array(uid, uidSize);
  }
  for (byte i = 0; i < NUM_SECTORS; i++) {
    calc_keya(uid, i, keys[i]);
    if (debug) {
      dump_byte_array(keys[i], MFRC522::MF_KEY_SIZE);
    }
  }
}


/*
   Try authenticating with the given key, wake up card if necessary
*/
bool auth_key(byte command, byte block, const byte key[MFRC522::MF_KEY_SIZE]) {
  MFRC522::MIFARE_Key *keyA = (MFRC522::MIFARE_Key *)key;
  if (debug) {
    Serial.print(F("AK ["));
    dump_byte_array_int(keyA->keyByte, MFRC522::MF_KEY_SIZE, 0);
    Serial.print(F("] "));
  }
  status = mfrc522.PCD_Authenticate(command, block, keyA, &(mfrc522.uid));
  if (status == MFRC522::STATUS_TIMEOUT && wake_card()) {
    status = mfrc522.PCD_Authenticate(command, block, keyA, &(mfrc522.uid));
  }
  if (status != MFRC522::STATUS_OK) {
    if (status != MFRC522::STATUS_TIMEOUT) {
      Serial.print(F("PCD_Authenticate() failed: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
    }
    return false;
  }
  return true;
}

/*
   Read block with a known key
*/
bool read_block(byte block, const byte keyA[MFRC522::MF_KEY_SIZE], bool dump)
{
  byte buffer[18];
  if (auth_key(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, keyA)) {
    // read block
    byte byteCount = sizeof(buffer);
    status = mfrc522.MIFARE_Read(block, buffer, &byteCount);
    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("MIFARE_Read() failed: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
    } else {
      // update key in the sector trailer
      if (isSectorTrailer(block)) {
        memcpy(buffer, keyA, MFRC522::MF_KEY_SIZE);
      }
      if (dump) {
        if (debug) {
          dump_byte_array_int(&block, 1);
          Serial.print(F("< "));
        }
        dump_byte_array(buffer, BLOCK_SIZE);
      }
      byte line = (block < 2) ? block : 2;
      memcpy(dataBuf[line], buffer, BLOCK_SIZE);
      return true;
    }
  }
  return false;
}

/*
   Read block with unknown key (key search)
*/
bool read_block(byte block, bool dump) {
  byte sector = block / BLOCKS_PER_SECTOR;
  if (block < 64) {
    if (block == 0) {
      for (byte k = 0; k < NR_KNOWN_KEYS; k++) {
        if (read_block(block, knownKeys[k], dump)) {
          if (k == 0) {
            // card is skylanders, generate sector keys
            key_gen(secKeys, mfrc522.uid.uidByte, mfrc522.uid.size);
          } else {
            // card is normal, default current key for all sectors
            for (byte j = 0; j < NUM_SECTORS; j++) {
              memcpy(secKeys[j], knownKeys[k], MFRC522::MF_KEY_SIZE);
            }
          }
          return true;
        }
      }
    } else {      // all other blocks
      for (byte k = 0; k < NR_KNOWN_KEYS; k++) {
        // try default key first, then known keys
        if (read_block(block, (k == 0) ? secKeys[sector] : knownKeys[k], dump)) {
          if (k != 0)   // update the sector key
            memcpy(secKeys[sector], knownKeys[k], MFRC522::MF_KEY_SIZE);
          return true;
        }
      }
    }
  } else {
    if (debug) {
      Serial.print(F("block "));
      dump_byte_array_int(&block, 1);
      Serial.println(F(" out of range"));
    }
  }
  return false;
}

inline bool isSectorTrailer(byte block) {
  return (block % BLOCKS_PER_SECTOR) == 3;
}

/*
   Initialize.
*/
void setup() {
  Serial.begin(115200);       // Initialize serial communications with the PC
  while (!Serial);            // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
  SPI.begin();                // Init SPI bus
  mfrc522.PCD_Init();         // Init MFRC522 card
  randomSeed(analogRead(0));
  menu();
  Serial.print(F("$"));
}

void menu() {
  Serial.println(F("0 Decrypt Toy\n1 Dump EML\n2 Factory dump\n3 Factory reset\n4 Firmware check\nF Format toy\nt[#] Set ToyType\nu[8X|*] Set UID\nU Update Skylander\nd[1|0] Debug on|off\n? Show menu"));
}

/*
   Main loop.
*/
void loop() {
  bool done = true;
  do {
    char choice = Serial.read();
    done = true;
    bool saved = debug;
    int t = 50;
    switch (choice) {
      /*
         Options useful on a serial monitor
      */
      case '0':                             // read card decrypted
        read_card(true);
        break;
      case '1':                             // read the card and dump it in eml format
        read_card(false);
        break;
      case '2':                             // internal dump card (only works on factory cards)
        dump_serial();
        break;
      case '3':                             // reset all keys to factory (requires a magic/backdoor card)
        Serial.print(reset_keys(wm_force) ? _PASS : _FAIL);
        break;
      case '4':                             // RC522 reader firmware self-check
        firmware_check();
        break;
      case 'd':                             // d1 turns on debug mode, d0 turns off debug mode
        debug = Serial.read() == '1';
        break;
      case 'F':                             // reset skylander figure
        reset_figure();
        break;
      case 't':                             // set toy id (must be followed by an update 'U')
        {
          byte data[4];
          byte l = getSerialBytes(data, 4); // optional 4 digit character number
          if (set_toy(data, l))
            Serial.println(F("Update card to write new toy"));
          break;
        }
      case 'u':                             // set the uid to a known or random value
        {
          byte data[8];
          byte l = getSerialBytes(data, 8);
          if (set_uid(data, l))
            Serial.println(F("Update card to write new toy"));
          break;
        }
      case 'U':                             // update card
        Serial.print(update_card() ? _PASS : _FAIL);
        break;
      /*
         The remaining options are useful for a connected app, they require extra data to be sent.
         read_card() must be run first before these work properly and the card must not change
         between operations.
      */
      case 'R':                             // read block (block ascii range 0x30 "0" - 0x6F "o")
        Serial.print(read_block(Serial.read() - '0', true) ? _PASS : _FAIL);
        break;
      case 'w':                             // TEST write the given block (offset by ascii '0')
      case 'W':
        Serial.print(write_block(Serial.read() - '0', (choice == 'w' ? wm_test : wm_normal)) ? _PASS : _FAIL);
        break;
      case 's':                             // TEST write a data stream to the card (authenticates but does not write)
      case 'S':
        debug = false;                      // debug needs to be off to stream blocks
        Serial.print(write_stream((choice == 's' ? wm_test : wm_normal)) ? _PASS : _FAIL);
        debug = saved;
        break;
      case '?':
        menu();
        done = false;
        break;
      /*
         Start a new loop on linefeed, will halt the card
      */
      case 0x0A:
        Serial.print(F("$"));
        break;
      case 0x0F:
      case 0x0D:
        t = 0;
      default:
        //dump_byte_array(&choice, 1);
        done = false;
        if (t) delay(t);
        break;
    }
  } while (!done);
  mfrc522.PICC_HaltA();       // Halt PICC
  mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
}

void firmware_check() {
  Serial.println();
  mfrc522.PCD_DumpVersionToSerial();    // Show version of PCD - MFRC522 Card Reader
  Serial.print(F("Self test... "));
  if (mfrc522.PCD_PerformSelfTest())    // perform the test
    Serial.println(F("OK"));
  else
    Serial.println(F("DEFECT or UNKNOWN"));
}

void fix_bricked() {
  // despite the name, UnbrickUidSector only writes to block 0, not the entire sector
  if ( mfrc522.MIFARE_UnbrickUidSector(true) ) {
    Serial.println(F("Cleared block 0, set UID to 1234. Card should be responsive again now."));
  }
}

/*
   Set a new UID from hexstring. if none, use default 0x31323334
   If skylander, also update block1 and sector keys
*/
bool set_uid(byte *uid, byte l) {
  if (l == 1 && uid[0] == '*') {                           // if *, make random
    newUid = random(0x80000000) * random(0x8000);
  } else if (l == 8) {                                     // 8 ascii chars
    if (!hex2array((byte*)&newUid, 4, uid)) {
      Serial.println(F("Invalid UID"));
      newUid = 0;
    }
  }
  if (newUid) {
    Serial.print(F("UID: "));
    dump_byte_array((byte*)&newUid, 4, 0);
    return true;
  }
  return false;
}

bool update_card() {
  if (wake_card()) {
    if (newUid || toyType != 0xFFFF) {                       // update uid and/or toy type
      if (read_block(0, false) &&                            // this will generate secKeys
          read_block(1, false)) {
        byte buf[2][BLOCK_SIZE];
        memcpy(buf[0], dataBuf[0], sizeof(buf));             // make a working copy
        if (newUid) {                                        // new uid, else keep old
          byte *s = (byte*)&newUid, bcc = 0;
          for (byte i=0; i < 4; i++) {
            buf[0][i] = s[i];
            bcc ^= s[i];
          }
          buf[0][4] = bcc;                                   // update bcc
          dump_byte_array(buf[0], 32, 0);
        }
        if (toyType != 0xFFFF) {                             // if we have a new toy type, change it
          memcpy(&buf[1], (byte*)&toyType, 2);
        }
        update_checksum(buf);
        if (!write_block(1, buf[1], wm_normal)) {            // write block 1 first
          return false;
        }
        byte keys[NUM_SECTORS][MFRC522::MF_KEY_SIZE];
        key_gen(keys, buf[0], 4);
        if (!update_keys(keys, am_locked, wm_normal)) {      // update the sector keys
          return false;
        }
        if (write_block(0, buf[0], wm_normal)) {            // finally write block 0
          toyType = 0xFFFF;
          newUid = 0;
          return true;
        }
      }
    }
  }
  return false;
}

bool wait_for_card() {
  Serial.println(F("Place card.."));
  // Look for cards for 10 seconds
  for (int i = 0; i <= 10; i++) {
    if (mfrc522.PICC_IsNewCardPresent()) {
      if (mfrc522.PICC_ReadCardSerial()) {
        mfrc522.PICC_HaltA();       // halt it, so we can wake it
        continue;
      }
    } else {
      if (wake_card()) {
        break;
      }
    }
    if (i == 10) {
      Serial.println(F("no card found."));
      return false;
    }
    delay(1000);
  }
  return true;
}

void read_card(bool decrypt) {
  if (!wait_for_card()) return;

  // Show some details of the PICC (that is: the tag/card)
  mfrc522.PICC_DumpDetailsToSerial(&mfrc522.uid);
  atqa_size = 2;
  mfrc522.PICC_RequestA(atqa, &atqa_size);
  Serial.print(F("ATQA: "));
  dump_byte_array(atqa, atqa_size, 1);

  if (!decrypt) Serial.println(F("--EML DUMP BEGIN"));
  bool result = false;
  byte seq1, seq2;
  bool blank = true;

  // For each block, try the known keys (might not be the same key for every sector)
  for (byte block = 0; block < NUM_BLOCKS; block++) {
    result = read_block(block, (decrypt) ? !shouldEncryptBlock(block) : true);
    if (!result) {
      Serial.print(F("Failed to read block "));
      Serial.println(block);
      break;
    }
    if (decrypt && block == 8) {
      for (byte i = 0; i < BLOCK_SIZE; i++) {
        if (dataBuf[2][i] != 0) {
          blank = false;
          break;
        }
      }
    }
    if (decrypt && !blank && decryptBlock(dataBuf[2], block)) {
      dump_byte_array_int(dataBuf[2], BLOCK_SIZE);
      Serial.print(F(" ["));
      dump_byte_array1(dataBuf[2], BLOCK_SIZE);
      Serial.println(F("]"));
      if (block == 8)  seq1 = dataBuf[2][9];
      if (block == 36) seq2 = dataBuf[2][9];
    }
  }
  if (decrypt) {
    dumpFigureInfo();
    dumpFigureData((blank) ? 0 : (seq2 > seq1) ? 36 : 8);
  }
  else Serial.println(F("--EML DUMP END"));
}

void make_access(byte *data, const byte *mode) {
  memcpy(&data[6], mode, 4);
}

/*
   Note: must have called read_block on block 0 before calling this method
   mode 0 = test, 1 = normal write, 2 = backdoor write
*/
bool write_block(byte block, byte* data, WRITE_MODE mode) {
  byte sector = block / BLOCKS_PER_SECTOR;
  byte line = (block < 2) ? block : 2;

#if 0
  // skip 0 and trailers
  if (isSectorTrailer(block) || block == 0)
    return true;
#endif

#if SAFE_ACCESS_TRAILER
  if (isSectorTrailer(block)) {           // Rewrite the sector trailer access to something safe
#else
  if (block == 3) {                       // Always make sector 0 safe
#endif
    make_access(data, safe);
  }

  if (data != dataBuf[line] &&            // only write on change
      memcmp(data, dataBuf[line], BLOCK_SIZE) == 0) {
    return true;
  }

  if (block == 0 || mode == wm_force) {    // open UID backdoor
    if (debug)
      Serial.print(F("[ OPEN BACKDOOR ] "));
    mfrc522.PICC_HaltA();       // Halt PICC
    mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
    if (!mfrc522.MIFARE_OpenUidBackdoor(true)) {
      Serial.println(F(" failed"));
      return false;
    }
  } else {                                 // otherwise authenticate using key A
    //    MFRC522::MIFARE_Key key;
    //    memcpy(key.keyByte, secKeys[sector], MFRC522::MF_KEY_SIZE);
    if (!auth_key(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, secKeys[sector])) {
      if (debug) {
        Serial.println(F(" failed"));
      }
      return false;
    }
  }
  // Write data to the block
  dump_byte_array_int(&block, 1, 0);
  Serial.print(F("> "));
  dump_byte_array(data, BLOCK_SIZE, 0);
  if (mode != wm_test) {
    status = (MFRC522::StatusCode) mfrc522.MIFARE_Write(block, data, BLOCK_SIZE);
    if (status != MFRC522::STATUS_OK) {
      if (debug) {
        Serial.print(F("MIFARE_Write() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
      }
      return false;
    }
    // update the sector key map if we wrote the trailer
    if (isSectorTrailer(block)) {
      memcpy(secKeys[sector], data, MFRC522::MF_KEY_SIZE);
    }
  }
#if USE_BLOCK0_BACKDOOR
  if (block == 0 || mode == wm_force) {    // wake up the card again
    atqa_size = 2;
    mfrc522.PICC_WakeupA(atqa, &atqa_size);
  }
#endif

  return true;
}

void stream_block(byte block, byte line) {
  while (Serial.available()) Serial.read();
  dump_byte_array_int(&block, 1, 0);
  Serial.print(F(":"));
  while (Serial.available() < BLOCK_SIZE);
  for (byte k = 0; k < BLOCK_SIZE; k++) {
    dataBuf[line][k] = Serial.read();
  }
}

bool write_block(byte block, WRITE_MODE mode) {
  if (block > 63) {
    if (debug) {
      Serial.print(F("block "));
      dump_byte_array_int(&block, 1);
      Serial.println(F(" out of range"));
    }
    return false;
  }
  byte line = (block < 2) ? block : 2;
  stream_block(block, line);
  return write_block(block, dataBuf[line], mode);
}

/*
   Stream blocks to write over the serial port, but block 0 is last.
*/
bool write_stream(WRITE_MODE mode) {
  if (wake_card()) {
    // block 0 write will change the card uid and cause a new card to be found,
    // so we will delay block 0 writing until the end
    for (byte block = 0; block < NUM_BLOCKS; block++) {
      if (block == 0) {
        stream_block(0, 0);
      } else if (!write_block(block, mode)) {
        return false;
      }
    }
    // write block 0 last
    return write_block(0, dataBuf[0], mode);
  }
  return false;
}

bool set_toy(byte *data, byte l) {
  if (l > 0 && l < 5) {                                              // up to 4 digit toy ids
    uint16_t toy = 0;
    for (byte i = 0; i < l; i++) {
      toy = toy * 10 + (data[i] - '0');
    }
    Serial.print("ToyType: ");
    Serial.println(toy);
    toyType = toy;
    return true;
  }
  return false;
}

void reset_figure() {
  if (!wait_for_card()) return;

  byte buf[BLOCK_SIZE];
  memset(buf, 0, BLOCK_SIZE);
  for (byte block = 5; block < NUM_BLOCKS; block++) {
    if (!isSectorTrailer(block) && block != 0x22 && block != 0x3e) {
      if (read_block(block, false)) {
        if (!write_block(block, buf, wm_normal)) {
          break;
        }
      }
    }
  }
}

/*
   Dumps the card, only works with factory keys
*/
void dump_serial() {
  if (!wait_for_card()) return;

  // Dump debug info about the card; PICC_HaltA() is automatically called
  mfrc522.PICC_DumpToSerial(&(mfrc522.uid));
}

bool update_keys(byte keys[][MFRC522::MF_KEY_SIZE], ACCESS_MODE access, WRITE_MODE mode) {
  byte buf[BLOCK_SIZE];
  byte locked[] = { 0x7f, 0x0f, 0x08, 0x69 };
  if (mode == wm_force) {
    memset(buf, 0, BLOCK_SIZE);
  } else if (mode == wm_normal) {
    if (!read_block(0, false)) {                          // get access keys
      return false;
    }
  }
  for (byte i = 0; i < NUM_SECTORS; i++) {
    WRITE_MODE m = mode;
    byte block = (i * BLOCKS_PER_SECTOR) + 3;
    if (m != wm_force) {
      if (!read_block(block, false))
        return false;
      memcpy(buf, dataBuf[2], BLOCK_SIZE);
    }
    memcpy(buf, keys[i], MFRC522::MF_KEY_SIZE);           // update the key
    if (memcmp(&buf[6], safe, 4) != 0) {                  // locked access, try to force it
      m = wm_force;
    }
    switch (access) {
      case am_safe:   make_access(buf, safe);    break;
      case am_locked: make_access(buf, locked);  break;
      default: break;
    }
    if (!write_block(block, buf, m))               // will update the secKey entry
      return false;
  }
  return true;
}

bool reset_keys(WRITE_MODE mode) {
  //  if (!wait_for_card()) return false;

  byte keys[NUM_SECTORS][MFRC522::MF_KEY_SIZE];
  for (byte i = 0; i < NUM_SECTORS; i++) {
    memcpy(keys[i], knownKeys[1], MFRC522::MF_KEY_SIZE);   // write factory keys for all sectors
  }
  update_keys(keys, am_safe, mode);
}


/*
   Skylander Figure
*/
uint16_t get16(byte *data) {
  return data[0] | ((uint16_t)data[1]) << 8;
}
uint32_t get24(byte*data) {
  return get16(data) | ((uint32_t)data[2]) << 16;
}
uint32_t get32(byte *data) {
  return get24(data) | ((uint32_t)data[3]) << 24;
}

const __FlashStringHelper *toyName(uint16_t toyId) {
  switch (toyId) {
    case 0 : return F("Whirlwind");                      //0000|0030|regular|air
    case 1 : return F("Sonic Boom");                     //0100|0030|regular|air
    case 2 : return F("Warnado");                        //0200|0030|regular|air
    case 3 : return F("Lightning Rod");                  //0300|0030|regular|air
    case 404 :                                           //9401|0030|legendary|earth
    case 4 : return F("Bash");                           //0400|0030|regular|earth
    case 5 : return F("Terrafin");                       //0500|0030|regular|earth
    case 6 : return F("Dino-Rang");                      //0600|0030|regular|earth
    case 7 : return F("Prism Break");                    //0700|0030|regular|earth
    case 8 : return F("Sunburn");                        //0800|0030|regular|fire
    case 9 : return F("Eruptor");                        //0900|0030|regular|fire
    case 10 : return F("Ignitor");                       //0a00|0030|regular|fire
    case 11 : return F("Flameslinger");                  //0b00|0030|regular|fire
    case 12 : return F("Zap");                           //0c00|0030|regular|water
    case 13 : return F("Wham-Shell");                    //0d00|0030|regular|water
    case 14 : return F("Gill Grunt");                    //0e00|0030|regular|water
    case 15 : return F("Slam Bam");                      //0f00|0030|regular|water
    case 416 :                                           //a001|0030|legendary|magic
    case 16 : return F("Spyro");                         //1000|0030|regular|magic
    case 17 : return F("Voodood");                       //1100|0030|regular|magic
    case 18 : return F("Double Trouble");                //1200|0030|regular|magic
    case 419 :                                           //a301|0030|legendary|tech
    case 19 : return F("Trigger Happy");                 //1300|0030|regular|tech
    case 20 : return F("Drobot");                        //1400|0030|regular|tech
    case 21 : return F("Drill Sergeant");                //1500|0030|regular|tech
    case 22 : return F("Boomer");                        //1600|0030|regular|tech
    case 23 : return F("Wrecking Ball");                 //1700|0030|regular|magic
    case 24 : return F("Camo");                          //1800|0030|regular|life
    case 25 : return F("Zook");                          //1900|0030|regular|life
    case 26 : return F("Stealth Elf");                   //1a00|0030|regular|life
    case 27 : return F("Stump Smash");                   //1b00|0030|regular|life
    case 28 : return F("Dark Spyro");                    //1c00|0030|regular|magic
    case 29 : return F("Hex");                           //1d00|0030|regular|undead
    case 430 :                                           //ae01|0030|legendary|undead
    case 30 : return F("Chop Chop");                     //1e00|0030|regular|undead
    case 31 : return F("Ghost Roaster");                 //1f00|0030|regular|undead
    case 32 : return F("Cynder");                        //2000|0030|regular|undead
#if 0
    case 100 : return F("Jet Vac");                      //6400|0030|regular|air
    case 101 : return F("Swarm");                        //6500|0030|giant|air
    case 102 : return F("Crusher");                      //6600|0030|giant|earth
    case 103 : return F("Flashwing");                    //6700|0030|regular|earth
    case 104 : return F("Hot Head");                     //6800|0030|giant|fire
    case 105 : return F("Hot Dog");                      //6900|0030|regular|fire
    case 106 : return F("Chill");                        //6a00|0030|regular|water
    case 107 : return F("Thumpback");                    //6b00|0030|giant|water
    case 108 : return F("Pop Fizz");                     //6c00|0030|regular|magic
    case 109 : return F("Ninjini");                      //6d00|0030|giant|magic
    case 110 : return F("Bouncer");                      //6e00|0030|giant|tech
    case 111 : return F("Sprocket");                     //6f00|0030|regular|tech
    case 112 : return F("Tree Rex");                     //7000|0030|giant|life
    case 113 : return F("Shroomboom");                   //7100|0030|regular|life
    case 114 : return F("Eye-Brawl");                    //7200|0030|giant|undead
    case 115 : return F("Fright Rider");                 //7300|0030|regular|undead
    case 200 : return F("Anvil Rain");                   //c800|0030|item|none
    case 201 : return F("Treasure Chest");               //c900|0030|item|none
    case 202 : return F("Healing Elixer");               //ca00|0030|item|none
    case 203 : return F("Ghost Swords");                 //cb00|0030|item|none
    case 204 : return F("Time Twister");                 //cc00|0030|item|none
    case 205 : return F("Sky-Iron Shield");              //cd00|0030|item|none
    case 206 : return F("Winged Boots");                 //ce00|0030|item|none
    case 207 : return F("Sparx Dragonfly");              //cf00|0030|item|none
    case 208 : return F("Dragonfire Cannon");            //d000|0030|item|none
    case 209 : return F("Scorpion Striker Catapult");    //d100|0030|item|none
    case 230 : return F("Hand Of Fate");                 //e600|0030|item|none
    case 231 : return F("Piggy Bank");                   //e700|0030|item|none
    case 232 : return F("Rocket Ram");                   //e800|0030|item|none
    case 233 : return F("Tiki Speaky");                  //e900|0030|item|none
    case 300 : return F("Dragons Peak");                 //2c01|0030|location|none
    case 301 : return F("Empire of Ice");                //2d01|0030|location|none
    case 302 : return F("Pirate Seas");                  //2e01|0030|location|none
    case 303 : return F("Darklight Crypt");              //2f01|0030|location|none
    case 304 : return F("Volcanic Vault");               //3001|0030|location|none
    case 305 : return F("Mirror Of Mystery");            //3101|0030|location|none
    case 306 : return F("Nightmare Express");            //3201|0030|location|none
    case 307 : return F("Sunscraper Spire");             //3301|0030|location|light
    case 308 : return F("Midnight Museum");              //3401|0030|location|dark
    case 450 : return F("Gusto");                        //c201|0030|trapmaster|air
    case 451 : return F("Thunderbolt");                  //c301|0030|trapmaster|air
    case 452 : return F("Fling Kong");                   //c401|0030|regular|air
    case 453 : return F("Blades");                       //c501|0030|regular|air
    case 454 : return F("Wallop");                       //c601|0030|trapmaster|earth
    case 455 : return F("Head Rush");                    //c701|0030|trapmaster|earth
    case 456 : return F("Fist Bump");                    //c801|0030|regular|earth
    case 457 : return F("Rocky Roll");                   //c901|0030|regular|earth
    case 458 : return F("Wildfire");                     //ca01|0030|trapmaster|fire
    case 459 : return F("Ka Boom");                      //cb01|0030|trapmaster|fire
    case 460 : return F("Trail Blazer");                 //cc01|0030|regular|fire
    case 461 : return F("Torch");                        //cd01|0030|regular|fire
    case 462 : return F("Snap Shot");                    //ce01|0030|trapmaster|water
    case 463 : return F("Lob Star");                     //cf01|0030|trapmaster|water
    case 464 : return F("Flip Wreck");                   //d001|0030|regular|water
    case 465 : return F("Echo");                         //d101|0030|regular|water
    case 466 : return F("Blastermind");                  //d201|0030|trapmaster|magic
    case 467 : return F("Enigma");                       //d301|0030|trapmaster|magic
    case 468 : return F("Deja Vu");                      //d401|0030|regular|magic
    case 469 : return F("Cobra Cadabra");                //d501|0030|regular|magic
    case 470 : return F("Jawbreaker");                   //d601|0030|trapmaster|tech
    case 471 : return F("Gearshift");                    //d701|0030|trapmaster|tech
    case 472 : return F("Chopper");                      //d801|0030|regular|tech
    case 473 : return F("Tread Head");                   //d901|0030|regular|tech
    case 474 : return F("Bushwhack");                    //da01|0030|trapmaster|life
    case 475 : return F("Tuff Luck");                    //db01|0030|trapmaster|life
    case 476 : return F("Food Fight");                   //dc01|0030|regular|life
    case 477 : return F("High Five");                    //dd01|0030|regular|life
    case 478 : return F("Krypt King");                   //de01|0030|trapmaster|undead
    case 479 : return F("Short Cut");                    //df01|0030|trapmaster|undead
    case 480 : return F("Bat Spin");                     //e001|0030|regular|undead
    case 481 : return F("Funny Bone");                   //e101|0030|regular|undead
    case 482 : return F("Knight Light");                 //e201|0030|trapmaster|light
    case 483 : return F("Spotlight");                    //e301|0030|regular|light
    case 484 : return F("Knight Mare");                  //e401|0030|trapmaster|dark
    case 485 : return F("Blackout");                     //e501|0030|regular|dark
    case 502 : return F("Bop");                          //f601|0030|mini|earth
    case 503 : return F("Spry");                         //f701|0030|mini|magic
    case 504 : return F("Hijinx");                       //f801|0030|mini|undead
    case 505 : return F("Terrabite");                    //f901|0030|mini|earth
    case 506 : return F("Breeze");                       //fa01|0030|mini|air
    case 507 : return F("Weeruptor");                    //fb01|0030|mini|fire
    case 508 : return F("Pet Vac");                      //fc01|0030|mini|air
    case 509 : return F("Small Fry");                    //fd01|0030|mini|fire
    case 510 : return F("Drobit");                       //fe01|0030|mini|tech
    case 514 : return F("Gill Runt");                    //0202|0030|mini|water
    case 519 : return F("Trigger Snappy");               //0702|0030|mini|tech
    case 526 : return F("Whisper Elf");                  //0e02|0030|mini|life
    case 540 : return F("Barkley");                      //1c02|0030|mini|life
    case 541 : return F("Thumpling");                    //1d02|0030|mini|water
    case 542 : return F("Mini Jini");                    //1e02|0030|mini|magic
    case 543 : return F("Eye Small");                    //1f02|0030|mini|undead
    case 1004 : return F("Blast Zone");                  //||swapforce|fire
    case 1015 : return F("Wash Buckler");                //||swapforce|water
    case 2004 : return F("Blast Zone (Head)");           //||swapforce|fire
    case 2015 : return F("Wash Buckler (Head)");         //||swapforce|water
    case 3000 : return F("Scratch");                     //b80b|0030|regular|air
    case 3001 : return F("Pop Thorn");                   //b90b|0030|regular|air
    case 3002 : return F("Slobber Tooth");               //ba0b|0030|regular|earth
    case 3003 : return F("Scorp");                       //bb0b|0030|regular|earth
    case 3004 : return F("Fryno");                       //bc0b|0030|regular|fire
    case 3005 : return F("Smolderdash");                 //bd0b|0030|regular|fire
    case 3006 : return F("Bumble Blast");                //be0b|0030|regular|life
    case 3007 : return F("Zoo Lou");                     //bf0b|0030|regular|life
    case 3008 : return F("Dune Bug");                    //c00b|0030|regular|magic
    case 3009 : return F("Star Strike");                 //c10b|0030|regular|magic
    case 3010 : return F("Countdown");                   //c20b|0030|regular|tech
    case 3011 : return F("Wind Up");                     //c30b|0030|regular|tech
    case 3012 : return F("Roller Brawl");                //c40b|0030|regular|undead
    case 3013 : return F("Grim Creeper");                //c50b|0030|regular|undead
    case 3014 : return F("Rip Tide");                    //c60b|0030|regular|water
    case 3015 : return F("Punk Shock");                  //c70b|0030|regular|water
#endif
    //Default fallback option
    default : return NULL;// F("Unknown");
  }
}


/*
   Dumps unencypted info from Sector 0
*/
void dumpFigureInfo() {
  uint32_t   serial = get32(&dataBuf[0][0]);
  uint16_t  toytype = get16(&dataBuf[1][0]);
  byte   *tradingId = &dataBuf[1][4];
  uint16_t  variant = get16(&dataBuf[1][12]);
  uint16_t checksum = get16(&dataBuf[1][14]);
  Serial.print(F("Serial: "));
  dump_byte_array_int((byte*)&serial, 4);
  Serial.print(F(" | Type: "));
  const __FlashStringHelper *fs = toyName(toytype);
  Serial.print((fs) ? fs : F("Unknown"));
  Serial.print(F(" ("));
  Serial.print(toytype);
  Serial.print(F(") | Variant: "));
  Serial.print(variant);
  Serial.print(F(" | TradingID: "));
  dump_byte_array_int(tradingId, 8);
  Serial.print(F(" | Checksum: "));
  dump_byte_array_int((byte*)&checksum, 2);
  byte cs[2] = { 0xFF, 0xFF };
  pseudo_crc16(cs, dataBuf[0], 30);
  Serial.println(checksum == get16((byte*)&cs) ? " O" : " X");
}

uint32_t getXP(byte *data) {
  return get24(&data[0]);
}
uint16_t getGold(byte *data) {
  return get16(&data[3]);
}
uint16_t getSkill(byte *data) {
  return get16(&data[0]);
}

const __FlashStringHelper *getPath(uint16_t skill) {
  if (skill & 1) {
    return (skill & 2) ? F("Path B (Right)") : F("Path A (Left)");
  }
  return F("No Path");
}

const __FlashStringHelper *getPlatformName(byte platform) {
  if (platform & 1) return F("Wii");
  if (platform & 2) return F("Xbox 360");
  if (platform & 4) return F("PS3");
  return NULL;
}

/*
   Dumps encrypted info from active slot
*/
void dumpFigureData(byte slot) {
  byte nickname[16];
  byte *data = dataBuf[2];
  Serial.print(F("Slot: "));
  Serial.print(slot);
  if (slot) {
    if (read_block(slot, false)) {
      decryptBlock(data, slot);
      Serial.print(F(" | XP: "));
      Serial.print(getXP(data));
      Serial.print(F(" | Gold: "));
      Serial.println(getGold(data));
    }
    if (read_block(slot + 1, false)) {
      decryptBlock(data, slot + 1);
      Serial.print(F("Skill: "));
      uint16_t skill = get16(&data[0]);
      Serial.print(skill, HEX);
      Serial.print(F(" | Path: "));
      Serial.print(getPath(skill));
      Serial.print(F(" | Platform: "));
      byte platform = data[3];
      const __FlashStringHelper *p = getPlatformName(platform);
      if (p) Serial.print(p);
      else Serial.print(platform, HEX);
      uint16_t hat = get16(&data[4]);
      Serial.print(F(" | Hat: "));
      Serial.println(hat);
    }
    if (read_block(slot + 2, false)) {
      decryptBlock(data, slot + 2);
      for (int i = 0; i < 8; i++) {
        nickname[i] = data[i << 1];
      }
    }
    if (read_block(slot + 4, false)) {
      decryptBlock(data, slot + 4);
      for (int i = 0; i < 8; i++) {
        nickname[8 + i] = data[i << 1];
      }
    }
    Serial.print(F("Nickname: "));
    Serial.println((char*)nickname);
    if (read_block(slot + 5, false)) {
      decryptBlock(data, slot + 5);
      uint16_t heroPoints = get16(&data[10]);
      Serial.print(F("Hero Points: "));
      Serial.println(heroPoints);
    }
    if (read_block(slot + 8, false)) {
      decryptBlock(data, slot + 8);
      uint32_t heroic = get32(&data[12]);
      Serial.print(F("Heroic Challanges: "));
      Serial.println(heroic, HEX);
    }
  } else {
    Serial.println(F(" | No Data"));
  }
}


/*
   Crypto
*/

bool shouldEncryptBlock(byte block) {
  return (block >= 8 && !isSectorTrailer(block));
}

void getEncryptionKey(byte keyOut[16], byte block) {
  byte *data = (byte *)"                                  Copyright (C) 2010 Activision. All Rights Reserved. ";
  memcpy(data, dataBuf[0], 32);         // blocks 0 and 1 data
  data[32] = block;                     // current block #
  MD5(data, 86, keyOut);
  //  dump_byte_array(keyOut, kMD5OutputBytes);
}

void encryptAES128ECB(byte *key, byte const *plain, byte *cipher) {
  aes.set_key(key, 128);
  aes.encrypt((byte*)plain, cipher);
}

void decryptAES128ECB(byte *key, byte const *cipher, byte *plain) {
  aes.set_key(key, 128);
  aes.decrypt ((byte*)cipher, plain);
}

bool encryptBlock(byte *data, byte block) {
  if (shouldEncryptBlock(block)) {
    byte key[16], cipher[16];
    getEncryptionKey(key, block);
    encryptAES128ECB(key, data, cipher);
    memcpy(data, cipher, sizeof(cipher));
    return true;
  }
  return false;
}

bool decryptBlock(byte *data, byte block) {
  if (shouldEncryptBlock(block)) {
    byte key[16], plain[16];
    getEncryptionKey(key, block);
    decryptAES128ECB(key, data, plain);
    memcpy(data, plain, sizeof(plain));
    return true;
  }
  return false;
}
