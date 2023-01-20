/*
 * Serial interface to a RFID-RC522 for use with Skyreader instead of a real Portal.
 * Implements a serial protocol to read and write blocks, detecting and authenticating
 * Skylander toys and/or standard NFC cards.
 * 
 * Requires the MFRC522 Library by miguelbalboa.
 * 
 * ----------------------------------------------------------------------------
 * Example sketch/program which will try the most used default keys listed in 
 * https://code.google.com/p/mfcuk/wiki/MifareClassicDefaultKeys to dump the
 * block 0 of a MIFARE RFID card using a RFID-RC522 reader.
 * 
 * Typical pin layout used:
 * -----------------------------------------------------------------------------------------
 *             MFRC522      Arduino       Arduino   Arduino    Arduino          Arduino
 *             Reader/PCD   Uno/101       Mega      Nano v3    Leonardo/Micro   Pro Micro
 * Signal      Pin          Pin           Pin       Pin        Pin              Pin
 * -----------------------------------------------------------------------------------------
 * RST/Reset   RST          9             5         D9         RESET/ICSP-5     RST
 * SPI SS      SDA(SS)      10            53        D10        10               10
 * SPI MOSI    MOSI         11 / ICSP-4   51        D11        ICSP-4           16
 * SPI MISO    MISO         12 / ICSP-1   50        D12        ICSP-1           14
 * SPI SCK     SCK          13 / ICSP-3   52        D13        ICSP-3           15
 *
 * More pin layouts for other boards can be found here: https://github.com/miguelbalboa/rfid#pin-layout
 *
 * Created by Peter Lin on 1/15/23
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

byte buffer[18];
byte atqa[2];
byte atqa_size;

byte daBlock[3][BLOCK_SIZE];        // [0] = block0, [1] = block1, [2] = general buffer
byte secKeys[NUM_SECTORS][MFRC522::MF_KEY_SIZE];

MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance.
MFRC522::StatusCode status;
    
bool debug = false;

AES aes;

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

static const char* _PASS = "O";
static const char* _FAIL = "X";

/*
 * Wake the card and select the old uid.  When an operation fails, the card will
 * halt and stop responding until it is woken again.
 */
bool wake_card() {
    atqa_size = 2;
    memset(atqa, 0, atqa_size);
    mfrc522.PICC_WakeupA(atqa, &atqa_size);
    if (!atqa[0] && !atqa[1]) return false;
    mfrc522.PICC_Select(&mfrc522.uid, mfrc522.uid.size*8);
    return true;
}

/*
 * Bitwise shift of a byte array in LE MSB. Returns the last carry bit.
 */
inline byte shift_crc(byte* crc, byte bytes) {
  byte carry = 0;     // shift in
  for (byte i=0; i < bytes; i++) {
    byte c = crc[i] >> 7;
    crc[i] = ((crc[i] << 1) | carry);
    carry = c;
  }
  return carry;       // shift out
}

/*
 * Psuedo crc of a byte array in LE MSB. The byte array defines the scope
 * of operation avoiding extra shifts and masks.
 */
void pseudo_crc(byte bytes, const byte* poly, byte* crc, byte *data, byte len) {
    for (byte i=0; i<len; i++) {
        crc[bytes-1] ^= data[i];
        for (byte k=0; k<8; k++) {
            if (shift_crc(crc, bytes)) {
              for (byte j=0; j<bytes; j++) {
                crc[j] ^= poly[j];
              }
            }
        }
    }
}

/*
 * ECMA-182 crc48 with 0x42f0e1eba9ea3693 polynomial (last 48 bits)
 */
void pseudo_crc48(byte *crc, byte* data, byte len) {
    const byte poly[MFRC522::MF_KEY_SIZE] = {0x93, 0x36, 0xea, 0xa9, 0xeb, 0xe1};
    pseudo_crc(sizeof(poly), poly, crc, data, len); 
}

/*
 * CCITT crc16 with 0x1021 polynomial 
 */
void pseudo_crc16(byte *crc, byte* data, byte len) {
    const byte poly[2] = {0x21, 0x10};
    pseudo_crc(sizeof(poly), poly, crc, data, len);
}

/*
 * Calculate access key (KeyA) for Skylander toys using pre-calculated primes:
 *  magic = 2 * 2 * 3 * 1103 * 12868356821
 */
void calc_keya(byte* uid, byte sector, byte* key) {
    const byte magic[MFRC522::MF_KEY_SIZE] = {0xc4, 0x0c, 0x26, 0x03, 0xe9, 0x9a};
    const byte *pk = (sector) ? magic : knownKeys[0];
    memcpy(key, pk, MFRC522::MF_KEY_SIZE);
    if (sector > 0 && sector < NUM_SECTORS) {
        byte data[5] = { uid[0], uid[1], uid[2], uid[3], sector };
        pseudo_crc48(key, data, 5);
    }
}

void dump_byte_array_int(byte *buffer, byte bufferSize, byte sep=0) {
    for (byte i = 0; i < bufferSize; i++) {
        if (buffer[i] < 0x10) Serial.print("0");
        Serial.print(buffer[i], HEX);
        if (sep) Serial.print(" ");
    }
}

void dump_byte_array(byte *buffer, byte bufferSize, byte sep=0) {
    dump_byte_array_int(buffer, bufferSize, sep);
    Serial.println();
}
 
void dump_byte_array1(byte *buffer, byte bufferSize) {
    for (byte i = 0; i < bufferSize; i++) {
      byte c = buffer[i];
      c = (c < 0x20 || c > 0x7E) ? '.' : c;
      Serial.write(c);
    }
}

/*
 * Generate all Skylander access keys for a given UID
 */
void key_gen(byte *uid, byte uidSize){
    if (debug) { 
      Serial.print(F("Generating keys for UID:"));
      dump_byte_array(uid, uidSize);
    }
    for (byte i=0; i<NUM_SECTORS; i++) {
      calc_keya(uid, i, secKeys[i]);
    }
    if (debug) {
      for (byte i=0; i<NUM_SECTORS; i++) {
        dump_byte_array(secKeys[i], MFRC522::MF_KEY_SIZE);
      }
    }
}


/*
 * Try authenticating with the given key, wake up card if necessary
 */
bool auth_key(byte command, byte block, MFRC522::MIFARE_Key *key) {
   status = mfrc522.PCD_Authenticate(command, block, key, &(mfrc522.uid));
   if (status == MFRC522::STATUS_TIMEOUT) {
      if (wake_card()) {
        status = mfrc522.PCD_Authenticate(command, block, key, &(mfrc522.uid));
      }
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
 * Read block with a known key
 */
bool read_block(byte block, MFRC522::MIFARE_Key *key, bool dump)
{
    bool result = false;
    byte len = sizeof(buffer);
    if (debug) {     
        Serial.print(F("Authenticating using key A: "));
        dump_byte_array(key->keyByte, MFRC522::MF_KEY_SIZE, 1);
    }
    if (!auth_key(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, key))
        return false;

    // read block
    byte byteCount = sizeof(buffer);
    status = mfrc522.MIFARE_Read(block, buffer, &byteCount);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("MIFARE_Read() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
    } else {
        result = true;
        // update key in the sector trailer
        if (isSectorTrailer(block)) {
          memcpy(buffer, key->keyByte, MFRC522::MF_KEY_SIZE);
        }
        if (dump) {
          if (debug) {        
            dump_byte_array_int(&block, 1);
            Serial.print(F(": "));
          }
          dump_byte_array(buffer, BLOCK_SIZE);
        }
        byte line = (block < 2) ? block : 2;
        memcpy(daBlock[line], buffer, BLOCK_SIZE);
    }
    return result;
}

/*
 * Read block with unknown key (key search)
 */
bool read_block(byte block, bool dump) {
    MFRC522::MIFARE_Key key;
    byte sector = block / BLOCKS_PER_SECTOR;
    bool result = false;
    if (block > 63) {
      if (debug) {
        Serial.print(F("block "));
        dump_byte_array_int(&block, 1);
        Serial.println(F(" out of range"));        
      }
      return false;
    }
    if (block == 0) {
        for (byte k = 0; k < NR_KNOWN_KEYS; k++) {
            memcpy(key.keyByte, knownKeys[k], MFRC522::MF_KEY_SIZE);
            result = read_block(block, &key, dump);
            if (result) {
                if (k == 0) {
                    // card is skylanders, generate sector keys
                    key_gen(mfrc522.uid.uidByte, mfrc522.uid.size);
                } else {  
                    // card is normal, default current key for all sectors
                    for (byte j = 0; j < NUM_SECTORS; j++) {
                        memcpy(secKeys[j], knownKeys[k], MFRC522::MF_KEY_SIZE);
                    }
                }
                break;
            }
        }
    } else {      // all other blocks
        for (byte k = 0; k < NR_KNOWN_KEYS; k++) {
            // try default key first, then known keys
            memcpy(key.keyByte, (k == 0) ? secKeys[sector] : knownKeys[k], MFRC522::MF_KEY_SIZE);
            result = read_block(block, &key, dump);
            if (result) {
                 if (k != 0)   // update the sector key
                     memcpy(secKeys[sector], knownKeys[k], MFRC522::MF_KEY_SIZE);
                 break;
            }
        }
    }
    return result;
}

inline bool isSectorTrailer(byte block) {
  return (block % BLOCKS_PER_SECTOR) == 3;
}

/*
 * Initialize.
 */
void setup() {
    Serial.begin(115200);         // Initialize serial communications with the PC
    while (!Serial);            // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
    SPI.begin();                // Init SPI bus
    mfrc522.PCD_Init();         // Init MFRC522 card
    menu();
    Serial.print(F("$"));
}

void menu() {
    Serial.println(F("0 Decrypt Toy\n1 Dump EML\n2 Serial dump\n3 Reset Toy\n4 Reset keys\n5 Set UID\n6 Unbrick UID\n7 Firmware check\nd[0|1] debug mode"));
}

/*
 * Main loop.
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
 * Options 0 - 7 are useful on a serial monitor
 */
      case '0':                           // read card decrypted
        read_card(true);    break;
      case '1':                           // read the card and dump it in eml format
        read_card(false);   break;
      case '2':                           // internal dump card (only works on factory cards)
        dump_serial();      break;
      case '3':                           // reset skylander figure
        reset_figure();     break;
      case '4':                           // reset all keys to factory (requires a magic/backdoor card)
        reset_keys();       break;
      case '5':                           // set the uid to a known value
        set_uid();          break;
      case '6':                           // rewrite block 0 of a non-responding card
        unbrick_uid();      break;
      case '7':                           // RC522 reader firmware self-check
        firmware_check();   break;
      case 'd':                           // d1 turns on debug mode, d0 turns off debug mode
        debug = Serial.read() == '1';
        break;
/*
 * The remaining options are useful for a connected app, they require extra data to be sent.
 * read_card() must be run first before these work properly and the card must not change
 * between operations.
 */
      case 'R':                           // read the given block (offset by ascii '0')
        choice = Serial.read();           // block ascii range 0x30 "0" - 0x6F "o"
        Serial.print(read_block(choice-'0', true) ? _PASS : _FAIL);       break;
      case 'w':                           // TEST write the given block (offset by ascii '0')
        Serial.print(write_block(Serial.read()-'0', false) ? _PASS : _FAIL);      break;
      case 'W':                           // write the given block (offset by ascii '0')
        Serial.print(write_block(Serial.read()-'0', true) ? _PASS : _FAIL);      break;    
      case 's':                           // TEST write a data stream to the card (authenticates but does not write)
        debug = false;                    // debug needs to be off to stream blocks
        Serial.print(write_stream(false) ? _PASS : _FAIL);
        debug = saved;
        break;
      case 'S':                           // write a data stream to the card
        debug = false;                    // debug needs to be off to stream blocks
        Serial.print(write_stream(true) ? _PASS : _FAIL);
        debug = saved;
        break;
/*        
 * Start a new loop on linefeed, will halt the card
 */
      case '?':
        menu();
        done = false;
        break;
      case 0x0A:
        Serial.print(F("$"));
        break;
      case 0x0F:
      case 0x0D:
        t = 0;
      default:
//        dump_byte_array(&choice, 1);
        done = false;
        if (t) delay(t);
        break;
    }
  } while (!done);
  mfrc522.PICC_HaltA();       // Halt PICC
  mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
}

void firmware_check() {
  Serial.println(F("*****************************"));
  Serial.println(F("MFRC522 Digital self test"));
  Serial.println(F("*****************************"));
  mfrc522.PCD_DumpVersionToSerial();  // Show version of PCD - MFRC522 Card Reader
  Serial.println(F("-----------------------------"));
  Serial.println(F("Only known versions supported"));
  Serial.println(F("-----------------------------"));
  Serial.println(F("Performing test..."));
  bool result = mfrc522.PCD_PerformSelfTest(); // perform the test
  Serial.println(F("-----------------------------"));
  Serial.print(F("Result: "));
  if (result)
    Serial.println(F("OK"));
  else
    Serial.println(F("DEFECT or UNKNOWN"));
  Serial.println();
}

void fix_bricked() {
  // despite the name, UnbrickUidSector only writes to block 0, not the entire sector
  if ( mfrc522.MIFARE_UnbrickUidSector(true) ) {
    Serial.println(F("Cleared block 0, set UID to 1234. Card should be responsive again now."));
  }
}

void set_uid() {
  if (wake_card()) {
    byte newUid[] = {0x31, 0x32, 0x33, 0x34};         // set known uid here
    if ( mfrc522.MIFARE_SetUid(newUid, (byte)4, true) ) {
      Serial.print(F("Wrote UID "));
      dump_byte_array(newUid, sizeof(newUid));
      Serial.println(F(" to card."));
    }
  }
}

bool wait_for_card() {
    Serial.println(F("Place card.."));
    // Look for cards for 10 seconds
    for (int i=0; i<=10; i++) {
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
            for (byte i=0; i < BLOCK_SIZE; i++) {
                if (daBlock[2][i] != 0) {
                    blank = false;
                    break;
                }
            }
        }
        if (decrypt && !blank && decryptBlock(daBlock[2], block)) {
            dump_byte_array_int(daBlock[2], BLOCK_SIZE);
            Serial.print(F(" ["));
            dump_byte_array1(daBlock[2], BLOCK_SIZE);
            Serial.println(F("]"));
            if (block == 8)  seq1 = daBlock[2][9];
            if (block == 36) seq2 = daBlock[2][9];
        }
    }
    if (decrypt) {
      dumpFigureInfo();
      dumpFigureData((blank) ? 0 : (seq2 > seq1) ? 36 : 8);
    }
    else Serial.println(F("--EML DUMP END"));
}

/*
 * Note: must have called read_block on block 0 before calling this method
 */
bool write_block(byte block, byte* data, bool doWrite) {
    byte sector = block / BLOCKS_PER_SECTOR;

#if SAFE_ACCESS_TRAILER
    if (isSectorTrailer(block)) {           // Rewrite the sector trailer access to something safe
#else
    if (block == 3) {                       // Always make sector 0 safe
#endif           
        data[6] = 0xFF;
        data[7] = 0x07;
        data[8] = 0x80;
        data[9] = 0x69;
    }

    // Write data to the block
    if (debug) {
        Serial.print(F("Writing data to sector ")); 
        Serial.print(sector);
        Serial.print(F(" block "));
        Serial.print(block);
        Serial.println();
    }
    dump_byte_array(data, BLOCK_SIZE, 0);
#if 0
    // skip 0 and trailers
    if (isSectorTrailer(block) || block == 0)
        return true;
#endif    
#if USE_BLOCK0_BACKDOOR
    if (block == 0) {    // open UID backdoor on block 0
        if (debug)
            Serial.print(F("Unlocking UID access..."));
        mfrc522.PICC_HaltA();       // Halt PICC
        mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
        if (!mfrc522.MIFARE_OpenUidBackdoor(true))
            return false;
        if (debug)
            Serial.println(F("done."));
    }
    else
#endif   
    {    // otherwise authenticate all other blocks usign key A
         MFRC522::MIFARE_Key key;
         memcpy(key.keyByte, secKeys[sector], MFRC522::MF_KEY_SIZE);

         if (debug) {
             Serial.print(F("Authenticating using key "));
             dump_byte_array(key.keyByte, MFRC522::MF_KEY_SIZE, 1);
         }
         if (!auth_key(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key)) {
             if (debug) {
                 Serial.println(F("auth failed"));
             }
             return false;
         } 
    }
    if (doWrite) {
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
    if (block == 0) {    // wake up the card again
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
        daBlock[line][k] = Serial.read();
    }
}

bool write_block(byte block, bool doWrite) {
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
    return write_block(block, daBlock[line], doWrite);
}

/*
 * Stream blocks to write over the serial port, but block 0 is last.
 */
bool write_stream(bool doWrite) {
    if (wake_card()) {
      // block 0 write will change the card uid and cause a new card to be found,
      // so we will delay block 0 writing until the end
      for (byte block = 0; block < NUM_BLOCKS; block++) {
        if (block == 0) {
          stream_block(0, 0);          
        } else if (!write_block(block, doWrite)) {
          return false;
        }
      }
      // write block 0 last
      return write_block(0, daBlock[0], doWrite);
    }
    return false;
}

void reset_figure() {
    if (!wait_for_card()) return;

    for (byte i = 0; i < 0x10; ++i) {
        daBlock[2][i] = 0;
    }
    for (byte block = 5; block < NUM_BLOCKS; block++) {
        if (!isSectorTrailer(block) && block != 0x22 && block != 0x3e) {
            if (!write_block(block, daBlock[2], true)) {
                break;
            }
        }
    } 
}
 
/*
 * Dumps the card, only works with factory keys
 */
void dump_serial() {
    if (!wait_for_card()) return;
  
    // Dump debug info about the card; PICC_HaltA() is automatically called
    mfrc522.PICC_DumpToSerial(&(mfrc522.uid));
}

bool unbrick_uid() {
  if (!wait_for_card()) return false;
  
  Serial.println(F("Open backdoor"));
  mfrc522.MIFARE_OpenUidBackdoor(true);
  
//  byte block0_buffer[] = {0x2C, 0x7B, 0x9F, 0x17, 0xDF, 0x81, 0x01, 0x0F, 0xC4, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12};  
  byte block0_buffer[] = {0x04, 0xCB, 0x90, 0x65, 0x3A, 0x81, 0x01, 0x0F, 0xC4, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12};  

  Serial.println(F("Writing new block"));
  // Write modified block 0 back to card
  MFRC522::StatusCode status = mfrc522.MIFARE_Write((byte)0, block0_buffer, (byte)16);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("MIFARE_Write() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  Serial.println(F("Done."));
  return true;  
}

bool reset_keys() {
  if (!wait_for_card()) return false;

  byte block0_buffer[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x07, 0x80, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};  
  for (byte i = 0; i < NUM_SECTORS; i++) {
    byte block = (i * BLOCKS_PER_SECTOR) + 3;
    MFRC522::MIFARE_Key key;
    memcpy(key.keyByte, secKeys[i], MFRC522::MF_KEY_SIZE);

    // Use the backdoor on all sector trailers if the keys are in an inconsisten state
    // This will reset them to factory default (requires a magic card)
#if USE_BLOCK0_BACKDOOR
    mfrc522.PICC_HaltA();       // Halt PICC
    mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
    if (!mfrc522.MIFARE_OpenUidBackdoor(true))
       return false;
#else
    Serial.print(F("Authenticating using key "));
    dump_byte_array(key.keyByte, MFRC522::MF_KEY_SIZE, 1);
    if (!auth_key(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key)) {
       Serial.println(F("Auth failed"));
       return false;
    }
#endif

    Serial.print(F("Writing block "));
    Serial.println(block);
    // Write modified block 0 back to card
    MFRC522::StatusCode status = mfrc522.MIFARE_Write(block, block0_buffer, (byte)16);
    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("MIFARE_Write() failed: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
      return false;
    }
  }
  return true;
}


/*
 * Skylander Figure
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
    case 16 : return F("Spyro");                         //1000|0030|regular|magic
    case 17 : return F("Voodood");                       //1100|0030|regular|magic
    case 18 : return F("Double Trouble");                //1200|0030|regular|magic
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
    case 30 : return F("Chop Chop");                     //1e00|0030|regular|undead
    case 31 : return F("Ghost Roaster");                 //1f00|0030|regular|undead
    case 32 : return F("Cynder");                        //2000|0030|regular|undead
    //Default fallback option with toyID
    default : return F("UNKNOWN");
  }
}


/*
 * Dumps unencypted info from Sector 0
 */
void dumpFigureInfo() {
    uint32_t   serial = get32(&daBlock[0][0]);
    uint16_t  toytype = get16(&daBlock[1][0]);
    byte   *tradingId = &daBlock[1][4];
    uint16_t  variant = get16(&daBlock[1][12]);
    uint16_t checksum = get16(&daBlock[1][14]);
    Serial.print(F("Serial: "));
    dump_byte_array_int((byte*)&serial, 4);
    Serial.print(F(" | Type: "));
    Serial.print(toytype);
    Serial.print(F(" ("));
    Serial.print(toyName(toytype));
    Serial.print(F(") | Variant: "));
    Serial.print(variant);
    Serial.print(F(" | TradingID: "));
    dump_byte_array_int(tradingId, 8);
    Serial.print(F(" | Checksum: "));
    dump_byte_array_int((byte*)&checksum, 2);
    byte cs[2] = { 0xFF, 0xFF };
    pseudo_crc16(cs, daBlock[0], 30);
    Serial.println(checksum == get16((byte*)&cs) ? " O" : " X");
}

uint32_t getXP(byte *data) {
  return get24(data);
}
uint16_t getGold(byte *data) {
  return get16(data);
}

/*
 * Dumps encrypted info from active slot
 */
void dumpFigureData(byte slot) {
    Serial.print(F("Slot: "));
    Serial.print(slot);
    if (slot && read_block(slot, false)) {
      byte *data = daBlock[2];
      decryptBlock(data, slot);
      Serial.print(F(" | XP: "));
      Serial.print(getXP(data));
      Serial.print(F(" | Gold: "));
      Serial.println(getGold(data));
    } else {
      Serial.println(F(" | No Data"));    
    }
 }


/*
 * Crypto
 */

bool shouldEncryptBlock(byte block) {
  return (block >= 8 && !isSectorTrailer(block));
}

 void getEncryptionKey(byte keyOut[kMD5OutputBytes], byte block) {
  byte data[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    block,
    ' ','C','o','p','y','r','i','g','h','t',' ','(','C',')',' ','2',
    '0','1','0',' ','A','c','t','i','v','i','s','i','o','n','.',' ',
    'A','l','l',' ','R','i','g','h','t','s',' ','R','e','s','e','r',
    'v','e','d','.',' '};
    
  memcpy(data, daBlock[0], 32);         // blocks 0 and 1 data
//  dump_byte_array(data, sizeof(data));
  md5(data, sizeof(data), keyOut);
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
