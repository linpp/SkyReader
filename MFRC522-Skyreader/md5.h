/*
   Simple md5 for memory constrained devices.  The goal is not fastest speed, but smaller footprint.
   Most md5 libraries take over 6k of available memory, this implementation takes less than 2k.

   1/25/2023 Peter Lin
*/
#ifndef _MD5_H_
#define _MD5_H_

#include <arduino.h>

#define MD5_BLOCK_BITS 512
#define MD5_BLOCK_SIZE (512/8)

typedef struct {
  uint32_t var[4];    // a, b, c, d
  uint32_t bytes;     // total bytes processed
  uint8_t  block[MD5_BLOCK_SIZE];
} MD5CONTEXT;

void MD5Init(MD5CONTEXT *context);
void MD5Update(MD5CONTEXT *context, const uint8_t *data, uint32_t len);
void MD5Finalize(MD5CONTEXT *context, uint8_t hash[16]);
void MD5(const uint8_t *data, uint32_t len, uint8_t hash[16]);

#endif
