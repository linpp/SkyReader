/*
   Simple md5 for memory constrained devices.  The goal is not fastest speed, but smaller footprint.
   Most md5 take over 6k of available memory, this implementation takes less than 2k.

   1/25/2023 Peter Lin
*/

#include <stdint.h>
#include <string.h>
#include "md5.h"
#include <avr/pgmspace.h>

#define F1(x, y, z) (x & y | ~x & z)
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

uint32_t MD5STEP(uint8_t f, uint32_t w, uint32_t x, uint32_t y, uint32_t z, uint32_t data, uint8_t s) {
  switch (f) {
    case 1:    w += F1(x, y, z); break;
    case 2:    w += F2(x, y, z); break;
    case 3:    w += F3(x, y, z); break;
    case 4:    w += F4(x, y, z); break;
  }
  w += data;
  w = w << s | w >> (32 - s);
  w += x;
  return w;
}

const uint32_t rounds[4][17] PROGMEM = {
  {0x00015557, 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821},
  {0x00156545, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a},
  {0x00537574, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665},
  {0x00076546, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391}
};

static void MD5Transform(uint32_t var[4], uint32_t const in[16])
{
  uint32_t a, b, c, d;
  a = *var++;
  b = *var++;
  c = *var++;
  d = *var;
  for (uint8_t i = 0; i < 4; i++) {                       // do 4 rounds
    uint32_t m = pgm_read_dword(&rounds[i][0]);
    uint8_t o  = (m >> 20) & 0xf;                         // initial offset
    uint8_t od = (m >> 16) & 0xf;                         // offset displacement
    uint8_t r0 = m & 0xf;                                 // generate rotations for this round
    uint8_t r1 = r0 + ((m >> 4) & 0xf);
    uint8_t r2 = r1 + ((m >> 8) & 0xf);
    uint8_t r3 = r2 + ((m >> 12) & 0xf);
    const uint32_t *pd = &rounds[i][1];                   // precalculated sines in progmem
    for (uint8_t j = 0; j < 4; j++) {
      a = MD5STEP(i + 1, a, b, c, d, in[o] + pgm_read_dword(pd++), r0); o = (o + od) & 0xf;
      d = MD5STEP(i + 1, d, a, b, c, in[o] + pgm_read_dword(pd++), r1); o = (o + od) & 0xf;
      c = MD5STEP(i + 1, c, d, a, b, in[o] + pgm_read_dword(pd++), r2); o = (o + od) & 0xf;
      b = MD5STEP(i + 1, b, c, d, a, in[o] + pgm_read_dword(pd++), r3); o = (o + od) & 0xf;
    }
  }
  *var-- += d;
  *var-- += c;
  *var-- += b;
  *var   += a;
}

void MD5Init(MD5CONTEXT *context)
{
  context->var[0] = 0x67452301;     // a0
  context->var[1] = 0xefcdab89;     // b0
  context->var[2] = 0x98badcfe;     // c0
  context->var[3] = 0x10325476;     // d0
  context->bytes = 0;
}

void MD5Update(MD5CONTEXT *context, uint8_t const *data, uint32_t len)
{
  byte t = context->bytes & 0x3F;
  context->bytes += len;
  while (len > 0) {
    byte pad = min(64 - t, len);
    memcpy(&context->block[t], data, pad);
    if (t + pad == 64) {
      MD5Transform(context->var, (uint32_t *)context->block);
      t = 0;
    }
    data += pad;
    len -= pad;
  }
}

void MD5Finalize(MD5CONTEXT *context, uint8_t hash[16])
{
  byte t = context->bytes & 0x3F;
  context->block[t++] = 0x80;

  // there must be 8 bytes left for the bit count
  if (MD5_BLOCK_SIZE - t < 8) {
    // if not pad the last full block
    memset(&context->block[t], 0, MD5_BLOCK_SIZE - t);
    MD5Transform(context->var, (uint32_t *)context->block);
    t = 0;
  }
  // pad to 56 bytes
  memset(&context->block[t], 0, MD5_BLOCK_SIZE - 8 - t);

  // add the bit count
  uint32_t bitsl = context->bytes << 3;
  uint32_t bitsh = context->bytes >> 29;
  memcpy(&context->block[56], &bitsl, sizeof(bitsl));
  memcpy(&context->block[60], &bitsh, sizeof(bitsh));
  MD5Transform(context->var, (uint32_t *)context->block);

  memcpy(hash, context->var, sizeof(context->var));
}

void MD5(const uint8_t *data, uint32_t len, uint8_t hash[16]) {
  static MD5CONTEXT ctx;
  MD5Init(&ctx);
  MD5Update(&ctx, data, len);
  MD5Finalize(&ctx, hash);
}
