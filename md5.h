/* md5.h - header file for md5.c */
/* RSA Data Security, Inc., MD5 Message-Digest Algorithm */

/* NOTE: Numerous changes have been made; the following notice is
included to satisfy legal requirements.

Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
*/

#ifndef H__MD5
#define H__MD5
#include <climits>

#if ULONG_MAX == 0xFFFFFFFF
typedef unsigned long UINT4;
#elif UINT_MAX == 0xFFFFFFFF
typedef unsigned int UINT4;
#endif

typedef struct
{
	UINT4 state[4];
	UINT4 count[2];
	unsigned char buffer[64];
} MD5;

void MD5Open(MD5 *);
void MD5Digest(MD5 *, const void *, unsigned int);
void MD5Close(MD5 *, unsigned char[16]);

#endif
