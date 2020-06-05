/*
 $Id: MD5.H 1.1 2000/02/25 02:56:41 ALIU Exp $
*/

/* MD5.H - header file for MD5C.C
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
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

/*
 $Log: MD5.H $
 Revision 1.1  2000/02/25 02:56:41  ALIU
 Initial Version
 Revision 1.2  1998/11/09 02:43:14  bsu
 restructed header files
 Revision 1.1  1998/08/31 03:40:27  bsu
 Initial revision
 Revision 1.1  1997/08/14 14:24:30  PHUANG
 Revision 1.1  1997/08/14 14:24:30  TROY
 Revision 1.1  1995/10/23 19:30:08  PHUANG
 Revision 1.1  1995/10/23 19:30:08  PHUANG
 Revision 1.1  1995/10/02 17:44:51  troy
 Initial revision
 Revision 1.1  1995/10/02 15:52:30  troy
 Initial revision
 * Revision 1.2  1995/07/06  20:13:59  troy
 * Wrapper added
 *
*/

#ifndef MD5_H
#define MD5_H

#define MD5_SIZE 16
#define WEP_256BIT 1
#define MAC_LENGTH	6
#ifdef WEP_256BIT
#define WEP_KEY_LEN 		  30	  
#else
#define WEP_KEY_LEN 		  14	 
#endif 
#define MAC_MAX_NUM	 10000
#ifndef NULL
#define NULL 0
#endif
#define WEP_KEY_LEN 30

/* for some feature */
// #define FULL_FORMAT 1
// #define INPUT_FILE 1

/* for error type */
#define RETURN_NO_ERROR 0
#define RETURN_ERROR_NO_ENOUGH_PARA	1<<0
#define RETURN_ERROR_CHAR_TO_DIG 1<<1
#define RETURN_ERROR_WRONG_MAC_FILE 1<<2
#define RETURN_ERROR_WRONG_MAC_FORMAT 1<<3
#define RETURN_ERROR_EXCEED_MAX_MAC_NUMBER 1<<4

#define is_digit(x)	((x)>='0'&&(x)<='9')
#define is_alpha(x)	( ( (x)>='a'&&(x)<='z' ) || ( (x)>='A'&&(x)<='Z' ) )
/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;
typedef unsigned long int	uint32;		/* 32-bit unsigned integer       */
typedef unsigned char		uint8;		/* 8-bit unsigned integer        */
typedef unsigned short		uint16;		/* 16-bit unsigned integer       */
typedef signed char int8;

typedef struct _mac{
	uint8 mac[6];
	uint8 output[MD5_SIZE];
	char essid[14]; /*"ChinaNet-XXXX", XXXXis the last four number of mac address*/
	char wepkey[14];
	char useradmin[9];
#if 1
	char SerialNumber[20];
#endif
}mac;

/* MD5 context. */
typedef struct {
  uint32 state[4];				     /* state (ABCD) */
  uint32 count[2];	  /* number of bits, modulo 2^64 (lsb first) */
  unsigned char buffer[64];                         /* input buffer */
} MD5_CTX;

void MD5Init (MD5_CTX *);
void MD5Update (MD5_CTX *, unsigned char *, unsigned int);
void MD5Final (MD5_CTX *, unsigned char [MD5_SIZE] );

void usage(void);
void do_with_error(void);
int dig2str( uint8 *dig, char *str, uint16 dig_len );
int str2dig( uint8 *dig, char *str);
void getMD5ExpectedContext (char *input, char *expected );
void produceEssid( uint8 *expected, char *essid );
void produceSerialNumber( uint8 *expected, char *SerialNumber,char * mac );
void produceWepKey( uint8 *expected, char *wepKey );
void spSetWepKey( uint8 *spwepkey );
uint8 *spGetWepKey( void );
int checkMac(char *mac_start, char *mac_end );
int checkMacRange(uint8 *mac_start, uint8 *mac_end );
int checkMacBit(uint8 *mac_start, uint8 *mac_end, int bit );
int increaseMac(char *mac);
int decreaseMac(char *mac);
int md5cInit(void);

#endif /* MD5_H */
