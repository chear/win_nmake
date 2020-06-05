#include "switch.h"
#include "md5.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "math.h"
#include "ctype.h"
#include <time.h> 

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static void MD5Transform(uint32 [4], unsigned char [64]);
static void Encode(unsigned char *, uint32 *, unsigned int);
static void Decode(uint32 *, unsigned char *, unsigned int);
static void MD5_memcpy(POINTER, POINTER, unsigned int);
static void MD5_memset(POINTER, int, unsigned int);

static unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (uint32)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (uint32)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (uint32)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (uint32)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }

#define MAC_RESERVE 2

int
md5cInit( void )
{
	return 0;
} /* md5cInit */


/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
void MD5Init (
	MD5_CTX *context                              /* context */
)
{
  context->count[0] = context->count[1] = 0;
  /* Load magic initialization constants.
*/
  context->state[0] = 0x67452301L;
  context->state[1] = 0xefcdab89L;
  context->state[2] = 0x98badcfeL;
  context->state[3] = 0x10325476L;
}

/* MD5 block update operation. Continues an MD5 message-digest
  operation, processing another message block, and updating the
  context.
 */
void MD5Update (
	MD5_CTX *context,                  /* context */
	unsigned char *input,              /* input block */
	unsigned int inputLen              /* length of input block */
)
{
  unsigned int i, index, partLen;

  /* Compute number of bytes mod 64 */
  index = (unsigned int)((context->count[0] >> 3) & 0x3F);

  /* Update number of bits */
  if ((context->count[0] += ((uint32)inputLen << 3))
   < ((uint32)inputLen << 3))
 context->count[1]++;
  context->count[1] += ((uint32)inputLen >> 29);

  partLen = 64 - index;

  /* Transform as many times as possible.
*/
  if (inputLen >= partLen) {
 MD5_memcpy
   ((POINTER)&context->buffer[index], (POINTER)input, partLen);
 MD5Transform (context->state, context->buffer);

 for (i = partLen; i + 63 < inputLen; i += 64)
   MD5Transform (context->state, &input[i]);

 index = 0;
  }
  else
 i = 0;

  /* Buffer remaining input */
  MD5_memcpy
 ((POINTER)&context->buffer[index], (POINTER)&input[i],
  inputLen-i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
  the message digest and zeroizing the context.
 */
void MD5Final (
	MD5_CTX *context,                        /* context */
	unsigned char digest[16]                 /* message digest */
)
{
  unsigned char bits[8];
  unsigned int index, padLen;

  /* Save number of bits */
  Encode (bits, context->count, 8);

  /* Pad out to 56 mod 64.
*/
  index = (unsigned int)((context->count[0] >> 3) & 0x3f);
  padLen = (index < 56) ? (56 - index) : (120 - index);
  MD5Update (context, PADDING, padLen);

  /* Append length (before padding) */
  MD5Update (context, bits, 8);

  /* Store state in digest */
  Encode (digest, context->state, 16);

  /* Zeroize sensitive information.
   */
  MD5_memset ((POINTER)context, 0, sizeof (*context));
}

/* MD5 basic transformation. Transforms state based on block.
 */
static void MD5Transform (
	uint32 state[4],
	unsigned char block[64]
)
{
  uint32 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

  Decode (x, block, 64);

  /* Round 1 */
  FF (a, b, c, d, x[ 0], S11, 0xd76aa478L); /* 1 */
  FF (d, a, b, c, x[ 1], S12, 0xe8c7b756L); /* 2 */
  FF (c, d, a, b, x[ 2], S13, 0x242070dbL); /* 3 */
  FF (b, c, d, a, x[ 3], S14, 0xc1bdceeeL); /* 4 */
  FF (a, b, c, d, x[ 4], S11, 0xf57c0fafL); /* 5 */
  FF (d, a, b, c, x[ 5], S12, 0x4787c62aL); /* 6 */
  FF (c, d, a, b, x[ 6], S13, 0xa8304613L); /* 7 */
  FF (b, c, d, a, x[ 7], S14, 0xfd469501L); /* 8 */
  FF (a, b, c, d, x[ 8], S11, 0x698098d8L); /* 9 */
  FF (d, a, b, c, x[ 9], S12, 0x8b44f7afL); /* 10 */
  FF (c, d, a, b, x[10], S13, 0xffff5bb1L); /* 11 */
  FF (b, c, d, a, x[11], S14, 0x895cd7beL); /* 12 */
  FF (a, b, c, d, x[12], S11, 0x6b901122L); /* 13 */
  FF (d, a, b, c, x[13], S12, 0xfd987193L); /* 14 */
  FF (c, d, a, b, x[14], S13, 0xa679438eL); /* 15 */
  FF (b, c, d, a, x[15], S14, 0x49b40821L); /* 16 */

 /* Round 2 */
  GG (a, b, c, d, x[ 1], S21, 0xf61e2562L); /* 17 */
  GG (d, a, b, c, x[ 6], S22, 0xc040b340L); /* 18 */
  GG (c, d, a, b, x[11], S23, 0x265e5a51L); /* 19 */
  GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aaL); /* 20 */
  GG (a, b, c, d, x[ 5], S21, 0xd62f105dL); /* 21 */
  GG (d, a, b, c, x[10], S22,  0x2441453L); /* 22 */
  GG (c, d, a, b, x[15], S23, 0xd8a1e681L); /* 23 */
  GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8L); /* 24 */
  GG (a, b, c, d, x[ 9], S21, 0x21e1cde6L); /* 25 */
  GG (d, a, b, c, x[14], S22, 0xc33707d6L); /* 26 */
  GG (c, d, a, b, x[ 3], S23, 0xf4d50d87L); /* 27 */
  GG (b, c, d, a, x[ 8], S24, 0x455a14edL); /* 28 */
  GG (a, b, c, d, x[13], S21, 0xa9e3e905L); /* 29 */
  GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8L); /* 30 */
  GG (c, d, a, b, x[ 7], S23, 0x676f02d9L); /* 31 */
  GG (b, c, d, a, x[12], S24, 0x8d2a4c8aL); /* 32 */

  /* Round 3 */
  HH (a, b, c, d, x[ 5], S31, 0xfffa3942L); /* 33 */
  HH (d, a, b, c, x[ 8], S32, 0x8771f681L); /* 34 */
  HH (c, d, a, b, x[11], S33, 0x6d9d6122L); /* 35 */
  HH (b, c, d, a, x[14], S34, 0xfde5380cL); /* 36 */
  HH (a, b, c, d, x[ 1], S31, 0xa4beea44L); /* 37 */
  HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9L); /* 38 */
  HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60L); /* 39 */
  HH (b, c, d, a, x[10], S34, 0xbebfbc70L); /* 40 */
  HH (a, b, c, d, x[13], S31, 0x289b7ec6L); /* 41 */
  HH (d, a, b, c, x[ 0], S32, 0xeaa127faL); /* 42 */
  HH (c, d, a, b, x[ 3], S33, 0xd4ef3085L); /* 43 */
  HH (b, c, d, a, x[ 6], S34,  0x4881d05L); /* 44 */
  HH (a, b, c, d, x[ 9], S31, 0xd9d4d039L); /* 45 */
  HH (d, a, b, c, x[12], S32, 0xe6db99e5L); /* 46 */
  HH (c, d, a, b, x[15], S33, 0x1fa27cf8L); /* 47 */
  HH (b, c, d, a, x[ 2], S34, 0xc4ac5665L); /* 48 */

  /* Round 4 */
  II (a, b, c, d, x[ 0], S41, 0xf4292244L); /* 49 */
  II (d, a, b, c, x[ 7], S42, 0x432aff97L); /* 50 */
  II (c, d, a, b, x[14], S43, 0xab9423a7L); /* 51 */
  II (b, c, d, a, x[ 5], S44, 0xfc93a039L); /* 52 */
  II (a, b, c, d, x[12], S41, 0x655b59c3L); /* 53 */
  II (d, a, b, c, x[ 3], S42, 0x8f0ccc92L); /* 54 */
  II (c, d, a, b, x[10], S43, 0xffeff47dL); /* 55 */
  II (b, c, d, a, x[ 1], S44, 0x85845dd1L); /* 56 */
  II (a, b, c, d, x[ 8], S41, 0x6fa87e4fL); /* 57 */
  II (d, a, b, c, x[15], S42, 0xfe2ce6e0L); /* 58 */
  II (c, d, a, b, x[ 6], S43, 0xa3014314L); /* 59 */
  II (b, c, d, a, x[13], S44, 0x4e0811a1L); /* 60 */
  II (a, b, c, d, x[ 4], S41, 0xf7537e82L); /* 61 */
  II (d, a, b, c, x[11], S42, 0xbd3af235L); /* 62 */
  II (c, d, a, b, x[ 2], S43, 0x2ad7d2bbL); /* 63 */
  II (b, c, d, a, x[ 9], S44, 0xeb86d391L); /* 64 */

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;

  /* Zeroize sensitive information.
   */
  MD5_memset ((POINTER)x, 0, sizeof (x));
}

/* Encodes input (uint32) into output (unsigned char). Assumes len is
  a multiple of 4.
 */
static void Encode (
	unsigned char *output,
	uint32 *input,
	unsigned int len
)
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[j] = (unsigned char)(input[i] & 0xff);
		output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
		output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
		output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
	}
}

/* Decodes input (unsigned char) into output (uint32). Assumes len is
  a multiple of 4.
 */
static void Decode (
	uint32 *output,
	unsigned char *input,
	unsigned int len
)
{
  unsigned int i, j;

  for (i = 0, j = 0; j < len; i++, j += 4)
 output[i] = ((uint32)input[j]) | (((uint32)input[j+1]) << 8) |
   (((uint32)input[j+2]) << 16) | (((uint32)input[j+3]) << 24);
}

/* Note: Replace "for loop" with standard memcpy if possible.
 */

static void MD5_memcpy (
	POINTER output,
	POINTER input,
	unsigned int len
)
{
  unsigned int i;

  for (i = 0; i < len; i++)
 output[i] = input[i];
}

/* Note: Replace "for loop" with standard memset if possible.
 */
static void MD5_memset (
	POINTER output,
	int value,
	unsigned int len
)
{
  unsigned int i;

  for (i = 0; i < len; i++)
 ((char *)output)[i] = (char)value;
}

char const ThreeLetterLIST[][4]={
	"agn","aha","ake","aks","alm",
	"alt","alv","and","ane","arm",
	"ask","asp","att","bag","bak",
	"bie","bil","bit","bla","ble",
	"bli","bly","boa","bod","bok",
	"bol","bom","bor","bra","bro",
	"bru","bud","bue","dal","dam",
	"deg","der","det","din","dis",
	"dra","due","duk","dun","dyp",
	"egg","eie","eik","elg","elv",
	"emu","ene","eng","enn","ert",
	"ess","ete","ett","fei","fem",
	"fil","fin","flo","fly","for",
	"fot","fra","fri","fus","fyr",
	"gen","gir","gla","gre","gro",
	"gry","gul","hai","ham","han",
	"hav","hei","hel","her","hit",
	"hiv","hos","hov","hue","huk",
	"hun","hus","hva","ide","ild",
	"ile","inn","ion","ise","jag",
	"jeg","jet","jod","jus","juv",
	"kai","kam","kan","kar","kle",
	"kli","klo","kna","kne","kok",
	"kor","kro","kry","kul","kun",
	"kur","lad","lag","lam","lav",
	"let","lim","lin","liv","lom",
	"los","lov","lue","lun","lur",
	"lut","lyd","lyn","lyr","lys",
	"mai","mal","mat","med","meg",
	"mel","men","mer","mil","min",
	"mot","mur","mye","myk","myr",
	"nam","ned","nes","nok","nye",
	"nys","obo","obs","odd","ode",
	"opp","ord","orm","ose","osp",
	"oss","ost","ovn","pai","par",
	"pek","pen","pep","per","pip",
	"pop","rad","rak","ram","rar",
	"ras","rem","ren","rev","rik",
	"rim","rir","ris","riv","rom",
	"rop","ror","ros","rov","rur",
	"sag","sak","sal","sau","seg",
	"sei","sel","sen","ses","sil",
	"sin","siv","sju","sjy","ski",
	"sko","sky","smi","sne","snu",
	"sol","som","sot","spa","sti",
	"sto","sum","sus","syd","syl",
	"syn","syv","tak","tal","tam",
	"tau","tid","tie","til","tja",
	"tog","tom","tre","tue","tun",
	"tur","uke","ull","ulv","ung",
	"uro","urt","ute","var","ved",
	"veg","vei","vel","vev","vid",
	"vik","vis","vri","yre","yte"};

char wlan_essid[14];
char wlan_wep_key[13];
uint8 spWepKey[WEP_KEY_LEN];
FILE *oldfp = NULL;
FILE *newfp = NULL;
FILE *backupfp = NULL;
char old_file_name[64];
char new_file_name[64];
mac	MAC[MAC_MAX_NUM];
uint8 errorType = RETURN_NO_ERROR;
int line_number = 0;


void spSetWepKey( uint8 *spwepkey )
{
	if ( spwepkey == NULL )
		return;

	memcpy( spWepKey, spwepkey, WEP_KEY_LEN );
	
	return;
}
uint8 *spGetWepKey( void )
{
	if( spWepKey == NULL )
		return NULL;

	return spWepKey;
}

void getMD5ExpectedContext (char *input, char *expected )
{
    MD5_CTX context;

	if ( expected == NULL || input == NULL )
		return;
    
    MD5Init( &context );
	
	/* The input message is secret */
    MD5Update( &context, input, 12 );
	MD5Final( &context, expected  );
	
	return;
}

void produceEssid( uint8 *expected, char *essid )
{
	int letter_index = 0;
	int total = 0;

	if ( expected == NULL || essid == NULL  ) {
		return;
	}
	
	sprintf(essid,"%s%02x%02x", "ChinaNet-", expected[4],expected[5]);

	return;
}
void produceSerialNumber( uint8 *expected, char *SerialNumber,char * mac )
{
	int letter_index = 0;
	int total = 0;
		int i = 0;
	char temp[3];
	temp[2] = '\0';

	if ( expected == NULL || SerialNumber == NULL  || mac == NULL) {
		return;
	}
	sprintf(temp,"%02x", expected[6]);
	sprintf(SerialNumber,"%02x%02x%01c%s", expected[4],expected[5],temp[0],mac);

	for(i=0;i<17;i++)
	{
		SerialNumber[i] = toupper(SerialNumber[i]); 
	}

	return;
}

int dig2str( uint8 *dig, char *str, uint16 dig_len )
{
	uint8	*dp = dig;
	char	*cp = str;
	int 	ii;

	for ( ii=0; ii<dig_len; ii++, cp+=2, dp++ ) {
		sprintf (cp, "%02x", *dp );
	} 
	return 0;
} 

uint8 char2dig( char ch )
{
	switch (ch) {
		case '0':
			return 0;
		case '1':
			return 1;
		case '2':
			return 2;
		case '3':
			return 3;
		case '4':
			return 4;
		case '5':
			return 5;
		case '6':
			return 6;
		case '7':
			return 7;
		case '8':
			return 8;
		case '9':
			return 9;
		case 'a':
		case 'A':
			return 10;
		case 'b':
		case 'B':
			return 11;
		case 'c':
		case 'C':
			return 12;
		case 'd':
		case 'D':
			return 13;
		case 'e':
		case 'E':
			return 14;
		case 'f':
		case 'F':
			return 15;
		default:
			return -1;
	}
}

int str2dig( uint8 *dig, char *str )
{
	int i, j;
	char tempch1, tempch2;
	int length;
	int8 tempuint1, tempuint2; 

	if ( str == NULL )
		return -1;
	
	length = strlen( str );
	if( length == 0 )
		return -1;

	for ( j = 0, i = 0; i < length; i = i + 2, j++ ) {
		tempch1 = str[i];
		tempuint1 = ( int8 ) char2dig( tempch1 );
		if ( tempuint1 == -1 )
			return -1;
		
		tempch2 = str[i+1];
		tempuint2 = (int8) char2dig( tempch2 );
		if ( tempuint2 == -1 )
			return -1;

		dig[j] = tempuint1 * 16 + tempuint2;
	}	
	
	return 0;
} 
 
	int makenum3(int rang)
	{
		int tempNum;
		if(rang==1)
		{
			tempNum=(rand()%10); //数字	
			tempNum += 48;
		}
		else if(rang==3)
		{
			tempNum=(rand()%26); //小写字母 
			tempNum += 97;	
		}
		/*remove "0,1,8,B,I,O,o,l"according to my e-home spec*/
		if( (tempNum ==48)|| (tempNum ==49)|| (tempNum ==66)|| (tempNum ==73)|| (tempNum ==79)|| (tempNum ==108)|| (tempNum ==111))
			tempNum +=2;		
		else if (tempNum ==56)
			tempNum =57;
		//printf("tempNum %c \n\n",tempNum);
		return tempNum; 
	}


void checkSSIDKey(uint8 *expected)
{
	char tempNum, i ,j,n,m;
	char checka = 0;
	char checkb = 0;

	for(i= 4;i<8;i++)
	{
		for(j=0;j<2;j++)
		{
			tempNum = (expected[i]>>(j*4))&0x0F;
			//printf("ee %02x  %02x\n",tempNum,expected[i]);
			if(tempNum < 10)//数字判断
			{
				if((tempNum==0)&&(i==4)&&(j==1))   //首位去0
				{
				//printf("eee %02x  %02x\n",tempNum,expected[i]);
					expected[i]=expected[i]|(1<<4);
				//printf("eeee %02x  %02x\n",tempNum,expected[i]);
				}
				checka='a';
			}
			else
			{
				if(tempNum==0x0e)//去e
				{
				//printf("e  %02x\n",expected[i]);
					tempNum+=1;
					if(j==0)
					{
						expected[i]=expected[i]&0xF0;        //低4位
						expected[i]=expected[i]|tempNum;
					}else{
						expected[i]=expected[i]&0x0F;        //高4位
						expected[i]=expected[i]|(tempNum<<4);
					}

				}
				checkb='b';
			}
			
		}
	}
	if((checka=='a')&&(checkb=='b'))
	 {
		 return;
	 }else{
	 	n=rand()%4;
		if(checka!='a')//缺数字
		{
			expected[n+4]=(expected[n+4] & 0xF0)|(rand()%10); //低4位
		}else if(checkb!='b')//缺字母
		{
			m = rand()%6;
			if(m==4) m=3; //去e
			expected[n+4]=(expected[n+4] & 0xF0)|(m+10); //低4位
		}
	 }		


}

void produceWepKey( uint8 *expected, char *wepKey )
{
	int length = 0;
	int tempNum, i ;
	char *cp = NULL;

	if( expected == NULL || wepKey == NULL )
		return;
/*
	for (i= 6;i<14;i++){  //11->14
		//printf("expected=%x\n",expected[i]);
		tempNum = expected[i] % 36;
		if (tempNum < 10)
			tempNum += 48;
		else if (tempNum < 36)
			tempNum += 87;
		
		//remove "0,1,8,B,I,O,o,l,-e-"according to my e-home spec
		if( (tempNum ==101)||(tempNum ==48)|| (tempNum ==49)|| (tempNum ==66)|| (tempNum ==73)|| (tempNum ==79)|| (tempNum ==108)|| (tempNum ==111))
			tempNum +=2;		
		else if (tempNum ==56)
			tempNum =57;		
		expected[i]=tempNum;
   }
*/
	//checkwepKey(expected);
	//sprintf(wepKey, "%c%c%c%c%c%c%c%c",  expected[6], expected[7], expected[8],  expected[9], expected[10],expected[11], expected[12], expected[13]);
	//最终字符串长度判断
for(i= 4;i<8;i++)
{
	//makenum3(expected[i]);

}
	checkSSIDKey(expected);
	 sprintf(wepKey, "%02x%02x%02x%02x",
		 expected[4], expected[5], expected[6],  expected[7]);
	//printf("wepKey %s expected[6]%x, expected[7]%x, expected[8]%x,  expected[9]%x,  expected[10]%x \n",wepKey,expected[6], expected[7], expected[8],  expected[9],  expected[10]);
	//if(strlen(wepKey)==8)
	//{
		//printf("OK =%s \n",useradmin);

	//	return 0;
	//}
	return 1;

}


int makenum2(int rang)
{
	int tempNum;
	if(rang==1)
	{
		tempNum=(rand()%10); //数字	
		tempNum += 48;
	}
	else if(rang==3)
	{
		tempNum=(rand()%26); //小写字母	
		tempNum += 97;	
	}
	else if(rang==4)
	{
		tempNum=(rand()%4); //特殊字符
		if(tempNum==0)  //特殊字符
			tempNum=33;       //!
		else if(tempNum==1)
 			tempNum=35;       //#
		else if(tempNum==2)
			tempNum=64; 	  //@
		else if(tempNum==3)
			tempNum=63;       //?			
	}
	/*remove "0,1,8,B,I,O,o,l"according to my e-home spec*/
	if( (tempNum ==48)|| (tempNum ==49)|| (tempNum ==66)|| (tempNum ==73)|| (tempNum ==79)|| (tempNum ==108)|| (tempNum ==111))
		tempNum +=2;		
	else if (tempNum ==56)//数字“8”
		tempNum =57;      //数字“9”
	//printf("tempNum %c \n\n",tempNum);
	return tempNum;	
}

void checkuseradmin(uint8 *expected)
{
	int tempNum, i ,t;
	char checka,checkb,checkc,checkd;
	if( expected == NULL)
		return;
	
	while(1)
	{
		checka=0;
		checkb=0;
		checkc=0;
		checkd=0;	
		//循环判断是否包含字母、数字、特殊字符
		 for (i= 6;i<14;i++)
		 {
			if((expected[i]>=48)&&(expected[i]<=57))
			{
				checka='a';
			}
			else if((expected[i]>=65)&&(expected[i]<=90))
			{
				checkb='b';
			}
			else if((expected[i]>=97)&&(expected[i]<=122))
			{
				checkc='c';
			}
			else 
			{
				 if(expected[i]==33) 
				 	checkd='d';
				 else if(expected[i]==35)
				 	checkd='d';
				 else if(expected[i]==63)
				 	checkd='d';
				 else if(expected[i]==64)
				 	checkd='d';
			}			
		}
		 if((checka=='a')&&((checkb=='b')||(checkc=='c'))&&(checkd=='d'))
		 {
			 return;
		 }else{
			if(checka!='a')
			{
				t =(rand()%7);		
				expected[t+7]= makenum2(1);	
			}else if((checkb!='b')&&(checkc!='c'))
			{
				t =(rand()%7);
				expected[t+7]= makenum2(3);		
			}else if(checkd!='d')
			{
				t =(rand()%7);	
				expected[t+7]= makenum2(4);			
			}
		 }		
	}	
}

void checkuseradmin5bit(uint8 *expected)
{
	int tempNum, i ,t;
	char checka,checkb,checkc,checkd;
	if( expected == NULL)
		return;
	
	while(1)
	{
		checka=0;
		checkb=0;
		checkc=0;
		checkd=0;	
		//判断是否包含字母、数字、特殊字符
		 for (i= 6;i<11;i++)
		 {
			if((expected[i]>=48)&&(expected[i]<=57))
			{
				checka='a';
			}
			else if((expected[i]>=65)&&(expected[i]<=90))
			{
				checkb='b';
			}
			else if((expected[i]>=97)&&(expected[i]<=122))
			{
				checkc='c';
			}	
            //printf("%c",expected[i]);			
		}
		//printf("\n");
		 if((checka=='a')&&((checkb=='b')||(checkc=='c')))
		 {
			 //printf("xx\n");
			 return;
		 }else{
			if(checka!='a')
			{
				//printf("#aa##\n\n");
				t =(rand()%5);		
				expected[t+6]= makenum3(1);	
			}else if((checkb!='b')&&(checkc!='c'))
			{
				//printf("#bb##\n\n");
				t =(rand()%5);
				expected[t+6]= makenum3(3);		
			}
		 }	
		/*
		t =(rand()%100);
		t=t%8;		
		expected[t+6]= makenum();
		*/
		
	}	
}


int produceUseradmin( uint8 *expected, char *useradmin ,int num)
{
	int length = 0;
	int tempNum, i ;
	char *cp = NULL;

	if( expected == NULL || useradmin == NULL )
		return;
	//printf("produceUseradmin num %d \n",num);
	if(num==8){
		for (i= 6;i<14;i++){  //11->14
			//printf("expected=%x\n",expected[i]);
			tempNum = expected[i] % 36;
			if (tempNum < 10)
				tempNum += 48;
			else if (tempNum < 36)
				tempNum += 87;
			
			/*remove "0,1,8,B,I,O,o,l"according to my e-home spec*/
			if( (tempNum ==48)|| (tempNum ==49)|| (tempNum ==66)|| (tempNum ==73)|| (tempNum ==79)|| (tempNum ==108)|| (tempNum ==111))
				tempNum +=2;		
			else if (tempNum ==56)
				tempNum =57;		
			expected[i]=tempNum;
	   }
		checkuseradmin(expected);
		sprintf(useradmin, "%c%c%c%c%c%c%c%c",  expected[6], expected[7], expected[8],  expected[9], expected[10],expected[11], expected[12], expected[13]);
		//最终字符串长度判断
		if(strlen(useradmin)==8)
		{
			//printf("OK =%s \n",useradmin);

			return 0;
		}
	}
	else if(num == 5)
	{
	//printf("produceUseradmin num %d ######\n",num);
		for (i= 6;i<11;i++){  //11->14
			tempNum = expected[i] % 36;
			if (tempNum < 10)
				tempNum += 48;
			else if (tempNum < 36)
				tempNum += 87;
			
			/*remove "0,1,8,B,I,O,o,l"according to my e-home spec*/
			if( (tempNum ==48)|| (tempNum ==49)|| (tempNum ==66)|| (tempNum ==73)|| (tempNum ==79)|| (tempNum ==108)|| (tempNum ==111))
				tempNum +=2;		
			else if (tempNum ==56)
				tempNum =57;		
			expected[i]=tempNum;
	   }
		checkuseradmin5bit(expected);
		sprintf(useradmin, "%c%c%c%c%c",  expected[6], expected[7], expected[8],  expected[9], expected[10]);
		if(strlen(useradmin)==5)
		{
			//printf("OK =%s \n",useradmin);

			return 0;
		}
	}
	
	return 1;

}

#if 1
void produceSSID( uint8 *expected, char *ssid )
{
	int length = 0;
	char *cp = NULL;
	int tempNum, i ;

    if( expected == NULL || ssid == NULL )
        return;
    /*sonya, create char in 0~9,a~z,A~Z*/
    for (i= 0;i<4;i++){					
//		printf("expected1=%x\n",expected1[i]);
        tempNum = expected[i] % 62;
        if (tempNum < 10)
            tempNum += 48;
        else if (tempNum < 36)
            tempNum += 55;
        else
            tempNum += 61;	
        /*remove "0,1,8,B,I,O,o,l"according to my e-home spec*/
        if( (tempNum ==48)|| (tempNum ==49)|| (tempNum ==66)|| (tempNum ==73)|| (tempNum ==79)|| (tempNum ==108)|| (tempNum ==111))
            tempNum +=2;		
        else if (tempNum ==56)
            tempNum =57;		
        expected[i]=tempNum;
    }
         sprintf(ssid, "%s%c%c%c%c","CMCC-", expected[0], expected[1], expected[2],  expected[3]);

	return;
}
void produceWPAPSKKey( uint8 *expected, char *pskKey )
{
	int length = 0;
	char *cp = NULL;

	if( expected == NULL || pskKey == NULL )
		return;
	
         sprintf(pskKey, "%02x%02x%02x%02x",expected[4], expected[5], expected[6], expected[7]);

	return;
}
#endif
void usage(void)
{
#ifndef INPUT_FILE
	printf( "\nUsage: TEtest.exe <OUTPUT-FILE-NAME> <MAC_INTERVAL> <MAC_from> <MAC_to> <GponSN> <Device type> <PROVINCE> <username><userkey:5bit/8bit>\n" );
	printf( "\te.g.: H2_pdt_tool_v3.exe test.txt 8 000000000000 000000000fff CMDCB2000001 H2-3 jiangsu user 8 \n or		H2_pdt_tool_v3.exe test.txt 8 000000000000 000000000fff CMDCB2000001 H2-3 jiangsu user 5\n");	
#else
	printf( "\nUsage: TEtest.exe INPUT-FILE-NAME [OUTPUT-FILE-NAME] \n" );
	printf( "\tMAC-FILE-NAME: Input file saving information of MAC address.\n" );
	printf( "\tOUTPUT-FILE-NAME: Output file to save information of Essid and Wep-Key.\n" );
#endif

	return;
}

void do_with_error(void)
{
	if ( oldfp != NULL )
		fclose( oldfp );
	if ( newfp != NULL )
		fclose( newfp );
	if (  errorType  == RETURN_NO_ERROR ) {
		//printf("\nwrite the file: %s successfully.\n", new_file_name );
		return;
	}
	if ( ( errorType & RETURN_ERROR_NO_ENOUGH_PARA ) == RETURN_ERROR_NO_ENOUGH_PARA ) {
		usage();
	}
	if ( (errorType & RETURN_ERROR_CHAR_TO_DIG ) == RETURN_ERROR_CHAR_TO_DIG ) {
		printf("Error: something unexcepted occurs in file:[%s] line:[%d], Please check.\n", old_file_name, line_number );
	}
	if ( (errorType & RETURN_ERROR_WRONG_MAC_FILE ) == RETURN_ERROR_WRONG_MAC_FILE ) {
		printf("Error: Can not open file:[%s] or file:[%s] not exist!\n", old_file_name, old_file_name );
	}
	if ( (errorType & RETURN_ERROR_WRONG_MAC_FORMAT ) == RETURN_ERROR_WRONG_MAC_FORMAT ) {
		printf("Error: Wrong mac format!\n");
	}
	if ( (errorType & RETURN_ERROR_EXCEED_MAX_MAC_NUMBER ) == RETURN_ERROR_EXCEED_MAX_MAC_NUMBER ) {
		printf("Error: Exceed the max number of MAC address:%d\n", MAC_MAX_NUM);
	}
	return;
}

int checkMacBit(uint8 *mac_start, uint8 *mac_end, int bit)
{
	int i = 0;


	if ( mac_start == NULL || mac_end == NULL || bit > 6 )
		return -1;
	//printf("mac_start[%d]:%X mac_end[%d]:%X \n",bit,mac_start[bit],bit,mac_end[bit]);

	if ( mac_start[bit] > mac_end[bit] )//大
		return -1;
	
	if ( mac_start[bit] == mac_end[bit] )//相等
		return 1;
	
	return 0;//小
}
#if 0
int checkMacRange(uint8 *mac_start, uint8 *mac_end, int interval )
#else
int checkMacRange(uint8 *mac_start, uint8 *mac_end)
#endif
{
	int ret_code = 0;
	int i;
	char tmp_mac[13];

	if( mac_start == NULL || mac_end == NULL ) {
		printf("error5\n");
		return -1;
	}
/*
	strncpy(tmp_mac,mac_start,13);
	printf("mac_start %s\n",mac_start);
	printf("tmp_mac %s\n",tmp_mac);
*/
	for( i =0; i< 6; i++ ) {
		ret_code = checkMacBit( mac_start, mac_end, i );
		if ( ret_code == 1 )
			continue;
		else
			return ret_code;
	}
/*
	for(i = 0;i<interval;i++)
	{
		increaseMac( tmp_mac );			
	}
	
	printf("new increase8:%s\n",tmp_mac);
	*/


	return ret_code;
}

int checkMac(char *mac_start, char *mac_end)
{
	uint8 u_start[13];
	uint8 u_end[13];

	if ( mac_start == NULL || mac_end == NULL ) {
		return -1;
	}
	
	if( strlen(mac_start) != 12 || strlen(mac_end) != 12 ) {
		return -1;
	}
	
	memset(u_start, 0x0, 13);
	memset(u_end, 0x0, 13 );
	if ( str2dig(u_start, mac_start ) == -1  || str2dig(u_end, mac_end ) == -1 ) {
		return -1;
	}
	
	if ( checkMacRange( u_start, u_end) == -1 ) {
		return -1;
	}

	return 0;
}

int increaseGponSnByHex(char *gonsn)
{
	uint8 u_gonsn[16];
	int i;

	if ( gonsn == NULL ) {
		return -1;
	}

	memset(u_gonsn, 0x0, 16 );
	if ( str2dig( u_gonsn, gonsn ) == -1  ) {
		return -1;
	}
 
	for ( i = 7; i >= 0; i-- ) {
		if ( u_gonsn[i] == 0xFF ) {
			u_gonsn[i] = 0;
			continue;
		}
		else {
			u_gonsn[i] = u_gonsn[i] + 1;
			break;
		}

	}

	dig2str(u_gonsn, gonsn, 16 );
	gonsn[16] = '\0';
	return 0;
}


/*
 *
 */
#define MAX_COUNT 16
int increaseGponSnByDecimal(char *gonsn ,unsigned int interval){
	unsigned int length , i,count ;
	unsigned char tmpch;	 
	uint8 u_gonsn[MAX_COUNT];
	char *strcp = gonsn;
	
	memset(u_gonsn, 0x0, MAX_COUNT );  
	length = strlen( strcp );
	if( length == 0 || length < MAX_COUNT || strcp == NULL){
		printf("increaseGponSnByDecimal: gonsn length less than MAX_COUNT\n");
		return -1;
	}	
		
	for (  i = 0; i < MAX_COUNT; i++ ) {
		tmpch = strcp[i];	 
		if ( tmpch == -1 )
			break;
		else 
			u_gonsn[i] = ( int8 ) char2dig( tmpch );
	}

	for ( i = MAX_COUNT-1; i >= 0; i-- ) {
		if ( u_gonsn[i] == 9 ) {
			u_gonsn[i] = 0;		 
			continue;
		}
		else {
			u_gonsn[i] += interval;
			break;
		}
	}	 
	for(i=0;i<MAX_COUNT; i++ ,strcp+=1){		
		sprintf (strcp, "%x", u_gonsn[i] ); 
	}
	strcp[MAX_COUNT] = '\0';	 
	return 0;
}

int increaseMac(char *mac)
{
	uint8 u_mac[13];
	int i;

	if ( mac == NULL ) {
		return -1;
	}

	memset(u_mac, 0x0, 13 );
	if ( str2dig( u_mac, mac ) == -1  ) {
		return -1;
	}

	for ( i = 5; i >= 0; i-- ) {
		if ( u_mac[i] == 0xff ) {
			u_mac[i] = 0;
			continue;
		}
		else {
			u_mac[i] = u_mac[i] + 1;
			break;
		}

	}

	dig2str(u_mac, mac, 6 );
	mac[12] = '\0';

	return 0;
}

int decreaseMac(char *mac)
{
	uint8 u_mac[13];
	int i;

	if ( mac == NULL ) {
		return -1;
	}

	memset(u_mac, 0x0, 13 );
	if ( str2dig( u_mac, mac ) == -1  ) {
		return -1;
	}

	for ( i = 5; i >= 0; i-- ) {
		if ( u_mac[i] == 0x00 ) {
			u_mac[i] = 0xff;
			continue;
		}
		else {
			u_mac[i] = u_mac[i] - 1;
			break;
		}

	}

	dig2str(u_mac, mac, 6 );
	mac[12] = '\0';

	return 0;
}

//typedef unsigned char UINT8

int ASCII_2_HEX(char *o_data,unsigned *n_data, int len)
{
	int i;
	char tempData;
	char temp[1];
	char *o_buf = o_data;
	unsigned *n_buf = n_data;

	for(i=0;i<len;i++)
	{
		memset(temp, 0x0, 1 );

		//printf("\n get o_buf[i] :%c \n",o_buf[i]);

		tempData = (int) o_buf[i];

		//o_buf[i]=tempData;

		//printf("\n get tempData :%x \n",tempData);
		//sprintf(n_buf[i],"%x",tempData);
		n_buf[i]=tempData;
		//strcat(n_buf,temp);

			//n_buf[i++]	sprintf(tempcp, "%02x", MAC[i].mac[j] );
	}


	return len;
}


int main( int argc, char *argv[] )
{
	static int i;
	static int count = 0;
	char *spwepkey = NULL;
	int j = 0, k = 0 , m =0;
	int interval = 0;
	char txt_mac[14];
	char txt_mac_hq[20];
	char txt_mac_upper[13];
	char txt_mac_upperhq[20];
	char tempcp[2];
	char tempcphq[3];
	char txt_mac_start[13];
	char txt_mac_end[13];
	char txt_mac_temp[13];
	char txt_mac_temp2[13];
	char txt_mac_md5[13];
	char *cp;
	char *cphq;
	
    char txt_model[27];
	char txt_vol[14];
	char txt_cur[14];
	char txt_snuse[10];
	char txt_province[5];
	char txt_sn_hq[30];
	char txt_bcc[3];
	unsigned txt_sn_16[50];

	unsigned backupsn;
	char gpon_sn[20];
	char gpon_sn_hd[7];
	char gpon_sn_num[7];

	char outgpon_sn[20];
	char mac_head[7];
	char productID[12];
	char gpon_province[20];  //省份

	int MAC_Interval = 10;
	int tmplen=0;
	char uCRC=0;//校验初始值
	int keynum=8;
	
	if ( argc < 7 ) {
		errorType |= RETURN_ERROR_NO_ENOUGH_PARA;
		atexit( do_with_error );
		return -1;
	}
	if ( argc > 11 ) {
		errorType |= RETURN_ERROR_NO_ENOUGH_PARA;
		atexit( do_with_error );
		return -1;
	}

	srand(time( NULL ));
#ifndef INPUT_FILE

	MAC_Interval = atoi(argv[2]);

	memset(txt_mac_start, 0x0, 13 );
	memset(txt_mac_end, 0x0, 13 );
	memset(txt_snuse, 0x0, 10 );
	memset(txt_province,0x0,5);
	memset(gpon_sn, 0x0, 20 );
	memset(gpon_sn_hd, 0x0, 7 );
	memset(gpon_sn_num, 0x0, 7 );
	memset(productID, 0x0, 12 );
	memset(gpon_province, 0x0, 20);//省份

	if ( argc > 5 ) {
		memset(txt_model, 0x0, 27 );
		memset(txt_vol, 0x0, 14 );	
		memset(txt_cur, 0x0, 14 );
	}
 
    if( argc == 5 ){
		txt_snuse[0] = '3';
		//txt_snuse[1] = '0';
		txt_province[0] = '0';
		txt_province[1] = '0';
	}
	else if ( argc == 9 ) {
		strncpy(txt_mac_start,argv[3],13);
		strncpy(txt_mac_end,argv[4],13);
		strncpy(gpon_sn,argv[5],20);		
		strncpy(productID,argv[6],12);
		strncpy(txt_snuse,argv[7],10);
        keynum = atoi(argv[8]);

	} else if (argc== 10 ){
		strncpy(txt_mac_start,argv[3],13);
		strncpy(txt_mac_end,argv[4],13);
		strncpy(gpon_sn,argv[5],20);
		strncpy(txt_model,argv[5],26);
        strncpy(productID,argv[6],12);
		strncpy(txt_cur,argv[7],13);
		strncpy(txt_snuse,argv[8],10);
        keynum = atoi(argv[9]);
	}
	
	strncpy(gpon_sn_hd,gpon_sn,6);	
	gpon_sn_hd[6]='\0';
	strncpy(gpon_sn_num,gpon_sn+6,7);

    printf(" argc = %d\n",argc);


	if((gpon_sn==NULL))	{
		errorType |= RETURN_ERROR_WRONG_MAC_FORMAT;
		atexit( do_with_error );
		return -1;
	}	
	
/*
    printf("MAC_Interval = %d\n",MAC_Interval);
    printf("keynum = %d\n",keynum);
	printf("txt_mac_start = %s ,txt_mac_end = %s , gpon_sn = %s ,productID = %s \n" ,txt_mac_start ,txt_mac_end, gpon_sn, productID);
	printf("MAC_Interval = %d\n",MAC_Interval);
	printf("Model_name = %s\n",productID);
	printf("gpon_sn = %s\n",gpon_sn);
	printf("txt_snuse = %s\n",txt_snuse);
*/	
    
    memcpy( txt_mac_temp, txt_mac_start, 13 );	
	memset(MAC, 0x0, sizeof( mac ) );
	while ( checkMac( txt_mac_temp, txt_mac_end) != -1 ) {
//		increaseMac( txt_mac_temp );//sonya 20100421, do not need increase 
		str2dig( MAC[count].mac, txt_mac_temp );

        /* Produce essid */
		getMD5ExpectedContext( txt_mac_temp, MAC[count].output );

        /*prroduct essid using MD5, too*/
		sprintf(MAC[count].essid,"%s%02x%02x", "Portal-", MAC[count].mac[4],MAC[count].mac[5]);
		
		produceSerialNumber(MAC[count].output, MAC[count].SerialNumber,txt_mac_temp);
		/*prroduct WPA-PSK presharedkey and WEP key*/
//		produceWPAPSKKey( MAC[count].output, MAC[count].pskkey);
		produceWepKey( MAC[count].output, MAC[count].wepkey );
		
		if((keynum!=5)&&(keynum!=8)) keynum=8;

		while(produceUseradmin( MAC[count].output, MAC[count].useradmin, keynum))
		{
			getMD5ExpectedContext( txt_mac_temp, MAC[count].output );
		}
		/* Update temp variable*/
		memcpy(txt_mac_temp2, txt_mac_temp, 13 );
		
		for(interval = 0;interval<MAC_Interval;interval++)
		{
			increaseMac( txt_mac_temp );			
		}
		count++;
		if ( count >= MAC_MAX_NUM ) 
		{
			errorType |= RETURN_ERROR_EXCEED_MAX_MAC_NUMBER;
			atexit( do_with_error );
			return -1;
		}	

	} /*End of while */

#else
	/* Open input file for reading */
	strcpy( old_file_name, argv[1] );
	oldfp = fopen( argv[1], "r" );
	if ( oldfp == NULL ) {
		errorType |= RETURN_ERROR_WRONG_MAC_FILE;
		atexit( do_with_error );
		return -1;
	}

	memset(MAC, 0x0, sizeof( mac ) );

	while ( ( !feof( oldfp ) ) && ( count < MAC_MAX_NUM )  ) {
		memset(txt_mac, 0x0, 13 );
		fscanf( oldfp, "%s", txt_mac );
		txt_mac[12] = '\0';
	
		/* convert format from string to uint8 */
		if( strlen(txt_mac) == 0 ) { /*skip blank line*/
			count = count + 1;
			break;
		}

		if ( ( strlen( txt_mac ) != 12 ) ||  str2dig( MAC[count].mac, txt_mac ) == -1 ) {
			errorType |= RETURN_ERROR_CHAR_TO_DIG;
			line_number = count + 1;
			atexit( do_with_error );
			return 0;
		}

        /* Produce essid */
        getMD5ExpectedContext( MAC[count].mac, MAC[count].output );
		produceEssid( MAC[count].output, MAC[count].essid );
		 
        /* Produce Wep-key */
        getMD5ExpectedContext(MAC[count].output, MAC[count].output2 );

		produceWepKey( MAC[count].output2, MAC[count].wepkey );
		spwepkey = spGetWepKey();
		if ( spwepkey != NULL )
			memcpy( MAC[count].spWepKey, spwepkey, strlen( spwepkey ) );
		
		count = count + 1;
	} /*End of while */
#endif

		
#ifndef INPUT_FILE
	/* Create or modify the output file for saving */
	if ( argv[1] == NULL ) {
		newfp = fopen("result.txt", "w+");
		strcpy( new_file_name, "result.txt" );
	}
	else {
		newfp = fopen(argv[1], "w+" );
		strcpy( new_file_name, argv[1] );
	}
#else
	if ( argv[2] == NULL ) {
		newfp = fopen("result.txt", "w+");
		strcpy( new_file_name, "result.txt" );
	}
	else {
		newfp = fopen(argv[2], "w+" );
		strcpy( new_file_name, argv[2] );
	}
#endif

	if ( newfp == NULL ) {
		printf("create the new file error\n");
		atexit( do_with_error );
		return -1;
	}

#ifndef FULL_FORMAT
	if ( argc == 5 ){ 
		fprintf(newfp, "MAC-Address\t\tMAC-Address[upper]\tEssid\t\tWPA-PSK-KEY[Hex]\tuser config password\tSerialNumber\n" );
		//fprintf(newfp, "MAC-Address\t\tMAC-Address[upper]\tEssid\t\t\tWPA-PSK-KEY[Hex]\tVPN-Presharekey\n");//\tSerialNumber*/\n" );
	}
#else	
	fprintf(newfp, "MAC-Address\t\tEssid\t\t\tWEP-KEY[Hex]\t\tWEP-KEY[Char]\n" );
#endif


#ifndef INPUT_FILE
	for ( i = 0; i < count; i++ ) {
#else	
	for ( i = 0; i < ( count - 1 ); i++ ) {
#endif
		//if (( i % MAC_RESERVE) !=0) continue ;  //隔5个产生一个
		/* MAC */ 
		memset(txt_mac, 0x0, 13 );
		memset(txt_mac_hq, 0x0, 20 );
		memset(txt_sn_hq, 0x0, 30 );
		memset(txt_bcc, 0x0, 3 );
		memset(txt_sn_16,0x0, 50);
		uCRC=0;


		for( j = 0; j < 6; j++ ) {
			tempcp[0] = tempcp[1] = '\0';
			tempcphq[0] = tempcphq[1] = tempcphq[2] = '\0';

			sprintf(tempcp, "%02x", MAC[i].mac[j] );
			strcat(txt_mac, tempcp );

			sprintf(tempcphq, ":%02x", MAC[i].mac[j] );
			strcat(txt_mac_hq, tempcphq );

			//printf("\n txt_mac: %s\n",txt_mac);
		}
//		decreaseMac(txt_mac);//sonya 20100421, do not need decrease
		/* change mac to upper */
		memcpy( txt_mac_upper, txt_mac, 13 );
		memcpy( txt_mac_upperhq,txt_mac_hq+1, 20 );
		
		memset(mac_head,0x0,7);
		mac_head[6]='\0';
		memcpy(mac_head,txt_mac_upper,6);
	//fprintf(stdout,"%s==%s\n",mac_head,txt_mac_upperhq);

		cp = txt_mac_upper;
		for( k = 0; k < 13; k++ ) {
			cp[k] = toupper(cp[k]); 
		}

		memcpy( txt_sn_hq,txt_snuse,1);
		strcat( txt_sn_hq,txt_province);
		//strcat( txt_sn_hq,"0");
		strcat( txt_sn_hq,txt_mac_upper);

//printf("\n 2 txt_sn_hq: %s\n",txt_sn_hq);
//-----------------------------------		
		tmplen = strlen(txt_sn_hq);

//printf("\n tmplen: %d\n",tmplen);
//printf("\n txt_sn_hq: %s\n",txt_sn_hq);

		tmplen = ASCII_2_HEX(txt_sn_hq,txt_sn_16,tmplen);

//printf("\n tmplen2: %d\n",tmplen);
//printf("\n txt_sn_16: %s\n",txt_sn_16);
//printf("\n txt_snuse: %s\n",txt_snuse);

		for(m =0; m < tmplen ; m++) 
		uCRC^=txt_sn_16[m];

		//printf("\n uCRC: %02x \n",uCRC);

		//tempcp[0] = tempcp[1] = '\0';
		memset( txt_sn_hq, 0x0, 30 );
		memset( tempcp, 0x0, 2 );
		memcpy( txt_sn_hq,txt_mac_upper,6);
		strcat( txt_sn_hq,"-");

		sprintf( tempcp, "%02X", uCRC);
		strcat( txt_sn_hq,tempcp);
		strcat( txt_sn_hq,txt_snuse);
		strcat( txt_sn_hq,txt_province);
		//strcat( txt_sn_hq,"0");
		strcat( txt_sn_hq,txt_mac_upper);

//printf("\n txt_sn_hq: %s\n",txt_sn_hq);
		memcpy( MAC[i].SerialNumber,txt_sn_hq+7,17);
		 
		cphq = txt_mac;
		for( k = 0; k < 20; k++ ) {
			cphq[k] = toupper(cphq[k]); 
		}
		


		cphq=NULL;
		cphq=gpon_sn_num;
		for( k = 0; k < 7; k++ ) {
			cphq[k] = toupper(cphq[k]); 
		}
	//	fprintf(stdout,"%s\n",gpon_sn);	
		memset(outgpon_sn,0x0,20);
		strncpy(outgpon_sn,gpon_sn,20);
		increaseGponSnByDecimal(gpon_sn,1);

#ifndef FULL_FORMAT

        fprintf(newfp, "%s,%s,%s,%s,%s,%s,%s,%s,%s\n", productID, txt_mac, MAC[i].essid, ((char *)MAC[i].wepkey),"myportalwifi.com ",txt_snuse,((char *)MAC[i].useradmin),"12V,1.0A,",outgpon_sn);
        fprintf(stdout,"%s,%s,%s,%s,%s,%s,%s,%s,%s\n", productID, txt_mac, MAC[i].essid, ((char *)MAC[i].wepkey),"myportalwifi.com ",txt_snuse,((char *)MAC[i].useradmin),"12V,1.0A,",outgpon_sn);

#else
		fprintf(newfp, "%s\t\t%s\t\t%s\t\t%s\n", txt_mac, MAC[i].essid, MAC[i].wepkey, MAC[i].spWepKey );
		fprintf(stdout, "%s\t%s\t%s\t%s\n", txt_mac, MAC[i].essid, MAC[i].wepkey, MAC[i].spWepKey );
#endif

#ifdef FULL_FORMAT
#ifndef INPUT_FILE	
		if ( ( 1 != count - 1 ) )
#else
		if ( ( i != count - 2 ) )
#endif

			fprintf(newfp, "---------------------------------------------------------------------------\n" );
#endif	
		//backupsn++;
	}
	atexit( do_with_error );
	return 0;
}
