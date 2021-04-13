/**************************************************************
                        AES128 
Author:   Uli Kretzschmar
             MSP430 Systems
             Freising
AES software support for encryption and decryption
ECCN 5D002 TSU - Technology / Software Unrestricted
**************************************************************/
//#define AES_DISABLE 1
#include "stdint.h"
#include "string.h"
#include "TI_aes.h"

unsigned char AES_default_key[] = {	0x7c, 0x52, 0x68, 0x4b, 0x3a, 0x25, 0x49, 0x25,
							0x0d, 0x0a, 0x69, 0x22, 0x6d, 0x37, 0x75, 0x46
};

unsigned char AES_key[sizeof(AES_default_key)];

unsigned char AES_boot_key[] = {0x12, 0x24, 0x17, 0x3a, 0x69, 0x46, 0x6d, 0x0a,
								0xf1, 0xc5, 0x96, 0x15, 0xa1, 0x29, 0x80, 0x73
};

// foreward sbox
const unsigned char sbox[256] = {
// 0    1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 1
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 2
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 3
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 4
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 5
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 6
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 7
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 8
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 9
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // A
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // B
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // C
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // D
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // E
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 // F
};
// inverse sbox
const unsigned char rsbox[256] = {
// 0    1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 1
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 2
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 3
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 4
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 5
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 6
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 7
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 8
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 9
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // A
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // B
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // C
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // D
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // E
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 // F
};
// round constant
const unsigned char Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};


// expand the key
void expandKey(unsigned char *expandedKey,
               unsigned char *key)
{
  unsigned short ii, buf1;
  for (ii=0;ii<16;ii++)
    expandedKey[ii] = key[ii];
  for (ii=1;ii<11;ii++){
    buf1 = expandedKey[ii*16 - 4];
    expandedKey[ii*16 + 0] = sbox[expandedKey[ii*16 - 3]]^expandedKey[(ii-1)*16 + 0]^Rcon[ii];
    expandedKey[ii*16 + 1] = sbox[expandedKey[ii*16 - 2]]^expandedKey[(ii-1)*16 + 1];
    expandedKey[ii*16 + 2] = sbox[expandedKey[ii*16 - 1]]^expandedKey[(ii-1)*16 + 2];
    expandedKey[ii*16 + 3] = sbox[buf1                  ]^expandedKey[(ii-1)*16 + 3];
    expandedKey[ii*16 + 4] = expandedKey[(ii-1)*16 + 4]^expandedKey[ii*16 + 0];
    expandedKey[ii*16 + 5] = expandedKey[(ii-1)*16 + 5]^expandedKey[ii*16 + 1];
    expandedKey[ii*16 + 6] = expandedKey[(ii-1)*16 + 6]^expandedKey[ii*16 + 2];
    expandedKey[ii*16 + 7] = expandedKey[(ii-1)*16 + 7]^expandedKey[ii*16 + 3];
    expandedKey[ii*16 + 8] = expandedKey[(ii-1)*16 + 8]^expandedKey[ii*16 + 4];
    expandedKey[ii*16 + 9] = expandedKey[(ii-1)*16 + 9]^expandedKey[ii*16 + 5];
    expandedKey[ii*16 +10] = expandedKey[(ii-1)*16 +10]^expandedKey[ii*16 + 6];
    expandedKey[ii*16 +11] = expandedKey[(ii-1)*16 +11]^expandedKey[ii*16 + 7];
    expandedKey[ii*16 +12] = expandedKey[(ii-1)*16 +12]^expandedKey[ii*16 + 8];
    expandedKey[ii*16 +13] = expandedKey[(ii-1)*16 +13]^expandedKey[ii*16 + 9];
    expandedKey[ii*16 +14] = expandedKey[(ii-1)*16 +14]^expandedKey[ii*16 +10];
    expandedKey[ii*16 +15] = expandedKey[(ii-1)*16 +15]^expandedKey[ii*16 +11];
  }
  
  
}

// multiply by 2 in the galois field
unsigned char galois_mul2(unsigned char value)
{
	if (value>>7)
	{
		value = value << 1;
		return (value^0x1b);
	} else
		return value<<1;
}

// straight foreward aes encryption implementation
//   first the group of operations
//     - addroundkey
//     - subbytes
//     - shiftrows
//     - mixcolums
//   is executed 9 times, after this addroundkey to finish the 9th round, 
//   after that the 10th round without mixcolums
//   no further subfunctions to save cycles for function calls
//   no structuring with "for (....)" to save cycles
void aes_encr(unsigned char *state, unsigned char *expandedKey)
{
  unsigned char buf1, buf2, buf3, round;

    
  for (round = 0; round < 9; round ++){
    // addroundkey, sbox and shiftrows
    // row 0
    state[ 0]  = sbox[(state[ 0] ^ expandedKey[(round*16)     ])];
    state[ 4]  = sbox[(state[ 4] ^ expandedKey[(round*16) +  4])];
    state[ 8]  = sbox[(state[ 8] ^ expandedKey[(round*16) +  8])];
    state[12]  = sbox[(state[12] ^ expandedKey[(round*16) + 12])];
    // row 1
    buf1 = state[1] ^ expandedKey[(round*16) + 1];
    state[ 1]  = sbox[(state[ 5] ^ expandedKey[(round*16) +  5])];
    state[ 5]  = sbox[(state[ 9] ^ expandedKey[(round*16) +  9])];
    state[ 9]  = sbox[(state[13] ^ expandedKey[(round*16) + 13])];
    state[13]  = sbox[buf1];
    // row 2
    buf1 = state[2] ^ expandedKey[(round*16) + 2];
    buf2 = state[6] ^ expandedKey[(round*16) + 6];
    state[ 2]  = sbox[(state[10] ^ expandedKey[(round*16) + 10])];
    state[ 6]  = sbox[(state[14] ^ expandedKey[(round*16) + 14])];
    state[10]  = sbox[buf1];
    state[14]  = sbox[buf2];
    // row 3
    buf1 = state[15] ^ expandedKey[(round*16) + 15];
    state[15]  = sbox[(state[11] ^ expandedKey[(round*16) + 11])];
    state[11]  = sbox[(state[ 7] ^ expandedKey[(round*16) +  7])];
    state[ 7]  = sbox[(state[ 3] ^ expandedKey[(round*16) +  3])];
    state[ 3]  = sbox[buf1];
    
    // mixcolums //////////
    // col1
    buf1 = state[0] ^ state[1] ^ state[2] ^ state[3];
    buf2 = state[0];
    buf3 = state[0]^state[1]; buf3=galois_mul2(buf3); state[0] = state[0] ^ buf3 ^ buf1;
    buf3 = state[1]^state[2]; buf3=galois_mul2(buf3); state[1] = state[1] ^ buf3 ^ buf1;
    buf3 = state[2]^state[3]; buf3=galois_mul2(buf3); state[2] = state[2] ^ buf3 ^ buf1;
    buf3 = state[3]^buf2;     buf3=galois_mul2(buf3); state[3] = state[3] ^ buf3 ^ buf1;
    // col2
    buf1 = state[4] ^ state[5] ^ state[6] ^ state[7];
    buf2 = state[4];
    buf3 = state[4]^state[5]; buf3=galois_mul2(buf3); state[4] = state[4] ^ buf3 ^ buf1;
    buf3 = state[5]^state[6]; buf3=galois_mul2(buf3); state[5] = state[5] ^ buf3 ^ buf1;
    buf3 = state[6]^state[7]; buf3=galois_mul2(buf3); state[6] = state[6] ^ buf3 ^ buf1;
    buf3 = state[7]^buf2;     buf3=galois_mul2(buf3); state[7] = state[7] ^ buf3 ^ buf1;
    // col3
    buf1 = state[8] ^ state[9] ^ state[10] ^ state[11];
    buf2 = state[8];
    buf3 = state[8]^state[9];   buf3=galois_mul2(buf3); state[8] = state[8] ^ buf3 ^ buf1;
    buf3 = state[9]^state[10];  buf3=galois_mul2(buf3); state[9] = state[9] ^ buf3 ^ buf1;
    buf3 = state[10]^state[11]; buf3=galois_mul2(buf3); state[10] = state[10] ^ buf3 ^ buf1;
    buf3 = state[11]^buf2;      buf3=galois_mul2(buf3); state[11] = state[11] ^ buf3 ^ buf1;
    // col4
    buf1 = state[12] ^ state[13] ^ state[14] ^ state[15];
    buf2 = state[12];
    buf3 = state[12]^state[13]; buf3=galois_mul2(buf3); state[12] = state[12] ^ buf3 ^ buf1;
    buf3 = state[13]^state[14]; buf3=galois_mul2(buf3); state[13] = state[13] ^ buf3 ^ buf1;
    buf3 = state[14]^state[15]; buf3=galois_mul2(buf3); state[14] = state[14] ^ buf3 ^ buf1;
    buf3 = state[15]^buf2;      buf3=galois_mul2(buf3); state[15] = state[15] ^ buf3 ^ buf1;    

  }
  // 10th round without mixcols
  state[ 0]  = sbox[(state[ 0] ^ expandedKey[(round*16)     ])];
  state[ 4]  = sbox[(state[ 4] ^ expandedKey[(round*16) +  4])];
  state[ 8]  = sbox[(state[ 8] ^ expandedKey[(round*16) +  8])];
  state[12]  = sbox[(state[12] ^ expandedKey[(round*16) + 12])];
  // row 1
  buf1 = state[1] ^ expandedKey[(round*16) + 1];
  state[ 1]  = sbox[(state[ 5] ^ expandedKey[(round*16) +  5])];
  state[ 5]  = sbox[(state[ 9] ^ expandedKey[(round*16) +  9])];
  state[ 9]  = sbox[(state[13] ^ expandedKey[(round*16) + 13])];
  state[13]  = sbox[buf1];
  // row 2
  buf1 = state[2] ^ expandedKey[(round*16) + 2];
  buf2 = state[6] ^ expandedKey[(round*16) + 6];
  state[ 2]  = sbox[(state[10] ^ expandedKey[(round*16) + 10])];
  state[ 6]  = sbox[(state[14] ^ expandedKey[(round*16) + 14])];
  state[10]  = sbox[buf1];
  state[14]  = sbox[buf2];
  // row 3
  buf1 = state[15] ^ expandedKey[(round*16) + 15];
  state[15]  = sbox[(state[11] ^ expandedKey[(round*16) + 11])];
  state[11]  = sbox[(state[ 7] ^ expandedKey[(round*16) +  7])];
  state[ 7]  = sbox[(state[ 3] ^ expandedKey[(round*16) +  3])];
  state[ 3]  = sbox[buf1];
  // last addroundkey
  state[ 0]^=expandedKey[160];
  state[ 1]^=expandedKey[161];
  state[ 2]^=expandedKey[162];
  state[ 3]^=expandedKey[163];
  state[ 4]^=expandedKey[164];
  state[ 5]^=expandedKey[165];
  state[ 6]^=expandedKey[166];
  state[ 7]^=expandedKey[167];
  state[ 8]^=expandedKey[168];
  state[ 9]^=expandedKey[169];
  state[10]^=expandedKey[170];
  state[11]^=expandedKey[171];
  state[12]^=expandedKey[172];
  state[13]^=expandedKey[173];
  state[14]^=expandedKey[174]; 
  state[15]^=expandedKey[175];
} 

// straight foreward aes decryption implementation
//   the order of substeps is the exact reverse of decryption
//   inverse functions:
//       - addRoundKey is its own inverse
//       - rsbox is inverse of sbox
//       - rightshift instead of leftshift
//       - invMixColumns = barreto + mixColumns
//   no further subfunctions to save cycles for function calls
//   no structuring with "for (....)" to save cycles
void aes_decr(unsigned char *state, unsigned char *expandedKey)
{
  unsigned char buf1, buf2, buf3;
  signed char round;
  round = 9;
   
  // initial addroundkey
  state[ 0]^=expandedKey[160];
  state[ 1]^=expandedKey[161];
  state[ 2]^=expandedKey[162];
  state[ 3]^=expandedKey[163];
  state[ 4]^=expandedKey[164];
  state[ 5]^=expandedKey[165];
  state[ 6]^=expandedKey[166];
  state[ 7]^=expandedKey[167];
  state[ 8]^=expandedKey[168];
  state[ 9]^=expandedKey[169];
  state[10]^=expandedKey[170];
  state[11]^=expandedKey[171];
  state[12]^=expandedKey[172];
  state[13]^=expandedKey[173];
  state[14]^=expandedKey[174]; 
  state[15]^=expandedKey[175];

  // 10th round without mixcols
  state[ 0]  = rsbox[state[ 0]] ^ expandedKey[(round*16)     ];
  state[ 4]  = rsbox[state[ 4]] ^ expandedKey[(round*16) +  4];
  state[ 8]  = rsbox[state[ 8]] ^ expandedKey[(round*16) +  8];
  state[12]  = rsbox[state[12]] ^ expandedKey[(round*16) + 12];
  // row 1
  buf1 =       rsbox[state[13]] ^ expandedKey[(round*16) +  1];
  state[13]  = rsbox[state[ 9]] ^ expandedKey[(round*16) + 13];
  state[ 9]  = rsbox[state[ 5]] ^ expandedKey[(round*16) +  9];
  state[ 5]  = rsbox[state[ 1]] ^ expandedKey[(round*16) +  5];
  state[ 1]  = buf1;
  // row 2
  buf1 =       rsbox[state[ 2]] ^ expandedKey[(round*16) + 10];
  buf2 =       rsbox[state[ 6]] ^ expandedKey[(round*16) + 14];
  state[ 2]  = rsbox[state[10]] ^ expandedKey[(round*16) +  2];
  state[ 6]  = rsbox[state[14]] ^ expandedKey[(round*16) +  6];
  state[10]  = buf1;
  state[14]  = buf2;
  // row 3
  buf1 =       rsbox[state[ 3]] ^ expandedKey[(round*16) + 15];
  state[ 3]  = rsbox[state[ 7]] ^ expandedKey[(round*16) +  3];
  state[ 7]  = rsbox[state[11]] ^ expandedKey[(round*16) +  7];
  state[11]  = rsbox[state[15]] ^ expandedKey[(round*16) + 11];
  state[15]  = buf1;

  for (round = 8; round >= 0; round--){
    // barreto
    //col1
    buf1 = galois_mul2(galois_mul2(state[0]^state[2]));
    buf2 = galois_mul2(galois_mul2(state[1]^state[3]));
    state[0] ^= buf1;     state[1] ^= buf2;    state[2] ^= buf1;    state[3] ^= buf2;
    //col2
    buf1 = galois_mul2(galois_mul2(state[4]^state[6]));
    buf2 = galois_mul2(galois_mul2(state[5]^state[7]));
    state[4] ^= buf1;    state[5] ^= buf2;    state[6] ^= buf1;    state[7] ^= buf2;
    //col3
    buf1 = galois_mul2(galois_mul2(state[8]^state[10]));
    buf2 = galois_mul2(galois_mul2(state[9]^state[11]));
    state[8] ^= buf1;    state[9] ^= buf2;    state[10] ^= buf1;    state[11] ^= buf2;
    //col4
    buf1 = galois_mul2(galois_mul2(state[12]^state[14]));
    buf2 = galois_mul2(galois_mul2(state[13]^state[15]));
    state[12] ^= buf1;    state[13] ^= buf2;    state[14] ^= buf1;    state[15] ^= buf2;
    // mixcolums //////////
    // col1
    buf1 = state[0] ^ state[1] ^ state[2] ^ state[3];
    buf2 = state[0];
    buf3 = state[0]^state[1]; buf3=galois_mul2(buf3); state[0] = state[0] ^ buf3 ^ buf1;
    buf3 = state[1]^state[2]; buf3=galois_mul2(buf3); state[1] = state[1] ^ buf3 ^ buf1;
    buf3 = state[2]^state[3]; buf3=galois_mul2(buf3); state[2] = state[2] ^ buf3 ^ buf1;
    buf3 = state[3]^buf2;     buf3=galois_mul2(buf3); state[3] = state[3] ^ buf3 ^ buf1;
    // col2
    buf1 = state[4] ^ state[5] ^ state[6] ^ state[7];
    buf2 = state[4];
    buf3 = state[4]^state[5]; buf3=galois_mul2(buf3); state[4] = state[4] ^ buf3 ^ buf1;
    buf3 = state[5]^state[6]; buf3=galois_mul2(buf3); state[5] = state[5] ^ buf3 ^ buf1;
    buf3 = state[6]^state[7]; buf3=galois_mul2(buf3); state[6] = state[6] ^ buf3 ^ buf1;
    buf3 = state[7]^buf2;     buf3=galois_mul2(buf3); state[7] = state[7] ^ buf3 ^ buf1;
    // col3
    buf1 = state[8] ^ state[9] ^ state[10] ^ state[11];
    buf2 = state[8];
    buf3 = state[8]^state[9];   buf3=galois_mul2(buf3); state[8] = state[8] ^ buf3 ^ buf1;
    buf3 = state[9]^state[10];  buf3=galois_mul2(buf3); state[9] = state[9] ^ buf3 ^ buf1;
    buf3 = state[10]^state[11]; buf3=galois_mul2(buf3); state[10] = state[10] ^ buf3 ^ buf1;
    buf3 = state[11]^buf2;      buf3=galois_mul2(buf3); state[11] = state[11] ^ buf3 ^ buf1;
    // col4
    buf1 = state[12] ^ state[13] ^ state[14] ^ state[15];
    buf2 = state[12];
    buf3 = state[12]^state[13]; buf3=galois_mul2(buf3); state[12] = state[12] ^ buf3 ^ buf1;
    buf3 = state[13]^state[14]; buf3=galois_mul2(buf3); state[13] = state[13] ^ buf3 ^ buf1;
    buf3 = state[14]^state[15]; buf3=galois_mul2(buf3); state[14] = state[14] ^ buf3 ^ buf1;
    buf3 = state[15]^buf2;      buf3=galois_mul2(buf3); state[15] = state[15] ^ buf3 ^ buf1;    

    // addroundkey, rsbox and shiftrows
    // row 0
    state[ 0]  = rsbox[state[ 0]] ^ expandedKey[(round*16)     ];
    state[ 4]  = rsbox[state[ 4]] ^ expandedKey[(round*16) +  4];
    state[ 8]  = rsbox[state[ 8]] ^ expandedKey[(round*16) +  8];
    state[12]  = rsbox[state[12]] ^ expandedKey[(round*16) + 12];
    // row 1
    buf1 =       rsbox[state[13]] ^ expandedKey[(round*16) +  1];
    state[13]  = rsbox[state[ 9]] ^ expandedKey[(round*16) + 13];
    state[ 9]  = rsbox[state[ 5]] ^ expandedKey[(round*16) +  9];
    state[ 5]  = rsbox[state[ 1]] ^ expandedKey[(round*16) +  5];
    state[ 1]  = buf1;
    // row 2
    buf1 =       rsbox[state[ 2]] ^ expandedKey[(round*16) + 10];
    buf2 =       rsbox[state[ 6]] ^ expandedKey[(round*16) + 14];
    state[ 2]  = rsbox[state[10]] ^ expandedKey[(round*16) +  2];
    state[ 6]  = rsbox[state[14]] ^ expandedKey[(round*16) +  6];
    state[10]  = buf1;
    state[14]  = buf2;
    // row 3
    buf1 =       rsbox[state[ 3]] ^ expandedKey[(round*16) + 15];
    state[ 3]  = rsbox[state[ 7]] ^ expandedKey[(round*16) +  3];
    state[ 7]  = rsbox[state[11]] ^ expandedKey[(round*16) +  7];
    state[11]  = rsbox[state[15]] ^ expandedKey[(round*16) + 11];
    state[15]  = buf1;
  }
} 

// encrypt
void aes_encrypt(unsigned char *state, unsigned char *key) {
	unsigned char expandedKey[176];

	expandKey(expandedKey, key);       // expand the key into 176 bytes
	aes_encr(state, expandedKey);
}

// decrypt
void aes_decrypt(unsigned char *state, unsigned char *key) {
	unsigned char expandedKey[176];

  expandKey(expandedKey, key);       // expand the key into 176 bytes
  aes_decr(state, expandedKey);
}

// Шифруем пакет, размер которого должен быть кратен 16.
// Размер данных может быть не кратен 16, но размер буфера должен
// давать возможность выровнять выходной размер.
uint16_t aes_encrypt_packet(uint8_t *data, uint16_t size) {
	#ifndef AES_DISABLE
	uint8_t packet16_numb = (size >> 4)	+ ((size % 16) == 0 ? 0 : 1);
	for(uint8_t i=0; i<packet16_numb; i++)
		aes_encrypt((unsigned char *)&data[i*16], (unsigned char *)AES_key);
	return packet16_numb*16;
	#else
	return size;
	#endif
}

// Дешифруем пакет (размер данных должен быть кратен 16)
uint16_t aes_decrypt_packet(uint8_t *data, uint16_t size) {
	#ifndef AES_DISABLE
	uint16_t block16 = size >> 4;
	if((size & 0x0F) != 0)
		block16 += 1;
	for(uint8_t i = 0; i < block16; i++)
		aes_decrypt((unsigned char *)&data[i*16], (unsigned char *)AES_key);
	return (uint16_t)(block16 << 4);
  #endif
}

// Дешифруем пакет (размер данных должен быть кратен 16)
uint8_t aes_decrypt_boot_packet(uint8_t *data, uint16_t size) {
	#ifndef AES_DISABLE
	uint8_t block16 = size >> 4;
	if((size & 0x0F) != 0)
		block16 += 1;
	for(uint8_t i = 0; i < block16; i++)
		aes_decrypt((unsigned char *)&data[i*16], (unsigned char *)AES_boot_key);
	return (uint8_t)(block16 << 4);
  #endif
}

uint8_t CRC8(uint8_t *data, uint16_t len) {
	uint8_t i, dat, crc = 0, fb;
	uint16_t j = 0;
	while(j < len ){
		dat=data[j++];
		for(i = 0; i < 8; i++) {
			fb = (crc ^ dat) & 1;
			crc >>= 1;
			dat >>= 1;
			if(fb)
				crc ^= 0x8c;
		}
	}
	return crc;
}

void set_cryptokey(uint8_t *key)
{
	memcpy(AES_key, key, sizeof(AES_key));
}
