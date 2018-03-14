// Reads a DES-encrypted file 8 bytes at a time, decryptes with the key specified in
//   a file contatining the key, and writes the decrypted data to a file.
//

#include "stdafx.h"
#include <iostream>

// Global variables
int myeof;
unsigned long long mykey;
unsigned long long myskey[17];
unsigned char key_chars[8];   // DES key read from the key file.
unsigned char PT[8];   // Plain text (decrypted)
unsigned char CT[8];   // Cyphertext (encrypted)
FILE* keyfp;
FILE* plainfp;
FILE* encryptfp;

// Function Prototypes
static unsigned long long rotate_left_56(unsigned long long val, int n);
static unsigned long long permute(unsigned char *ptab, unsigned long long val, int src_len, int dst_len);
static unsigned long long f(unsigned int val, unsigned long long key);
void create_keys(unsigned long long key, unsigned long long *skey);
void decrypt_block(volatile unsigned char *msg, volatile unsigned char *imsg, unsigned long long *skey);

int main(int argc, char* argv[])
{
	 if( argc != 4 ) {
		 printf("Must provide three parameters: source key file, source data file, destination output file. \n");
		 exit(1);
	 }

	// Open file containing the DES decryption key.
	 if ((keyfp = fopen(argv[1],"rb")) == NULL){
       printf("Error opening key file!");
       exit(1);
    }
	fseek( keyfp, 0, SEEK_END);
	myeof = ftell(keyfp);
    fseek( keyfp, 0, SEEK_SET );   // Reset pointer to beginning of key file.
	if( myeof != 8 ) {
		printf("Error: Key file must contain exactly 8 hex bytes.");
        exit(1);
	}

	// Open ecrypted data file.
	if ((encryptfp = fopen(argv[2],"rb")) == NULL){
       printf("Error opening encrypted data file!");
       exit(1);
    }
	// Open a file to write the decrypted data
	if ((plainfp = fopen(argv[3],"wb")) == NULL){
       printf("Error opening video file!");
       exit(1);
    }
	// Find out how many bytes in the encrypted file, so can predict when to stop reading from it.
	fseek( encryptfp, 0, SEEK_END);
	myeof = ftell(encryptfp);
	printf("Number of bytes in encrypted file: %ld \n", myeof ); // Print value of pointer, referenced to start of file.
    fseek( encryptfp, 0, SEEK_SET );   // Reset pointer to beginning of file.

	// Create the "unsigned long long" key from the bytes read from the file.
	fread( key_chars, 1, 8, keyfp );
	mykey = 0;
	for( int j=0; j <= 7; j++ ) {
	   mykey |= key_chars[j];
	   if( j != 7 ) mykey = mykey << 8;
	}
	printf("Key = %llx \n", mykey );

	// Create the set of 16 keys used by the DES algorithm to decrypt.
	create_keys( mykey, &myskey[0] );

	// While >=8  bytes left in source (encrypted) file, read 8 bytes into CT[] array.
	while( (ftell(encryptfp)+8) <= myeof ) {
	   // Note: CT[0] is the MSbyte of encrypted word. CT[7] = LSByte.
       fread( &CT, 1, 8, encryptfp );  // 8 bytes into cyphertext array.
	   printf("Cyphertext: %2x %2x %2x %2x %2x %2x %2x %2x \n", CT[0],CT[1],CT[2],CT[3],CT[4],CT[5],CT[6],CT[7] );
	   // Decrypt 8 bytes
	   decrypt_block( &PT[0], &CT[0], &myskey[0] );
	   // Write the 8 decrypted bytes (in PT[] array) out to the output file.
	   // Note: PT[0] is the MSbyte. PT[7] is the LSbyte.
	   fwrite( &PT, 1, 8, plainfp );
	   printf("Cleartext: %2x %2x %2x %2x %2x %2x %2x %2x \n", PT[0],PT[1],PT[2],PT[3],PT[4],PT[5],PT[6],PT[7] );
	}
	return 0;
}

// All code below pulled from https://github.com/dmandalidis/des.
// Note the bug fix needed in that create_keys() function. Fixed code is provided below.
/* Copyright (C) Dimitris Mandalidis */

static unsigned long long rotate_left_56(unsigned long long val, int n)
{
	unsigned long long mask;
	unsigned long long rval;

	mask = (n == 1)? val & 0x80000008000000LL: val & 0xc000000c000000LL;
	mask >>= 28-n;
	rval = val << n;
	rval &= (n == 1)? 0xffffffeffffffeLL: 0xffffffcffffffcLL;
	rval |= mask;
	return rval;
}	

static unsigned long long permute(unsigned char *ptab, unsigned long long val, int src_len, int dst_len)
{
	unsigned int i; 
	unsigned long long rval = 0;

	for (i = 0; i < dst_len; i++) 
		rval |= (val & (1LL << (src_len-ptab[i])))? 0x1LL << (dst_len-i-1): 0;
	return rval;
}	

static unsigned long long f(unsigned int val, unsigned long long key)
{
	unsigned char i;

	unsigned char ef[] = { 32,     1,    2,     3,    4,    5,
                  4,     5,    6,     7,     8,    9,
                  8,     9,   10,    11,    12,   13,
                 12,    13,   14,    15,    16,   17,
                 16,    17,   18,    19,    20,   21,
                 20,    21,   22,    23,    24,   25,
                 24,    25,   26,    27,    28,   29,
                 28,    29,   30,    31,    32,    1 };

    unsigned char s1[] = { 14,  4,  13,  1,   2, 15,  11,  8,   3, 10,   6, 12,   5,  9,   0,  7,
                  0, 15,   7,  4,  14,  2,  13,  1,  10,  6,  12, 11,   9,  5,   3,  8,
                  4,  1,  14,  8,  13,  6,   2, 11,  15, 12,   9,  7,   3, 10,   5,  0,
                 15, 12,   8,  2,   4,  9,   1,  7,   5, 11,   3, 14,  10,  0,   6, 13 };

    unsigned char s2[] = { 15,  1,   8, 14,   6, 11,   3,  4,   9,  7,   2, 13,  12,  0,   5, 10,
                  3, 13,   4,  7,  15,  2,   8, 14,  12,  0,   1, 10,   6,  9,  11,  5,
                  0, 14,   7, 11,  10,  4,  13,  1,   5,  8,  12,  6,   9,  3,   2, 15,
                 13,  8,  10,  1,   3, 15,   4,  2,  11,  6,   7, 12,   0,  5,  14,  9 };

    unsigned char s3[] = { 10,  0,   9, 14,   6,  3,  15,  5,   1, 13,  12,  7,  11,  4,   2,  8,
                 13,  7,   0,  9,   3,  4,   6, 10,   2,  8,   5, 14,  12, 11,  15,  1,
                 13,  6,   4,  9,   8, 15,   3,  0,  11,  1,   2, 12,   5, 10,  14,  7,
                  1, 10,  13,  0,   6,  9,   8,  7,   4, 15,  14,  3,  11,  5,   2, 12 };

    unsigned char s4[] = { 7, 13,  14,  3,   0,  6,   9, 10,   1,  2,   8,  5,  11, 12,   4, 15,
                13,  8,  11,  5,   6, 15,   0,  3,   4,  7,   2, 12,   1, 10,  14,  9,
                10,  6,   9,  0,  12, 11,   7, 13,  15,  1,   3, 14,   5,  2,   8,  4,
                 3, 15,   0,  6,  10,  1,  13,  8,   9,  4,   5, 11,  12,  7,   2, 14 };

    unsigned char s5[] = { 2, 12,  4,  1,   7, 10,  11,  6,   8,  5,   3, 15,  13,  0,  14,  9,
                14, 11,  2, 12,   4,  7,  13,  1,   5,  0,  15, 10,   3,  9,   8,  6,
                 4,  2,  1, 11,  10, 13,   7,  8,  15,  9,  12,  5,   6,  3,   0, 14,
                11,  8, 12,  7,   1, 14,   2, 13,   6, 15,   0,  9,  10,  4,   5,  3 };

    unsigned char s6[] = { 12,  1,  10, 15,   9,  2,   6,  8,  0, 13,   3,  4,  14,  7,   5, 11,
                 10, 15,   4,  2,   7, 12,   9,  5,  6,  1,  13, 14,   0, 11,   3,  8,
                  9, 14,  15,  5,   2,  8,  12,  3,  7,  0,   4, 10,   1, 13,  11,  6,
                  4,  3,   2, 12,   9,  5,  15, 10,  11, 14,   1,  7,   6,  0,   8, 13 };

    unsigned char s7[] = { 4, 11,   2, 14,  15,  0,   8, 13,   3, 12,   9,  7,   5, 10,   6,  1,
                13,  0,  11,  7,   4,  9,   1, 10,  14,  3,   5, 12,   2, 15,   8,  6,
                 1,  4,  11, 13,  12,  3,   7, 14,  10, 15,   6,  8,   0,  5,   9,  2,
                 6, 11,  13,  8,   1,  4,  10,  7,   9,  5,   0, 15,  14,  2,   3, 12 };

    unsigned char s8[] = { 13,  2,   8,  4,   6, 15,  11,  1,  10,  9,   3, 14,   5,  0,  12,  7,
                  1, 15,  13,  8,  10,  3,   7,  4,  12,  5,   6, 11,   0, 14,   9,  2,
                  7, 11,   4,  1,   9, 12,  14,  2,   0,  6,  10, 13,  15,  3,   5,  8,
                  2,  1,  14,  7,   4, 10,   8, 13,  15, 12,   9,  0,   3,  5,   6, 11 };
	
    unsigned char p[] = { 16,   7,  20,  21,
                29,  12,  28,  17,
                 1,  15,  23,  26,
                 5,  18,  31,  10,
                 2,   8,  24,  14,
                32,  27,   3,   9,
                19,  13,  30,   6,
                22,  11,   4,  25 };

	unsigned long long xval = 0;
	unsigned long long pos; // int
	unsigned long long row, col; // char
	unsigned int offset; //char
	unsigned long long fval = 0; // int

	xval = permute(ef, val, 32, 48);
	xval ^= key;
	for (i = 0; i < 8; i++) {
		offset = i*6;
		pos = (xval & (0x3fLL << offset)) >> offset;
		row = ((pos & 0x21) >> 4) | (pos & 1); 
		col = (pos & 0x1e) >> 1;
		pos = (row << 4) + col;
		switch (i) {
			case 0:
				fval |= s8[pos];
				break;
			case 1:
				fval |= (unsigned long long) (s7[pos] << 4);
				break;
			case 2:
				fval |= (unsigned long long) (s6[pos] << 8);
				break;
			case 3:
				fval |= (unsigned long long) (s5[pos] << 12);
				break;
			case 4:
				fval |= (unsigned long long) (s4[pos] << 16);
				break;
			case 5:
				fval |= (unsigned long long) (s3[pos] << 20);
				break;
			case 6:
				fval |= (unsigned long long) (s2[pos] << 24);
				break;
			case 7:
				fval |= (unsigned long long) (s1[pos] << 28);
				break;
		}
	}
	fval = permute(p, fval, 32, 32);
	return fval;
}

void create_keys(unsigned long long key, unsigned long long *skey)
{
	unsigned char pc1[] = { 57,   49,    41,   33,    25,    17,    9,
                   1,   58,    50,   42,    34,    26,   18,
                  10,    2,    59,   51,    43,    35,   27,
                  19,   11,     3,   60,    52,    44,   36,
                  63,   55,    47,   39,    31,    23,   15,
                   7,   62,    54,   46,    38,    30,   22,
                  14,    6,    61,   53,    45,    37,   29,
                  21,   13,     5,   28,    20,    12,    4 };

    unsigned char pc2[] = { 14,    17,   11,    24,     1,    5,
                    3,    28,   15,     6,    21,   10,
                   23,    19,   12,     4,    26,    8,
                   16,     7,   27,    20,    13,    2,
                   41,    52,   31,    37,    47,   55,
                   30,    40,   51,    45,    33,   48,
                   44,    49,   39,    56,    34,   53,
                   46,    42,   50,    36,    29,   32 };

	unsigned char erot[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}; // 16 values
	
	unsigned long long pkey[17];			 
	unsigned int i;

	pkey[0] = permute(pc1, key, 64, 56);
	for (i = 0; i < 16; i++)  // {DRH} Fixed bug in original code on this line. Was:17 Is:16
        pkey[i+1] = rotate_left_56(pkey[i], erot[i]);
    for (i = 0; i < 16; i++)
        skey[i] = permute(pc2, pkey[i+1], 56, 48);
	return;
}
	
void decrypt_block(volatile unsigned char *msg, volatile unsigned char *imsg, unsigned long long *skey)
{
	unsigned char ip[] = { 58,    50,   42,    34,    26,   18,    10,    2,
                60,    52,   44,    36,    28,   20,    12,    4,
                62,    54,   46,    38,    30,   22,    14,    6,
                64,    56,   48,    40,    32,   24,    16,    8,
                57,    49,   41,    33,    25,   17,     9,    1,
                59,    51,   43,    35,    27,   19,    11,    3,
                61,    53,   45,   37,   29,   21,    13,    5,
                63,    55,   47,    39,    31,   23,    15,    7 };

    unsigned char ipf[] = { 40,     8,   48,    16,    56,   24,    64,   32,
                  39,     7,   47,    15,    55,   23,    63,   31,
                  38,     6,   46,    14,    54,   22,    62,   30,
                  37,     5,   45,    13,    53,   21,    61,   29,
                  36,     4,   44,    12,    52,   20,    60,   28,
                  35,     3,   43,    11,    51,   19,    59,   27,
                  34,     2,   42,    10,    50,   18,    58,   26,
                  33,     1,   41,     9,    49,   17,    57,   25 };
	unsigned int i;
	unsigned long long pmsg, emsg = 0LL, rmsg;
	unsigned long long lower, upper, n_lower, n_upper;
	
	for (i = 0; i < 8; i++)
		emsg |= (unsigned long long) imsg[i] << ((7-i) << 3);
	pmsg = permute(ip, emsg, 64, 64);
	lower = pmsg & 0xffffffff;
    upper = pmsg >> 32;
	for (i = 0; i < 16; i++) {
        n_upper = lower;
        n_lower = upper ^ f((unsigned int) lower, skey[15-i]); // Uses skey[15] to [0]
        lower = n_lower;
        upper = n_upper;
    }
	rmsg = permute(ipf, (n_lower << 32LL) | n_upper, 64, 64);
	for (i = 0; i < 8; i++)
		msg[i] = (unsigned char) ((rmsg & (0xff00000000000000uLL >> (i << 3))) >> ((7-i) << 3));
	return;	
}