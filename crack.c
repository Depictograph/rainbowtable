#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "aes.h"
#include <math.h>

static void printhex(unsigned char* input, int bytes);
static void aeshash(unsigned char *key, unsigned char *ciphertext);
static void reduction(unsigned char *ciphertext, unsigned char *key, int n, int seed);
static unsigned long binarytonum(unsigned char *binary); 
static unsigned long power(unsigned long a, int power);
static void assign(unsigned char *pass, unsigned long val);
static void pad(unsigned char *topad, unsigned char *padded);
static void crack(int n, int s, unsigned long rows, unsigned char (*table)[2][16], unsigned char *hash);
static void deepcopy(unsigned char *copy, unsigned char *paste);
static int equals(unsigned char *a, unsigned char* b);
static int aesevals = 0;

int main(int argc, char* argv[]) {
	if (argc != 4) {
		printf("Need 3 arguments n and s.");
		exit(0);
	} else {
		int n = atoi(argv[1]);
		int s = atoi(argv[2]);
		unsigned char hash[16];
		char *input = argv[3]+2;

		int x;
		for(x = 0; x < 16; x++) {
			char byte[2] = {argv[3][2*(x+1)], argv[3][2*(x+1)+1]};
			hash[x] = strtol(byte, NULL, 16);
		}

		FILE *read = fopen("rainbow", "rb");
		if (read == NULL) {fputs ("File error",stderr); exit (1);}

		long lsize;
	  	fseek (read , 0 , SEEK_END);
  		lsize = ftell (read);
  		rewind (read);
  		//printf("%lu \n", lsize);
  		unsigned long rows = lsize / 20;
  		int y; 
  		unsigned char (*table)[2][16];
  		table = (unsigned char(*)[2][16]) malloc(sizeof(unsigned char) * rows * 32);

		int j;
		for(j = 0; j < rows; j++) {
			unsigned char temp[4];
			fread(temp, sizeof(unsigned char), 4, read);
			pad(temp, table[j][0]);
			//printhex(table[j][0], 16);
			fread(table[j][1], sizeof(unsigned char), 16, read);
			//printhex(table[j][1], 16);
		}
		fclose(read);
		crack(n, s, rows, table, hash);
		free(table);

}
}

void crack(int n, int s, unsigned long rows, unsigned char (*table)[2][16], unsigned char *hash) {
	unsigned long bits = 1 << n;
	int i;
	int numreductions;
	int alpha = 8; 
	long chainlength = alpha*(1<<(n-s));
	unsigned char targethash[16];
	deepcopy(hash, targethash);
	for (numreductions = 1; numreductions <= chainlength; numreductions++) {
		//printhex(hash, 16);
		for (i=0; i < rows; i++) {
			unsigned char currenthash[16];
			deepcopy(table[i][1], currenthash);
			//printhex(currenthash, 16);
			if (equals(currenthash, hash)) {
				//printf("\n\n matched \n\n");
				unsigned char suspectedkey[16];
				deepcopy(table[i][0], suspectedkey);
				int k;
				//printhex(suspectedkey, 16);
				//printf("\n\n");

				for (k = 0; k <=chainlength; k++) {
					unsigned char suspectedhash[16];
					aeshash(suspectedkey, suspectedhash);
					//printhex(suspectedkey, 16);
					//printhex(suspectedhash, 16);
					if (equals(suspectedhash, targethash)) {
						printf("Password is: ");
						printhex(suspectedkey, 16);
						printf(". AES was evaluated: %d times\n", aesevals);
						return;
					}
					reduction(suspectedhash, suspectedkey, n, k);
				}
			}

		} 
		int j;
		deepcopy(targethash, hash);
		for (j = numreductions; j > 0; j--) {
			int seed = chainlength - j;
			//printf("%d \n", seed);
			unsigned char plaintext[16];
			reduction(hash, plaintext, n, seed);
			aeshash(plaintext, hash);
		}

	}
	printf("failed \n");
	return;
}


int equals(unsigned char *a, unsigned char* b) {
	int i;
	for(i=0; i<16; i++) {
		if (a[i] != b[i])
			return 0;
	}
	return 1;
}

void deepcopy(unsigned char *copy, unsigned char *paste) {
	int i;
	for(i=0; i<16; i++)
		paste[i] = copy[i];
}

void printhex(unsigned char *input, int bytes) {
	int i;
	for (i=0; i < bytes; i++) {
    	printf("%02x", input[i]);
	}	
	//printf(" \n");  
}

unsigned long binarytonum(unsigned char *binary) {
	unsigned long output = 0;
	int i; 
	for (i = 12; i <= 15; i++) {
		output += binary[i];
		output <<= 8;
	}
	output >>= 8;
	return output; 
}

void pad(unsigned char *topad, unsigned char *pass) {
	int i;
    for (i = 15; i >= 12; i--)
    {
            pass[i] = topad[i-12];
    }
	for (i =11; i >= 0; i--)
		pass[i] = 0x00;
}
void assign (unsigned char *pass, unsigned long val) {
    int i;
    for (i = 15; i >= 12; i--)
    {
            pass[i] = (unsigned char) val & 0xFF;
            val >>= 8;
    }
	for (i =11; i >= 0; i--)
		pass[i] = 0;
}

void aeshash(unsigned char *key, unsigned char *ciphertext) {
	aes_context     ctx;
	unsigned char plaintext[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}; 
	aes_setkey_enc (&ctx, key, 128);
	aes_crypt_ecb (&ctx, AES_ENCRYPT, plaintext, ciphertext);
	aesevals++;
}

unsigned long power(unsigned long a, int power) {
	while (power > 0) {
		a *= a;
		power--;
	}
	return a;
}

void reduction(unsigned char *ciphertext, unsigned char *key, int n, int seed) {
	unsigned long decimal = binarytonum(ciphertext);
	decimal = (decimal + seed + (power(decimal, seed) % 547)) % (1<<n);
	decimal = decimal & ((1<<n)-1);
	assign(key, decimal);
}

