#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "aes.h"
#include <math.h>

static void gentable(int n, int s, FILE *file);
static void printhex(unsigned char* input);
static void writefile(FILE *file, unsigned char *array, int n);
static void assign(unsigned char *pass, unsigned long val);
static void aeshash(unsigned char *key, unsigned char *ciphertext);
static void reduction(unsigned char *ciphertext, unsigned char *key, int n, int seed);
static unsigned long binarytonum(unsigned char *binary); 
static unsigned long power(unsigned long a, int power);

int main(int argc, char* argv[]) {
	if (argc != 3) {
		printf("Need 2 arguments n and s.");
		exit(0);
	} else {
		int n = atoi(argv[1]);
		int s = atoi(argv[2]);

		//printf("%d, %d \n", n, s);

		FILE *rainbow = fopen("rainbow", "wb");
		if (rainbow == NULL) {fputs ("File error",stderr); exit (1);}

		gentable(n, s, rainbow);
		fclose(rainbow);

		// FILE *read = fopen("rainbow", "rb");
		// if (read == NULL) {fputs ("File error",stderr); exit (1);}

		// long lsize;
	 //  	fseek (read , 0 , SEEK_END);
  // 		lsize = ftell (read);
  // 		rewind (read);

		// unsigned char *x = (unsigned char*) malloc(lsize);

		// fread(x, sizeof(unsigned char), lsize, read);
		// fclose(rainbow);
		// int k, j = 0;
		// unsigned char array[lsize/16][2][16];

		// for (k = 0; k < lsize/32; k++) {
		// 	int w;
		// 	for (w = 0; w<16; w++)
		// 		array[k][0][w] = x[j*16+w];
		// 	//printhex(array[k][0]);
		// 	j++;
		// 	for (w = 0; w<16; w++)
		// 		array[k][1][w] = x[j*16+w];
		// 	//printhex(array[k][1]);
		// 	j++;
		// }
		// free(x);


		// unsigned char stuff[16];
		// printf("%lu \n", binarytonum(x));
		// reduction(x, stuff, 28);
		// printhex(stuff);

		// unsigned long val = 23333441;
		// unsigned char *pass;
		// assign(pass, val);
		// printhex(pass);
		// printf("%lu \n", binarytonum(pass));

	}


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

void printhex(unsigned char* input) {
	int i;
	for (i=0; i < 16; i++) {
    	printf("%02x", input[i]);
	}	
	printf(" \n");  
}

void writefile(FILE *file, unsigned char *array, int n) {
	fwrite(array, sizeof(unsigned char), n, file);
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

void gentable(int n, int s, FILE *file) {
	unsigned long bits = 1 << n;
	unsigned long rows = 1 << s;
	unsigned char  *keys = (unsigned char*)calloc(bits, sizeof(unsigned char));
	if (keys == NULL)
		printf("Keys array is null");
	unsigned long i;
	int collisions = 0;
	for (i = 0; i < bits; i++) {
		if (keys[i] == 0x01) {
			continue; 
		}
		keys[i] = 0x01;
		unsigned char currentkey[16];
		assign(currentkey, i);
		unsigned char fourbytes[4] =  {currentkey[12], currentkey[13], currentkey[14], currentkey[15]};
		writefile(file, fourbytes, 4);
		//printhex(currentkey);
		unsigned char lasthash[16];
		int k;
		int alpha = 8;
		for (k = 0; k < alpha*(1<<(n-s)); k++) {
			unsigned char ciphertext[16]; 
			aeshash(currentkey, ciphertext);
			//printhex(ciphertext);
			unsigned char nextkey[16];
			int seed = k;
			reduction(ciphertext, nextkey, n, seed);
			if (keys[binarytonum(nextkey)] == 0x01)
				collisions++;
			keys[binarytonum(nextkey)] = 0x01; 
			int p;	
			for (p = 0; p < 16; p++)
				currentkey[p] = nextkey[p];
			if (k == alpha*(1<<(n-s))-1) {
				aeshash(nextkey, lasthash);
				//printhex(lasthash);
				//printf("\n\n");
			}
		}
		//printhex(currentkey);
		//printhex(lasthash);
		writefile(file, lasthash, 16);
	}
	//printf("collisions: %d \n", collisions);
	free(keys);
}
