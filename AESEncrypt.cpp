/* 	Written by Thomas Upfold, Jared Cooper, Ki Soon Park and Min Ho Juag for
	Assignment 3 of COMP3260 Data Security. This file includes the AES
	round functions (subBytes etc), the inverse AES functions 
	(invSubBytes etc) and the avalanche functions that compute the mean
	number of differing bits with each different AES encryption.
	
	This program uses standard input and expects as input:
		"e" or "d" for encryption/decryption followed by
		<128 length string> followed by
		<128 length string>
	These can either be inputted in the console (have fun) or
	specified using input redirection when running the program.
	
	Important Notes:
		-	The Block class uses an operator overload on the () operator.
			This is used to access the 4 by 4 array stored in the object
			and replaces the need for something like 
			exampleBlock.elementAt(2,3) with exampleBlock(2,3).
		-	
*/

#include <iostream>
#include <cstdlib>
#include <iomanip>
#include <cmath>
#include <ctime>
#include "AESTables.h"
#include "Block.h"

using namespace std;
using namespace AES;

void expandKey(Block (&blockArr)[11], Block keyBlock);

Block shiftRows(Block in);
Block invShiftRows(Block in);

Block subBytes(Block in);
Block invSubBytes(Block in);

unsigned char GFMult(unsigned char a, unsigned char b);
Block mixColumns(Block in);
Block invMixColumns(Block in);

Block encrypt(Block plain, Block key);
Block decrypt (Block cipher, Block key);

void getAverageUnderP(Block plain, Block key, int AEStype, int(&retArr)[11]);
void getAverageUnderK(Block plain, Block key, int AEStype, int(&retArr)[11]);

/* Note: needs to be tidied up with a header file 
	Also, Block has an operator overload on it for (). 
	If you see a Block varaible with (i,j) after it.
	It's just accessing the array member variable at[i,j]
	Saves writing out either blockObj.getElementAt(i,j) or
	blockObj.arr[i,j] each time
*/
/*Utility function to print the block in hex (easier visual checking) */
void printBlock(Block b) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			cout << hex << (int) b(j,i) << " ";
		}
		cout << endl;
	}
	cout << endl;
}
string byteToBinary(unsigned char c) {
	string out = "";
	for (int i = 0; i < 8; i++) {
		//1XXX XXXX & 1000 0000 = 10000000
		if (c & 0x80) { //10000000 in bin = 0x80 in hex
			out += "1";
		} else {
			out += "0";
		}
		c <<= 1;
	}
	return out;
}
void printBlockBin(Block b) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			cout << byteToBinary(b(j,i)) << " ";
		}
		cout << endl;
	}
	cout << endl;
}
int main() {
	Block plainBlock, keyBlock, cipherBlock;
	string line1, line2, operation;
	cin >> operation;
	cin >> line1;
	cin >> line2;
	if (operation == "e") {
		clock_t start = clock();
		plainBlock = Block(line1);
		keyBlock = Block(line2);
		cipherBlock = encrypt(plainBlock, keyBlock);
		cout << "Plaintext: " << endl;
		//printBlock(plainBlock);
		printBlockBin(plainBlock);
		cout << "Ciphertext: " << endl;
		//printBlock(cipherBlock);
		printBlockBin(cipherBlock);
		cout << "Keytext: " << endl;
		//printBlock(keyBlock);
		printBlockBin(keyBlock);
		/*
		int pAES0[11], pAES1[11], pAES2[11], pAES3[11], pAES4[11];
		int kAES0[11], kAES1[11], kAES2[11], kAES3[11], kAES4[11];
		
		getAverageUnderP(plainBlock, keyBlock, 0, pAES0);
		getAverageUnderP(plainBlock, keyBlock, 1, pAES1);
		getAverageUnderP(plainBlock, keyBlock, 2, pAES2);
		getAverageUnderP(plainBlock, keyBlock, 3, pAES3);
		getAverageUnderP(plainBlock, keyBlock, 4, pAES4);
		
		getAverageUnderK(plainBlock, keyBlock, 0, kAES0);
		getAverageUnderK(plainBlock, keyBlock, 1, kAES1);
		getAverageUnderK(plainBlock, keyBlock, 2, kAES2);
		getAverageUnderK(plainBlock, keyBlock, 3, kAES3);
		getAverageUnderK(plainBlock, keyBlock, 4, kAES4);
		
		clock_t ends = clock();
		cout << "Running time(ms): " << (double) (ends - start) / (CLOCKS_PER_SEC/1000) << endl << endl;
		cout << "P and Pi under K:" << endl;
		cout << "Round\t\tAES0\tAES1\tAES2\tAES3\tAES4" << endl;
		for (int i = 0; i < 11; i++) {
			cout << dec << setw(5) << i << "\t\t" << setw(4) << pAES0[i] << "\t" << setw(4) << pAES1[i] << "\t";
			cout << setw(4) << pAES2[i] << "\t" << setw(4) << pAES3[i] << "\t" << setw(4) << pAES4[i] << "\t" << endl;
		}
		cout << "P under K and Ki:" << endl;
		cout << "Round\t\tAES0\tAES1\tAES2\tAES3\tAES4" << endl;
		for (int i = 0; i < 11; i++) {
			cout << dec << setw(5) << i << "\t\t" << setw(4) << kAES0[i] << "\t" << setw(4) << kAES1[i] << "\t";
			cout << setw(4) << kAES2[i] << "\t" << setw(4) << kAES3[i] << "\t" << setw(4) << kAES4[i] << "\t" << endl;
		}
		*/
	} else if (operation == "d") {
		cipherBlock = Block(line1);
		keyBlock = Block(line2);
		plainBlock = decrypt(cipherBlock, keyBlock);
		cout << "Cipher text:" << endl;
		printBlockBin(cipherBlock);
		cout << "Plain text:" << endl;
		printBlockBin(plainBlock);
		cout << "Key:" << endl;
		printBlockBin(keyBlock);
	}
	return 0;
}
Block shiftRows(Block in) {
	/*Tested and working correctly */
	Block out = Block();
	/* Row 0, no change*/
	for (int i = 0; i < 4; i++) {
		out(i,0) = in (i,0);
	}
	/*Row 1, 1 left shift */
	out(0,1) = in(1,1);
	out(1,1) = in(2,1);
	out(2,1) = in(3,1);
	out(3,1) = in(0,1);
	/*Row 2, 2 left shift*/
	out(0,2) = in(2,2);
	out(1,2) = in(3,2);
	out(2,2) = in(0,2);
	out(3,2) = in(1,2);
	/*Row 3, 3 left shift*/
	out(0,3) = in(3,3);
	out(1,3) = in(0,3);
	out(2,3) = in(1,3);
	out(3,3) = in(2,3);
	return out;
}
Block subBytes(Block in) {
	/* Tested and Working */
	Block out = Block();
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			out(i,j) = sbox[in(i,j)];
		}
	}
	return out;
}
/*Multiplication in GF(2^8)*/
unsigned char GFMult(unsigned char a, unsigned char b) {
	unsigned char highBit, product = 0;
	for (int i = 0; i < 8; i++) {
		if (b&1) product^=a; 	//If low bit of b is set, XOR p by a
		highBit = (a & 0x80); 	//Checking high bit (0x80 = 1000 0000b)
		a <<= 1; 				//Rotate left once to allow us to XOR by 0x1b instead of 0x11b
		if(highBit > 0) a^=0x1b;//If high bit was set XOR a with 0x1b
		b>>=1;
	}
	return product;
}
Block mixColumns(Block in) {
	Block out = Block();
	for (int i = 0; i < 4; i++) {
		for(int j = 0; j < 4; j++) {
			out(j,i) = 	GFMult(mixTable[0+(i*4)],in(j,0)) ^ GFMult(mixTable[1+(i*4)],in(j,1)) ^ 
						GFMult(mixTable[2+(i*4)],in(j,2)) ^ GFMult(mixTable[3+(i*4)],in(j,3));
		}
	}
	return out;
}
void expandKey(Block (&blockArr)[11], Block keyBlock) {
	/*Tested and Working IFF subbytes is working*/
	blockArr[0] = keyBlock;
	for (int i = 1; i < 11; i++) {
		Block currentBlock = Block();
		/* Special operation needs to be done
			1) Get prev word
			2) Rotate
			3) Sub Bytes
			4) XOR with 4 back
			5) XOR with Rcon
		*/
		//Prev Word
		for (int j = 0; j < 4; j++) {
			currentBlock(0, j) = blockArr[i-1](3,j);
		}
		//Rotate
		unsigned char temp = currentBlock(0,0);
		for (int j = 0; j < 3; j++) {
			currentBlock(0,j) = currentBlock(0,j+1);
		}
		currentBlock(0,3) = temp;
		//Sub Bytes
		for (int j = 0; j < 4; j++) {
			currentBlock(0,j) = sbox[currentBlock(0,j)];
		}
		//XOR with 4 back
		for (int j = 0; j < 4; j++) {
			currentBlock(0,j) = currentBlock(0,j) ^ blockArr[i-1](0,j);
		}
		//XOR with Rcon;
		currentBlock(0,0) = currentBlock(0,0) ^ Rcon[i];
		/* Now for the remainind 3 columns of this block */
		for (int j = 1; j < 4; j++) {
			for (int k = 0; k < 4; k++) {
				currentBlock(j,k) = currentBlock(j-1,k) ^ blockArr[i-1](j,k);
			}
		}
		blockArr[i] = currentBlock;
	}
}
Block addRoundKey(Block in, Block roundBlock) {
	/* Working and Tested*/
	Block out = Block();
	for(int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			out(i,j) = (int)in(i,j) ^ roundBlock(i,j);
		}
	}
	return out;
}
Block encrypt(Block plain, Block key) {
	Block expKey[11], plainCopy = plain, keyCopy = key;
	expandKey(expKey, key);
	plainCopy = addRoundKey(plainCopy, expKey[0]);
	/* 10 rounds in 128, 9 normal and the final without mixColumns */
	for (int i = 1; i < 10; i++) {
		plainCopy = subBytes(plainCopy);
		plainCopy = shiftRows(plainCopy);
		plainCopy = mixColumns(plainCopy);
		plainCopy = addRoundKey(plainCopy, expKey[i]);
	}
	/* final round without mixCol */
	plainCopy = subBytes(plainCopy);
	plainCopy = shiftRows(plainCopy);
	plainCopy = addRoundKey(plainCopy, expKey[10]);
	return plainCopy;
}
/*encryptRound is used in the calculation of the average bit difference functions*/
Block encryptRound(Block plain, Block expandKey, int AEStype) {
	if (AEStype != 1) plain = subBytes(plain);
	if (AEStype != 2) plain = shiftRows(plain);
	if (AEStype != 3) plain = mixColumns(plain);
	if (AEStype != 4) plain = addRoundKey(plain, expandKey);
	return plain;
}
/*Flips the bit found at (x,y) at location bit and returns the changed block*/
Block changeBit(Block in, int x, int y, int bit) {
	// Takes the byte location co-ords and bit value between 0-7 and outputs a block with that bit flipped
	const static unsigned char bitVals[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}; //Sets up a relation between bit num and number to XOR by
	Block out = in;
	out(x,y) = out(x,y) ^ bitVals[bit];
	return out;
}
/*Calculates the bit difference between first and second. Used in average calculation functions*/
int getBitDiff(Block first, Block second) {
	unsigned char firstByte, secondByte;
	int bitCount = 0;
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			firstByte = first(i,j);
			secondByte = second(i,j);
			unsigned char diffByte = firstByte ^ secondByte;
			for (int i = 0; i < 8; i++) {
				if (diffByte & 0x01 == 0x01) bitCount++;
				diffByte >>= 1;
			}
		}
	}
	if (bitCount > 90) cout << bitCount << endl;
	return bitCount;
}
/*	Both getAverageUnderP and getAverageUnderK return an integer array which contains the average
	bit difference after each round in the comparison. For example, retArr[0] would contain the
	average after 0 rounds
*/
void getAverageUnderP(Block plain, Block key, int AEStype, int(&retArr)[11]) {
	/* Sums together the differing bits after each round and then divides by 128 at the end */
	int total = 0;
	int sum[11] = {1,0,0,0,0,0,0,0,0,0};
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 8; k++) {
				Block plainCopy = plain;
				Block oneOff = changeBit(plainCopy,i,j,k);
				Block expKey[11];
				expandKey(expKey, key);
				if (AEStype != 4) plainCopy = addRoundKey(plainCopy, expKey[0]);
				if (AEStype != 4) oneOff = addRoundKey(oneOff, expKey[0]);
				sum[0] += getBitDiff(plainCopy, oneOff);
				for (int l = 1; l < 10; l++) {
					plainCopy = encryptRound(plainCopy, key, AEStype);
					oneOff = encryptRound(oneOff, key, AEStype);
					sum[l] += getBitDiff(plainCopy, oneOff);
				}
				if (AEStype != 1) { 
					plainCopy = subBytes(plainCopy);
					oneOff = subBytes(oneOff);
				}
				if (AEStype != 2) { 
					plainCopy = shiftRows(plainCopy);
					oneOff = shiftRows(oneOff);
				}
				if (AEStype != 4) { 
					plainCopy = addRoundKey(plainCopy, expKey[10]);
					oneOff = addRoundKey(oneOff, expKey[10]);
				}
				sum[10] += getBitDiff(plainCopy, oneOff);
			}
		}
	};
	for (int i = 0; i < 11; i++) {
		retArr[i] = floor((sum[i]/128.0)+0.5);
	}
}
void getAverageUnderK(Block plain, Block key, int AEStype, int(&retArr)[11]) {
	/* Sums together the differing bits after each round and then divides by 128 at the end */
	int total = 0;
	int sum[11] = {1,0,0,0,0,0,0,0,0,0};
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 8; k++) {
				Block keyOneOff = changeBit(key,i,j,k), stateOneOff = plain, plainCopy = plain;
				Block expKeyOriginal[11], expKeyOneOff[11];
				expandKey(expKeyOriginal, key);
				expandKey(expKeyOneOff, keyOneOff);
				//sum[0] += getBitDiff(plainCopy,stateOneOff);
				if (AEStype != 4) plainCopy = addRoundKey(plainCopy, expKeyOriginal[0]);
				if (AEStype != 4) stateOneOff = addRoundKey(stateOneOff, expKeyOneOff[0]);
				sum[0] += getBitDiff(plainCopy,stateOneOff);
				for (int l = 1; l < 10; l++) {
					plainCopy = encryptRound(plainCopy, key, AEStype);
					stateOneOff = encryptRound(stateOneOff, expKeyOneOff[l], AEStype);
					sum[l] += getBitDiff(plainCopy, stateOneOff);
				}
				if (AEStype != 1) { 
					plainCopy = subBytes(plainCopy);
					stateOneOff = subBytes(stateOneOff);
				}
				if (AEStype != 2) { 
					plainCopy = shiftRows(plainCopy);
					stateOneOff = shiftRows(stateOneOff);
				}
				if (AEStype != 4) { 
					plainCopy = addRoundKey(plainCopy, expKeyOriginal[10]);
					stateOneOff = addRoundKey(stateOneOff, expKeyOneOff[10]);
				}
				sum[10] += getBitDiff(plainCopy, stateOneOff);
			}
		}
	}
	for (int i = 0; i < 11; i++) {
		retArr[i] = floor((sum[i]/128.0)+0.5);
	}
}
/*	The following functions are the inverse functions used in decrypting and the decrypt function itself.
	the logic used in them should be straightforward and similar to the corresponding encryption functions.
 */
Block invSubBytes(Block in) {
	Block out = Block();
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			out(i,j) = invsbox[in(i,j)];
		}
	}
	return out;
}
Block invShiftRows(Block in) {
	/*Tested and working correctly */
	Block out = Block();
	/* Row 0, no change*/
	for (int i = 0; i < 4; i++) {
		out(i,0) = in (i,0);
	}
	/*Row 1, 1 right shift */
	out(1,1) = in(0,1);
	out(2,1) = in(1,1);
	out(3,1) = in(2,1);
	out(0,1) = in(3,1);
	/*Row 2, 2 right shift*/
	out(2,2) = in(0,2);
	out(3,2) = in(1,2);
	out(0,2) = in(2,2);
	out(1,2) = in(3,2);
	/*Row 3, 3 right shift*/
	out(3,3) = in(0,3);
	out(0,3) = in(1,3);
	out(1,3) = in(2,3);
	out(2,3) = in(3,3);
	return out;
}
Block invMixColumns (Block in) {
	Block out = Block();
	for (int i = 0; i < 4; i++) {
		for(int j = 0; j < 4; j++) {
			out(j,i) = 	GFMult(invMixTable[0+(i*4)],in(j,0)) ^ GFMult(invMixTable[1+(i*4)],in(j,1)) ^ 
						GFMult(invMixTable[2+(i*4)],in(j,2)) ^ GFMult(invMixTable[3+(i*4)],in(j,3));
		}
	}
	return out;
}
Block decrypt (Block cipher, Block key) {
	Block expKey[11];
	int expCount = 10;
	expandKey(expKey, key);
	cipher = addRoundKey(cipher, expKey[expCount--]);
	for (int i = 0; i < 9; i++) {
		cipher = invSubBytes(cipher);
		cipher = invShiftRows(cipher);
		cipher = invMixColumns(cipher);
		cipher = addRoundKey(cipher, invMixColumns(expKey[expCount--]));
	}
	cipher = invSubBytes(cipher);
	cipher = invShiftRows(cipher);
	cipher = addRoundKey(cipher, expKey[0]);
	return cipher;
}
		
		
		
		
		
		