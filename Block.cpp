/*	Written by Thomas Upfold, Jared Cooper, Ki Soon Park and Min Ho Juag for
	Assignment 3 of COMP3260 Data Security. This file contains the implementation
	of the Block class */
#include "Block.h"
#include <iostream>
namespace AES {
	Block::Block() {
		for (int y = 0 ; y < 4; y++) {
			for (int x = 0 ; x < 4; x++) {
				array[x][y] = 0;
			}
		}
	}
	Block::Block(std::string s) {
		//Takes first 128 characters of s and assumes they are valid input
		int count = 0;
		for (int y = 0 ; y < 4; y++) {
			for (int x = 0 ; x < 4; x++) {
				unsigned char currentByte = 0x00;
				for (int i = 0; i < 8; i++) {
					if (s[count++] == '1') {
						currentByte += 1;
					}
					if (i != 7) currentByte <<= 1;					
				}
				array[x][y] = currentByte;
			}
		}
	}
	std::string Block::toString() {
		//Outputs block array elements
		std::string out = "";
		for (int x = 0 ; x < 4; x++) {
			for (int y = 0 ; y < 4; y++) {
				out += array[x][y];
			}
			out += '\n';
		}
		return out;
	}
		
};