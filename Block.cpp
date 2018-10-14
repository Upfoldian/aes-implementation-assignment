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
				unsigned char currentByte = 0x00, firstNib, secondNib;
				
				firstNib = getHexValue(s[count++]);
				secondNib = getHexValue(s[count++]);

				currentByte = (firstNib << 4) + secondNib;
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

	int Block::getHexValue(unsigned char c) {
		if (c >= '0' && c <= '9') {
			return c - 48;
		} else if (c >= 'A' && c <= 'F') {
			return c - 65 + 10;
		} else if (c >= 'a' && c <= 'f') {
			return c - 97 + 10;
		} else {
			return 0x0F;
		}
	}
		
};