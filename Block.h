/*	Written by Thomas Upfold, Jared Cooper, Ki Soon Park and Min Ho Juag for
	Assignment 3 of COMP3260 Data Security. This file contains the
	function delcarations for the Block class and also contains the
	operator overload for the () operator
	
	Important Notes:
		-	Please note the operator overload on ()
*/

#ifndef BLOCK_H
#define BLOCK_H
#include <string>
namespace AES {
	class Block {
		private:
			unsigned char array[4][4];

		public:
			Block();
			Block(std::string s); //Takes first 16 characters of s and inits a block with it in the right order
			
			std::string toString(); //Outputs Block array elements
			int getHexValue(unsigned char c); //Helper function for class
		unsigned char& operator() (int a, int b) { //Operator overload to allow array access quickly
			return array[b][a];
		}

	};
};
#endif