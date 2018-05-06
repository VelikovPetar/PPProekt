#include "Rijndael.h"
#include "CudaRijndael.h"
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <time.h>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <ctime>  
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include "Utils.h"


#define BLOCK_SIZE 32

using namespace std;

//Function to convert unsigned char to string of length 2
void Char2Hex(unsigned char ch, char* szHex)
{
	unsigned char byte[2];
	byte[0] = ch / 16;
	byte[1] = ch % 16;
	for (int i = 0; i < 2; i++)
	{
		if (byte[i] >= 0 && byte[i] <= 9)
			szHex[i] = '0' + byte[i];
		else
			szHex[i] = 'A' + byte[i] - 10;
	}
	szHex[2] = 0;
}

//Function to convert string of length 2 to unsigned char
void Hex2Char(char const* szHex, unsigned char& rch)
{
	rch = 0;
	for (int i = 0; i < 2; i++)
	{
		if (*(szHex + i) >= '0' && *(szHex + i) <= '9')
			rch = (rch << 4) + (*(szHex + i) - '0');
		else if (*(szHex + i) >= 'A' && *(szHex + i) <= 'F')
			rch = (rch << 4) + (*(szHex + i) - 'A' + 10);
		else
			break;
	}
}

//Function to convert string of unsigned chars to string of chars
void CharStr2HexStr(unsigned char const* pucCharStr, char* pszHexStr, int iSize)
{
	int i;
	char szHex[3];
	pszHexStr[0] = 0;
	for (i = 0; i < iSize; i++)
	{
		Char2Hex(pucCharStr[i], szHex);
		strcat(pszHexStr, szHex);
	}
}

//Function to convert string of chars to string of unsigned chars
void HexStr2CharStr(char const* pszHexStr, unsigned char* pucCharStr, int iSize)
{
	int i;
	unsigned char ch;
	for (i = 0; i < iSize; i++)
	{
		Hex2Char(pszHexStr + 2 * i, ch);
		pucCharStr[i] = ch;
	}
}

void EncryptBlockCpu(char *plaintext, char *ciphertext, CRijndael rijndael) {
	rijndael.EncryptBlock(plaintext, ciphertext);
}

void DecryptBlockCpu(char *ciphertext, char* decrypted, CRijndael rijndael) {
	rijndael.DecryptBlock(ciphertext, decrypted);
}


static vector<vector<char>> EncryptBlocksCpu(vector<vector<char>> blocks, CRijndael rijndael) {
	Utils::Log("Start encryption of blocks.");
	vector<vector<char>> encryptedBlocks;
	for (int i = 0; i < blocks.size(); ++i) {
		/*if (i % 1000 == 0) {
			stringstream ss;
			ss << "Encrypting block " << i << ".";
			Log(ss.str());
		}*/
		vector<char> block = blocks[i];
		char * plaintext = Utils::VectorToArray(block, block.size());
		char ciphertext[BLOCK_SIZE];
		EncryptBlockCpu(plaintext, ciphertext, rijndael);
		vector<char> ciphertextBlock(ciphertext, ciphertext + sizeof(ciphertext) / sizeof(ciphertext[0]));
		encryptedBlocks.push_back(ciphertextBlock);
	}
	Utils::Log("End encryption of blocks.");
	return encryptedBlocks;
}

static vector<vector<char>> DecryptBlocksCpu(vector<vector<char>> blocks, CRijndael rijndael) {
	Utils::Log("Start decryption of blocks.");
	vector<vector<char>> decryptedBlocks;
	for (int i = 0; i < blocks.size(); ++i) {
		/*if (i % 1000 == 0) {
			stringstream ss;
			ss << "Decrypting block " << i << ".";
			Log(ss.str());
		}*/
		vector<char> block = blocks[i];
		char * ciphertext = Utils::VectorToArray(block, block.size());
		char decrypted[BLOCK_SIZE];
		DecryptBlockCpu(ciphertext, decrypted, rijndael);
		vector<char> decryptedBlock(decrypted, decrypted + sizeof(decrypted) / sizeof(decrypted[0]));
		decryptedBlocks.push_back(decryptedBlock);
	}
	Utils::Log("End decryption of blocks.");
	return decryptedBlocks;
}

static vector<char> MergeBlocks(vector<vector<char>> blocks) {
	Utils::Log("Start merging blocks.");
	vector<char> data;
	for (int i = 0; i < blocks.size(); ++i) {
		for (int j = 0; j < blocks[i].size(); ++j) {
			data.push_back(blocks[i][j]);
		}
	}
	Utils::Log("End merging blocks.");
	return data;
}

void PrintBlocks(vector<vector<char>> blocks) {
	for (int i = 0; i < blocks.size(); ++i) {
		for (int j = 0; j < blocks[i].size(); ++j) {
			cout << blocks[i][j];
		}
		cout << endl;
	}
}

void RunSerialOnCpu(CRijndael rijndael) {
	vector<char> data = Utils::ReadBytes("data/image.jpg");
	auto startTime = Utils::CurrentTime();
	vector<vector<char>> blocks = Utils::GetBlocks(data, BLOCK_SIZE);
	auto encryptionStartTime = Utils::CurrentTime();
	vector<vector<char>> encryptedBlocks = EncryptBlocksCpu(blocks, rijndael);
	auto encryptionEndTime = Utils::CurrentTime();
	chrono::duration<double> elapsedEncryptionTime = encryptionEndTime - encryptionStartTime;
	stringstream ss;
	ss << "Elapsed time for serial encryption of each block with size " << BLOCK_SIZE << ":\t" << elapsedEncryptionTime.count();
	Utils::Log(ss.str());
	vector<char> encryptedFileBytes = MergeBlocks(encryptedBlocks);
	auto endTime = Utils::CurrentTime();
	chrono::duration<double> elapsedTime = endTime - startTime;
	double elapsedTimeSeconds = elapsedTime.count();
	ss.str(string());
	ss << "Total elapsed time(divide + encrypt + merge) for serial encryption of a file with size " << data.size() << "B on CPU:\t" << elapsedTimeSeconds << "s";
	Utils::Log(ss.str());
	Utils::WriteBytes(encryptedFileBytes, "data/enc_image.jpg");
	vector<vector<char>> decryptedBlocks = DecryptBlocksCpu(encryptedBlocks, rijndael);
	vector<char> decryptedFileBytes = MergeBlocks(decryptedBlocks);
	Utils::WriteBytes(decryptedFileBytes, "data/dec_image.jpg");

}

//void main()
//{
//	try
//	{
//		CRijndael rijndael;
//		rijndael.MakeKey("abcdefghabcdefgh", "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16, BLOCK_SIZE);
//		RunSerialOnCpu(rijndael);
//		int k;
//		cin >> k;
//	}
//	catch (exception& roException)
//	{
//		cout << roException.what() << endl;
//		int k;
//		cin >> k;
//	}
//}

