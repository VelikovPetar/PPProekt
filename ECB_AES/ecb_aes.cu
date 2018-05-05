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


#define BLOCK_SIZE 16

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

auto CurrentTime() {
	auto now = chrono::system_clock::now();
	return now;
}

string FormatTime(const char* format) {
	auto now = chrono::system_clock::now();
	auto in_time_t = chrono::system_clock::to_time_t(now);
	stringstream ss;
	ss << put_time(localtime(&in_time_t), format);
	return ss.str();
}

void Log(string message) {
	cout << FormatTime("%Y-%m-%d %X") << ": " << message << endl;
}

static char* VectorToArray(vector<char> vec, int size) {
	char * arr = new char[size];
	for (int i = 0; i < size; ++i) {
		arr[i] = vec[i];
	}
	return arr;
}

static vector<char> PadToMultipleOfN(vector<char> data, int N) {
	if (data.size() % N == 0) {
		return data;
	}
	int desiredSize = ((data.size() / N) + 1) * N;
	int diff = desiredSize - data.size();
	for (int i = 0; i < diff; ++i) {
		data.push_back('\0');
	}
	return data;
}

static vector<char> ReadBytes(char const* filename) {
	Log("Start reading bytes.");
	ifstream ifs(filename, ios::binary | ios::ate);
	ifstream::pos_type pos = ifs.tellg();

	vector<char> result(pos);

	ifs.seekg(0, ios::beg);
	ifs.read(&result[0], pos);
	ifs.close();
	Log("End reading bytes.");
	return result;
}

static void WriteBytes(vector<char> data, char const* filename) {
	Log("Start writing bytes.");
	ofstream ofs;
	ofs.open(filename, ios::binary | ios::out);
	char * bytes = &data[0];
	ofs.write(bytes, sizeof(char) * data.size());
	ofs.close();
	Log("End writing bytes.");
}

static vector<vector<char>> GetBlocks(vector<char> data, int blockSize) {
	Log("Start dividing on blocks.");
	bool needsPadding = data.size() % blockSize != 0;
	int numBlocks = data.size() / blockSize;
	if (needsPadding) {
		numBlocks += 1;
	}
	vector<vector<char>> blocks;
	int j = 0;
	for (int i = 0; i < numBlocks - 1; ++i) {
		vector<char> block;
		for (j = i * blockSize; j < (i + 1) * blockSize; ++j) {
			block.push_back(data[j]);
		}
		blocks.push_back(block);
	}
	// Last block may need padding
	vector<char> lastBlock;
	while (j < data.size()) {
		lastBlock.push_back(data[j]);
		j++;
	}
	while (lastBlock.size() < blockSize) {
		lastBlock.push_back('\0');
	}
	blocks.push_back(lastBlock);
	Log("End dividing on blocks.");
	return blocks;
}

void EncryptBlockCpu(char *plaintext, char *ciphertext, CRijndael rijndael) {
	rijndael.EncryptBlock(plaintext, ciphertext);
}

void DecryptBlockCpu(char *ciphertext, char* decrypted, CRijndael rijndael) {
	rijndael.DecryptBlock(ciphertext, decrypted);
}


static vector<vector<char>> EncryptBlocksCpu(vector<vector<char>> blocks, CRijndael rijndael) {
	Log("Start encryption of blocks.");
	vector<vector<char>> encryptedBlocks;
	for (int i = 0; i < blocks.size(); ++i) {
		/*if (i % 1000 == 0) {
			stringstream ss;
			ss << "Encrypting block " << i << ".";
			Log(ss.str());
		}*/
		vector<char> block = blocks[i];
		char * plaintext = VectorToArray(block, block.size());
		char ciphertext[BLOCK_SIZE];
		EncryptBlockCpu(plaintext, ciphertext, rijndael);
		vector<char> ciphertextBlock(ciphertext, ciphertext + sizeof(ciphertext) / sizeof(ciphertext[0]));
		encryptedBlocks.push_back(ciphertextBlock);
	}
	Log("End encryption of blocks.");
	return encryptedBlocks;
}

static vector<vector<char>> DecryptBlocksCpu(vector<vector<char>> blocks, CRijndael rijndael) {
	Log("Start decryption of blocks.");
	vector<vector<char>> decryptedBlocks;
	for (int i = 0; i < blocks.size(); ++i) {
		/*if (i % 1000 == 0) {
			stringstream ss;
			ss << "Decrypting block " << i << ".";
			Log(ss.str());
		}*/
		vector<char> block = blocks[i];
		char * ciphertext = VectorToArray(block, block.size());
		char decrypted[BLOCK_SIZE];
		DecryptBlockCpu(ciphertext, decrypted, rijndael);
		vector<char> decryptedBlock(decrypted, decrypted + sizeof(decrypted) / sizeof(decrypted[0]));
		decryptedBlocks.push_back(decryptedBlock);
	}
	Log("End decryption of blocks.");
	return decryptedBlocks;
}

static vector<char> MergeBlocks(vector<vector<char>> blocks) {
	Log("Start merging blocks.");
	vector<char> data;
	for (int i = 0; i < blocks.size(); ++i) {
		for (int j = 0; j < blocks[i].size(); ++j) {
			data.push_back(blocks[i][j]);
		}
	}
	Log("End merging blocks.");
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
	vector<char> data = ReadBytes("data/image.jpg");
	auto startTime = CurrentTime();
	vector<vector<char>> blocks = GetBlocks(data, BLOCK_SIZE);
	auto encryptionStartTime = CurrentTime();
	vector<vector<char>> encryptedBlocks = EncryptBlocksCpu(blocks, rijndael);
	auto encryptionEndTime = CurrentTime();
	chrono::duration<double> elapsedEncryptionTime = encryptionEndTime - encryptionStartTime;
	stringstream ss;
	ss << "Elapsed time for serial encryption of each block with size " << BLOCK_SIZE << ":\t" << elapsedEncryptionTime.count();
	Log(ss.str());
	vector<char> encryptedFileBytes = MergeBlocks(encryptedBlocks);
	auto endTime = CurrentTime();
	chrono::duration<double> elapsedTime = endTime - startTime;
	double elapsedTimeSeconds = elapsedTime.count();
	ss.str(string());
	ss << "Total elapsed time(divide + encrypt + merge) for serial encryption of a file with size " << data.size() << "B on CPU:\t" << elapsedTimeSeconds << "s";
	Log(ss.str());
	WriteBytes(encryptedFileBytes, "data/enc_image.jpg");
	vector<vector<char>> decryptedBlocks = DecryptBlocksCpu(encryptedBlocks, rijndael);
	vector<char> decryptedFileBytes = MergeBlocks(decryptedBlocks);
	WriteBytes(decryptedFileBytes, "data/dec_image.jpg");

}

__global__ void kernel(char* plaintext, char * ciphertext, int * size, CudaRijndael * rijndael) {
	int idx = blockIdx.x * blockDim.x + threadIdx.x;
	int startIndex = idx * BLOCK_SIZE;
	int endIndex = (idx + 1) * BLOCK_SIZE;
	char blockPlain[BLOCK_SIZE];
	if (endIndex >= *size) {
		endIndex = *size;
	}
	int p_i = 0;
	for (int i = startIndex; i < endIndex; ++i) {
		blockPlain[p_i++] = plaintext[i];
	}
	while (p_i < BLOCK_SIZE) {
		blockPlain[p_i++] = '\0';
	}
	char blockCipher[BLOCK_SIZE];
	rijndael->EncryptBlock(blockPlain, blockCipher);
	int c_i = 0;
	for (int i = startIndex; i < endIndex; ++i) {
		ciphertext[i] = blockCipher[c_i++];
	}
}

void RunOnGpu(CRijndael rijndael) {
	vector<char> data = ReadBytes("data/test.txt");
	stringstream ss;
	ss << "Original size: " << data.size();
	Log(ss.str());
	data = PadToMultipleOfN(data, BLOCK_SIZE);
	ss.str(string());
	ss << "Padded data size: " << data.size();
	Log(ss.str());
	auto startTime = CurrentTime();
	// TODO:
}


void main()
{
	try
	{
		//One block testing
		CRijndael rijndael;
		rijndael.MakeKey("abcdefghabcdefgh", "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16, BLOCK_SIZE);
		// Create key
		RunSerialOnCpu(rijndael);
		/*char *plaintext = new char[data.size() + 1];
		for (int i = 0; i < data.size(); ++i) {
			plaintext[i] = data[i];
		}
		plaintext[data.size()] = '\0';*/
		//char ciphertext[17] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
		//oRijndael.EncryptBlock(plaintext, ciphertext);
		//// Print original plain text
		//cout << "Plaintext:\t" << plaintext << endl;
		//// Print encrypted data
		//cout << "Ciphertext:\t" << ciphertext << endl;
		//memset(plaintext, 0, 16);
		//char decrypted[17];
		//memset(decrypted, 0, 17);
		//oRijndael.DecryptBlock(ciphertext, decrypted);
		//// Print decrypted data
		//cout << "Decrypted:\t" << decrypted << endl;
		//cout << "Waiting for key..." << endl;
		int k;
		cin >> k;
	}
	catch (exception& roException)
	{
		cout << roException.what() << endl;
		int k;
		cin >> k;
	}
}

