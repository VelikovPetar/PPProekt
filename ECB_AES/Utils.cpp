// Utils.cpp

#include "Utils.h"
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <time.h>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <ctime>  

using namespace std;

chrono::time_point<chrono::system_clock> Utils::CurrentTime() {
	auto now = chrono::system_clock::now();
	return now;
}

string Utils::FormatTime(const char* format) {
	auto now = chrono::system_clock::now();
	auto in_time_t = chrono::system_clock::to_time_t(now);
	stringstream ss;
	ss << put_time(localtime(&in_time_t), format);
	return ss.str();
}

void Utils::Log(string message) {
	cout << FormatTime("%Y-%m-%d %X") << ": " << message << endl;
}

char* Utils::VectorToArray(vector<char> vec, int size) {
	char * arr = new char[size];
	for (int i = 0; i < size; ++i) {
		arr[i] = vec[i];
	}
	return arr;
}

vector<char> Utils::ArrayToVector(char * arr, int size) {
	vector<char> vec;
	for (int i = 0; i < size; ++i) {
		vec.push_back(arr[i]);
	}
	return vec;
}

vector<char> Utils::PadToMultipleOfN(vector<char> data, int N) {
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

vector<char> Utils::ReadBytes(char const* filename) {
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

void Utils::WriteBytes(vector<char> data, char const* filename) {
	Log("Start writing bytes.");
	ofstream ofs;
	ofs.open(filename, ios::binary | ios::out);
	char * bytes = &data[0];
	ofs.write(bytes, sizeof(char) * data.size());
	ofs.close();
	Log("End writing bytes.");
}

vector<vector<char>> Utils::GetBlocks(vector<char> data, int blockSize) {
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