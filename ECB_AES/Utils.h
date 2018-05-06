#include <string>
#include <vector>
#include <chrono>

#ifndef __UTILS_H__
#define __UTILS_H__

class Utils {
public:
	static std::chrono::time_point<std::chrono::system_clock> CurrentTime();

	static std::string FormatTime(const char* format);

	static void Log(std::string message);

	static char* VectorToArray(std::vector<char> vec, int size);

	static std::vector<char> ArrayToVector(char * arr, int size);

	static std::vector<char> PadToMultipleOfN(std::vector<char> data, int N);

	static std::vector<char> ReadBytes(char const* filename);

	static void WriteBytes(std::vector<char> data, char const* filename);

	static std::vector<std::vector<char>> GetBlocks(std::vector<char> data, int blockSize);
};

#endif