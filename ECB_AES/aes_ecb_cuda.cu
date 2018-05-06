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

#define BLOCK_SIZE 16
#define THREADS_PER_BLOCK 1024

using namespace std;

//CONSTRUCTOR
__device__ __host__ CudaRijndael::CudaRijndael() : m_bKeyInit(false)
{
}

//DESTRUCTOR
__device__ __host__ CudaRijndael::~CudaRijndael()
{
}

//Expand a user-supplied key material into a session key.
// key        - The 128/192/256-bit user-key to use.
// chain      - initial chain block for CBC and CFB modes.
// keylength  - 16, 24 or 32 bytes
// blockSize  - The block size in bytes of this Rijndael (16, 24 or 32 bytes).
__device__ __host__ void CudaRijndael::MakeKey(char const* key, char const* chain, int keylength, int blockSize)
{
	m_keylength = keylength;
	m_blockSize = blockSize;
	//Initialize the chain
	memcpy(m_chain0, chain, m_blockSize);
	memcpy(m_chain, chain, m_blockSize);
	//Calculate Number of Rounds
	switch (m_keylength)
	{
	case 16:
		m_iROUNDS = (m_blockSize == 16) ? 10 : (m_blockSize == 24 ? 12 : 14);
		break;

	case 24:
		m_iROUNDS = (m_blockSize != 32) ? 12 : 14;
		break;

	default: // 32 bytes = 256 bits
		m_iROUNDS = 14;
	}
	int BC = m_blockSize / 4;
	int i, j;
	for (i = 0; i <= m_iROUNDS; i++)
	{
		for (j = 0; j<BC; j++)
			m_Ke[i][j] = 0;
	}
	for (i = 0; i <= m_iROUNDS; i++)
	{
		for (j = 0; j<BC; j++)
			m_Kd[i][j] = 0;
	}
	int ROUND_KEY_COUNT = (m_iROUNDS + 1) * BC;
	int KC = m_keylength / 4;
	//Copy user material bytes into temporary ints
	int* pi = tk;
	char const* pc = key;
	for (i = 0; i<KC; i++)
	{
		*pi = (unsigned char)*(pc++) << 24;
		*pi |= (unsigned char)*(pc++) << 16;
		*pi |= (unsigned char)*(pc++) << 8;
		*(pi++) |= (unsigned char)*(pc++);
	}
	//Copy values into round key arrays
	int t = 0;
	for (j = 0; (j<KC) && (t<ROUND_KEY_COUNT); j++, t++)
	{
		m_Ke[t / BC][t%BC] = tk[j];
		m_Kd[m_iROUNDS - (t / BC)][t%BC] = tk[j];
	}
	int tt, rconpointer = 0;
	while (t < ROUND_KEY_COUNT)
	{
		//Extrapolate using phi (the round key evolution function)
		tt = tk[KC - 1];
		tk[0] ^= (sm_S[(tt >> 16) & 0xFF] & 0xFF) << 24 ^
			(sm_S[(tt >> 8) & 0xFF] & 0xFF) << 16 ^
			(sm_S[tt & 0xFF] & 0xFF) << 8 ^
			(sm_S[(tt >> 24) & 0xFF] & 0xFF) ^
			(sm_rcon[rconpointer++] & 0xFF) << 24;
		if (KC != 8)
			for (i = 1, j = 0; i<KC;)
				tk[i++] ^= tk[j++];
		else
		{
			for (i = 1, j = 0; i<KC / 2; )
				tk[i++] ^= tk[j++];
			tt = tk[KC / 2 - 1];
			tk[KC / 2] ^= (sm_S[tt & 0xFF] & 0xFF) ^
				(sm_S[(tt >> 8) & 0xFF] & 0xFF) << 8 ^
				(sm_S[(tt >> 16) & 0xFF] & 0xFF) << 16 ^
				(sm_S[(tt >> 24) & 0xFF] & 0xFF) << 24;
			for (j = KC / 2, i = j + 1; i<KC; )
				tk[i++] ^= tk[j++];
		}
		//Copy values into round key arrays
		for (j = 0; (j<KC) && (t<ROUND_KEY_COUNT); j++, t++)
		{
			m_Ke[t / BC][t%BC] = tk[j];
			m_Kd[m_iROUNDS - (t / BC)][t%BC] = tk[j];
		}
	}
	//Inverse MixColumn where needed
	for (int r = 1; r<m_iROUNDS; r++)
		for (j = 0; j<BC; j++)
		{
			tt = m_Kd[r][j];
			m_Kd[r][j] = sm_U1[(tt >> 24) & 0xFF] ^
				sm_U2[(tt >> 16) & 0xFF] ^
				sm_U3[(tt >> 8) & 0xFF] ^
				sm_U4[tt & 0xFF];
		}
	m_bKeyInit = true;
}

//Convenience method to encrypt exactly one block of plaintext, assuming
//Rijndael's default block size (128-bit).
// in         - The plaintext
// result     - The ciphertext generated from a plaintext using the key
__device__ __host__ void CudaRijndael::DefEncryptBlock(char const* in, char* result)
{
	int* Ker = m_Ke[0];
	int t0 = ((unsigned char)*(in++) << 24);
	t0 |= ((unsigned char)*(in++) << 16);
	t0 |= ((unsigned char)*(in++) << 8);
	(t0 |= (unsigned char)*(in++)) ^= Ker[0];
	int t1 = ((unsigned char)*(in++) << 24);
	t1 |= ((unsigned char)*(in++) << 16);
	t1 |= ((unsigned char)*(in++) << 8);
	(t1 |= (unsigned char)*(in++)) ^= Ker[1];
	int t2 = ((unsigned char)*(in++) << 24);
	t2 |= ((unsigned char)*(in++) << 16);
	t2 |= ((unsigned char)*(in++) << 8);
	(t2 |= (unsigned char)*(in++)) ^= Ker[2];
	int t3 = ((unsigned char)*(in++) << 24);
	t3 |= ((unsigned char)*(in++) << 16);
	t3 |= ((unsigned char)*(in++) << 8);
	(t3 |= (unsigned char)*(in++)) ^= Ker[3];
	int a0, a1, a2, a3;
	//Apply Round Transforms
	for (int r = 1; r < m_iROUNDS; r++)
	{
		Ker = m_Ke[r];
		a0 = (sm_T1[(t0 >> 24) & 0xFF] ^
			sm_T2[(t1 >> 16) & 0xFF] ^
			sm_T3[(t2 >> 8) & 0xFF] ^
			sm_T4[t3 & 0xFF]) ^ Ker[0];
		a1 = (sm_T1[(t1 >> 24) & 0xFF] ^
			sm_T2[(t2 >> 16) & 0xFF] ^
			sm_T3[(t3 >> 8) & 0xFF] ^
			sm_T4[t0 & 0xFF]) ^ Ker[1];
		a2 = (sm_T1[(t2 >> 24) & 0xFF] ^
			sm_T2[(t3 >> 16) & 0xFF] ^
			sm_T3[(t0 >> 8) & 0xFF] ^
			sm_T4[t1 & 0xFF]) ^ Ker[2];
		a3 = (sm_T1[(t3 >> 24) & 0xFF] ^
			sm_T2[(t0 >> 16) & 0xFF] ^
			sm_T3[(t1 >> 8) & 0xFF] ^
			sm_T4[t2 & 0xFF]) ^ Ker[3];
		t0 = a0;
		t1 = a1;
		t2 = a2;
		t3 = a3;
	}
	//Last Round is special
	Ker = m_Ke[m_iROUNDS];
	int tt = Ker[0];
	result[0] = sm_S[(t0 >> 24) & 0xFF] ^ (tt >> 24);
	result[1] = sm_S[(t1 >> 16) & 0xFF] ^ (tt >> 16);
	result[2] = sm_S[(t2 >> 8) & 0xFF] ^ (tt >> 8);
	result[3] = sm_S[t3 & 0xFF] ^ tt;
	tt = Ker[1];
	result[4] = sm_S[(t1 >> 24) & 0xFF] ^ (tt >> 24);
	result[5] = sm_S[(t2 >> 16) & 0xFF] ^ (tt >> 16);
	result[6] = sm_S[(t3 >> 8) & 0xFF] ^ (tt >> 8);
	result[7] = sm_S[t0 & 0xFF] ^ tt;
	tt = Ker[2];
	result[8] = sm_S[(t2 >> 24) & 0xFF] ^ (tt >> 24);
	result[9] = sm_S[(t3 >> 16) & 0xFF] ^ (tt >> 16);
	result[10] = sm_S[(t0 >> 8) & 0xFF] ^ (tt >> 8);
	result[11] = sm_S[t1 & 0xFF] ^ tt;
	tt = Ker[3];
	result[12] = sm_S[(t3 >> 24) & 0xFF] ^ (tt >> 24);
	result[13] = sm_S[(t0 >> 16) & 0xFF] ^ (tt >> 16);
	result[14] = sm_S[(t1 >> 8) & 0xFF] ^ (tt >> 8);
	result[15] = sm_S[t2 & 0xFF] ^ tt;
}

//Convenience method to decrypt exactly one block of plaintext, assuming
//Rijndael's default block size (128-bit).
// in         - The ciphertext.
// result     - The plaintext generated from a ciphertext using the session key.
__device__ __host__ void CudaRijndael::DefDecryptBlock(char const* in, char* result)
{
	int* Kdr = m_Kd[0];
	int t0 = ((unsigned char)*(in++) << 24);
	t0 = t0 | ((unsigned char)*(in++) << 16);
	t0 |= ((unsigned char)*(in++) << 8);
	(t0 |= (unsigned char)*(in++)) ^= Kdr[0];
	int t1 = ((unsigned char)*(in++) << 24);
	t1 |= ((unsigned char)*(in++) << 16);
	t1 |= ((unsigned char)*(in++) << 8);
	(t1 |= (unsigned char)*(in++)) ^= Kdr[1];
	int t2 = ((unsigned char)*(in++) << 24);
	t2 |= ((unsigned char)*(in++) << 16);
	t2 |= ((unsigned char)*(in++) << 8);
	(t2 |= (unsigned char)*(in++)) ^= Kdr[2];
	int t3 = ((unsigned char)*(in++) << 24);
	t3 |= ((unsigned char)*(in++) << 16);
	t3 |= ((unsigned char)*(in++) << 8);
	(t3 |= (unsigned char)*(in++)) ^= Kdr[3];
	int a0, a1, a2, a3;
	for (int r = 1; r < m_iROUNDS; r++) // apply round transforms
	{
		Kdr = m_Kd[r];
		a0 = (sm_T5[(t0 >> 24) & 0xFF] ^
			sm_T6[(t3 >> 16) & 0xFF] ^
			sm_T7[(t2 >> 8) & 0xFF] ^
			sm_T8[t1 & 0xFF]) ^ Kdr[0];
		a1 = (sm_T5[(t1 >> 24) & 0xFF] ^
			sm_T6[(t0 >> 16) & 0xFF] ^
			sm_T7[(t3 >> 8) & 0xFF] ^
			sm_T8[t2 & 0xFF]) ^ Kdr[1];
		a2 = (sm_T5[(t2 >> 24) & 0xFF] ^
			sm_T6[(t1 >> 16) & 0xFF] ^
			sm_T7[(t0 >> 8) & 0xFF] ^
			sm_T8[t3 & 0xFF]) ^ Kdr[2];
		a3 = (sm_T5[(t3 >> 24) & 0xFF] ^
			sm_T6[(t2 >> 16) & 0xFF] ^
			sm_T7[(t1 >> 8) & 0xFF] ^
			sm_T8[t0 & 0xFF]) ^ Kdr[3];
		t0 = a0;
		t1 = a1;
		t2 = a2;
		t3 = a3;
	}
	//Last Round is special
	Kdr = m_Kd[m_iROUNDS];
	int tt = Kdr[0];
	result[0] = sm_Si[(t0 >> 24) & 0xFF] ^ (tt >> 24);
	result[1] = sm_Si[(t3 >> 16) & 0xFF] ^ (tt >> 16);
	result[2] = sm_Si[(t2 >> 8) & 0xFF] ^ (tt >> 8);
	result[3] = sm_Si[t1 & 0xFF] ^ tt;
	tt = Kdr[1];
	result[4] = sm_Si[(t1 >> 24) & 0xFF] ^ (tt >> 24);
	result[5] = sm_Si[(t0 >> 16) & 0xFF] ^ (tt >> 16);
	result[6] = sm_Si[(t3 >> 8) & 0xFF] ^ (tt >> 8);
	result[7] = sm_Si[t2 & 0xFF] ^ tt;
	tt = Kdr[2];
	result[8] = sm_Si[(t2 >> 24) & 0xFF] ^ (tt >> 24);
	result[9] = sm_Si[(t1 >> 16) & 0xFF] ^ (tt >> 16);
	result[10] = sm_Si[(t0 >> 8) & 0xFF] ^ (tt >> 8);
	result[11] = sm_Si[t3 & 0xFF] ^ tt;
	tt = Kdr[3];
	result[12] = sm_Si[(t3 >> 24) & 0xFF] ^ (tt >> 24);
	result[13] = sm_Si[(t2 >> 16) & 0xFF] ^ (tt >> 16);
	result[14] = sm_Si[(t1 >> 8) & 0xFF] ^ (tt >> 8);
	result[15] = sm_Si[t0 & 0xFF] ^ tt;
}

//Encrypt exactly one block of plaintext.
// in           - The plaintext.
// result       - The ciphertext generated from a plaintext using the key.
__device__ __host__ void CudaRijndael::EncryptBlock(char const* in, char* result)
{
	if (DEFAULT_BLOCK_SIZE == m_blockSize)
	{
		DefEncryptBlock(in, result);
		return;
	}
	int BC = m_blockSize / 4;
	int SC = (BC == 4) ? 0 : (BC == 6 ? 1 : 2);
	int s1 = sm_shifts[SC][1][0];
	int s2 = sm_shifts[SC][2][0];
	int s3 = sm_shifts[SC][3][0];
	//Temporary Work Arrays
	int i;
	int tt;
	int* pi = t;
	for (i = 0; i<BC; i++)
	{
		*pi = ((unsigned char)*(in++) << 24);
		*pi |= ((unsigned char)*(in++) << 16);
		*pi |= ((unsigned char)*(in++) << 8);
		(*(pi++) |= (unsigned char)*(in++)) ^= m_Ke[0][i];
	}
	//Apply Round Transforms
	for (int r = 1; r<m_iROUNDS; r++)
	{
		for (i = 0; i<BC; i++)
			a[i] = (sm_T1[(t[i] >> 24) & 0xFF] ^
				sm_T2[(t[(i + s1) % BC] >> 16) & 0xFF] ^
				sm_T3[(t[(i + s2) % BC] >> 8) & 0xFF] ^
				sm_T4[t[(i + s3) % BC] & 0xFF]) ^ m_Ke[r][i];
		memcpy(t, a, 4 * BC);
	}
	int j;
	//Last Round is Special
	for (i = 0, j = 0; i<BC; i++)
	{
		tt = m_Ke[m_iROUNDS][i];
		result[j++] = sm_S[(t[i] >> 24) & 0xFF] ^ (tt >> 24);
		result[j++] = sm_S[(t[(i + s1) % BC] >> 16) & 0xFF] ^ (tt >> 16);
		result[j++] = sm_S[(t[(i + s2) % BC] >> 8) & 0xFF] ^ (tt >> 8);
		result[j++] = sm_S[t[(i + s3) % BC] & 0xFF] ^ tt;
	}
}

//Decrypt exactly one block of ciphertext.
// in         - The ciphertext.
// result     - The plaintext generated from a ciphertext using the session key.
__device__ __host__ void CudaRijndael::DecryptBlock(char const* in, char* result)
{
	if (DEFAULT_BLOCK_SIZE == m_blockSize)
	{
		DefDecryptBlock(in, result);
		return;
	}
	int BC = m_blockSize / 4;
	int SC = BC == 4 ? 0 : (BC == 6 ? 1 : 2);
	int s1 = sm_shifts[SC][1][1];
	int s2 = sm_shifts[SC][2][1];
	int s3 = sm_shifts[SC][3][1];
	//Temporary Work Arrays
	int i;
	int tt;
	int* pi = t;
	for (i = 0; i<BC; i++)
	{
		*pi = ((unsigned char)*(in++) << 24);
		*pi |= ((unsigned char)*(in++) << 16);
		*pi |= ((unsigned char)*(in++) << 8);
		(*(pi++) |= (unsigned char)*(in++)) ^= m_Kd[0][i];
	}
	//Apply Round Transforms
	for (int r = 1; r<m_iROUNDS; r++)
	{
		for (i = 0; i<BC; i++)
			a[i] = (sm_T5[(t[i] >> 24) & 0xFF] ^
				sm_T6[(t[(i + s1) % BC] >> 16) & 0xFF] ^
				sm_T7[(t[(i + s2) % BC] >> 8) & 0xFF] ^
				sm_T8[t[(i + s3) % BC] & 0xFF]) ^ m_Kd[r][i];
		memcpy(t, a, 4 * BC);
	}
	int j;
	//Last Round is Special
	for (i = 0, j = 0; i<BC; i++)
	{
		tt = m_Kd[m_iROUNDS][i];
		result[j++] = sm_Si[(t[i] >> 24) & 0xFF] ^ (tt >> 24);
		result[j++] = sm_Si[(t[(i + s1) % BC] >> 16) & 0xFF] ^ (tt >> 16);
		result[j++] = sm_Si[(t[(i + s2) % BC] >> 8) & 0xFF] ^ (tt >> 8);
		result[j++] = sm_Si[t[(i + s3) % BC] & 0xFF] ^ tt;
	}
}

__device__ __host__ void CudaRijndael::Encrypt(char const* in, char* result, size_t n, int iMode)
{
	int i;
	char const* pin;
	char* presult;
	if (CBC == iMode) //CBC mode, using the Chain
	{
		for (i = 0, pin = in, presult = result; i<n / m_blockSize; i++)
		{
			Xor(m_chain, pin);
			EncryptBlock(m_chain, presult);
			memcpy(m_chain, presult, m_blockSize);
			pin += m_blockSize;
			presult += m_blockSize;
		}
	}
	else if (CFB == iMode) //CFB mode, using the Chain
	{
		for (i = 0, pin = in, presult = result; i<n / m_blockSize; i++)
		{
			EncryptBlock(m_chain, presult);
			Xor(presult, pin);
			memcpy(m_chain, presult, m_blockSize);
			pin += m_blockSize;
			presult += m_blockSize;
		}
	}
	else //ECB mode, not using the Chain
	{
		for (i = 0, pin = in, presult = result; i<n / m_blockSize; i++)
		{
			EncryptBlock(pin, presult);
			pin += m_blockSize;
			presult += m_blockSize;
		}
	}
}

__device__ __host__ void CudaRijndael::Decrypt(char const* in, char* result, size_t n, int iMode)
{
	int i;
	char const* pin;
	char* presult;
	if (CBC == iMode) //CBC mode, using the Chain
	{
		for (i = 0, pin = in, presult = result; i<n / m_blockSize; i++)
		{
			DecryptBlock(pin, presult);
			Xor(presult, m_chain);
			memcpy(m_chain, pin, m_blockSize);
			pin += m_blockSize;
			presult += m_blockSize;
		}
	}
	else if (CFB == iMode) //CFB mode, using the Chain, not using Decrypt()
	{
		for (i = 0, pin = in, presult = result; i<n / m_blockSize; i++)
		{
			EncryptBlock(m_chain, presult);
			//memcpy(presult, pin, m_blockSize);
			Xor(presult, pin);
			memcpy(m_chain, pin, m_blockSize);
			pin += m_blockSize;
			presult += m_blockSize;
		}
	}
	else //ECB mode, not using the Chain
	{
		for (i = 0, pin = in, presult = result; i<n / m_blockSize; i++)
		{
			DecryptBlock(pin, presult);
			pin += m_blockSize;
			presult += m_blockSize;
		}
	}
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

void RunOnGpu(CudaRijndael rijndael, int numThreadsPerBlock) {
	vector<char> data = Utils::ReadBytes("data/image.jpg");
	stringstream ss;
	data = Utils::PadToMultipleOfN(data, BLOCK_SIZE);;
	int size = data.size();
	ss << "Paded size : " << data.size();
	Utils::Log(ss.str());
	ss.str(string());
	char *h_plaintext = Utils::VectorToArray(data, size);
	char *h_ciphertext = new char[size];
	char *d_plaintext;
	char *d_ciphertext;
	int * d_size;
	CudaRijndael *d_rijndael;
	Utils::Log("Allocating cuda mem...");
	auto startTime = Utils::CurrentTime();
	cudaMalloc((void**)&d_plaintext, size * sizeof(char));
	cudaMalloc((void**)&d_ciphertext, size * sizeof(char));
	cudaMalloc((void**)&d_size, sizeof(int));
	cudaMalloc((void**)&d_rijndael, sizeof(CudaRijndael));
	cudaMemcpy(d_plaintext, h_plaintext, size * sizeof(char), cudaMemcpyHostToDevice);
	cudaMemcpy(d_size, &size, sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_rijndael, &rijndael, sizeof(CudaRijndael), cudaMemcpyHostToDevice);
	auto endAllocationTime = Utils::CurrentTime();
	Utils::Log("Alocated cuda mem.");
	int numEncryptionBlocks = size / BLOCK_SIZE;
	int numGpuBlocks = numEncryptionBlocks / numThreadsPerBlock + 1;
	kernel <<<numGpuBlocks, numThreadsPerBlock>>> (d_plaintext, d_ciphertext, d_size, d_rijndael);
	cudaDeviceSynchronize();
	auto endEncryptionTime = Utils::CurrentTime();
	cudaMemcpy(h_ciphertext, d_ciphertext, size * sizeof(char), cudaMemcpyDeviceToHost);
	auto endCopyResultToCpuTime = Utils::CurrentTime();
	ss.str(string());
	ss << "Elapsed time for parallel encryption:" << endl;
	ss << "Encryption block size: " << BLOCK_SIZE; ss << endl;
	ss << "GPU blocks: " << numGpuBlocks << endl;
	ss << "Threads per block: " << numThreadsPerBlock << endl;
	chrono::duration<double> time = endAllocationTime - startTime;
	ss << "Cuda memory allocation time: " << time.count() << "s" << endl;
	time = endEncryptionTime - endAllocationTime;
	ss << "Encryption Time: " << time.count() << "s" << endl;
	time = endCopyResultToCpuTime - endEncryptionTime;
	ss << "Copy result to CPU time: " << time.count() << "s" << endl;
	time = endCopyResultToCpuTime - startTime;
	ss << "Total elapsed time:" << time.count() << "s" << endl;
	Utils::Log(ss.str());
	cudaError_t code = cudaPeekAtLastError();
	if (code != cudaSuccess) {
		Utils::Log(cudaGetErrorString(code));
	}

	// Write the decrypted file for correctness check
	/*vector<char> encrypted(h_ciphertext, h_ciphertext + sizeof(h_ciphertext) / sizeof(h_ciphertext[0]));
	vector<vector<char>> encBlocks = Utils::GetBlocks(encrypted, BLOCK_SIZE);*/
	char * decrypted = new char[size];
	vector<char> vEncrypted = Utils::ArrayToVector(h_ciphertext, size);
	Utils::Log("Start writing to file.[encrypted]");
	Utils::WriteBytes(vEncrypted, "data/encrypted_image.jpg");
	Utils::Log("End writing to file.[encrypted]");
	Utils::Log("Decrypting...");
	rijndael.Decrypt(h_ciphertext, decrypted, size, CudaRijndael::ECB);
	Utils::Log("Decrypted.");
	vector<char> vDecrypted = Utils::ArrayToVector(decrypted, size);
	vector<char> decrNoPadding(vDecrypted.begin(), vDecrypted.begin() + size);
	Utils::Log("Start writing to file.[decrypted]");
	Utils::WriteBytes(decrNoPadding, "data/decrypted_image.jpg");
	Utils::Log("End writing to file.[decrypted]");
	delete[] h_ciphertext;
	delete[] decrypted;
	cudaFree(d_plaintext);
	cudaFree(d_ciphertext);
	cudaFree(d_size);
	cudaFree(d_rijndael);
}

int main() {
	CudaRijndael rijndael;
	rijndael.MakeKey("abcdefghabcdefgh", "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16, BLOCK_SIZE);
	RunOnGpu(rijndael, THREADS_PER_BLOCK);
	cout << "Enter a key...";
	char k;
	cin >> k;
	return 0;
}