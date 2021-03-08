// AesTool.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <string>
#include "openssl/sha.h"
#include "openssl/aes.h"
#include <openssl/evp.h>

#include <cassert>


using std::string;
using std::cout;
using std::endl;

char* base64(const unsigned char* input, int length) {
	const auto pl = 4 * ((length + 2) / 3);
	auto output = reinterpret_cast<char*>(calloc(pl + 1, 1)); //+1 for the terminating null that EVP_EncodeBlock adds on
	const auto ol = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(output), input, length);
	if (pl != ol) { std::cerr << "Whoops, encode predicted " << pl << " but we got " << ol << "\n"; }
	return output;
}

unsigned char* decode64(const char* input, int length) {
	const auto pl = 3 * length / 4;
	auto output = reinterpret_cast<unsigned char*>(calloc(pl + 1, 1));
	const auto ol = EVP_DecodeBlock(output, reinterpret_cast<const unsigned char*>(input), length);
	if (pl != ol) { std::cerr << "Whoops, decode predicted " << pl << " but we got " << ol << "\n"; }
	return output;
}


string aes128Encrypt(string content, string password) {
	//prepare key
	unsigned char key[20];
	SHA1((unsigned char*)password.data(), password.size(), key);

	cout << "密钥sha-1 hexString:";
	for (int i = 0; i < 20; ++i) {
		cout << std::hex << (int)key[i];
	}
	cout << endl;

	//aes128 with ecb
	EVP_CIPHER_CTX* ctx;
	ctx = EVP_CIPHER_CTX_new();
	int ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
	assert(ret == 1);

	//init a buff
	unsigned char* result = new unsigned char[content.size() + 64]; 
	int len1 = 0;
	ret = EVP_EncryptUpdate(ctx, result, &len1, (unsigned char *)content.data(), content.size());
	assert(ret == 1);
	int len2 = 0;
	ret = EVP_EncryptFinal_ex(ctx, result + len1, &len2);
	assert(ret == 1);
	ret = EVP_CIPHER_CTX_cleanup(ctx);
	assert(ret == 1);
	EVP_CIPHER_CTX_free(ctx);

	//base64 result
	char* baseResult = base64(result, len1 + len2);
	return string(baseResult, strlen(baseResult));
}


string aes128Decrypt(string cipher, string password) {
	//debase64
	unsigned char* debaseCipher = decode64((char*)cipher.data(), cipher.size());

	//prepare key
	unsigned char key[20];
	SHA1((unsigned char*)password.data(), password.size(), key);

	//aes128 with ecb
	EVP_CIPHER_CTX* ctx;
	ctx = EVP_CIPHER_CTX_new();
	int ret = EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
	assert(ret == 1);

	unsigned char* result = new unsigned char[cipher.size() + 64]; 
	int len1 = 0;
	ret = EVP_DecryptUpdate(ctx, result, &len1, debaseCipher, strlen((char *)debaseCipher));
	assert(ret == 1);
	int len2 = 0;
	ret = EVP_DecryptFinal_ex(ctx, result + len1, &len2);
	assert(ret == 1);
	ret = EVP_CIPHER_CTX_cleanup(ctx);
	assert(ret == 1);
	EVP_CIPHER_CTX_free(ctx);
	std::string res((char*)result, len1 + len2);
	delete[] result;
	return res;
}


int main()
{
	string content = "1234567890";
	string pwd = "123456";
	string funcResult = aes128Encrypt(content, pwd);



	cout << "密钥: " << pwd << endl;

	cout << "密文: " << funcResult << endl;

	string decryption = aes128Decrypt(funcResult, pwd);
	cout << "解密后的明文: " << decryption << endl;

    return 0;
}

