#include<iostream>
#include <string.h> 
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
//int BN_is_prime_ex(const BIGNUM *p, int nchecks, BN_CTX *ctx, BN_GENCB *cb);
//to reach the 128 bit security level, nchecks should be set to 64.
using namespace std;

// ---- sha512摘要哈希 ---- //    
void sha512(const std::string &srcStr, std::string &encodedStr, std::string &encodedHexStr)  
{  
    // 调用sha512哈希    
    unsigned char mdStr[65] = {0};  
    SHA512((const unsigned char *)srcStr.c_str(), srcStr.length(), mdStr);  
  
    // 哈希后的字符串    
    encodedStr = std::string((const char *)mdStr);  
    // 哈希后的十六进制串 64字节    
    char buf[129] = {0};  
    char tmp[3] = {0};  
    for (int i = 0; i < 64; i++)  
    {  
        sprintf(tmp, "%02x", mdStr[i]);  
        strcat(buf, tmp);  
    }  

    buf[128] = '\0'; // 后面都是0，从64字节截断    
    encodedHexStr = std::string(buf);  
}  


  
// ---- sha256摘要哈希 ---- //    
void sha256(const std::string &srcStr, std::string &encodedStr, std::string &encodedHexStr)  
{  
    // 调用sha256哈希    
    unsigned char mdStr[33] = {0};  
    SHA256((const unsigned char *)srcStr.c_str(), srcStr.length(), mdStr);  
  
    // 哈希后的字符串    
    encodedStr = std::string((const char *)mdStr);  
    // 哈希后的十六进制串 32字节    
    char buf[65] = {0};  
    char tmp[3] = {0};  
    for (int i = 0; i < 32; i++)  
    {  
        sprintf(tmp, "%02x", mdStr[i]);  
        strcat(buf, tmp);  
    }  
    buf[64] = '\0'; // 后面都是0，从32字节截断    
    encodedHexStr = std::string(buf);  
}  


int is_prime(const std::string &encryptHexText)
{
    BIGNUM *bn = BN_new();
    BN_CTX *bnCtx = BN_CTX_new();
    const char* a = encryptHexText.c_str();
    if(BN_hex2bn(&bn,a) == 0) 
	return -2;

    int res = BN_is_prime_ex(bn,256,bnCtx,NULL);
    BN_CTX_free(bnCtx);
    BN_free(bn);
    return res;
}

int main()
{
   int count = 0;
   int num = 0;
   bool isfind = false;
   string srcText = "hello world";
   string encryptText,encryptHexText;
   while(!isfind)
   {
	string newSrc = to_string(count) + srcText;
	sha256(newSrc, encryptText, encryptHexText);  
	if(is_prime(encryptHexText) == 1)
	{
	   num++;
	   if(num == 100)
	      isfind = true;
	   std::cout << "new src : " << newSrc << std::endl; 
	   std::cout << "摘要串  : " << encryptHexText << std::endl; 
	}

	count++;
	 
   }

    // sha256    
/*
    std::cout << "=== sha256哈希 ===" << std::endl;  
    sha256(srcText, encryptText, encryptHexText);  
    std::cout << "摘要字符： " << encryptText << std::endl;  
    std::cout << "摘要串： " << encryptHexText << std::endl; 
    cout<<is_prime(encryptHexText)<<endl;
    encryptHexText = "E5C2CBEA6A2BD2A758BDB9195B594645";
    std::cout << "摘要串： " << encryptHexText << std::endl;  

    cout<<is_prime(encryptHexText)<<endl;
*/
   return 0;
}
