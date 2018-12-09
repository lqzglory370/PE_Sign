#ifndef PESIGN_H
#define PESIGN_H
#define S_PE 1
#define V_PE 0
#define MAXPATH 257

#include <time.h>
#include <windows.h>
#include <openssl/rsa.h>
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

struct SignerInfo						// 签名者信息结构体
{
	char Name[30];						// 姓名
	char Mail[50];						// 邮箱
	char TimeStamp[20];					// 时间戳
	char Comment[200];					// 备注信息
};
typedef struct SignerInfo *pInfo;


// getopt.cpp
int getOpts(int argc, char **argv);

// pe_hash.cpp
void File_Hash(void);
void Clean_PE_Cer(void);
int isSigned(char *path);
void printHash(unsigned char *md, int len);
void reversestr(char*source, char *target, unsigned int length);
void tohex(unsigned long num, char *hexStr);
long int atoi1(char *str);
int BigToSmall4(unsigned char *str);
void myHash256(unsigned char *orgStr, long size);
void get_filename(char *path, char *name);

// singer_info.cpp
pInfo SignInformation(void);
void FormatData(void);

// RSA.cpp
void rsa_pri_en();
void rsa_pub_de();
unsigned char *my_encrypt(unsigned char *str, char *prikey_path);
unsigned char *my_decrypt(unsigned char *str, char *pubkey_path);

// insert_pe.cpp
void FormatCer(void);
void Insert_PE_Cer(void);
void SmalltoBig4(unsigned char *str, int num);

// extract_pe.cpp
void Extract_PE_Cer();
void Analy_Cert_Data();
int atoi2(unsigned char *str);

// analy_data.cpp
int Analy_Signer_Data();

#endif