#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wintrust.h> 
#include <openssl/sha.h>
#include "pesign.h"

unsigned char *pe_hash_ex;
extern pInfo inf;
extern unsigned char *pe_hash;


/*****************************************************
	Analy_Signer_Data():
		1. 通过公钥解密密文
		2. 分析解密后的明文，提取其中的PE文件摘要
			和签名者信息两部分数据
		3. 输出签名者信息数据
		4. 校验PE的摘要值，来判断文件是否被修改
*****************************************************/
int Analy_Signer_Data()
{
	FILE *fdata = '\0';
	char datapath[MAXPATH] = { '\0' };
	char tBuff[10001] = { '\0' };
	unsigned char temp[10] = { '\0' };
	char t1[10] = { '\0' };
	int size = 0;
	int i = 0;

	//************************
	strcpy(datapath, "E:\\Temp4\\testde.dat");
	//************************
	fdata = fopen(datapath, "rb");

	// 通过FILEDATA判断数据是否损坏
	fseek(fdata, 0x0, SEEK_SET);
	fread(t1, 0x08, 1, fdata);
	if (strcmp(t1, "FILEDATA") != 0)
	{
		printf("The data had been broken.\n");
		return -1;
	}
	memset(t1, '\0', sizeof(t1));

	// 读取摘要长度，通过长度获取摘要值
	fread(temp, 0x01, 1, fdata);
	size = atoi2(temp);
	size = size - 1;
	pe_hash_ex = (unsigned char *)malloc(sizeof(unsigned char) * (SHA256_DIGEST_LENGTH + 1));
	memset(pe_hash_ex, '\0', SHA256_DIGEST_LENGTH + 1);
	fread(pe_hash_ex, size, 1, fdata);
	memset(temp, '\0', sizeof(temp));

	// 初始化签名者信息结构体
	inf = (pInfo)malloc(sizeof(struct SignerInfo));
	memset(inf, '\0', sizeof(struct SignerInfo));

	// 读取签名者信息中姓名的长度，并获取姓名
	fread(temp, 0x01, 1, fdata);
	size = atoi2(temp);
	size = size - 1;
	fread(inf->Name, size, 1, fdata);
	memset(temp, '\0', sizeof(temp));

	// 读取签名者信息中邮箱的长度，并获取邮箱
	fread(temp, 0x01, 1, fdata);
	size = atoi2(temp);
	size = size - 1;
	fread(inf->Mail, size, 1, fdata);
	memset(temp, '\0', sizeof(temp));

	// 读取签名者信息中时间戳的长度，并获取时间戳
	fread(temp, 0x01, 1, fdata);
	size = atoi2(temp);
	size = size - 1;
	fread(inf->TimeStamp, size, 1, fdata);
	memset(temp, '\0', sizeof(temp));

	// 读取签名者信息中备注信息的长度，并获取备注信息
	fread(temp, 0x01, 1, fdata);
	size = atoi2(temp);
	size = size - 1;
	fread(inf->Comment, size, 1, fdata);
	memset(temp, '\0', sizeof(temp));

	// 输出签名者信息
	printf("\n\tThe signer's information:\n");
	printf("\tName:\t\t%s\n", inf->Name);
	printf("\tMail:\t\t%s\n", inf->Mail);
	printf("\tTimeStamp:\t%s\n", inf->TimeStamp);
	printf("\tComment:\t%s\n", inf->Comment);

	fclose(fdata);

	// 计算PE文件哈希值
	File_Hash();

	// 判断计算的哈希值与从证书中提取的哈希值是否一致
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		if (pe_hash_ex[i] != pe_hash[i])
		{
			// 若不一致则结束分析
			printf("[ERROR] The file had been changed.\n");
			remove(datapath);
			return -1;
		}
	}
	remove(datapath);
	printf("\tThe file hasn't been changed.\n");

	return 1;
}