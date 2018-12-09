#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wintrust.h> 
#include "pesign.h"

extern char File_PATH[];
extern unsigned char *encrypted;
extern int encrypted_length;
extern char Public_PATH[];					// 公钥绝对路径
extern char Private_PATH[];					// 私钥绝对路径


/*****************************************************
	Extract_PE_Cer():
		1. 解析PE格式
		2. 从已签名的PE文件中提取证书部分
		3. 将提取出的证书保存到临时文件
*****************************************************/
void Extract_PE_Cer()
{
	unsigned char SecRVA[11] = { '\0' };
	unsigned char SecSize[11] = { '\0' };
	char tBuff[10001] = { '\0' };
	int secRVA = 0, secSize = 0;
	char path[MAXPATH] = { '\0' };
	char datapath[MAXPATH] = { '\0' };
	FILE *pFile = '\0';
	FILE *pCer = '\0';

	strcpy(path, File_PATH);
	//************************
	strcpy(datapath, "E:\\Temp4\\formatcert.dat");
	//************************
	
	pFile = fopen(path, "rb");
	if (pFile == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", path);
		exit(0);
	}
	pCer = fopen(datapath, "w+b");
	if (pCer == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", datapath);
		exit(0);
	}

	fseek(pFile, 0x128, SEEK_SET);   // 读取安全目录
	fread(SecRVA, 0x04, 1, pFile);   // 获取SECURITY RVA
	fread(SecSize, 0x04, 1, pFile);

	secRVA = BigToSmall4(SecRVA);    // 将rva转为十进制整型
	secSize = BigToSmall4(SecSize);

	fseek(pFile, secRVA, SEEK_SET);
	fread(tBuff, secSize, 1, pFile);
	fwrite(tBuff, secSize, 1, pCer);

	fclose(pFile);
	fclose(pCer);

	return;
}


/*****************************************************
	Analy_Cert_Data():
		1. 分析导出的证书数据
		2. 通过CERTDATA标识来判断数据是否被损坏
		3. 从证书中提取出加密后的签名者信息和公钥
		4. 将密文输出到临时文件
*****************************************************/
void Analy_Cert_Data()
{
	FILE *fdata = '\0';
	FILE *fcert = '\0';
	FILE *f_pub = '\0';
	unsigned char SecRVA[11] = { '\0' };
	unsigned char SecSize[11] = { '\0' };
	char tBuff[10001] = { '\0' };
	unsigned char temp[2048] = { '\0' };
	char t1[10] = { '\0' };
	int secRVA = 0, secSize = 0;
	char datapath[MAXPATH] = { '\0' };
	char certpath[MAXPATH] = { '\0' };
	int size = 0;

	//************************
	strcpy(datapath, "E:\\Temp4\\formatdata_en.dat");
	strcpy(certpath, "E:\\Temp4\\formatcert.dat");
	strcpy(Public_PATH, "E:\\Temp4\\pub.pem");
	//************************

	fcert = fopen(certpath, "rb");
	if (fcert == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", certpath);
		exit(0);
	}
	fdata = fopen(datapath, "w+b");
	if (fdata == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", datapath);
		exit(0);
	}
	f_pub = fopen(Public_PATH, "w+b");
	if (f_pub == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", Public_PATH);
		exit(0);
	}

	// 判断证书数据是否损坏
	fseek(fcert, 0x08, SEEK_SET);
	fread(t1, 0x08, 1, fcert);
	if (strcmp(t1, "CERTDATA") != 0)
	{
		printf("The cert had been broken.\n");
		exit(0);
	}
	memset(t1, '\0', sizeof(t1));

	// 读取密文长度，通过长度提取密文
	fread(temp, 0x02, 1, fcert);
	size = atoi2(temp);
	size = size - 2;					// size位，占两位
	fread(tBuff, size, 1, fcert);
	//printf("\nmiwen: %s\n", tBuff);
	fwrite(tBuff, size, 1, fdata);
	memset(tBuff, '\0', sizeof(tBuff));
	memset(temp, '\0', sizeof(temp));

	// 读取公钥长度，通过长度提取公钥
	fread(temp, 0x02, 1, fcert);
	size = atoi2(temp);
	size = size - 2;
	fread(tBuff, size, 1, fcert);
	//printf("pub: %s\n", tBuff);
	//exit(0);
	fwrite(tBuff, size, 1, f_pub);
	memset(tBuff, '\0', sizeof(tBuff));
	memset(temp, '\0', sizeof(temp));

	fclose(fcert);
	fclose(fdata);
	fclose(f_pub);

	// 移除临时证书文件
	remove(certpath);

	return;
}

// unsigned char *字符串（十六进制）转为int整型
int atoi2(unsigned char *str)
{
	int num;
	unsigned char b[10] = { '\0' };
	unsigned char tmp[10] = { '\0' };


	tohex((int)str[0], (char *)b);
	strcpy((char *)tmp, "0x");
	if (strlen((char *)b) == 1)
	{
		tmp[strlen((char *)tmp)] = '0';
	}
	strcat((char *)tmp, (char *)b);
	memset(b, '\0', sizeof(b));
	tohex((int)str[1], (char *)b);
	if (strlen((char *)b) == 1)
	{
		tmp[strlen((char *)tmp)] = '0';
	}
	strcat((char *)tmp, (char *)b);
	num = atoi1((char *)tmp);

	return num;
}