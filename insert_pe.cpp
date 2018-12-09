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
	FormatCer():
		1. 格式化数据包括加密后的数据和公钥两部分
		2. 该部分数据以CERTDATA作为标志
		3. 后面数据为两个字节存储接下来的数据长度，
			后面跟着数据内容
		4. 如： len(pubkey) pubkey
		5. 这种格式便于验证签名时对数据的解析
		6. 格式化后的数据存入formatcert.dat备用
*****************************************************/
void FormatCer()
{
	int i = 0;
	int len = 0;
	FILE *fp = '\0';
	FILE *f_pub = '\0';
	unsigned char Buff1[4098] = { '\0' };
	unsigned char Buff[5002] = { '\0' };
	int SizeofFile = 0;
	int num = 0;
	char clear[8] = { '\0' };
	char datapath[MAXPATH] = { '\0' };

	//************************
	strcpy(datapath, "E:\\Temp4\\formatcert.dat");
	//************************

	fp = fopen(datapath, "w+b");
	if (fp == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", datapath);
		exit(0);
	}

	// 将CERTDATA作为格式化开始标志
	strcpy((char *)Buff, "CERTDATA");      

	// 写入密文
	// 设置两个字节来表示长度
	Buff[8] = (unsigned char)((encrypted_length + 2) >> 8);
	Buff[9] = (unsigned char)((encrypted_length + 2) - (((encrypted_length + 1) >> 8) << 8));
	fwrite(Buff, strlen((char *)Buff), 1, fp);
	fclose(fp);
	memset(Buff, '\0', sizeof(Buff));

	fp = fopen(datapath, "a+b");
	if (fp == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", datapath);
		exit(0);
	}
	fseek(fp, 0, SEEK_END);
	fwrite(encrypted, encrypted_length, 1, fp);



	// 写入公钥
	f_pub = fopen(Public_PATH, "rb");
	if (f_pub == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", Public_PATH);
		exit(0);
	}
	fseek(f_pub, 0, SEEK_END);
	SizeofFile = ftell(f_pub);

	Buff[0] = (unsigned char)((SizeofFile + 2) >> 8);
	Buff[1] = (unsigned char)((SizeofFile + 2) - (((SizeofFile + 1) >> 8) << 8));
	fseek(f_pub, 0, SEEK_SET);
	fread(Buff1, SizeofFile, 1, f_pub);
	strcat((char *)Buff, (char *)Buff1);
	//printf("\nBUFF: %s", Buff);
	fseek(fp, 0, SEEK_END);
	fwrite(Buff, SizeofFile + 2, 1, fp);

	fclose(f_pub);
	fclose(fp);

	// 补齐8位
	fp = fopen(datapath, "a+b");
	if (fp == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", datapath);
		exit(0);
	}
	fseek(fp, 0, SEEK_END);
	SizeofFile = ftell(fp);
	
	num = 8 - (SizeofFile % 8);
	for (i = 0; i < num; i++)
	{
		clear[i] = (char)0x0;
	}
	fwrite(clear, num, 1, fp);
	fclose(fp);

	return;
}


/*****************************************************
	Insert_PE_Cer():
		1. 将格式化的整数插入原PE文件中
		2. 修改PE文件的安全目录RVA、SIZE来读取新的证书
		3. 修改文件名
*****************************************************/
void Insert_PE_Cer()
{
	unsigned char SecRVA[11] = { '\0' };
	unsigned char SecRVAt[11] = { '\0' };
	unsigned char SecSize[11] = { '\0' };
	unsigned char *tp = '\0';
	char tBuff[10001] = { '\0' };
	char checkSum[10] = { '\0' };
	int cirN = 0, yuN = 0;
	int secRVA = 0, secSize = 0;
	char clean[4] = { '\0' };
	char filename_0[50] = { '\0' };
	char path[MAXPATH] = { '\0' };
	char patht[MAXPATH] = { '\0' };
	char temp[MAXPATH] = { '\0' };
	char datapath[MAXPATH] = { '\0' };
	char name[MAXPATH] = { '\0' };
	int SizeofFile = 0;
	int SizeofPE = 0;
	int flag = 0;
	FILE *pFile = '\0';
	FILE *pt = '\0';
	FILE *pCer = '\0';

	// shan
	int i = 0;
	//

	strcpy(path, File_PATH);
	//************************
	strcpy(datapath, "E:\\Temp4\\formatcert.dat");
	strcpy(patht, "E:\\Temp4\\signed_PE.exe");
	//************************
	
	pFile = fopen(path, "r+b");
	if(pFile == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", path);
		exit(0);
	}
	pt = fopen(patht, "w+b");
	if(pt == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", patht);
		exit(0);
	}
	pCer = fopen(datapath, "rb");
	if(pCer == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", datapath);
		exit(0);
	}

	// 获取pe文件大小，使得证书插入至末尾
	fseek(pFile, 0, SEEK_END);
	SizeofPE = ftell(pFile);

	// 获取证书数据大小
	fseek(pCer, 0, SEEK_END);
	SizeofFile = ftell(pCer);
	fseek(pCer, 0, SEEK_SET);

	// 数据目录的安全目录前的数据至缓冲区中
	fseek(pFile, 0, SEEK_SET);
	fread(tBuff, 0x128, 1, pFile);   
	fwrite(tBuff, 0x128, 1, pt);
	fclose(pt);

	pt = fopen(patht, "a+b");
	if (pt == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", patht);
		exit(0);
	}
	
	fseek(pFile, 0x128, SEEK_SET);			// 读取安全目录
	fread(SecRVA, 0x04, 1, pFile);			// 获取SECURITY RVA

	strcpy((char *)SecRVAt, (char *)SecRVA);// 为了不影响SecRVA的值，使用SecRVAt来转换十进制整型
	secRVA = BigToSmall4(SecRVAt);			// 将rva转为十进制整型
	memset(SecRVAt, '\0', sizeof(SecRVAt));

	if (secRVA == 0)						// 若原文件中secRVA的值为0
	{
		SmalltoBig4(SecRVAt, secRVA);
		flag = 1;
	}
	else
	{
		flag = 0;
	}
	if (flag)
	{
		tp = SecRVAt;
	}
	else
	{
		tp = SecRVA;
	}
	fseek(pt, 0, SEEK_END);
	fwrite(tp, 0x04, 1, pt);			// RVA写入文件
	SmalltoBig4(SecSize, SizeofFile + 8);
	fwrite(SecSize, 0x04, 1, pt);			// 写入SecSize
	secSize = SizeofFile + 8;

	fseek(pFile, 0x130, SEEK_SET);
	cirN = (secRVA - 0x130) / 10000;		// 数据过大，分段复制至临时文件
	yuN = (secRVA - 0x130) % 10000;
	memset(tBuff, '\0', sizeof(tBuff));
	for (int i = 0; i < cirN; i++)
	{
		fread(tBuff, 10000, 1, pFile);
		fwrite(tBuff, 10000, 1, pt);
		memset(tBuff, '\0', 10001);
	}
	fread(tBuff, yuN, 1, pFile);
	fwrite(tBuff, yuN, 1, pt);

	strcpy(temp, (char *)SecSize);			// 根据证书格式，前4个字节为安全证书大小
	temp[4] = (char)0x00;					// 之后的四个字节为版本号0x00 0x02 0x02 0x00
	temp[5] = (char)0x02;
	temp[6] = (char)0x02;
	temp[7] = (char)0x00;
	fwrite(temp, 8, 1, pt);
	
	fseek(pt, 0, SEEK_END);
	memset(tBuff, '\0', sizeof(tBuff));		// 写入证书数据
	fread(tBuff, SizeofFile, 1, pCer);
	fwrite(tBuff, SizeofFile, 1, pt);

	fclose(pCer);
	fclose(pFile);
	fclose(pt);

	// 给文件重命名。保持原文件名字不动，签名后的文件命名为signed_filename.exe
	get_filename(path, name);
	strcat(path, "signed_");
	strcat(path, name);
	rename(patht, path);
	//remove(datapath);

	return;
}


// int型的四字节小端转大端
void SmalltoBig4(unsigned char *str, int num)
{
	int t1 = 0, t2 = 0;
	int num1 = 0, num2 = 0;
	int num3 = 0, num4 = 0;

	t1 = num >> 16;
	t2 = num - ((num >> 16) << 16);

	num1 = t1 >> 8;
	num2 = t1 - ((t1 >> 8) << 8);

	num3 = t2 >> 8;
	num4 = t2 - ((t2 >> 8) << 8);

	str[0] = (unsigned char)num4;
	str[1] = (unsigned char)num3;
	str[2] = (unsigned char)num2;
	str[3] = (unsigned char)num1;

	return;
}