#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wintrust.h> 
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include "pesign.h"
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

extern char File_PATH[];
extern int SorV;
extern unsigned char *pe_hash;

/*****************************************************
	File_Hash():
		1. 分析PE文件结构。
		2. 复制除去校验和、数据目录中安全目录项和
			安全目录指向的证书部分内容外的数据到
			临时文件。
		3. 采用SHA256算法，计算临时文件hash值作为
			该PE文件的摘要。
*****************************************************/
void File_Hash(void)
{ 
	unsigned char SecRVA[11] = { '\0' };
	unsigned char SecSize[11] = { '\0' };
	char tBuff[10001] = { '\0' };
	char checkSum[10] = { '\0' };
	unsigned char *fileBuff = '\0';
	int SizeofFile = 0;
	int cirN = 0, yuN = 0;
	int secRVA = 0, secSize = 0;
	FILE *pFile = '\0';
	FILE *pt = '\0';
	char tempPath[MAXPATH] = { '\0' };

	//*****************************************************
	strcpy(tempPath, "E:\\Temp4\\tempp.txt");
	//*****************************************************

	pFile = fopen(File_PATH, "rb");
	pt = fopen(tempPath, "w+b");
	if (pFile == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", File_PATH);
		exit(0);
	}
	if (pt == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", tempPath);
		exit(0);
	}

	// 将除去checksum和数字目录中SECURITY项与属性证书区的数据存入临时文件
	fread(tBuff, 0xD8, 1, pFile);		 // 0xD8为checksum的文件偏移
	fseek(pFile, 0xDC, SEEK_SET);		 // 除去checksum所占的四个字节
	fwrite(tBuff, 0xD8, 1, pt);			 // 将checksum之前的数据存到临时文件里
	fclose(pt);

	pt = fopen(tempPath, "a+b");
	if (pt == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", tempPath);
		exit(0);
	}
	memset(tBuff, '\0', sizeof(tBuff));  // 清空临时缓冲区
	fread(tBuff, 0x4C, 1, pFile);		 // 0xDC+0x4C= 0x128  即读取checksum后至数据目录的安全目录前的数据至缓冲区中
	fwrite(tBuff, 0x4C, 1, pt);
	fseek(pFile, 0x128, SEEK_SET);		 // 读取安全目录
	fread(SecRVA, 0x04, 1, pFile);		 // 获取SECURITY RVA
	fread(SecSize, 0x04, 1, pFile);		 // 获取SECURITY SIZE
	
	secRVA = BigToSmall4(SecRVA);		 // 将rva与size其转为十进制整型
	secSize = BigToSmall4(SecSize);
	cirN = (secRVA - 0x130) / 10000;	 // 数据过大，分段复制至临时文件
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

	fclose(pFile);
	fclose(pt);
	
	
	// 计算临时文件hash值，hash算法采用SHA256
	pt = fopen(tempPath, "rb");			 // 以只读重新打开临时文件
	if (pt == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", tempPath);
		exit(0);
	}

	fseek(pt, 0, SEEK_END);				 // 获取文件大小
	SizeofFile = ftell(pt);

	fileBuff = (unsigned char *)malloc((SizeofFile + 100) * sizeof(unsigned char));
	memset(fileBuff, '\0', (SizeofFile + 100) * sizeof(unsigned char));
	pe_hash = (unsigned char *)malloc(sizeof(unsigned char) * (SHA256_DIGEST_LENGTH + 1));
	memset(pe_hash, '\0', SHA256_DIGEST_LENGTH + 1);

	fseek(pt, 0, SEEK_SET);
	fread(fileBuff, SizeofFile, 1, pt);

	myHash256(fileBuff, SizeofFile);	 // 计算PE文件哈希值
	pe_hash[SHA256_DIGEST_LENGTH] = '\0';
	
	fclose(pt);
	remove(tempPath);					 // 删除临时文件

	return;
}




/*****************************************************
	Clean_PE_Cer():
		1. 清除PE文件原有证书信息
		2. 如果原PE文件不含证书，则通过isSigned()
			函数跳过该函数
		3. 若含有证书，则清除SECURITY SIZE项
			与SECURITY RVA指向的偏移证书数据
			来清除原证书信息
		4. 为了后期写入数据方便，并没有清除
			SECURITY RVA的值
*****************************************************/
void Clean_PE_Cer(void)
{
	unsigned char SecRVA[11] = { '\0' };
	unsigned char SecSize[11] = { '\0' };
	char tBuff[10001] = { '\0' };
	char checkSum[10] = { '\0' };
	int cirN = 0, yuN = 0;
	int secRVA = 0, secSize = 0;
	char clean[4] = { '\0' };
	char filename_0[50] = { '\0' };
	char path[MAXPATH] = { '\0' };
	char patht[MAXPATH] = { '\0' };
	char ptemp[MAXPATH] = { '\0' };
	char name[MAXPATH] = { '\0' };
	FILE *pFile = '\0';
	FILE *pt = '\0';

	strcpy(path, File_PATH);
	//*****************************************************
	strcpy(patht, "E:\\Temp4\\temp_clean.exe");
	//*****************************************************

	// 该文件没有签名信息，不需清除
	if (isSigned(File_PATH) == 0)
	{
		printf("\n\t☆The file hasn't been signed.\n");
		return;
	}

	// 该文件有签名信息，清除文件签名
	printf("\n\t☆The file has been signed!\n");
	printf("\t☆Now begin to clear the sign!\n");

	pFile = fopen(path, "r+b");
	pt = fopen(patht, "w+b");
	if (pFile == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", path);
		exit(0);
	}
	if (pt == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", patht);
		exit(0);
	}

	fseek(pFile, 0, SEEK_SET);
	fread(tBuff, 0x128, 1, pFile);		// 数据目录的安全目录前的数据至缓冲区中
	fwrite(tBuff, 0x128, 1, pt);		// 写入临时文件
	fclose(pt);

	pt = fopen(patht, "a+b");
	fseek(pFile, 0x128, SEEK_SET);		// 读取安全目录
	fread(SecRVA, 0x04, 1, pFile);		// 获取SECURITY RVA
	fread(SecSize, 0x04, 1, pFile);		// 获取SECURITY SIZE
	fwrite(SecRVA, 0x04, 1, pt);		// 将SECURITY RVA保留，直接写入临时文件
	fwrite(clean, sizeof(clean), 1, pt);// 将清零后的SECURITY SIZE写入临时文件

	secRVA = BigToSmall4(SecRVA);		// 将rva与size其转为十进制整型
	secSize = BigToSmall4(SecSize);

	cirN = (secRVA - 0x130) / 10000;	// 数据过大，分段复制至临时文件
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
	fclose(pFile);
	fclose(pt);

	//将原文件命名为old_filename.exe，清除原有证书后的文件命名为filename.exe
	strcpy(ptemp, path);
	get_filename(path, name);
	strcat(path, "old_");
	strcat(path, name);
	rename(ptemp, path);
	rename(patht, ptemp);

	return;
}


/*****************************************************
	isSigned(char *path):
		1. 通过读取参数路径文件，获取
			其安全目录SIZE来判断是否含有原签名
		2. 没有通过安全目录RVA判断是因为清除PE
			文件的安全目录项时，RVA保留，方便
			后期写入新的证书信息
*****************************************************/
int isSigned(char *path)
{
	FILE *p = '\0';
	int secRVA = -1, secSize = -1;
	unsigned char *SecRVA;
	unsigned char *SecSize;

	SecRVA = (unsigned char *)malloc(sizeof(unsigned char) * 5);
	memset(SecRVA, '\0', 5);
	SecSize = (unsigned char *)malloc(sizeof(unsigned char) * 5);
	memset(SecSize, '\0', 5);

	p = fopen(path, "rb");
	if (p == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", path);
		exit(0);
	}

	fseek(p, 0x128, SEEK_SET);			// 读取安全目录
	fread(SecRVA, 0x04, 1, p);			// 获取SECURITY RVA
	fread(SecSize, 0x04, 1, p);
	secRVA = BigToSmall4(SecRVA);		// 将rva与size其转为十进制整型
	secSize = BigToSmall4(SecSize);

	if (secSize == 0)					// 若secSize均为0，则不存在签名
	{
		fclose(p);
		return 0;
	}
	else
	{
		fclose(p);
		return 1;
	}
}


/*****************************************************
	get_filename(char *path, char *name):
		1. 通过绝对路径获取文件名与文件路径
		2. 经该函数后，原path路径变为该文件
			除了文件名外的路径部分；name为
			该文件的文件名
		3. 该函数方便修改临时文件的文件名
*****************************************************/
void get_filename(char *path, char *name)
{
	int i = 0, j = 0;
	for (i = 0; path[i]; i++)
	{
		if (path[i] == '\\')
		{
			j = i;
		}
	}

	strcpy(name, &path[j + 1]);
	path[j + 1] = '\0';
	memset(&path[j + 2], '\0', strlen(&path[j + 2]));

	return;
}


// 将文件哈希输出为十六进制形式
void printHash(unsigned char *md, int len)
{
	int i = 0;
	for (i = 0; i < len; i++)
	{
		printf("%02x", md[i]);
	}
	printf("\n");
	return;
}


// 字符串倒置
void reversestr(char *source, char *target, unsigned int length)
{
	unsigned int i = 0;

	for (i = 0; i < length; i++)
	{
		target[i] = source[length - 1 - i];
	}
	target[i] = 0;

	return;
}


// 转换为16进制
void tohex(unsigned long num, char *hexStr)
{
	unsigned long n = num;
	char hextable[] = "0123456789ABCDEF";
	char temphex[16] = { '\0' };
	char hex[16] = { '\0' };
	unsigned long int i = 0;

	while (n)
	{
		temphex[i++] = hextable[n % 16];
		n /= 16;
	}
	temphex[i] = 0;
	reversestr(temphex, hex, i);
	strcpy(hexStr, hex);

	return;
}


// 字符串转整型
long int atoi1(char *str)
{
	int value = 0;
	int sign = 1;
	int radix = 0;


	if (*str == '-')
	{
		sign = -1;
		str++;
	}
	if (*str == '0' && (*(str + 1) == 'x' || *(str + 1) == 'X'))
	{
		radix = 16;
		str += 2;
	}
	else if (*str == '0')
	{
		radix = 8;
		str++;
	}
	else
		radix = 10;

	while (*str)
	{
		if (radix == 16)
		{
			if (*str >= '0' && *str <= '9')
				value = value * radix + *str - '0';
			else if (*str >= 'A' && *str <= 'F')
				value = value * radix + *str - 'A' + 10;
			else if (*str >= 'a' && *str <= 'f')
				value = value * radix + *str - 'a' + 10;
		}
		else
			value = value * radix + *str - '0';
		str++;
	}

	return sign * value;
}


// 修改大小端（四字节）
int BigToSmall4(unsigned char *str)
{
	int i = 0;
	unsigned char cTemp = '\0';
	int num = 0;
	unsigned char str2[10] = { '\0' };
	unsigned char ct[20] = { '\0' };

	for (i = 0; i < 2; i++)
	{
		cTemp = str[i];
		str[i] = str[4 - i - 1];
		str[4 - i - 1] = cTemp;
	}

	for (i = 0; i < 0x04; i++)
	{
		if ((unsigned int)str[i] <= 0x0F && (unsigned int)str[i] > 0)
		{
			strcat((char *)str2, "0");
		}
		tohex((unsigned int)str[i], (char *)ct);
		strcat((char *)str2, (char *)ct);
	}

	if (str2[0] == '\0')
	{
		str2[0] = '0';
	}

	memset(str, '\0', sizeof(str));

	strcat((char *)str, "0x");
	strcat((char *)str, (char *)str2);
	num = atoi1((char *)str);

	return num;
}


// 调用openssl计算文件哈希值，算法为sha256
void myHash256(unsigned char *orgStr, long size)
{
	SHA256_CTX c;
	unsigned char md[SHA256_DIGEST_LENGTH + 1] = { '\0' };

	SHA256_Init(&c);
	SHA256_Update(&c, orgStr, size);
	SHA256_Final(md, &c);
	strcpy((char *)pe_hash, (char *)md);		// 将哈希值保存至全局变量pe_hash里
	OPENSSL_cleanse(&c, sizeof(c));

	return;
}


