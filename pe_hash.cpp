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
		1. ����PE�ļ��ṹ��
		2. ���Ƴ�ȥУ��͡�����Ŀ¼�а�ȫĿ¼���
			��ȫĿ¼ָ���֤�鲿������������ݵ�
			��ʱ�ļ���
		3. ����SHA256�㷨��������ʱ�ļ�hashֵ��Ϊ
			��PE�ļ���ժҪ��
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

	// ����ȥchecksum������Ŀ¼��SECURITY��������֤���������ݴ�����ʱ�ļ�
	fread(tBuff, 0xD8, 1, pFile);		 // 0xD8Ϊchecksum���ļ�ƫ��
	fseek(pFile, 0xDC, SEEK_SET);		 // ��ȥchecksum��ռ���ĸ��ֽ�
	fwrite(tBuff, 0xD8, 1, pt);			 // ��checksum֮ǰ�����ݴ浽��ʱ�ļ���
	fclose(pt);

	pt = fopen(tempPath, "a+b");
	if (pt == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", tempPath);
		exit(0);
	}
	memset(tBuff, '\0', sizeof(tBuff));  // �����ʱ������
	fread(tBuff, 0x4C, 1, pFile);		 // 0xDC+0x4C= 0x128  ����ȡchecksum��������Ŀ¼�İ�ȫĿ¼ǰ����������������
	fwrite(tBuff, 0x4C, 1, pt);
	fseek(pFile, 0x128, SEEK_SET);		 // ��ȡ��ȫĿ¼
	fread(SecRVA, 0x04, 1, pFile);		 // ��ȡSECURITY RVA
	fread(SecSize, 0x04, 1, pFile);		 // ��ȡSECURITY SIZE
	
	secRVA = BigToSmall4(SecRVA);		 // ��rva��size��תΪʮ��������
	secSize = BigToSmall4(SecSize);
	cirN = (secRVA - 0x130) / 10000;	 // ���ݹ��󣬷ֶθ�������ʱ�ļ�
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
	
	
	// ������ʱ�ļ�hashֵ��hash�㷨����SHA256
	pt = fopen(tempPath, "rb");			 // ��ֻ�����´���ʱ�ļ�
	if (pt == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", tempPath);
		exit(0);
	}

	fseek(pt, 0, SEEK_END);				 // ��ȡ�ļ���С
	SizeofFile = ftell(pt);

	fileBuff = (unsigned char *)malloc((SizeofFile + 100) * sizeof(unsigned char));
	memset(fileBuff, '\0', (SizeofFile + 100) * sizeof(unsigned char));
	pe_hash = (unsigned char *)malloc(sizeof(unsigned char) * (SHA256_DIGEST_LENGTH + 1));
	memset(pe_hash, '\0', SHA256_DIGEST_LENGTH + 1);

	fseek(pt, 0, SEEK_SET);
	fread(fileBuff, SizeofFile, 1, pt);

	myHash256(fileBuff, SizeofFile);	 // ����PE�ļ���ϣֵ
	pe_hash[SHA256_DIGEST_LENGTH] = '\0';
	
	fclose(pt);
	remove(tempPath);					 // ɾ����ʱ�ļ�

	return;
}




/*****************************************************
	Clean_PE_Cer():
		1. ���PE�ļ�ԭ��֤����Ϣ
		2. ���ԭPE�ļ�����֤�飬��ͨ��isSigned()
			���������ú���
		3. ������֤�飬�����SECURITY SIZE��
			��SECURITY RVAָ���ƫ��֤������
			�����ԭ֤����Ϣ
		4. Ϊ�˺���д�����ݷ��㣬��û�����
			SECURITY RVA��ֵ
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

	// ���ļ�û��ǩ����Ϣ���������
	if (isSigned(File_PATH) == 0)
	{
		printf("\n\t��The file hasn't been signed.\n");
		return;
	}

	// ���ļ���ǩ����Ϣ������ļ�ǩ��
	printf("\n\t��The file has been signed!\n");
	printf("\t��Now begin to clear the sign!\n");

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
	fread(tBuff, 0x128, 1, pFile);		// ����Ŀ¼�İ�ȫĿ¼ǰ����������������
	fwrite(tBuff, 0x128, 1, pt);		// д����ʱ�ļ�
	fclose(pt);

	pt = fopen(patht, "a+b");
	fseek(pFile, 0x128, SEEK_SET);		// ��ȡ��ȫĿ¼
	fread(SecRVA, 0x04, 1, pFile);		// ��ȡSECURITY RVA
	fread(SecSize, 0x04, 1, pFile);		// ��ȡSECURITY SIZE
	fwrite(SecRVA, 0x04, 1, pt);		// ��SECURITY RVA������ֱ��д����ʱ�ļ�
	fwrite(clean, sizeof(clean), 1, pt);// ��������SECURITY SIZEд����ʱ�ļ�

	secRVA = BigToSmall4(SecRVA);		// ��rva��size��תΪʮ��������
	secSize = BigToSmall4(SecSize);

	cirN = (secRVA - 0x130) / 10000;	// ���ݹ��󣬷ֶθ�������ʱ�ļ�
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

	//��ԭ�ļ�����Ϊold_filename.exe�����ԭ��֤�����ļ�����Ϊfilename.exe
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
		1. ͨ����ȡ����·���ļ�����ȡ
			�䰲ȫĿ¼SIZE���ж��Ƿ���ԭǩ��
		2. û��ͨ����ȫĿ¼RVA�ж�����Ϊ���PE
			�ļ��İ�ȫĿ¼��ʱ��RVA����������
			����д���µ�֤����Ϣ
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

	fseek(p, 0x128, SEEK_SET);			// ��ȡ��ȫĿ¼
	fread(SecRVA, 0x04, 1, p);			// ��ȡSECURITY RVA
	fread(SecSize, 0x04, 1, p);
	secRVA = BigToSmall4(SecRVA);		// ��rva��size��תΪʮ��������
	secSize = BigToSmall4(SecSize);

	if (secSize == 0)					// ��secSize��Ϊ0���򲻴���ǩ��
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
		1. ͨ������·����ȡ�ļ������ļ�·��
		2. ���ú�����ԭpath·����Ϊ���ļ�
			�����ļ������·�����֣�nameΪ
			���ļ����ļ���
		3. �ú��������޸���ʱ�ļ����ļ���
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


// ���ļ���ϣ���Ϊʮ��������ʽ
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


// �ַ�������
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


// ת��Ϊ16����
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


// �ַ���ת����
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


// �޸Ĵ�С�ˣ����ֽڣ�
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


// ����openssl�����ļ���ϣֵ���㷨Ϊsha256
void myHash256(unsigned char *orgStr, long size)
{
	SHA256_CTX c;
	unsigned char md[SHA256_DIGEST_LENGTH + 1] = { '\0' };

	SHA256_Init(&c);
	SHA256_Update(&c, orgStr, size);
	SHA256_Final(md, &c);
	strcpy((char *)pe_hash, (char *)md);		// ����ϣֵ������ȫ�ֱ���pe_hash��
	OPENSSL_cleanse(&c, sizeof(c));

	return;
}


