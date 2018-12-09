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
		1. ͨ����Կ��������
		2. �������ܺ�����ģ���ȡ���е�PE�ļ�ժҪ
			��ǩ������Ϣ����������
		3. ���ǩ������Ϣ����
		4. У��PE��ժҪֵ�����ж��ļ��Ƿ��޸�
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

	// ͨ��FILEDATA�ж������Ƿ���
	fseek(fdata, 0x0, SEEK_SET);
	fread(t1, 0x08, 1, fdata);
	if (strcmp(t1, "FILEDATA") != 0)
	{
		printf("The data had been broken.\n");
		return -1;
	}
	memset(t1, '\0', sizeof(t1));

	// ��ȡժҪ���ȣ�ͨ�����Ȼ�ȡժҪֵ
	fread(temp, 0x01, 1, fdata);
	size = atoi2(temp);
	size = size - 1;
	pe_hash_ex = (unsigned char *)malloc(sizeof(unsigned char) * (SHA256_DIGEST_LENGTH + 1));
	memset(pe_hash_ex, '\0', SHA256_DIGEST_LENGTH + 1);
	fread(pe_hash_ex, size, 1, fdata);
	memset(temp, '\0', sizeof(temp));

	// ��ʼ��ǩ������Ϣ�ṹ��
	inf = (pInfo)malloc(sizeof(struct SignerInfo));
	memset(inf, '\0', sizeof(struct SignerInfo));

	// ��ȡǩ������Ϣ�������ĳ��ȣ�����ȡ����
	fread(temp, 0x01, 1, fdata);
	size = atoi2(temp);
	size = size - 1;
	fread(inf->Name, size, 1, fdata);
	memset(temp, '\0', sizeof(temp));

	// ��ȡǩ������Ϣ������ĳ��ȣ�����ȡ����
	fread(temp, 0x01, 1, fdata);
	size = atoi2(temp);
	size = size - 1;
	fread(inf->Mail, size, 1, fdata);
	memset(temp, '\0', sizeof(temp));

	// ��ȡǩ������Ϣ��ʱ����ĳ��ȣ�����ȡʱ���
	fread(temp, 0x01, 1, fdata);
	size = atoi2(temp);
	size = size - 1;
	fread(inf->TimeStamp, size, 1, fdata);
	memset(temp, '\0', sizeof(temp));

	// ��ȡǩ������Ϣ�б�ע��Ϣ�ĳ��ȣ�����ȡ��ע��Ϣ
	fread(temp, 0x01, 1, fdata);
	size = atoi2(temp);
	size = size - 1;
	fread(inf->Comment, size, 1, fdata);
	memset(temp, '\0', sizeof(temp));

	// ���ǩ������Ϣ
	printf("\n\tThe signer's information:\n");
	printf("\tName:\t\t%s\n", inf->Name);
	printf("\tMail:\t\t%s\n", inf->Mail);
	printf("\tTimeStamp:\t%s\n", inf->TimeStamp);
	printf("\tComment:\t%s\n", inf->Comment);

	fclose(fdata);

	// ����PE�ļ���ϣֵ
	File_Hash();

	// �жϼ���Ĺ�ϣֵ���֤������ȡ�Ĺ�ϣֵ�Ƿ�һ��
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		if (pe_hash_ex[i] != pe_hash[i])
		{
			// ����һ�����������
			printf("[ERROR] The file had been changed.\n");
			remove(datapath);
			return -1;
		}
	}
	remove(datapath);
	printf("\tThe file hasn't been changed.\n");

	return 1;
}