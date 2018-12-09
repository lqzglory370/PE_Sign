#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wintrust.h> 
#include <openssl/sha.h>
#include <time.h>
#include "pesign.h"

extern char File_PATH[];
extern int SorV;
extern unsigned char *pe_hash;
extern pInfo inf;
SYSTEMTIME T;


struct t				// ʱ����ṹ��
{
	char year[5];		// ��
	char month[3];		// ��
	char day[3];		// ��
	char hour[3];		// ʱ
	char minute[3];		// ��
	char second[3];		// ��
};

/*****************************************************
	pInfo SignInformation()��
		1. Ҫ��ǩ���������Լ�����Ϣ��PE�ļ�����ǩ��
		2. Ҫ�������Ϣ������ֱ������������䡢ǩ
			��ʱ���뱸ע��Ϣ������ǩ��ʱ��Ϊ��������
			ʱ�Զ���ȡ��ǰʱ�����ɡ�
		3. ���������󣬿���������д����
*****************************************************/
pInfo SignInformation(void)
{
	char flag = '\0';
	int timeStamp[6] = {0};
	char time11[20] = { '\0' };
	struct t *t1 = NULL;
	t1 = (struct t *)malloc(sizeof(struct t));

	while (1)
	{
		inf = (pInfo)malloc(sizeof(struct SignerInfo));
		memset(inf, '\0', sizeof(struct SignerInfo));

		// Ҫ��ǩ����������Ϣ
		printf("\n------------------------------------------------\n");
		printf("\tPlease input the signer's information:\n");
		printf("\tName:\t\t");
		scanf("%s", inf->Name);

		printf("\tMail:\t\t");
		scanf("%s", inf->Mail);

		// ��ȡ��ǰʱ����Ϊʱ���������TimeStamp�ַ���
		GetLocalTime(&(T));
		timeStamp[0] = T.wYear;
		timeStamp[1] = T.wMonth;
		timeStamp[2] = T.wDay;
		timeStamp[3] = T.wHour;
		timeStamp[4] = T.wMinute;
		timeStamp[5] = T.wSecond;
		_itoa(timeStamp[0], t1->year, 10);
		_itoa(timeStamp[1], t1->month, 10);
		_itoa(timeStamp[2], t1->day, 10);
		_itoa(timeStamp[3], t1->hour, 10);
		_itoa(timeStamp[4], t1->minute, 10);
		_itoa(timeStamp[5], t1->second, 10);
		strcpy(time11, t1->year);
		time11[strlen(time11)] = '/';
		strcat(time11, t1->month);
		time11[strlen(time11)] = '/';
		strcat(time11, t1->day);
		time11[strlen(time11)] = ' ';
		strcat(time11, t1->hour);
		time11[strlen(time11)] = ':';
		strcat(time11, t1->minute);
		time11[strlen(time11)] = ':';
		strcat(time11, t1->second);
		time11[strlen(time11)] = '\0';
		strcpy(inf->TimeStamp, time11);
		printf("\tTimeStamp:\t%s\n", inf->TimeStamp);

		printf("\tComment:\t");
		scanf("%s", inf->Comment);

		setbuf(stdin, NULL);

		// �����Ϣ���
		printf("\n\tPlease check the signer's information:\n");
		printf("\tName:\t\t%s\n", inf->Name);
		printf("\tMail:\t\t%s\n", inf->Mail);
		printf("\tTimeStamp:\t%s\n", inf->TimeStamp);
		printf("\tComment:\t%s\n", inf->Comment);
		printf("\n\t\tRight? (Y/N):\t");

		// �����Ϣ�Ƿ����󣬿�������д
		while (1)
		{
			setbuf(stdin, NULL);
			scanf("%c", &flag);
			if (flag == 'Y' || flag == 'y')
			{
				printf("------------------------------------------------\n\n");
				return inf;
			}
			else if (flag == 'N' || flag == 'n')
			{
				printf("\nPlease input the information again.\n");
				free(inf);
				fflush(stdin);
				break;
			}
			else
			{
				printf("\nPlease check your input.\n");
			}
		}
	}

	return inf;
}


/*****************************************************
	FormatData():
		1. ��ʽ�����ݰ���PE�ļ���ժҪֵ��
			ǩ������Ϣ������
		2. �ò���������FILEDATA��Ϊ��־
		3. ��������Ϊһ���ֽڴ洢������
			�����ݳ��ȣ����������������
		4. �磺 len(pe_hash) pe_hash
		5. ���ָ�ʽ������֤ǩ��ʱ�����ݵĽ���
		6. ��ʽ��������ݴ���formatdata.dat
			����
*****************************************************/
void FormatData(void)
{
	int i = 0;
	int len = 0;
	FILE *fp = '\0';
	unsigned char Buff[300] = {'\0'};
	int SizeofFile = 0;
	char tempPath[MAXPATH] = { '\0' };

	//*****************************************************
	strcpy(tempPath, "E:\\Temp4\\formatdata.dat");
	//*****************************************************

	fp = fopen(tempPath, "w+b");
	if (fp == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", tempPath);
		exit(0);
	}

	// ��FD��Ϊ��ʽ����ʼ��־
	strcpy((char *)Buff, "FILEDATA");						

	// pe_hash������
	Buff[strlen((char *)Buff)] = (unsigned char)(SHA256_DIGEST_LENGTH + 1);
	len = strlen((char*)Buff);

	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		Buff[len + i] = (unsigned char)pe_hash[i];
	}
	fwrite(Buff, strlen((char *)Buff), 1, fp);
	memset(Buff, '\0', sizeof(Buff));
	fclose(fp);

	// signer_info�����֣���name��mail��timestamp��comment�Ĳ���
	fp = fopen(tempPath, "a+b");
	if (fp == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", tempPath);
		exit(0);
	}

	len = strlen(inf->Name);
	Buff[0] = (char)(len + 1);
	strcpy((char *)(Buff + sizeof(unsigned char)), inf->Name);
	fseek(fp, 0, SEEK_END);
	fwrite(Buff, strlen((char *)Buff), 1, fp);
	memset(Buff, '\0', sizeof(Buff));

	len = strlen(inf->Mail);
	Buff[0] = (char)(len + 1);
	strcpy((char *)(Buff + sizeof(unsigned char)), inf->Mail);
	fseek(fp, 0, SEEK_END);
	fwrite(Buff, strlen((char *)Buff), 1, fp);
	memset(Buff, '\0', sizeof(Buff));

	len = strlen(inf->TimeStamp);
	Buff[0] = (char)(len + 1);
	strcpy((char *)(Buff + sizeof(unsigned char)), inf->TimeStamp);
	fseek(fp, 0, SEEK_END);
	fwrite(Buff, strlen((char *)Buff), 1, fp);
	memset(Buff, '\0', sizeof(Buff));

	len = strlen(inf->Comment);
	Buff[0] = (char)(len + 1);
	strcpy((char *)(Buff + sizeof(unsigned char)), inf->Comment);
	fseek(fp, 0, SEEK_END);
	fwrite(Buff, strlen((char *)Buff), 1, fp);
	memset(Buff, '\0', sizeof(Buff));

	fclose(fp);
	return;
}