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


struct t				// 时间戳结构体
{
	char year[5];		// 年
	char month[3];		// 月
	char day[3];		// 日
	char hour[3];		// 时
	char minute[3];		// 分
	char second[3];		// 秒
};

/*****************************************************
	pInfo SignInformation()：
		1. 要求签名者输入自己的信息对PE文件进行签名
		2. 要输入的信息有四项，分别是姓名、邮箱、签
			名时间与备注信息。其中签名时间为运行至此
			时自动获取当前时间生成。
		3. 若输入有误，可以重新填写内容
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

		// 要求签名者输入信息
		printf("\n------------------------------------------------\n");
		printf("\tPlease input the signer's information:\n");
		printf("\tName:\t\t");
		scanf("%s", inf->Name);

		printf("\tMail:\t\t");
		scanf("%s", inf->Mail);

		// 获取当前时间作为时间戳，生成TimeStamp字符串
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

		// 输出信息检查
		printf("\n\tPlease check the signer's information:\n");
		printf("\tName:\t\t%s\n", inf->Name);
		printf("\tMail:\t\t%s\n", inf->Mail);
		printf("\tTimeStamp:\t%s\n", inf->TimeStamp);
		printf("\tComment:\t%s\n", inf->Comment);
		printf("\n\t\tRight? (Y/N):\t");

		// 检查信息是否有误，可重新填写
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
		1. 格式化数据包括PE文件的摘要值和
			签名者信息两部分
		2. 该部分数据以FILEDATA作为标志
		3. 后面数据为一个字节存储接下来
			的数据长度，后面跟着数据内容
		4. 如： len(pe_hash) pe_hash
		5. 这种格式便于验证签名时对数据的解析
		6. 格式化后的数据存入formatdata.dat
			备用
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

	// 将FD作为格式化开始标志
	strcpy((char *)Buff, "FILEDATA");						

	// pe_hash处理部分
	Buff[strlen((char *)Buff)] = (unsigned char)(SHA256_DIGEST_LENGTH + 1);
	len = strlen((char*)Buff);

	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		Buff[len + i] = (unsigned char)pe_hash[i];
	}
	fwrite(Buff, strlen((char *)Buff), 1, fp);
	memset(Buff, '\0', sizeof(Buff));
	fclose(fp);

	// signer_info处理部分，含name、mail、timestamp、comment四部分
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