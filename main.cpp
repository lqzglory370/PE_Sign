#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <windows.h>
#include <wintrust.h> 
#include "pesign.h"


char File_PATH[MAXPATH] = { "\0" };			// pe文件绝对路径
char Public_PATH[MAXPATH] = { '\0' };		// 公钥绝对路径
char Private_PATH[MAXPATH] = { '\0' };		// 私钥绝对路径
int SorV = 0;								// 选择功能，签名或验证
int Auto = 1;								// 默认自动生成RSA公私钥
unsigned char *pe_hash;						// pe文件的哈希值
pInfo inf;									// 签名者信息结构体


int main(int argc, char* argv[])
{
	FILE *pkey = '\0';
	int flag = 0;
	char pTemp[30] = { '\0' };
	char CreatePri[MAXPATH] = { '\0' };
	char CreatePub[MAXPATH] = { '\0' };

	if (getOpts(argc, argv) == 1)
	{
		// 自动生成RSA公私钥
		if (SorV == S_PE && Auto == 1)
		{
			// 设定私钥路径与生成命令
			strcpy(Private_PATH, "E:\\Temp4\\PrivateKey.pem");
			strcpy(CreatePri, "openssl genrsa -out ");
			strcat(CreatePri, Private_PATH);
			strcat(CreatePri, " 2048");

			// 设定公钥路径与生成命令
			strcpy(Public_PATH, "E:\\Temp4\\PublicKey.pem");
			strcpy(CreatePub, "openssl rsa -in ");
			strcat(CreatePub, Private_PATH);
			strcat(CreatePub, " -outform PEM -pubout -out ");
			strcat(CreatePub, Public_PATH);

			// 调用openssl命令行直接生成公钥私钥
			system(CreatePri);
			system(CreatePub);
			printf("Create RSA Keys Success.\n");
		}
		// 导入已有公私钥文件
		else if (S_PE && Auto == 0)
		{
			// 判断私钥是否符合格式
			pkey = fopen(Private_PATH, "rb");
			if (pkey == NULL)
			{
				printf("[ERROR] Cannot open the file: %s\n", Private_PATH);
				fclose(pkey);
				exit(0);
			}
			fseek(pkey, 0, SEEK_SET);
			fread(pTemp, 31, 1, pkey);
			if (strcmp(pTemp, "-----BEGIN RSA PRIVATE KEY-----") != 0)
			{
				printf("[ERROR] The Private Key File is Wrong.\n");
				fclose(pkey);
				exit(0);
			}
			fclose(pkey);
			memset(pTemp, '\0', sizeof(pTemp));

			// 判断公钥是否符合格式
			pkey = fopen(Public_PATH, "rb");
			if (pkey == NULL)
			{
				printf("[ERROR] Cannot open the file: %s\n", Public_PATH);
				fclose(pkey);
				exit(0);
			}
			fseek(pkey, 0, SEEK_SET);
			fread(pTemp, 26, 1, pkey);
			if (strcmp(pTemp, "-----BEGIN PUBLIC KEY-----") != 0)
			{
				printf("[ERROR] The Public Key File is Wrong.\n");
				fclose(pkey);
				exit(0);
			}
			fclose(pkey);
		}
	}
	else
	{
		printf("[ERROR] Please use -h to get help.\n");
		exit(0);
	}


	// 选择功能为签名
	if (SorV)
	{
		printf("\n*****  Now begin to sign the PE file.  *****\n");

		// 计算除去checksum和安全目录项的pe值
		printf("\n1. Get file hash except the checksum and securityDirectory.");
		File_Hash();				
		printf("\n\t[SUCCESS]\n");

		// 清除pe文件中原有的证书信息
		printf("\n2. Clear file original certificate.");
		Clean_PE_Cer();				
		printf("\n\t[SUCCESS]\n");
		
		// 生成签名信息
		printf("\n3. Generate singer information.");
		inf = SignInformation();	
		printf("\n\t[SUCCESS]\n");
		
		// 将签名信息格式化
		printf("\n4. Format singer information.");
		FormatData();				
		printf("\n\t[SUCCESS]\n");
		
		// 用私钥加密格式化后的信息
		printf("\n5. Use the privatekey to encrypt PE hash and singer information.");
		rsa_pri_en();				
		printf("\n\t[SUCCESS]\n");
		
		// 将生成的证书文件格式化
		printf("\n6. Format certificate data.");
		FormatCer();				
		printf("\n\t[SUCCESS]\n");
		
		// 将格式化后的证书文件插入pe文件中
		printf("\n7. Insert the certificate in the PE file.");
		Insert_PE_Cer();			
		printf("\n\t[SUCCESS]\n");
		printf("\n*****  Signed Finish!  *****\n");
	}  

	// 选择功能为验证
	else
	{
		printf("*****  Now begin to verify the PE file.  *****\n\n");
		
		// 提取签名后pe文件中的证书数据
		printf("\n1. Extract the certificate from the signed file.");
		Extract_PE_Cer();			
		printf("\n\t[SUCCESS]\n");
		
		// 分析证书格式
		printf("\n2. Analy the certificate.");
		Analy_Cert_Data();			
		printf("\n\t[SUCCESS]\n");
		
		// 对证书中使用rsa加密部分使用公钥解密
		printf("\n3. Use the publickey to decrypt PE hash and siger information.");
		rsa_pub_de();				
		printf("\n\t[SUCCESS]\n");
		
		// 提取签名者信息并验证文件哈希值看是否匹配
		printf("\n4. Analy the signer's information and verify file hash.");
		flag = Analy_Signer_Data(); 
		if (flag == 1)
		{
			printf("\n\t[SUCCESS]\n");
			printf("\n*****  File Validation Successful.  *****\n");
		}
		else
		{
			printf("\n[ERROR] The file validation false.\n");
		}
	}

	return 0;
}
