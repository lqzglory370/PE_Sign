#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <windows.h>
#include <wintrust.h> 
#include "pesign.h"


char File_PATH[MAXPATH] = { "\0" };			// pe�ļ�����·��
char Public_PATH[MAXPATH] = { '\0' };		// ��Կ����·��
char Private_PATH[MAXPATH] = { '\0' };		// ˽Կ����·��
int SorV = 0;								// ѡ���ܣ�ǩ������֤
int Auto = 1;								// Ĭ���Զ�����RSA��˽Կ
unsigned char *pe_hash;						// pe�ļ��Ĺ�ϣֵ
pInfo inf;									// ǩ������Ϣ�ṹ��


int main(int argc, char* argv[])
{
	FILE *pkey = '\0';
	int flag = 0;
	char pTemp[30] = { '\0' };
	char CreatePri[MAXPATH] = { '\0' };
	char CreatePub[MAXPATH] = { '\0' };

	if (getOpts(argc, argv) == 1)
	{
		// �Զ�����RSA��˽Կ
		if (SorV == S_PE && Auto == 1)
		{
			// �趨˽Կ·������������
			strcpy(Private_PATH, "E:\\Temp4\\PrivateKey.pem");
			strcpy(CreatePri, "openssl genrsa -out ");
			strcat(CreatePri, Private_PATH);
			strcat(CreatePri, " 2048");

			// �趨��Կ·������������
			strcpy(Public_PATH, "E:\\Temp4\\PublicKey.pem");
			strcpy(CreatePub, "openssl rsa -in ");
			strcat(CreatePub, Private_PATH);
			strcat(CreatePub, " -outform PEM -pubout -out ");
			strcat(CreatePub, Public_PATH);

			// ����openssl������ֱ�����ɹ�Կ˽Կ
			system(CreatePri);
			system(CreatePub);
			printf("Create RSA Keys Success.\n");
		}
		// �������й�˽Կ�ļ�
		else if (S_PE && Auto == 0)
		{
			// �ж�˽Կ�Ƿ���ϸ�ʽ
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

			// �жϹ�Կ�Ƿ���ϸ�ʽ
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


	// ѡ����Ϊǩ��
	if (SorV)
	{
		printf("\n*****  Now begin to sign the PE file.  *****\n");

		// �����ȥchecksum�Ͱ�ȫĿ¼���peֵ
		printf("\n1. Get file hash except the checksum and securityDirectory.");
		File_Hash();				
		printf("\n\t[SUCCESS]\n");

		// ���pe�ļ���ԭ�е�֤����Ϣ
		printf("\n2. Clear file original certificate.");
		Clean_PE_Cer();				
		printf("\n\t[SUCCESS]\n");
		
		// ����ǩ����Ϣ
		printf("\n3. Generate singer information.");
		inf = SignInformation();	
		printf("\n\t[SUCCESS]\n");
		
		// ��ǩ����Ϣ��ʽ��
		printf("\n4. Format singer information.");
		FormatData();				
		printf("\n\t[SUCCESS]\n");
		
		// ��˽Կ���ܸ�ʽ�������Ϣ
		printf("\n5. Use the privatekey to encrypt PE hash and singer information.");
		rsa_pri_en();				
		printf("\n\t[SUCCESS]\n");
		
		// �����ɵ�֤���ļ���ʽ��
		printf("\n6. Format certificate data.");
		FormatCer();				
		printf("\n\t[SUCCESS]\n");
		
		// ����ʽ�����֤���ļ�����pe�ļ���
		printf("\n7. Insert the certificate in the PE file.");
		Insert_PE_Cer();			
		printf("\n\t[SUCCESS]\n");
		printf("\n*****  Signed Finish!  *****\n");
	}  

	// ѡ����Ϊ��֤
	else
	{
		printf("*****  Now begin to verify the PE file.  *****\n\n");
		
		// ��ȡǩ����pe�ļ��е�֤������
		printf("\n1. Extract the certificate from the signed file.");
		Extract_PE_Cer();			
		printf("\n\t[SUCCESS]\n");
		
		// ����֤���ʽ
		printf("\n2. Analy the certificate.");
		Analy_Cert_Data();			
		printf("\n\t[SUCCESS]\n");
		
		// ��֤����ʹ��rsa���ܲ���ʹ�ù�Կ����
		printf("\n3. Use the publickey to decrypt PE hash and siger information.");
		rsa_pub_de();				
		printf("\n\t[SUCCESS]\n");
		
		// ��ȡǩ������Ϣ����֤�ļ���ϣֵ���Ƿ�ƥ��
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
