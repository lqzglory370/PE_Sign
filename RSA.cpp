#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wintrust.h> 
#include <errno.h>
#include <openssl/applink.c>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "pesign.h"
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

unsigned char *plainText;
unsigned char *encrypted;
unsigned char *decrypted;
int encrypted_length;
int decrypted_length;
char Plaintext_PATH[MAXPATH] = { '\0' };	// ���ľ���·��
extern char Public_PATH[];					// ��Կ����·��
extern char Private_PATH[];					// ˽Կ����·��

unsigned char* my_encrypt(unsigned char *str, char *path_key);    //����
unsigned char* my_decrypt(unsigned char *str, char *path_key);    //����


/*****************************************************
	rsa_pri_en():
		˽Կ��������
*****************************************************/
void rsa_pri_en()
{
	FILE *f_pla = '\0';
	int SizeofPlain = 0;

	//**********************
	strcpy(Plaintext_PATH, "E:\\Temp4\\formatdata.dat");
	//**********************

	// ��ȡ����
	f_pla = fopen(Plaintext_PATH, "rb");
	if (f_pla == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", Plaintext_PATH);
		exit(0);
	}

	// ��ȡ���ĳ���
	fseek(f_pla, 0, SEEK_END);
	SizeofPlain = ftell(f_pla);

	plainText = (unsigned char *)malloc(sizeof(unsigned char) * (SizeofPlain + 1));
	memset(plainText, '\0', sizeof(unsigned char) * (SizeofPlain + 1));
	
	// �����Ķ���plainText��
	fseek(f_pla, 0, SEEK_SET);		
	fread(plainText, sizeof(unsigned char), SizeofPlain, f_pla);
	fclose(f_pla);

	// ʹ��˽Կ�����ļ���
	encrypted = my_encrypt(plainText, Private_PATH);
	encrypted_length = strlen((char *)encrypted);

	remove(Plaintext_PATH);
	
	return;

}



/*****************************************************
	rsa_pub_de():
		��Կ��������
*****************************************************/
void rsa_pub_de()
{
	FILE *f_pla = '\0';
	FILE *f_en = '\0';
	char ENC[MAXPATH] = { '\0' };	// ����·��
	int SizeofPub = 0;
	int SizeofPlain = 0;
	int encrypted_length = 0;


	printf("%s\n", Public_PATH);
	//**********************
	strcpy(Plaintext_PATH, "E:\\Temp4\\testde.dat");
	strcpy(ENC, "E:\\Temp4\\formatdata_en.dat");
	//**********************

	decrypted = (unsigned char *)malloc(sizeof(unsigned char) * 4098);
	memset(decrypted, '\0', sizeof(unsigned char) * 4098);

	f_pla = fopen((char *)Plaintext_PATH, "w+b");
	if (f_pla == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", Plaintext_PATH);
		exit(0);
	}

	f_en = fopen(ENC, "rb");
	if (f_en == NULL)
	{
		printf("[ERROR] Cannot open the file: %s\n", ENC);
		exit(0);
	}

	// ��ȡ���ĳ���
	fseek(f_en, 0, SEEK_END);				
	encrypted_length = ftell(f_en);

	fseek(f_en, 0, SEEK_SET);
	encrypted = (unsigned char *)malloc(sizeof(unsigned char) * (encrypted_length + 1));
	memset(encrypted, '\0', (encrypted_length + 1));
	fread(encrypted, encrypted_length, 1, f_en);

	// ʹ�ù�Կ�����Ľ��н���
	decrypted = my_decrypt(encrypted, Public_PATH);
	decrypted_length = strlen((char *)decrypted);

	// ���ܺ����ݴ����ļ�
	fwrite(decrypted, decrypted_length, sizeof(unsigned char), f_pla);

	fclose(f_pla);
	fclose(f_en);

	// �Ƴ���Կ�������ļ�
	remove(Public_PATH);
	remove(ENC);

	return;
}



unsigned char *my_encrypt(unsigned char *str, char *prikey_path)
{
	RSA *rsa = NULL;
	FILE *fp = NULL;
	unsigned char *en = NULL;
	int len = 0;
	int rsa_len = 0;

	if ((fp = fopen(prikey_path, "rb")) == NULL) {
		return NULL;
	}

	if ((rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)) == NULL) {
		return NULL;
	}

	len = strlen((char *)str);
	rsa_len = RSA_size(rsa);

	en = (unsigned char *)malloc(rsa_len + 100);
	memset(en, '\0', rsa_len + 100);

	if (RSA_private_encrypt(rsa_len, str, en, rsa, RSA_NO_PADDING) < 0) {
		return NULL;
	}

	RSA_free(rsa);
	fclose(fp);

	return en;
}

unsigned char *my_decrypt(unsigned char *str, char *pubkey_path)
{
	RSA *rsa = NULL;
	FILE *fp = NULL;
	unsigned char *de = NULL;
	int rsa_len = 0;

	if ((fp = fopen(pubkey_path, "r")) == NULL) {
		return NULL;
	}

	if ((rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL)) == NULL) {
		return NULL;
	}

	rsa_len = RSA_size(rsa);
	de = (unsigned char *)malloc(rsa_len + 100);
	memset(de, '\0', rsa_len + 100);

	if (RSA_public_decrypt(rsa_len, str, de, rsa, RSA_NO_PADDING) < 0) {
		return NULL;
	}

	RSA_free(rsa);
	fclose(fp);

	return de;
}
