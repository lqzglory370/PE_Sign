#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pesign.h"

extern char File_PATH[];
extern char Public_PATH[];
extern char Private_PATH[];
extern int SorV;
extern int Auto;

// ��ȡ�����в���������
int getOpts(int argc, char **argv)
{

	int Sign = 0, Verify = 0, hasFile = 0;
	int autokey = 1, hasPubKey = 0, hasPriKey = 0;
	int flag = 0, hasOpt = 0, hasKey = 0, help = 0;

	Auto = 1;

	if (argc == 1)
	{
		printf("[ERROR] Please use -h to get help.\n");
	}

	for (int i = 1; i < argc; i++) 
	{
		// ѡ����Ϊǩ��
		if ((!strcmp(argv[i], "-S") || !strcmp(argv[i], "-s") || !strcmp(argv[i], "--sign")) && i < argc) 
		{
			SorV = S_PE;
			Sign = 1;
		}

		// ѡ����Ϊ��֤
		else if ((!strcmp(argv[i], "-V") || !strcmp(argv[i], "-v") || !strcmp(argv[i], "--verify")) && i < argc) 
		{
			SorV = V_PE;
			Verify = 1;
		}

		// �����˵�
		else if ((!strcmp(argv[i], "-H") || !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) && i < argc) 
		{
			printf("This program is for digital signature.\n");
			printf("=== To Sign ===\n\tPESign.exe -s -f [filepath] -a / (-pu [PubKey path] -pr [PriKey path])\n");
			printf("=== To Verify ===\n\tPESign.exe -v -f [filepath]\n");
			printf("\n\tcommand list:\n");
			printf("\t\t-h -H --help: \t\thelp\n");
			printf("\t\t-s -S --sign: \t\tsign the file\n");
			printf("\t\t-v -V --verify: \tverify the file\n");
			printf("\t\t-f -F --file: \t\tthe file's path\n");
			printf("\t\t-a -A --auto: \t\tAutomatically generate keys\n");
			printf("\t\t-pu -PU --public: \tpublicKey path\n");
			printf("\t\t-pr -PR --private: \tprivate path\n");
			help = 1;
		}

		// ��ȡ��Ҫǩ������֤��PE�ļ�
		else if ((!strcmp(argv[i], "-F") || !strcmp(argv[i], "-f") || !strcmp(argv[i], "--file")) && i + 1 < argc) 
		{
			strcpy(File_PATH, argv[++i]);
			hasFile = 1;
		}

		// �Զ����ɹ�˽Կ��Ĭ���Զ�����
		else if ((!strcmp(argv[i], "-A") || !strcmp(argv[i], "-a") || !strcmp(argv[i], "--auto")) && i < argc)
		{
			SorV = S_PE;
			Auto = 1;
			autokey = 1;
		}

		// ���ݾ���·�����빫Կ
		else if ((!strcmp(argv[i], "-PU") || !strcmp(argv[i], "-pu") || !strcmp(argv[i], "--public")) && i + 1 < argc)
		{
			SorV = S_PE;
			Auto = 0;
			strcpy(Public_PATH, argv[++i]);
			autokey = 0;
			hasPubKey = 1;
		}

		// ���ݾ���·������˽Կ
		else if ((!strcmp(argv[i], "-PR") || !strcmp(argv[i], "-pr") || !strcmp(argv[i], "--private")) && i + 1 < argc)
		{
			SorV = S_PE;
			Auto = 0;
			strcpy(Private_PATH, argv[++i]);
			autokey = 0;
			hasPriKey = 1;
		}

		// ��������
		else 
		{
			printf("[ERROR] Please use -h to get help.\n");
			exit(0);
		}
	}
	
	hasOpt = (Sign && hasFile) || (Verify && hasFile);					// ��֤��ѡ���ܣ�ǩ������֤
	hasKey = (autokey && Sign) || (hasPubKey && hasPriKey && Sign);		// ��ѡ��ǩ������֤�й�˽Կ·���������е���Ҳ���Զ�����
	flag = help || (hasOpt && Sign && hasKey) || (hasOpt && Verify);	// flag���ز����Ƿ��������
	if ((Verify == 1 && hasPriKey) || (Verify == 1 && hasPubKey))		// ��ѡ����Ϊ��֤����ʹ���˵��빫˽Կ�Ĳ������ж���������
		flag = 0;

	return (flag);
}



