#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pesign.h"

extern char File_PATH[];
extern char Public_PATH[];
extern char Private_PATH[];
extern int SorV;
extern int Auto;

// 获取命令行参数并解析
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
		// 选择功能为签名
		if ((!strcmp(argv[i], "-S") || !strcmp(argv[i], "-s") || !strcmp(argv[i], "--sign")) && i < argc) 
		{
			SorV = S_PE;
			Sign = 1;
		}

		// 选择功能为验证
		else if ((!strcmp(argv[i], "-V") || !strcmp(argv[i], "-v") || !strcmp(argv[i], "--verify")) && i < argc) 
		{
			SorV = V_PE;
			Verify = 1;
		}

		// 帮助菜单
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

		// 读取需要签名或验证的PE文件
		else if ((!strcmp(argv[i], "-F") || !strcmp(argv[i], "-f") || !strcmp(argv[i], "--file")) && i + 1 < argc) 
		{
			strcpy(File_PATH, argv[++i]);
			hasFile = 1;
		}

		// 自动生成公私钥，默认自动生成
		else if ((!strcmp(argv[i], "-A") || !strcmp(argv[i], "-a") || !strcmp(argv[i], "--auto")) && i < argc)
		{
			SorV = S_PE;
			Auto = 1;
			autokey = 1;
		}

		// 根据绝对路径导入公钥
		else if ((!strcmp(argv[i], "-PU") || !strcmp(argv[i], "-pu") || !strcmp(argv[i], "--public")) && i + 1 < argc)
		{
			SorV = S_PE;
			Auto = 0;
			strcpy(Public_PATH, argv[++i]);
			autokey = 0;
			hasPubKey = 1;
		}

		// 根据绝对路径导入私钥
		else if ((!strcmp(argv[i], "-PR") || !strcmp(argv[i], "-pr") || !strcmp(argv[i], "--private")) && i + 1 < argc)
		{
			SorV = S_PE;
			Auto = 0;
			strcpy(Private_PATH, argv[++i]);
			autokey = 0;
			hasPriKey = 1;
		}

		// 输入有误
		else 
		{
			printf("[ERROR] Please use -h to get help.\n");
			exit(0);
		}
	}
	
	hasOpt = (Sign && hasFile) || (Verify && hasFile);					// 保证有选择功能，签名或验证
	hasKey = (autokey && Sign) || (hasPubKey && hasPriKey && Sign);		// 若选择签名，保证有公私钥路径，可自行导入也可自动生成
	flag = help || (hasOpt && Sign && hasKey) || (hasOpt && Verify);	// flag返回参数是否符合条件
	if ((Verify == 1 && hasPriKey) || (Verify == 1 && hasPubKey))		// 若选择功能为验证，但使用了导入公私钥的参数，判定参数有误
		flag = 0;

	return (flag);
}



