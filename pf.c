#include<stdio.h>
#include<stdlib.h>
#include<getopt.h>


#define print_value(x) (x==NULL?"-":x)


//防火墙规则结构体
static struct pf_rule_struct
{
	int in_out;				//0:不进不出; 1:进; 2:出;
	char *src_ip;
	char *src_netmask;
	char *src_port;
	char *dest_ip;
	char *dest_netmask;
	char *dest_port;
	char *protocol;			//0:任何; 1:TCP; 2:UDP;
	char *action;			//0:堵塞; 1:不堵塞;
}pf_rule;


//防火墙删除规则结构体
static struct pf_delete_struct
{
	char *cmd;
	char *row;
}pf_delete;


void send_to_proc(char *str)
{
	FILE *pf;
	
	pf=fopen("/proc/personalFirewall","w");
	if(pf==NULL)
	{
		printf("cannot open /proc/personalFirewall for writting\n");
		return;
	}
	else
	{
		fprintf(pf,"%s",str);
	}
	
	fclose(pf);
	
	return;
}


int get_protocol(char *protocol)
{
	if(strcmp(protocol,"ALL")==0)
		return 0;
	else if(strcmp(protocol,"TCP")==0)
		return 1;
	else if(strcmp(protocol,"UDP")==0)
		return 2;
}


int get_action(char *action)
{
	if(strcmp(action,"BLOCK")==0)
		return 0;
	else if(strcmp(action,"UNBLOCK")==0)
		return 1;
}


void send_rule_to_proc()
{
	char a_rule[200];
	
	sprintf(a_rule,"%u %s %s %s %s %s %s %u %u\n",pf_rule.in_out+1,print_value(pf_rule.src_ip),print_value(pf_rule.src_netmask),print_value(pf_rule.src_port),print_value(pf_rule.dest_ip),print_value(pf_rule.dest_netmask),print_value(pf_rule.dest_port),get_protocol(pf_rule.protocol),get_action(pf_rule.action));
	
	send_to_proc(a_rule);
}


void send_delete_to_proc()
{
	char delete_cmd[20];
	
	sprintf(delete_cmd, "%s%s\n","d",print_value(pf_delete.row));
	
	send_to_proc(delete_cmd);
}


void print_rule()
{
	FILE *pf;
	char token[200];
	char ch;
	int i=0,j=0;
	
	printf("in/out\tsrc_ip\tsrc_netmask\tsrc_port\tdest_ip\tdest_netmask\tdest_port\tprotocol\taction\n");
	
	pf=fopen("/proc/personalFirewall","r");
	if(pf==NULL)
	{
		printf("cannot open /proc/personalFirewall for reading\n");
		return;
	}
	else
	{
		while(1)
		{
			while (((ch=fgetc(pf))==' ') || (ch == '\n'));
			if (ch == EOF) break;
	 
			//in_out
			i = 0;
			token[i++] = ch;
			while (((ch=fgetc(pf))!=EOF) && (ch!=' '))
			{
				token[i++] = ch;
			}
			token[i] = '\0';
			printf("  %s  ", token);
			if (ch==EOF) break;
	 
			//src_ip
			i = 0;
			while (((ch=fgetc(pf))!=EOF) && (ch!=' '))
			{
				token[i++] = ch;
			}
			token[i] = '\0';
			if (strcmp(token, "-")==0)
			{
				printf("      %s     ", token);
			}
			else
			{
				printf(" %s ", token);
			}
			if (ch==EOF) break;
	 
			//src_netmask
			i = 0;
			while (((ch=fgetc(pf))!=EOF) && (ch!=' '))
			{
				token[i++] = ch;
			}
			token[i] = '\0';
			if (strcmp(token, "-")==0)
			{
				printf("      %s     ", token);
			}
			else
			{
				printf(" %s ", token);
			}
			if (ch==EOF) break;
	 
			//src_port        
			i = 0;
			while (((ch=fgetc(pf))!=EOF) && (ch!=' '))
			{
				token[i++] = ch;
			}
			token[i] = '\0';
			printf("%s     ", token);
			if (ch==EOF) break;
	 
			//dest_ip
			i = 0;
			while (((ch=fgetc(pf))!=EOF) && (ch!=' '))
			{
				token[i++] = ch;
			}
			token[i] = '\0';
			if (strcmp(token, "-")==0)
			{
				printf("      %s     ", token);
			}
			else
			{
				printf(" %s ", token);
			}
			if (ch==EOF) break;
			
			//dest_netmask
			i = 0;
			while (((ch=fgetc(pf))!=EOF) && (ch!=' '))
			{
				token[i++] = ch;
			}
			token[i] = '\0';
			if (strcmp(token, "-")==0)
			{
				printf("      %s     ", token);
			}
			else
			{
				printf(" %s ", token);
			}
			if (ch==EOF) break;

			//dest_port
			i = 0;
			while (((ch=fgetc(pf))!=EOF) && (ch!=' '))
			{
				token[i++] = ch;
			}
			token[i] = '\0';
			printf("%s     ", token);
			if (ch==EOF) break;
	 
			//protocol
			i = 0;
			while (((ch=fgetc(pf))!=EOF) && (ch!=' '))
			{
				token[i++] = ch;
			}
			token[i] = '\0';
			printf("    %s    ", token);
			if (ch==EOF) break;

			//action
			i = 0;
			while (((ch=fgetc(pf))!=EOF) && (ch!=' ') && (ch!='\n'))
			{
				token[i++] = ch;
			}
			token[i] = '\0';
			printf(" %s\n", token);
			if (ch==EOF) break;
		}
	}
	
	fclose(pf);
	
	return;
}

void usage()
{
	printf("Usage: sudo ./pf [In or Out] [Option][Detail][,Option][,Detail]\n");
	printf("   or: ./pf --print\n");
	printf("   or: ./pf --delete [Rule No.]\n");
	printf("\nIn or Out:\n");
	printf("       --in			control the incoming packet\n");
	printf("       --out			control the outgoing packet\n");
	printf("\nOption:\n");
	printf("   -s: --srcip			set the source IP\n");
	printf("   -m: --srcnetmask		set the source netmask\n");
	printf("   -p: --srcport		set the source port\n");
	printf("   -t: --destip			set the destination IP\n");
	printf("   -n: --destnetmask		set the destination netmask\n");
	printf("   -q: --destport		set the destination port\n");
	printf("   -c: --protocol		set the protocol\n");
	printf("					ALL: all protocol\n");
	printf("					TCP: TCP protocol\n");
	printf("					UDP: UDP protocol\n");
	printf("   -a: --action			set the action\n");
	printf("					BLOCK: block the packet\n");
	printf("					UNBLOCK: unblock the packet\n");
	printf("\nPrint:\n   -o: --print			print the rule\n");
	printf("\nDelete:\n   -d: --delete			delete the rule\n\n");
	
}

int main(int argc,char **argv)
{
	int opt=0;
	int option_index=0;
	int action=0;//行为：1==新规则 2==打印 3==删除
	char optstr[]="od:s:m:p:t:n:q:c:a:h";
	static struct option long_option[]=
		{
		//设置pf_rule.in_out为flag
			{"in", no_argument, &pf_rule.in_out, 0},
			{"out", no_argument, &pf_rule.in_out, 1},
		//这些不设置flag
			{"print", no_argument, 0, 'o'},
			{"delete", required_argument, 0, 'd'},
			{"srcip", required_argument, 0, 's'},
			{"srcnetmask", required_argument, 0, 'm'},
			{"srcport", required_argument, 0, 'p'},
			{"destip", required_argument, 0, 't'},
			{"destnetmask", required_argument, 0, 'n'},
			{"destport", required_argument, 0, 'q'},
			{"protocol", required_argument, 0, 'c'},
			{"action", required_argument, 0, 'a'},
			{"help", no_argument, 0, 'h'},
			{0, 0, 0, 0}
		};
 
	pf_rule.in_out=-1;
	pf_rule.src_ip=NULL;
	pf_rule.src_netmask=NULL;
	pf_rule.src_port=NULL;
	pf_rule.dest_ip=NULL;
	pf_rule.dest_netmask=NULL;
	pf_rule.dest_port=NULL;
	pf_rule.protocol=NULL;
	pf_rule.action=NULL;
	
	if(argc<2)
	{
		usage();
		exit(0);
	}
	else
	{
		while(-1!=(opt=getopt_long(argc,argv,optstr,long_option,&option_index)))
		{
			switch(opt)
			{
				case 0:
					action=1;
					printf("flag option: %s, pf_rule.in_out=%d\n",long_option[option_index].name,pf_rule.in_out);
					break;
				case 'o':
					action=2;
					break;
				case 'd':
					action=3;
					pf_delete.cmd=(char*)long_option[option_index].name;
					pf_delete.row=optarg;
					break;
				case 's':
					pf_rule.src_ip=optarg;
					break;
				case 'm':
					pf_rule.src_netmask=optarg;
					break;
				case 'p':
					pf_rule.src_port=optarg;
					break;
				case 't':
					pf_rule.dest_ip=optarg;
					break;
				case 'n':
					pf_rule.dest_netmask=optarg;
					break;
				case 'q':
					pf_rule.dest_port=optarg;
					break;
				case 'c':
					pf_rule.protocol=optarg;
					break;
				case 'a':
					pf_rule.action=optarg;
					break;
				case 'h':
					usage();
					break;
				default:
					usage();
			}
		}
	}
	
	if (action == 1)
		send_rule_to_proc();
	else if (action == 2)
		print_rule();
	else if (action == 3)
        send_delete_to_proc();
	
	if (optind < argc)
    {
		printf("non-option ARGV-elements: ");
		while (optind < argc)
			printf("%s\n", argv[optind++]);
    }
}


















