#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/proc_fs.h>
#include<linux/list.h>
#include<asm/uaccess.h>
#include<linux/udp.h>
#include<linux/tcp.h>
#include<linux/skbuff.h>
#include<linux/ip.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/string.h>


#define PROCF_MAX_SIZE 1024
#define PROCF_NAME "personalFirewall"


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linux personal firewall");
MODULE_AUTHOR("Liu Mingjian & Zhu Bingquan");


//进程文件系统使用的结构体
static struct proc_dir_entry *pf_proc_file;
unsigned long procf_buffer_pos;
char *procf_buffer;


//netfilter相关hook的结构体
static struct nf_hook_ops nfho;
static struct nf_hook_ops nfho_out;


//防火墙规则结构体
struct pf_rule_desp
{
	unsigned char in_out;	//0:不进不出; 1:进; 2:出;
	char *src_ip;
	char *src_netmask;
	char *src_port;
	char *dest_ip;
	char *dest_netmask;
	char *dest_port;
	unsigned char protocol;	//0:任何; 1:TCP; 2:UDP;
	unsigned char action;	//0:堵塞; 1:不堵塞;
};


//防火墙规则结构体
struct pf_rule
{
	unsigned char in_out;
	char *src_ip;
	char *src_netmask;
	char *src_port;
	char *dest_ip;
	char *dest_netmask;
	char *dest_port;
	unsigned char protocol;
	unsigned char action;
	struct list_head list;
};


static struct pf_rule policy_list;


//将字符串转换成整型
unsigned int str_to_int(char *port_str)
{
	unsigned int port = 0;
	int i = 0;
	if (port_str==NULL)
	{
		return 0;
	}
	while (port_str[i]!='\0')
	{
		port = port*10 + (port_str[i]-'0');
		++i;
	}
	return port;
}

//将字符串ip转换成主机字节顺序
unsigned int ip_str_to_hl(char *ip_str)
{
	unsigned char ip_array[4];
	int i=0,j=0;
	unsigned int ip=0;
	
	if(ip_str==NULL)
		return 0;
	
	memset(ip_array,0,4);
	
	for(;ip_str[i]!='\0';i++)
	{
		if(ip_str[i]!='.')
			ip_array[j] = ip_array[j]*10 + (ip_str[i]-'0');
		else
			j++;
	}
	
	for(i=0;i<4;i++)
	{
		ip=(ip|ip_array[i]<<((3-i)*8));
	}
	
	return ip;
}


//将ip主机字节顺序转换成字符串
void ip_hl_to_str(unsigned int ip, char *ip_str)
{
	unsigned char ip_array[4];
	int i=0;
	
	memset(ip_array, 0, 4);
	
	for(;i<4;i++)
		ip_array[i]=(ip_array[i]|(ip>>((3-i))*8));
	
	sprintf(ip_str, "%u.%u.%u.%u",ip_array[0],ip_array[1],ip_array[2],ip_array[3]);
}


//根据掩码的长度检查两个ip地址是否匹配
bool check_ip(unsigned int ip,unsigned int ip_rule,unsigned int mask)
{
	unsigned int temp=ntohl(ip);
	int cmp_len=32;
	int i=0,j=0;
	
	printk(KERN_INFO "compare ip: %u <=> %u\n",temp,ip_rule);
	
	if(mask!=0)
	{
		cmp_len=0;
		for(;i<32;i++)
		{
			if(mask & (1 << (32-1-i)))
				cmp_len++;
			else
				break;
		}
	}
	
	for(i=31,j=0;j<cmp_len;--i,++j)
	{
		if((temp&(1<<i))!=(ip_rule&(1 << i)))
		{
			printk(KERN_INFO "ip compare: %d bit doesn't match\n", (32-i));
            return false;
		}
	}
	
	return true;
}


//添加规则
void add_a_rule(struct pf_rule_desp *a_rule_desp)
{
	struct pf_rule *a_rule;
	a_rule=kmalloc(sizeof(*a_rule),GFP_KERNEL);
	
	if(a_rule==NULL)
	{
		printk(KERN_INFO "error: cannot allocate memory for a_new_rule\n");
		return;
	}
	
	a_rule->in_out=a_rule_desp->in_out;
	if (strcmp(a_rule_desp->src_ip,"-")!=0) 
		a_rule->src_ip=ip_str_to_hl(a_rule_desp->src_ip);
	else
		a_rule->src_ip=NULL;
	if (strcmp(a_rule_desp->src_netmask,"-")!=0)
		a_rule->src_netmask=ip_str_to_hl(a_rule_desp->src_netmask);
	else
		a_rule->src_netmask=NULL;
	if (strcmp(a_rule_desp->src_port,"-")!=0)
		a_rule->src_port=str_to_int(a_rule_desp->src_port);
	else 
		a_rule->src_port=NULL;
	if (strcmp(a_rule_desp->dest_ip,"-")!=0)
		a_rule->dest_ip=ip_str_to_hl(a_rule_desp->dest_ip);
	else 
		a_rule->dest_ip=NULL;
	if (strcmp(a_rule_desp->dest_netmask,"-")!=0)
		a_rule->dest_netmask=ip_str_to_hl(a_rule_desp->dest_netmask);
	else 
		a_rule->dest_netmask=NULL;
	if (strcmp(a_rule_desp->dest_port,"-")!=0)
		a_rule->dest_port=str_to_int(a_rule_desp->dest_port);
	else 
		a_rule->dest_port=NULL;
	a_rule->protocol=a_rule_desp->protocol;
	a_rule->action=a_rule_desp->action;
	
	printk(KERN_INFO "add_a_rule: in_out=%u, src_ip=%u, src_netmask=%u, src_port=%u, dest_ip=%u, dest_netmask=%u, dest_port=%u, protocol=%u, action=%u\n", a_rule->in_out,a_rule->src_ip,a_rule->src_netmask,a_rule->src_port,a_rule->dest_ip,a_rule->dest_netmask,a_rule->dest_port,a_rule->protocol,a_rule->action);
	
	INIT_LIST_HEAD(&(a_rule->list));
	list_add_tail(&(a_rule->list),&(policy_list.list));
}


//初始化结构体
void init_pf_rule_desp(struct pf_rule_desp *a_rule_desp)
{
	a_rule_desp->in_out=0;
	a_rule_desp->src_ip=(char *)kmalloc(16, GFP_KERNEL);
	a_rule_desp->src_netmask=(char *)kmalloc(16, GFP_KERNEL);
	a_rule_desp->src_port=(char *)kmalloc(16, GFP_KERNEL);
	a_rule_desp->dest_ip=(char *)kmalloc(16, GFP_KERNEL);
	a_rule_desp->dest_netmask=(char *)kmalloc(16, GFP_KERNEL);
	a_rule_desp->dest_port=(char *)kmalloc(16, GFP_KERNEL);
	a_rule_desp->protocol=0;
    a_rule_desp->action=0;
}


//删除规则
void delete_a_rule(int num)
{
	int i=0;
	struct list_head *p,*q;
	struct pf_rule *a_rule;
	
	printk(KERN_INFO "delete a rule: %d\n",num);
	
	list_for_each_safe(p,q,&policy_list.list)
	{
		++i;
		if (i==num)
		{
			a_rule = list_entry(p,struct pf_rule,list);
			list_del(p);
			kfree(a_rule);
			return;
		}
	}
}


//将相关信息写到进程文件相关的缓冲区
int procf_read(char *buffer,char **buffer_location,off_t offset,int buffer_length,int *eof,void *data)
{
	int ret;
	struct pf_rule *a_rule;
	char token[20];
	
	printk(KERN_INFO "procf_read (/proc/%s) called \n",PROCF_NAME);
	
	if(offset>0)
	{
		printk(KERN_INFO "eof is 1, nothing to read\n");
		*eof=1;
		return 0;
	}
	else
	{
		procf_buffer_pos=0;
		ret=0;
		
		list_for_each_entry(a_rule,&policy_list.list,list)
		{
			//in_out
			if(a_rule->in_out==1)
				strcpy(token,"in");
			else if(a_rule->in_out==2)
				strcpy(token,"out");
			printk(KERN_INFO "token: %s\n",token);
			memcpy(procf_buffer+procf_buffer_pos,token,strlen(token));
			procf_buffer_pos+=strlen(token);
			memcpy(procf_buffer+procf_buffer_pos," ",1);
			procf_buffer_pos++;
			
			//src_ip
			if(a_rule->src_ip==NULL)
				strcpy(token,"-");
			else
				ip_hl_to_str(a_rule->src_ip,token);
			printk(KERN_INFO "token: %s\n",token);
			memcpy(procf_buffer+procf_buffer_pos,token,strlen(token));
			procf_buffer_pos+=strlen(token);
			memcpy(procf_buffer+procf_buffer_pos," ",1);
			procf_buffer_pos++;
			
			//src_netmask
			if(a_rule->src_netmask==NULL)
				strcpy(token,"-");
			else
				ip_hl_to_str(a_rule->src_netmask,token);
			printk(KERN_INFO "token: %s\n",token);
			memcpy(procf_buffer+procf_buffer_pos,token,strlen(token));
			procf_buffer_pos+=strlen(token);
			memcpy(procf_buffer+procf_buffer_pos," ",1);
			procf_buffer_pos++;
			
			//src_port
			if(a_rule->src_port==0)
				strcpy(token,"-");
			else
				sprintf(token,"%u",a_rule->src_port);
			printk(KERN_INFO "token: %s\n",token);
			memcpy(procf_buffer+procf_buffer_pos,token,strlen(token));
			procf_buffer_pos+=strlen(token);
			memcpy(procf_buffer+procf_buffer_pos," ",1);
			procf_buffer_pos++;
			
			//dest_ip
			if(a_rule->dest_ip==NULL)
				strcpy(token,"-");
			else
				ip_hl_to_str(a_rule->dest_ip,token);
			printk(KERN_INFO "token: %s\n",token);
			memcpy(procf_buffer+procf_buffer_pos,token,strlen(token));
			procf_buffer_pos+=strlen(token);
			memcpy(procf_buffer+procf_buffer_pos," ",1);
			procf_buffer_pos++;
			
			//dest_netmask
			if(a_rule->dest_netmask==NULL)
				strcpy(token,"-");
			else
				ip_hl_to_str(a_rule->dest_netmask,token);
			printk(KERN_INFO "token: %s\n",token);
			memcpy(procf_buffer+procf_buffer_pos,token,strlen(token));
			procf_buffer_pos+=strlen(token);
			memcpy(procf_buffer+procf_buffer_pos," ",1);
			procf_buffer_pos++;
			
			//dest_port
			if(a_rule->dest_port==0)
				strcpy(token,"-");
			else
				sprintf(token,"%u",a_rule->dest_port);
			printk(KERN_INFO "token: %s\n",token);
			memcpy(procf_buffer+procf_buffer_pos,token,strlen(token));
			procf_buffer_pos+=strlen(token);
			memcpy(procf_buffer+procf_buffer_pos," ",1);
			procf_buffer_pos++;
			
			//protocol
			if(a_rule->protocol==0)
				strcpy(token,"ALL");
			else if(a_rule->protocol==1)
				strcpy(token,"TCP");
			else if(a_rule->protocol==2)
				strcpy(token,"UDP");
			printk(KERN_INFO "token: %s\n",token);
			memcpy(procf_buffer+procf_buffer_pos,token,strlen(token));
			procf_buffer_pos+=strlen(token);
			memcpy(procf_buffer+procf_buffer_pos," ",1);
			procf_buffer_pos++;
			
			//action
			if(a_rule->action==0)
				strcpy(token,"BLOCK");
			else if(a_rule->action==1)
				strcpy(token,"UNBLOCK");
			printk(KERN_INFO "token: %s\n",token);
			memcpy(procf_buffer+procf_buffer_pos,token,strlen(token));
			procf_buffer_pos+=strlen(token);
			memcpy(procf_buffer+procf_buffer_pos," ",1);
			procf_buffer_pos++;
			
			printk(KERN_INFO "procf_buffer_pos: %ld\n",procf_buffer_pos);
			memcpy(buffer, procf_buffer,procf_buffer_pos);
			ret=procf_buffer_pos;
		}
	}
	
	return ret;
}


//进程文件根据相关信息做对应操作
int procf_write(struct file *file,const char *buffer,unsigned long count,void *data)
{
	int i,j;
	struct pf_rule_desp *rule_desp;
	
	printk(KERN_INFO "procf_write is called.\n");
	
	procf_buffer_pos=0;
	printk(KERN_INFO "pos: %ld; count: %ld\n",procf_buffer_pos,count);
	
	if(procf_buffer_pos+count>PROCF_MAX_SIZE)
		count=PROCF_MAX_SIZE-procf_buffer_pos;
	if(copy_from_user(procf_buffer+procf_buffer_pos,buffer,count))
		return -EFAULT;
	
	if(procf_buffer[procf_buffer_pos]=='p')
	{
		//打印命令
		return 0;
	}
	else if(procf_buffer[procf_buffer_pos]=='d')
	{
		//删除命令
		i=procf_buffer_pos+1;
		j=0;
		
		while((procf_buffer[i]!=' ')&&(procf_buffer[i]!='\n'))
		{
			printk(KERN_INFO "delete: %d\n",procf_buffer[i]-'0');
			j=j*10+(procf_buffer[i]-'0');
			i++;
		}
		
		printk(KERN_INFO "delete a rule: %d\n", j);
		delete_a_rule(j);
		
		return count;
	}

	//根据缓冲区增加新规则
	rule_desp=kmalloc(sizeof(*rule_desp),GFP_KERNEL);
	if(rule_desp==NULL)
	{
		printk(KERN_INFO "error: cannot allocate memory for rule_desp\n");
		return -ENOMEM;
	}
	
	init_pf_rule_desp(rule_desp);
	
	//in_out
	i=procf_buffer_pos;
	j=0;
	if(procf_buffer[i]!=' ')
		rule_desp->in_out=(unsigned char)(procf_buffer[i++]-'0');
	i++;
	printk(KERN_INFO "in or out: %u\n",rule_desp->in_out);
	
	//src_ip
	j=0;
	while(procf_buffer[i]!=' ')
		rule_desp->src_ip[j++]=procf_buffer[i++];
	i++;
	rule_desp->src_ip[j]='\0';
	printk(KERN_INFO "src_ip: %s\n",rule_desp->src_ip);
	
	//src_netmask
	j=0;
	while(procf_buffer[i]!=' ')
		rule_desp->src_netmask[j++]=procf_buffer[i++];
	i++;
	rule_desp->src_netmask[j]='\0';
	printk(KERN_INFO "src_netmask: %s\n",rule_desp->src_netmask);
	
	//src_port
	j=0;
	while (procf_buffer[i]!=' ')
		rule_desp->src_port[j++]=procf_buffer[i++];
	++i;
	rule_desp->src_port[j] = '\0';
	printk(KERN_INFO "src_port: %s\n",rule_desp->src_port);
	
	//dest_ip
	j=0;
	while (procf_buffer[i]!=' ')
		rule_desp->dest_ip[j++]=procf_buffer[i++];
	++i;
	rule_desp->dest_ip[j] = '\0';
	printk(KERN_INFO "dest ip: %s\n",rule_desp->dest_ip);
	
	//dest_netmask
	j=0;
	while(procf_buffer[i]!=' ')
		rule_desp->dest_netmask[j++]=procf_buffer[i++];
	i++;
	rule_desp->dest_netmask[j]='\0';
	printk(KERN_INFO "dest_netmask: %s\n",rule_desp->dest_netmask);
	
	//dest_port
	j=0;
	while (procf_buffer[i]!=' ')
		rule_desp->dest_port[j++]=procf_buffer[i++];
	++i;
	rule_desp->dest_port[j] = '\0';
	printk(KERN_INFO "dest_port: %s\n",rule_desp->dest_port);
	
	//protocol
	j=0;
	if(procf_buffer[i]!=' ')
	{
		if(procf_buffer[i]!='-')
			rule_desp->protocol=(unsigned char)(procf_buffer[i++]-'0');
		else
			++i;
	}
	++i;
	printk(KERN_INFO "protocol: %d\n",rule_desp->protocol);
	
	//action
	j = 0;
	if (procf_buffer[i]!=' ')
	{
		if (procf_buffer[i] != '-')
			rule_desp->action = (unsigned char)(procf_buffer[i++]-'0');
		else
			++i;
	}
	++i;
	printk(KERN_INFO "action: %d\n", rule_desp->action);
	
	add_a_rule(rule_desp);
	kfree(rule_desp);
	printk(KERN_INFO "--------------------\n");
	
	return count;
}


//用来过滤出去的包
unsigned int hook_func_out(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header=(struct iphdr *)skb_network_header(skb);
	struct udphdr *udp_header;
	struct tcphdr *tcp_header;
	struct list_head *p;
	struct pf_rule *a_rule;
	char src_ip_str[16],dest_ip_str[16];
	int i=0;
	
	unsigned int src_ip=(unsigned int)ip_header->saddr;
	unsigned int dest_ip=(unsigned int)ip_header->daddr;
	unsigned int src_port=0;
	unsigned int dest_port=0;
	
	if(ip_header->protocol==17)
	{
		udp_header = (struct udphdr *)skb_transport_header(skb);
		src_port = (unsigned int)ntohs(udp_header->source);
		dest_port = (unsigned int)ntohs(udp_header->dest);
	}
	else if(ip_header->protocol == 6)
	{
		tcp_header = (struct tcphdr *)skb_transport_header(skb);
		src_port = (unsigned int)ntohs(tcp_header->source);
		dest_port = (unsigned int)ntohs(tcp_header->dest);
	}
	ip_hl_to_str(ntohl(src_ip),src_ip_str);
	ip_hl_to_str(ntohl(dest_ip),dest_ip_str);
	
	printk(KERN_INFO "OUT packet info: src ip: %u = %s, src port: %u; dest ip: %u = %s, dest port: %u; protocol: %u\n",src_ip,src_ip_str,src_port,dest_ip,dest_ip_str,dest_port,ip_header->protocol);
	
	list_for_each(p,&policy_list.list)
	{
		i++;
		
		a_rule=list_entry(p,struct pf_rule,list);
		
		if(a_rule->in_out!=2)
		{
			printk(KERN_INFO "rule %d (a_rule->in_out: %u) not match: out packet, rule doesn't specify as out\n",i,a_rule->in_out);
			continue;
		}
		else
		{
			if((a_rule->protocol==1)&&(ip_header->protocol!=6))
			{
				printk(KERN_INFO "rule %d not match: rule-TCP, packet->not TCP\n",i);
				continue;
			}
			else if((a_rule->protocol==2)&&(ip_header->protocol!=17))
			{
				printk(KERN_INFO "rule %d not match: rule-UDP, packet->not UDP\n",i);
				continue;
			}
			if(a_rule->src_ip!=0)
				if(!check_ip(src_ip,a_rule->src_ip,a_rule->src_netmask))
				{
					printk(KERN_INFO "rule %d not match: src ip mismatch\n",i);
					continue;
				}
			if(a_rule->dest_ip!=0)
				if(!check_ip(dest_ip,a_rule->dest_ip,a_rule->dest_netmask))
				{
					printk(KERN_INFO "rule %d not match: dest ip mismatch\n",i);
					continue;
				}
			if(a_rule->src_port!=0)
				if(src_port!=a_rule->src_port)
				{
					printk(KERN_INFO "rule %d not match: src port dismatch\n",i);
					continue;
				}
			if(a_rule->dest_port!=0)
				if(dest_port!=a_rule->dest_port)
				{
					printk(KERN_INFO "rule %d not match: dest port mismatch\n",i);
					continue;
				}
			if (a_rule->action==0)
			{
				printk(KERN_INFO "a match is found: %d, drop the packet\n",i);
				printk(KERN_INFO "---------------------------------------\n");
				return NF_DROP;
			} 
			else
			{
				printk(KERN_INFO "a match is found: %d, accept the packet\n",i);
				printk(KERN_INFO "---------------------------------------\n");
				return NF_ACCEPT;
			}
		}
	}
	
	printk(KERN_INFO "no matching is found, accept the packet\n");
	printk(KERN_INFO "---------------------------------------\n");
	
	return NF_ACCEPT;   
}

//用来过滤进来的包
unsigned int hook_func_in(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header=(struct iphdr *)skb_network_header(skb);
	struct udphdr *udp_header;
	struct tcphdr *tcp_header;
	struct list_head *p;
	struct pf_rule *a_rule;
	char src_ip_str[16],dest_ip_str[16];
	int i=0;
	
	unsigned int src_ip=(unsigned int)ip_header->saddr;
	unsigned int dest_ip=(unsigned int)ip_header->daddr;
	unsigned int src_port=0;
	unsigned int dest_port=0;
	
	if(ip_header->protocol==17)
	{
		udp_header = (struct udphdr *)skb_transport_header(skb);
		src_port = (unsigned int)ntohs(udp_header->source);
		dest_port = (unsigned int)ntohs(udp_header->dest);
	}
	else if(ip_header->protocol == 6)
	{
		tcp_header = (struct tcphdr *)skb_transport_header(skb);
		src_port = (unsigned int)ntohs(tcp_header->source);
		dest_port = (unsigned int)ntohs(tcp_header->dest);
	}

	ip_hl_to_str(ntohl(src_ip),src_ip_str);
	ip_hl_to_str(ntohl(dest_ip),dest_ip_str);
	
	printk(KERN_INFO "IN packet info: src ip: %u = %s, src port: %u; dest ip: %u = %s, dest port: %u; proto: %u\n",src_ip,src_ip_str,src_port,dest_ip,dest_ip_str,dest_port,ip_header->protocol); 
	
	list_for_each(p,&policy_list.list)
	{
		i++;
		
		a_rule=list_entry(p,struct pf_rule,list);
		
		if(a_rule->in_out!=1)
		{
			printk(KERN_INFO "rule %d (a_rule->in_out: %u) not match: out packet, rule doesn't specify as in\n",i,a_rule->in_out);
			continue;
		}
		else
		{
			if((a_rule->protocol==1)&&(ip_header->protocol!=6))
			{
				printk(KERN_INFO "rule %d not match: rule-TCP, packet->not TCP\n",i);
				continue;
			}
			else if((a_rule->protocol==2)&&(ip_header->protocol!=17))
			{
				printk(KERN_INFO "rule %d not match: rule-UDP, packet->not UDP\n",i);
				continue;
			}
			if(a_rule->src_ip!=0)
				if(!check_ip(src_ip,a_rule->src_ip,a_rule->src_netmask))
				{
					printk(KERN_INFO "rule %d not match: src ip mismatch\n",i);
					continue;
				}
			if(a_rule->dest_ip!=0)
				if(!check_ip(dest_ip,a_rule->dest_ip,a_rule->dest_netmask))
				{
					printk(KERN_INFO "rule %d not match: dest ip mismatch\n",i);
					continue;
				}
			if(a_rule->src_port!=0)
				if(src_port!=a_rule->src_port)
				{
					printk(KERN_INFO "rule %d not match: src port dismatch\n",i);
					continue;
				}
			if(a_rule->dest_port!=0)
				if(dest_port!=a_rule->dest_port)
				{
					printk(KERN_INFO "rule %d not match: dest port mismatch\n",i);
					continue;
				}
			if (a_rule->action==0)
			{
				printk(KERN_INFO "a match is found: %d, drop the packet\n",i);
				printk(KERN_INFO "---------------------------------------\n");
				return NF_DROP;
			} 
			else
			{
				printk(KERN_INFO "a match is found: %d, accept the packet\n",i);
				printk(KERN_INFO "---------------------------------------\n");
				return NF_ACCEPT;
			}
		}
	}
	
	printk(KERN_INFO "no matching is found, accept the packet\n");
	printk(KERN_INFO "---------------------------------------\n");
	
	return NF_ACCEPT;  
}


//初始化程序
int init_module()
{
	printk(KERN_INFO "initialize kernel module\n");
	procf_buffer=(char *)vmalloc(PROCF_MAX_SIZE);
	INIT_LIST_HEAD(&policy_list.list);
	
	pf_proc_file=create_proc_entry(PROCF_NAME,0644,NULL);
	if(pf_proc_file==NULL)
	{
		printk(KERN_INFO "Error: could not initialize /proc/%s\n",PROCF_NAME);
		return -ENOMEM;
	}
	pf_proc_file->read_proc=procf_read;
	pf_proc_file->write_proc=procf_write;
	printk(KERN_INFO "/proc/%s is created\n",PROCF_NAME);
	
	nfho.hook=hook_func_in;
	nfho.hooknum=NF_INET_LOCAL_IN;
	nfho.pf=PF_INET;
	nfho.priority=NF_IP_PRI_FIRST;
	//注册进包相关的hook
	nf_register_hook(&nfho);
	
	nfho_out.hook = hook_func_out;
	nfho_out.hooknum = NF_INET_LOCAL_OUT;
	nfho_out.pf = PF_INET;
	nfho_out.priority = NF_IP_PRI_FIRST;
	//注册出包相关的hook
	nf_register_hook(&nfho_out);
	
	return 0;
}


//清除程序
void cleanup_module()
{
	struct list_head *p,*q;
	struct pf_rule *a_rule;
	
	nf_unregister_hook(&nfho);
	nf_unregister_hook(&nfho_out);
	
	printk(KERN_INFO "free policy list\n");
	list_for_each_safe(p, q, &policy_list.list)
	{
		printk(KERN_INFO "free one\n");
		a_rule=list_entry(p,struct pf_rule,list);
		list_del(p);
		kfree(a_rule);
	}
	
	remove_proc_entry(PROCF_NAME, NULL);
	printk(KERN_INFO "kernel module unloaded.\n");
}












