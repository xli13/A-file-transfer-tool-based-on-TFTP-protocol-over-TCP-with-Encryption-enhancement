#include<stdio.h>  
#include<stdlib.h>  
#include <pthread.h>
#include "common.h"

BIGNUM *bN,*bE;

int GetInitPacket(int sockfd, unsigned char *data)
{
      struct pkhead *pk=(struct pkhead *)data;
      int ret=recv(sockfd,data,4,0);
      int len;
	if(ret!=4)
      	{
      		printf("error in recv head, len<4.\n");
		return -1;
      	}
	 len=pk->len-4;
	if(pk->cmd!=RRQ && pk->cmd!=WRQ)
	{
		printf("unknown cmd: %d\n",pk->cmd);
		return -2;
	}
	int offset=4;
	while(len)
	{
		ret=recv(sockfd,data+offset,len,0);
		if(ret<0)
		{
			printf("recv error: %s(errno: %d)\n",strerror(errno),errno);
			return -3;
		}
		if(ret==0)
		{
			printf("connection closed by peer.\n");
			return -4;
		}
		offset+=ret;
		len-=ret;		
	}
	return 0;

  
}


void DoReadCmd(int socketfd,unsigned char *key,FILE *fp)
{
	unsigned char data[MAXLEN];
	struct pkhead *pk=(struct pkhead *)data;
	unsigned char sbox[256];
	int res=0;
	int packnum=1;
	rc4_init(sbox,key,32);
	int first=1;
	while((res=fread(data+4,1,MAXLEN-4,fp))>=0)
	{
		pk->cmd=DATA;
		pk->idx=packnum;
		pk->len=res+4;
		if(first==1)
		{
			printf("partial file data dumped from the first package sent to client before encryption:\n");
			dump(data+4,pk->len-4);
		}			
		rc4_crypt(sbox, data+4, res);
		if(first==1)
		{
			printf("partial file data dumped from the first package sent to client after encryption:\n");
			dump(data+4,pk->len-4);
			first=0;
		}	
		if(MySend(socketfd,data,pk->len))
			return;
		if(GetACK(socketfd,packnum,data))
			return;

		if(res<MAXLEN-4)
			return;

		packnum++;
		if(packnum==256)
		{
			packnum=1;
			printf("*");
			fflush(stdout);
		}
		
	}

}

void DoWriteCmd(int socketfd,unsigned char *key,FILE *fp)
{
      unsigned char data[MAXLEN];
	struct pkhead *pk=(struct pkhead *)data;
	unsigned char sbox[256];
	rc4_init(sbox,key,32);
	int packnum=0;
	int first=1;
	while(1)
	{
		pk->cmd=ACK;
		pk->idx=packnum;
		pk->len=4;
		if(MySend(socketfd, data,4))
			return;
		packnum++;
		if(packnum==256)
		{
			packnum=1;		
			printf("*");
			fflush(stdout);
		}
		if(GetDATA(socketfd, packnum, data))
			return;
		if(first==1)
		{
			printf("partial file data dumped from the first package from client before decryption:\n");
			dump(data+4,pk->len-4);
		}			
		rc4_crypt(sbox, data+4, pk->len-4);
		if(first==1)
		{
			printf("partial file data dumped from the first package sent to client after decryption:\n");
			dump(data+4,pk->len-4);
			first=0;
		}			
		fwrite(data+4,1,pk->len-4,fp);
		if(pk->len<MAXLEN)
			break;
	}
	//the last ACK
	pk->cmd=ACK;
	pk->idx=packnum;
	pk->len=4;
	MySend(socketfd, data,4);  	
}

void *workthread(void *arg)
{
   int socketfd=*(int *)arg;
   int i,ret,len;
   unsigned char key[32];
  BIGNUM *x=BN_new(),*y=BN_new();    
  BN_CTX *ctx;
  char *hexn;
   unsigned char data[MAXLEN];
   unsigned char err[1024];
    struct pkhead *pk=(struct pkhead *)data;
FILE *fp;
   free(arg);

   if(GetInitPacket(socketfd,data))
   {
	printf("workthread at sockfd %d exit.\n",socketfd);
	 close(socketfd);	
	return NULL;
   }

  if(pk->cmd==RRQ)
   	fp=fopen(data+4,"rb");
  else
  	fp=fopen(data+4,"wb");	

  if(fp==NULL)
  {
  	printf("error in opening file %s\n",data+4);
	
	if(pk->cmd==RRQ)
		sprintf(err,"can't find file: %s.",data+4);
	else
		sprintf(err,"can't open file: %s for writing.",data+4);
	pk->cmd=ERROR;
	strcpy(data+4,err);
	pk->len=strlen(data+4)+5;
	MySend(socketfd, data,pk->len);
	printf("workthread at sockfd %d exit.\n",socketfd);
	 close(socketfd);		
	return NULL;
  }

  len=strlen(data+4);
  ret= BN_hex2bn(&x, data+5+len);
  if(ret==0)
  {
  	printf("error in BN_hex2bn for x.\n");
	 BN_free(x);
  	BN_free(y);  
	printf("workthread at sockfd %d exit.\n",socketfd);
	 close(socketfd);		
  	return NULL;
  } 
   printf("ciphered RC4 key: ");
  BN_print_fp(stdout,x);
  printf("\n");  

  
  ctx=BN_CTX_new();
  ret=BN_mod_exp(y,x,bE,bN,ctx);
  if(ret==0)
  {
  	printf("error in BN_mod_exp()\n");
	 BN_free(x);
  	BN_free(y);  
 	 OPENSSL_free(hexn);
	printf("workthread at sockfd %d exit.\n",socketfd);
	 close(socketfd);		 
	return NULL;
  }
   printf("RSA decyped : ");
  BN_print_fp(stdout,y);
  printf("\n"); 
  
  hexn=BN_bn2hex(y);
  len=strlen(hexn);  
  if(len!=64)
  {
  	printf("error in RSA decryption.");
  OPENSSL_free(hexn);
  BN_free(x);
  BN_free(y);
 printf("workthread at sockfd %d exit.\n",socketfd);
	close(socketfd);	 
  return 0;
  }
  str2hex(hexn,64,key); 

  OPENSSL_free(hexn);
  BN_free(x);
  BN_free(y);  
 
printf("the plain RC4 Key is:\n");
for(i=0;i<32;i++)
  	printf("%02x,",key[i]);
  printf("\n");

  if(pk->cmd==RRQ)
  	DoReadCmd(socketfd,key,fp);
  else
  	DoWriteCmd(socketfd,key,fp);

  fclose(fp);
 close(socketfd);	
 printf("Transfer is over,workthread at sockfd %d exit.\n",socketfd);	 
  return NULL;

}


int LoadPrikey()
{
   char p1[MAXLEN];	
   int len,ret;
   char *s;
   FILE *fp=fopen("pri.txt","r");
   if(fp==NULL)
   {
   	printf("error in openning pri.txt.\n");
   	return -1;
   }
  //modulus
  s=fgets(p1,sizeof(p1),fp);
  if(s==NULL)
  {
  	printf("error in reading N...\n");
  	fclose(fp);
  	return -1;
  }
     
  len=strlen(p1);
  if(s[len-1]=='\n')
  	s[len-1]=0;   
  
  bN=BN_new(); 
  ret= BN_hex2bn(&bN, p1);
  if(ret==0)
  {
  	printf("error in BN_hex2bn for N.\n");
  	fclose(fp);
  	return -1;
  }
  
  s=fgets(p1,sizeof(p1),fp);
  if(s==NULL)
  {
  	printf("error in reading E...\n");
  	fclose(fp);
  	return -1;
  }
     
  len=strlen(p1);
  if(s[len-1]=='\n')
  	s[len-1]=0;   
  
  bE=BN_new(); 
  ret= BN_hex2bn(&bE, p1);
  if(ret==0)
  {
  	printf("error in BN_hex2bn for E\n");
  	fclose(fp);
  	return -1;
  }
  fclose(fp);     

   printf("RSA N: ");
  BN_print_fp(stdout,bN);
  printf("\n");  

   printf("RSA e: ");
  BN_print_fp(stdout,bE);
  printf("\n");  
 
  return 0;	 	

}

int main()
{
  int sockfd,connect_fd;
  pthread_t tidp;
  int error;
  struct sockaddr_in    servaddr;  

  if(LoadPrikey())
  	return 0;
  if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1 )
  {  
    printf("create socket error: %s(errno: %d)\n",strerror(errno),errno);  
   return 0;
  }
    memset(&servaddr, 0, sizeof(servaddr));  
    servaddr.sin_family = AF_INET;  
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(DEFAULT_PORT);
  

    if( bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) == -1){  
    printf("bind socket error: %s(errno: %d)\n",strerror(errno),errno);  
    exit(0);  
    }  

    if( listen(sockfd, 10) == -1){  
    printf("listen socket error: %s(errno: %d)\n",strerror(errno),errno);  
    exit(0);  
    }  
    printf("======waiting for client's request======\n");  
  while(1)
  {  
	  struct sockaddr_in recv_addr;
        socklen_t len=sizeof(recv_addr);
        if( (connect_fd = accept(sockfd, (struct sockaddr*)&recv_addr,&len)) == -1)
        {  
         printf("accept socket error: %s(errno: %d)",strerror(errno),errno);  
         continue;  
        }
	printf("working thread at socketfd %d ,accept connection from IP: %s, Port:%d\n",connect_fd,inet_ntoa(recv_addr.sin_addr),ntohs(recv_addr.sin_port) ); 	
	int *sfd=malloc(sizeof(int));
	*sfd=connect_fd;
	error=pthread_create(&tidp,NULL,workthread,sfd);

    	if(error)
     	{
       	  printf("pthread_create error...\n");
          return -1;
        }
   }  
    
              
}
