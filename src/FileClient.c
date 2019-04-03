#include "common.h"

BIGNUM *bN,*bD;


void DoGet(int sockfd, char *filename)
{
  unsigned char data[MAXLEN];
  unsigned char key[32];
  unsigned char dx[80];
  unsigned char sbox[256];
  char *hexn;
  BIGNUM *x=BN_new(),*y=BN_new(); 
  BN_CTX *ctx;
  FILE *fp;
  int ret,i,offset=0;
  memset(data,0,sizeof(data));
  int len=strlen(filename);
  struct pkhead *pk=(struct pkhead *)data;
  pk->cmd=RRQ;
  if(len>MAXLEN-5-256)
  {
  	printf("error filename too long.\n");
	return;
  }
  memcpy(data+4,filename,len);
  offset=len+5;
  srand(time(NULL));
  for(i=0;i<32;i++)
  	key[i]=rand()&0xff;
  key[0]|=1;

printf("plain RC4 key:\n");
  for(i=0;i<32;i++)
  	printf("%02x,",key[i]);
  printf("\n");
  
  hex2str(key,32,dx);
  ret= BN_hex2bn(&x, dx);
  if(ret==0)
  {
  	printf("error in BN_hex2bn for x.\n");
  	return;
  }

  printf("plain RC4 key to BN: ");
  BN_print_fp(stdout,x);
  printf("\n");  

  
  ctx=BN_CTX_new();
  ret=BN_mod_exp(y,x,bD,bN,ctx);
  if(ret==0)
  {
  	printf("error in BN_mod_exp()\n");
  	return;
  }
printf("RSA ciphered RC4 key: ");
  BN_print_fp(stdout,y);
  printf("\n");  
  
  hexn=BN_bn2hex(y);
  len=strlen(hexn);
  memcpy(data+offset,hexn,len);
  offset+=len;
  data[offset]=0;
  offset++;
  OPENSSL_free(hexn);
  BN_free(x);
  BN_free(y);
  pk->len=offset;
  fp=fopen(filename,"wb");
  if(fp==NULL)
  {
  	printf("error in opening %s for writing.\n",filename);
	return;	
  }
  
  
  if(MySend(sockfd,data,offset))
  	return;
   
  int packnum=1;	
  int first=1;
  rc4_init(sbox,key,32);
  while(1)
  {
  	if(GetDATA(sockfd,packnum,data))
		return;

	if(first==1)
	{
		printf("partial file data dumped from the first package received from server before decryption:\n");
		dump(data+4,pk->len-4);
	}
	//after decrypt,we need show the plain for the first package
	rc4_crypt(sbox, data+4, pk->len-4);

	if(first==1)
	{
		printf("partial file data in the first package received from server after decryption:\n");
		dump(data+4,pk->len-4);
		first=0;
	}
	
	fwrite(data+4,1,pk->len-4,fp);
	len=pk->len-4;
	pk->cmd=ACK;
	pk->len=4;
	if(MySend(sockfd,data,4))
		return;
	packnum++;
	if(packnum==256)
	{
		packnum=1;
		printf("*");
		fflush(stdout);
	}
	if(len<MAXLEN-4)
		break;
  }
  fclose(fp);
  	  
}

void DoPut(int sockfd, char *filename)
{
  unsigned char data[MAXLEN];
  unsigned char key[32];
  unsigned char dx[80];
  char *hexn;
  unsigned char sbox[256];
  FILE *fp=fopen(filename,"rb");
  if(fp==NULL)
  {
  	printf("error in opening %s for reading.\n",filename);
	return;	
  }  
  BIGNUM *x=BN_new(),*y=BN_new(); 
  BN_CTX *ctx;

  int ret,i,offset=0;
  memset(data,0,sizeof(data));
  int len=strlen(filename);
  struct pkhead *pk=(struct pkhead *)data;
  pk->cmd=WRQ;
  if(len>MAXLEN-5-256)
  {
  	printf("error filename too long.\n");
	return;
  }
  memcpy(data+4,filename,len);
  offset=len+5;
  srand(time(NULL));
  
  for(i=0;i<32;i++)
  	key[i]=rand()&0xff;
  key[0]|=1;

printf("plain RC4 key:\n");
for(i=0;i<32;i++)
  	printf("%02x,",key[i]);
  printf("\n");
 
  hex2str(key,32,dx);
  ret= BN_hex2bn(&x, dx);
  if(ret==0)
  {
  	printf("error in BN_hex2bn for x.\n");
  	return;
  }
  printf("plain RC4 key to BN: ");
  BN_print_fp(stdout,x);
  printf("\n");  
  
  ctx=BN_CTX_new();
  ret=BN_mod_exp(y,x,bD,bN,ctx);
  if(ret==0)
  {
  	printf("error in BN_mod_exp()\n");
  	return ;
  }
printf("RSA ciphered RC4 key: ");
  BN_print_fp(stdout,y);
  printf("\n");  
  
  hexn=BN_bn2hex(y);
  len=strlen(hexn);
  memcpy(data+offset,hexn,len);
  offset+=len;
  data[offset]=0;
  offset++;
  OPENSSL_free(hexn);
  BN_free(x);
  BN_free(y);
  pk->len=offset;
   
  if(MySend(sockfd,data,offset))
  	return;

  if(GetACK( sockfd, 0, data))
  	return;

  int packnum=1;
  int first=1;
  rc4_init(sbox,key,32);
  while(1)
  {
	ret=fread(data+4,1,MAXLEN-4,fp);
	pk->len=4+ret;
	pk->cmd=DATA;
	pk->idx=packnum;
	if(first==1)
	{
		printf("partial file data dumped from the first package sent to server before encryption:\n");
		dump(data+4,pk->len-4);
	}	
	//we need encry here
	rc4_crypt(sbox, data+4, pk->len-4);
	if(first==1)
	{
		printf("partial file data in the first package sent to server after encryption:\n");
		dump(data+4,pk->len-4);
		first=0;
	}	
	if(MySend(sockfd,data,pk->len))
  		return;	
	if(GetACK( sockfd, packnum, data))
  		return;
	packnum++;
	if(packnum==256)
	{
		packnum=1;
		printf("*");
		fflush(stdout);
	}
	if(ret!=MAXLEN-4)
		break;
  }
  fclose(fp);
  
	
}

int LoadPk()
{
   char p1[MAXLEN];	
   int len,ret;
   char *s;
   FILE *fp=fopen("pk.txt","r");
   if(fp==NULL)
   {
   	printf("error in openning pk.txt.\n");
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
  	printf("error in reading D...\n");
  	fclose(fp);
  	return -1;
  }
     
  len=strlen(p1);
  if(s[len-1]=='\n')
  	s[len-1]=0;   
  
  bD=BN_new(); 
  ret= BN_hex2bn(&bD, p1);
  if(ret==0)
  {
  	printf("error in BN_hex2bn for D\n");
  	fclose(fp);
  	return -1;
  }
  fclose(fp);     
   printf("RSA N: ");
  BN_print_fp(stdout,bN);
  printf("\n");  

   printf("RSA d: ");
  BN_print_fp(stdout,bD);
  printf("\n");    
  return 0;	 	
}

  
int main(int argc, char** argv)  
{  
    int    sockfd;
    int    cmdtype;
    struct sockaddr_in    servaddr;  
  
  
    if( argc != 4){  
    printf("usage: ./FileClient <ipaddress> -get|-put  <filename>\n");  
    return 0;  
    }  
  
    if(strcmp(argv[2],"-get")==0)
    	cmdtype=0;
    else if(strcmp(argv[2],"-put")==0)
    	cmdtype=1;
    else 
    	cmdtype=-1;
    
    if(cmdtype==-1)
    {
	printf("error command, only '-get' or '-put' is allowed.\n");
	return 0;    	
    }	
    
    if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {  
    	printf("create socket error: %s(errno: %d)\n", strerror(errno),errno);  
    	return 0;  
    }  
  
  
    memset(&servaddr, 0, sizeof(servaddr));  
    servaddr.sin_family = AF_INET;  
    servaddr.sin_port = htons(DEFAULT_PORT);  
    if( inet_pton(AF_INET, argv[1], &servaddr.sin_addr) <= 0)
    {  
    	printf("inet_pton error for %s\n",argv[1]);  
    	return 0;  
    }   
  
    if( connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
    {  
    	printf("connect error: %s(errno: %d)\n",strerror(errno),errno);  
    	return 0;  
    }  
    
    if(LoadPk())
    	return -1;
    
    if(cmdtype==0)
    	DoGet(sockfd,argv[3]);
    else
    	DoPut(sockfd,argv[3]);

    if(bN)
	BN_free(bN);
	
    if(bD)
	BN_free(bD);

    printf("transfer is over.\n");
    return 0;
 
      
}  
