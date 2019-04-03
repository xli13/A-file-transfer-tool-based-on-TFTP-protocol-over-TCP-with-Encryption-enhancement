#include "common.h"
int MySend(int sockfd,unsigned char *data,int len)
{
       int left=len;
       int ret;
	int go=0;
	while(left>0)
	{
	   ret=send(sockfd,data+go,left,0);
	   if(ret<0)
	   {
		printf("send error: %s(errno: %d)\n",strerror(errno),errno); 
		return -1;
	   }
	   left-=ret;
	   go+=ret;
	}
	return 0;
}
  
void hex2str(unsigned char *in, int len, unsigned char *out)
{
      int i,j=0,k;
      for(i=0;i<len;i++)
      {
          	k=(in[i]>>4);
		if(k<10)
			out[j]='0'+k;
		else
			out[j]='A'+k-10;
		j++;
          	k=in[i]&0xf;
		if(k<10)
			out[j]='0'+k;
		else
			out[j]='A'+k-10;
		j++;		
      }
      out[j]=0;
}

int GetACK(int sockfd, int packnum,unsigned char *data)
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
	if(pk->cmd==ERROR)
	{
		printf("Server return Error msg: %s\n",data+4);
		return -2;
	}
	else if(pk->cmd!=ACK)
	{
		printf("ACK packet opcode not ACK\n");
		return -3;
	}
       if(packnum!=pk->idx)
       {
       	printf("packnum want: %d, but get %d\n",packnum,pk->idx);
		return  -4;
       }
	return 0;
	
}

int GetDATA(int sockfd, int packnum,unsigned char *data)
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
	int offset=4;
	while(len)
	{
		ret=recv(sockfd,data+offset,len,0);
		if(ret<0)
		{
			printf("recv error: %s(errno: %d)\n",strerror(errno),errno);
			return -5;
		}
		if(ret==0)
		{
			printf("connection closed by peer.\n");
			return -6;
		}
		offset+=ret;
		len-=ret;		
	}
	
	if(pk->cmd==ERROR)
	{
		printf("Server return Error msg: %s\n",data+4);
		return -2;
	}
	else if(pk->cmd!=DATA)
	{
		printf("DATA packet opcode not DATA\n");
		return -3;
	}
       if(packnum!=pk->idx)
       {
       	printf("packnum want: %d, but get %d\n",packnum,pk->idx);
		return  -4;
       }

	return 0;
	
}

void rc4_init(unsigned char*s, unsigned char*key, unsigned int Len)
{
    int i = 0, j = 0;
    unsigned char k[256] = { 0 };
    unsigned char tmp = 0;
    for (i = 0; i<256; i++)
    {
        s[i] = i;
        k[i] = key[i%Len];
    }
    for (i = 0; i<256; i++)
    {
        j = (j + s[i] + k[i]) % 256;
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }
}

void rc4_crypt(unsigned char*s, unsigned char*Data, unsigned int Len)
{
    int i = 0, j = 0, t = 0;
    unsigned long k = 0;
    unsigned char tmp;
    for (k = 0; k<Len; k++)
    {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
        t = (s[i] + s[j]) % 256;
        Data[k] ^= s[t];
    }
}

void str2hex(unsigned char *hex, int len, unsigned char *out)
{
   int i,j=0,k;
	for(i=0;i<len;i++)
	{
		k=0;
		if(hex[i]>='A')
			k|=(hex[i]-'A'+10)<<4;
		else
			k|=(hex[i]-'0')<<4;

		i++;
		if(hex[i]>='A')
			k|=(hex[i]-'A'+10);
		else
			k|=(hex[i]-'0');

		out[j]=k;
		j++;
	}
}

void dump(unsigned char *s, int len)
{
      int i,j,t;
	len= (len>256) ? 256 : len;
	int k=len/16;
	for(i=0;i<k;i++)
	{
	     t=i*16;
		for(j=0;j<16;j++)
			printf("%02x ",s[t+j]);
		printf("\n");		
	}
	i=len%16;
	if(i)
	{
		t=k*16;
	       for(j=0;j<i;j++)     
		   printf("%02x ",s[t+j]);
				
		 printf("\n");
	}
	
}
