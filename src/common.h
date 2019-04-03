#include<stdio.h>  
#include<stdlib.h>  
#include<string.h>  
#include<errno.h>  
#include<sys/types.h>  
#include<sys/socket.h>  
#include<netinet/in.h>  
#include <openssl/bn.h>
#include <openssl/crypto.h>
#define DEFAULT_PORT 9527
#define MAXLEN 4096
#define RRQ 1
#define WRQ 2 
#define DATA 3
#define ACK 4
#define ERROR 5

 
struct pkhead{
unsigned short len;
unsigned char cmd;
unsigned char idx;
};

int MySend(int sockfd,unsigned char *data,int len);
void hex2str(unsigned char *in, int len, unsigned char *out);
int GetACK(int sockfd, int packnum,unsigned char *data);
int GetDATA(int sockfd, int packnum,unsigned char *data);
void rc4_init(unsigned char*s, unsigned char*key, unsigned int Len);
void rc4_crypt(unsigned char*s, unsigned char*Data, unsigned int Len);
void str2hex(unsigned char *hex, int len, unsigned char *out);
void dump(unsigned char *s, int len);
