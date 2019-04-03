#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <string.h>

int main()
{
  char p1[4096];
  BIGNUM *b1,*b2,*b3;
  b1=BN_new();
  b2=BN_new();
  b3=BN_new();
  RSA * rsa =RSA_generate_key(1024,RSA_F4,NULL,NULL);
  printf("n: ");
  BN_print_fp(stdout,rsa->n);
  printf("\n");

  printf("e: ");
  BN_print_fp(stdout,rsa->e);
  printf("\n");

  printf("d: ");
  BN_print_fp(stdout,rsa->d);
  printf("\n");

  int ret=BN_rand(b1,1020,1,1);
  if(ret==0)
  {
  	printf("error in BN_rand()");
	return 0;
  }
  printf("plain: ");
  BN_print_fp(stdout,b1);
  printf("\n");  
  
  BN_CTX *ctx=BN_CTX_new();
  ret=BN_mod_exp(b2,b1,rsa->d,rsa->n,ctx);
  if(ret==0)
  {
  	printf("error in BN_mod_exp()\n");
  	return -1;
  }
  printf("cipher: ");
  BN_print_fp(stdout,b2);
  printf("\n");  
  
  ret=BN_mod_exp(b3,b2,rsa->e,rsa->n,ctx);
  if(ret==0)
  {
  	printf("error in BN_mod_exp()\n");
  	return -1;
  }
  printf("decrpyted: ");
  BN_print_fp(stdout,b3);
  printf("\n");  
  
  if(BN_cmp(b1,b3))
  	printf("error in RSA\n");
  else 
  	printf("ok in RSA.\n");

  FILE *fp=fopen("pri.txt","w");
  if(fp==NULL)
  {
  	printf("error in open pri.txt\n");
	return 0;
  }
  char *hexn=BN_bn2hex(rsa->n);
  char *hexd=BN_bn2hex(rsa->d);
  char *hexe=BN_bn2hex(rsa->e);
  fprintf(fp,"%s\n",hexn);
  fprintf(fp,"%s\n",hexe);
  fclose(fp);

  fp=fopen("pk.txt","w");
  fprintf(fp,"%s\n",hexn);
  fprintf(fp,"%s\n",hexd);
  fclose(fp);

  return 0;
  
}
