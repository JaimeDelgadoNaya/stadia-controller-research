/* Minimal freestanding runtime for the RAM-only diagnostic. */
#include <stddef.h>
void *memset(void *dest,int ch,size_t n){
 volatile unsigned char *p=(volatile unsigned char*)dest;
 for(size_t i=0;i<n;i++)p[i]=(unsigned char)ch;
 return dest;
}
void *memcpy(void *dest,const void *source,size_t n){
 volatile unsigned char *d=(volatile unsigned char*)dest;
 const volatile unsigned char *s=(const volatile unsigned char*)source;
 for(size_t i=0;i<n;i++)d[i]=s[i];
 return dest;
}
void __aeabi_memclr4(void *d,size_t n){(void)memset(d,0,n);}
void __aeabi_memclr(void *d,size_t n){(void)memset(d,0,n);}
