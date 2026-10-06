/* Independent normal-value C float/double arithmetic checks. Original MIT code. */
#include <stdint.h>
#include <string.h>
#include <math.h>
#define FN(T,SFX,BITS,UT) \
static int check_##SFX(const char*n,const uint8_t*ap,const uint8_t*bp,const uint8_t*cp,const uint8_t*rp){ \
 T a,b,c,r,expected;UT bits,actual;memcpy(&a,ap,sizeof a);memcpy(&b,bp,sizeof b);memcpy(&c,cp,sizeof c);memcpy(&r,rp,sizeof r); \
 if(!isnormal(a)||!isnormal(b)||!isfinite(a)||!isfinite(b)||fabs((double)a)>1e10||fabs((double)b)>1e10||fabs((double)a)<1e-10||fabs((double)b)<1e-10)return -1; \
 if(*n=='v')n++; \
 if(strstr(n,"fm")||strstr(n,"fnm")){ \
 if(!isnormal(c)||fabs((double)c)>1e10||fabs((double)c)<1e-10)return -1; \
 T x,y,z;if(strstr(n,"132")){x=a;y=c;z=b;}else if(strstr(n,"213")){x=b;y=a;z=c;}else{x=b;y=c;z=a;} \
 if(!strncmp(n,"fnm",3))x=-x; \
 if((!strncmp(n,"fmsub",5)&&strncmp(n,"fmsubadd",8))||!strncmp(n,"fnmsub",6))z=-z; \
 if(!strncmp(n,"fmaddsub",8))z=-z; \
 expected=fma##SFX(x,y,z); \
 }else if(!strncmp(n,"add",3))expected=a+b; \
 else if(!strncmp(n,"sub",3))expected=a-b; \
 else if(!strncmp(n,"mul",3))expected=a*b; \
 else if(!strncmp(n,"div",3))expected=a/b; \
 else if(!strncmp(n,"sqrt",4)){if(b<0)return -1;expected=sqrt##SFX(b);} \
 else if(!strncmp(n,"min",3))expected=a<b?a:b; \
 else if(!strncmp(n,"max",3))expected=a>b?a:b;else return -1; \
 memcpy(&bits,&expected,sizeof bits);memcpy(&actual,&r,sizeof actual);return bits==actual; }
FN(float,f,32,uint32_t)
FN(double,,64,uint64_t)
int normal_crosscheck(const char*n,int lane,const uint8_t*a,const uint8_t*b,const uint8_t*c,const uint8_t*r){return lane==4?check_f(n,a,b,c,r):check_(n,a,b,c,r);}
