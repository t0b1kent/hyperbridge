/* Independent C expression/conversion crosschecks; original MIT code. */
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <fenv.h>
#include <stdlib.h>
#pragma STDC FENV_ACCESS ON
static long double get80(const unsigned char *p){long double x=0;memcpy(&x,p,10);return x;}
static void setcw(uint16_t cw){__asm__ volatile("fnclex; fldcw %0"::"m"(cw):"memory");}
static int finiteordinary(long double x){return isfinite(x)&&(x==0|| (fabsl(x)>0x1p-100L&&fabsl(x)<0x1p100L));}
static long double expression(const char*op,long double x,long double y){
 volatile long double a=x,b=y,r;
 if(!strncmp(op,"FADD",4)||!strncmp(op,"FIADD",5))r=a+b;
 else if(!strncmp(op,"FSUBR",5)||!strncmp(op,"FISUBR",6))r=b-a;
 else if(!strncmp(op,"FSUB",4)||!strncmp(op,"FISUB",5))r=a-b;
 else if(!strncmp(op,"FMUL",4)||!strncmp(op,"FIMUL",5))r=a*b;
 else if(!strncmp(op,"FDIVR",5)||!strncmp(op,"FIDIVR",6))r=b/a;
 else if(!strncmp(op,"FDIV",4)||!strncmp(op,"FIDIV",5))r=a/b;
 else if(!strcmp(op,"FSQRT"))r=sqrtl(a);
 else if(!strcmp(op,"FABS"))r=fabsl(a);
 else if(!strcmp(op,"FCHS"))r=-a;
 else if(!strcmp(op,"FRNDINT"))r=rintl(a);
 else return nanl("");
 return r;
}
static double dexpression(const char*op,double x,double y){volatile double a=x,b=y,r;
 if(!strncmp(op,"FADD",4)||!strncmp(op,"FIADD",5))r=a+b;
 else if(!strncmp(op,"FSUBR",5)||!strncmp(op,"FISUBR",6))r=b-a;
 else if(!strncmp(op,"FSUB",4)||!strncmp(op,"FISUB",5))r=a-b;
 else if(!strncmp(op,"FMUL",4)||!strncmp(op,"FIMUL",5))r=a*b;
 else if(!strncmp(op,"FDIVR",5)||!strncmp(op,"FIDIVR",6))r=b/a;
 else if(!strncmp(op,"FDIV",4)||!strncmp(op,"FIDIV",5))r=a/b;
 else if(!strcmp(op,"FSQRT"))r=sqrt(a);
 else if(!strcmp(op,"FABS"))r=fabs(a);
 else if(!strcmp(op,"FCHS"))r=-a;
 else if(!strcmp(op,"FRNDINT"))r=nearbyint(a);
 else return NAN;
 return r;
}
/* Returns -1 outside bounded ordinary test domain, else writes the C-produced bits. */
int arithmetic(const char*op,int cw,const unsigned char*ap,const unsigned char*bp,const unsigned char*mp,unsigned char*expected){
 int pc=(cw>>8)&3;if(pc!=3&&cw!=0x27f)return -1;setcw(0x37f);long double x=get80(ap),y=get80(bp);
 if(strstr(op,"_m")){
  if(strncmp(op,"FI",2)==0){if(strstr(op,"m16")){int16_t z;memcpy(&z,mp,2);y=z;}else{int32_t z;memcpy(&z,mp,4);y=z;}}
  else if(strstr(op,"m32")){float z;memcpy(&z,mp,4);y=z;}else{double z;memcpy(&z,mp,8);y=z;}
 }else if(strstr(op,"_ST1_ST0")){long double t=x;x=y;y=t;}
 if(!finiteordinary(x)||!finiteordinary(y))return -1;
 int unary=!strcmp(op,"FSQRT")||!strcmp(op,"FABS")||!strcmp(op,"FCHS")||!strcmp(op,"FRNDINT");if(unary)y=1;
 if((strstr(op,"DIVR")&&x==0)||(strstr(op,"DIV")&&!strstr(op,"DIVR")&&y==0)||(!strcmp(op,"FSQRT")&&x<0))return -1;
 int rm=(cw>>10)&3;fesetround((int[]){FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO}[rm]);setcw((uint16_t)cw);
 long double z;
 if(pc==3)z=expression(op,x,y);
 else {double a=(double)x,b=(double)y;if((long double)a!=x||(long double)b!=y){setcw(0x37f);fesetround(FE_TONEAREST);return -1;}double d=dexpression(op,a,b);setcw(0x37f);z=d;}
 setcw(0x37f);fesetround(FE_TONEAREST);if(!isfinite(z))return -1;memcpy(expected,&z,10);return 0;
}
int conversion(const char*op,int cw,const unsigned char*ap,const unsigned char*mp,unsigned char*expected){
 if(((cw>>8)&3)!=3&&cw!=0x27f)return -1;setcw(0x37f);long double x=get80(ap);int rm=(cw>>10)&3;
 fesetround((int[]){FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO}[rm]);setcw(cw);
 int n=10;
 if(!strncmp(op,"FLD_m",5)){
  if(strstr(op,"m32")){float f;memcpy(&f,mp,4);x=f;}else if(strstr(op,"m64")){double d;memcpy(&d,mp,8);x=d;}else x=get80(mp);
  if(!finiteordinary(x))goto skip;memcpy(expected,&x,10);
 }else if(!strncmp(op,"FILD_m",6)){
  if(strstr(op,"m16")){int16_t z;memcpy(&z,mp,2);x=z;}else if(strstr(op,"m32")){int32_t z;memcpy(&z,mp,4);x=z;}else{int64_t z;memcpy(&z,mp,8);x=z;}memcpy(expected,&x,10);
 }else if(!strncmp(op,"FST",3)&&strstr(op,"_m")){
  if(!finiteordinary(x))goto skip;
  if(strstr(op,"m32")){volatile float f=x;memcpy(expected,(const void*)&f,4);n=4;}else if(strstr(op,"m64")){volatile double d=x;memcpy(expected,(const void*)&d,8);n=8;}else memcpy(expected,&x,10);
 }else if(!strncmp(op,"FIST",4)){
  if(!finiteordinary(x))goto skip;long double z=strstr(op,"FISTTP")?truncl(x):rintl(x);
  if(strstr(op,"m16")){if(z<-32768||z>32767)goto skip;int16_t q=z;memcpy(expected,&q,2);n=2;}
  else if(strstr(op,"m32")){if(z<-2147483648.0L||z>2147483647.0L)goto skip;int32_t q=z;memcpy(expected,&q,4);n=4;}
  else {if(z<-9223372036854775808.0L||z>9223372036854775807.0L)goto skip;int64_t q=z;memcpy(expected,&q,8);n=8;}
 }else goto skip;
 setcw(0x37f);fesetround(FE_TONEAREST);return n;
 skip:setcw(0x37f);fesetround(FE_TONEAREST);return -1;
}
