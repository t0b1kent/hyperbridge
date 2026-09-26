/* Independent native x86-64 oracle: no HyperBridge interpreter. */
#include <stdint.h>
#include <string.h>
#include <immintrin.h>
uint64_t ea_native(uint64_t base,uint64_t idx,int scale,int64_t disp,int a32) {
 uint64_t v=0;
 switch(scale) {
 #define L(S) case S: __asm__("leaq (%1,%2," #S "),%0":"=r"(v):"r"(base),"r"(idx));break
 L(1);L(2);L(4);L(8);
 #undef L
 default:return UINT64_MAX;
 }
 if(a32){uint32_t r;__asm__("leal (%1,%2),%0":"=r"(r):"r"(v),"r"((uint64_t)disp));return r;}
 __asm__("leaq (%1,%2),%0":"=r"(v):"r"(v),"r"((uint64_t)disp));return v;
}
void vector_native(int op,const void *a,const void *b,void *out,int imm) {
 __m128i x=_mm_loadu_si128(a),y=_mm_loadu_si128(b),z;
 switch(op) {
 case 0:z=_mm_xor_si128(x,y);break;
 case 1:z=_mm_and_si128(x,y);break;
 case 2:z=_mm_andnot_si128(x,y);break;
 case 3:z=_mm_or_si128(x,y);break;
 case 4:z=_mm_unpackhi_epi64(x,y);break;
 case 5:z=_mm_unpacklo_epi64(x,y);break;
 case 6:z=y;break;
 case 7:switch(imm&255) {
 case 0:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),0));break;
 case 1:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),1));break;
 case 2:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),2));break;
 case 3:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),3));break;
 case 4:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),4));break;
 case 5:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),5));break;
 case 6:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),6));break;
 case 7:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),7));break;
 case 8:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),8));break;
 case 9:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),9));break;
 case 10:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),10));break;
 case 11:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),11));break;
 case 12:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),12));break;
 case 13:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),13));break;
 case 14:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),14));break;
 case 15:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),15));break;
 case 16:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),16));break;
 case 17:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),17));break;
 case 18:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),18));break;
 case 19:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),19));break;
 case 20:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),20));break;
 case 21:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),21));break;
 case 22:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),22));break;
 case 23:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),23));break;
 case 24:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),24));break;
 case 25:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),25));break;
 case 26:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),26));break;
 case 27:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),27));break;
 case 28:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),28));break;
 case 29:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),29));break;
 case 30:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),30));break;
 case 31:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),31));break;
 case 32:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),32));break;
 case 33:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),33));break;
 case 34:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),34));break;
 case 35:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),35));break;
 case 36:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),36));break;
 case 37:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),37));break;
 case 38:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),38));break;
 case 39:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),39));break;
 case 40:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),40));break;
 case 41:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),41));break;
 case 42:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),42));break;
 case 43:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),43));break;
 case 44:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),44));break;
 case 45:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),45));break;
 case 46:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),46));break;
 case 47:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),47));break;
 case 48:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),48));break;
 case 49:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),49));break;
 case 50:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),50));break;
 case 51:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),51));break;
 case 52:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),52));break;
 case 53:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),53));break;
 case 54:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),54));break;
 case 55:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),55));break;
 case 56:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),56));break;
 case 57:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),57));break;
 case 58:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),58));break;
 case 59:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),59));break;
 case 60:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),60));break;
 case 61:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),61));break;
 case 62:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),62));break;
 case 63:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),63));break;
 case 64:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),64));break;
 case 65:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),65));break;
 case 66:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),66));break;
 case 67:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),67));break;
 case 68:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),68));break;
 case 69:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),69));break;
 case 70:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),70));break;
 case 71:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),71));break;
 case 72:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),72));break;
 case 73:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),73));break;
 case 74:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),74));break;
 case 75:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),75));break;
 case 76:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),76));break;
 case 77:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),77));break;
 case 78:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),78));break;
 case 79:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),79));break;
 case 80:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),80));break;
 case 81:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),81));break;
 case 82:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),82));break;
 case 83:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),83));break;
 case 84:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),84));break;
 case 85:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),85));break;
 case 86:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),86));break;
 case 87:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),87));break;
 case 88:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),88));break;
 case 89:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),89));break;
 case 90:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),90));break;
 case 91:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),91));break;
 case 92:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),92));break;
 case 93:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),93));break;
 case 94:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),94));break;
 case 95:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),95));break;
 case 96:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),96));break;
 case 97:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),97));break;
 case 98:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),98));break;
 case 99:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),99));break;
 case 100:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),100));break;
 case 101:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),101));break;
 case 102:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),102));break;
 case 103:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),103));break;
 case 104:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),104));break;
 case 105:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),105));break;
 case 106:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),106));break;
 case 107:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),107));break;
 case 108:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),108));break;
 case 109:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),109));break;
 case 110:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),110));break;
 case 111:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),111));break;
 case 112:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),112));break;
 case 113:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),113));break;
 case 114:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),114));break;
 case 115:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),115));break;
 case 116:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),116));break;
 case 117:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),117));break;
 case 118:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),118));break;
 case 119:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),119));break;
 case 120:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),120));break;
 case 121:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),121));break;
 case 122:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),122));break;
 case 123:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),123));break;
 case 124:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),124));break;
 case 125:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),125));break;
 case 126:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),126));break;
 case 127:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),127));break;
 case 128:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),128));break;
 case 129:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),129));break;
 case 130:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),130));break;
 case 131:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),131));break;
 case 132:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),132));break;
 case 133:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),133));break;
 case 134:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),134));break;
 case 135:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),135));break;
 case 136:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),136));break;
 case 137:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),137));break;
 case 138:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),138));break;
 case 139:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),139));break;
 case 140:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),140));break;
 case 141:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),141));break;
 case 142:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),142));break;
 case 143:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),143));break;
 case 144:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),144));break;
 case 145:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),145));break;
 case 146:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),146));break;
 case 147:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),147));break;
 case 148:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),148));break;
 case 149:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),149));break;
 case 150:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),150));break;
 case 151:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),151));break;
 case 152:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),152));break;
 case 153:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),153));break;
 case 154:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),154));break;
 case 155:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),155));break;
 case 156:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),156));break;
 case 157:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),157));break;
 case 158:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),158));break;
 case 159:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),159));break;
 case 160:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),160));break;
 case 161:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),161));break;
 case 162:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),162));break;
 case 163:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),163));break;
 case 164:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),164));break;
 case 165:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),165));break;
 case 166:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),166));break;
 case 167:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),167));break;
 case 168:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),168));break;
 case 169:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),169));break;
 case 170:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),170));break;
 case 171:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),171));break;
 case 172:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),172));break;
 case 173:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),173));break;
 case 174:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),174));break;
 case 175:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),175));break;
 case 176:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),176));break;
 case 177:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),177));break;
 case 178:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),178));break;
 case 179:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),179));break;
 case 180:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),180));break;
 case 181:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),181));break;
 case 182:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),182));break;
 case 183:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),183));break;
 case 184:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),184));break;
 case 185:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),185));break;
 case 186:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),186));break;
 case 187:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),187));break;
 case 188:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),188));break;
 case 189:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),189));break;
 case 190:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),190));break;
 case 191:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),191));break;
 case 192:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),192));break;
 case 193:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),193));break;
 case 194:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),194));break;
 case 195:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),195));break;
 case 196:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),196));break;
 case 197:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),197));break;
 case 198:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),198));break;
 case 199:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),199));break;
 case 200:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),200));break;
 case 201:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),201));break;
 case 202:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),202));break;
 case 203:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),203));break;
 case 204:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),204));break;
 case 205:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),205));break;
 case 206:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),206));break;
 case 207:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),207));break;
 case 208:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),208));break;
 case 209:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),209));break;
 case 210:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),210));break;
 case 211:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),211));break;
 case 212:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),212));break;
 case 213:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),213));break;
 case 214:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),214));break;
 case 215:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),215));break;
 case 216:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),216));break;
 case 217:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),217));break;
 case 218:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),218));break;
 case 219:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),219));break;
 case 220:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),220));break;
 case 221:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),221));break;
 case 222:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),222));break;
 case 223:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),223));break;
 case 224:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),224));break;
 case 225:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),225));break;
 case 226:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),226));break;
 case 227:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),227));break;
 case 228:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),228));break;
 case 229:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),229));break;
 case 230:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),230));break;
 case 231:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),231));break;
 case 232:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),232));break;
 case 233:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),233));break;
 case 234:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),234));break;
 case 235:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),235));break;
 case 236:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),236));break;
 case 237:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),237));break;
 case 238:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),238));break;
 case 239:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),239));break;
 case 240:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),240));break;
 case 241:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),241));break;
 case 242:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),242));break;
 case 243:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),243));break;
 case 244:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),244));break;
 case 245:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),245));break;
 case 246:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),246));break;
 case 247:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),247));break;
 case 248:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),248));break;
 case 249:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),249));break;
 case 250:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),250));break;
 case 251:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),251));break;
 case 252:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),252));break;
 case 253:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),253));break;
 case 254:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),254));break;
 case 255:z=_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(x),_mm_castsi128_ps(y),255));break;
 }break;
 case 8: {int q;switch(imm&3){case 0:q=_mm_extract_ps(_mm_castsi128_ps(x),0);break;case 1:q=_mm_extract_ps(_mm_castsi128_ps(x),1);break;case 2:q=_mm_extract_ps(_mm_castsi128_ps(x),2);break;case 3:q=_mm_extract_ps(_mm_castsi128_ps(x),3);break;default:__builtin_trap();}z=_mm_cvtsi32_si128(q);break;}
 case 9:switch(imm){case 1:z=_mm_unpacklo_epi8(x,y);break;case 257:z=_mm_unpackhi_epi8(x,y);break;case 2:z=_mm_unpacklo_epi16(x,y);break;case 258:z=_mm_unpackhi_epi16(x,y);break;case 4:z=_mm_unpacklo_epi32(x,y);break;case 260:z=_mm_unpackhi_epi32(x,y);break;case 8:z=_mm_unpacklo_epi64(x,y);break;case 264:z=_mm_unpackhi_epi64(x,y);break;default:__builtin_trap();}break;

 default:__builtin_trap();
 }
 _mm_storeu_si128(out,z);(void)imm;
}
#define DO(OP,T,S) do {T x=(T)a,y=(T)b;uint64_t f; __asm__ volatile(OP S " %2,%0\n\tpushfq\n\tpopq %1":"+r"(x),"=&r"(f):"r"(y):"cc","memory");*flags=f;return (uint64_t)x;}while(0)
#define SIZES(OP) switch(width){case 1:DO(OP,uint8_t,"b");case 2:DO(OP,uint16_t,"w");case 4:DO(OP,uint32_t,"l");case 8:DO(OP,uint64_t,"q");default:__builtin_trap();}
uint64_t scalar_native(int op,int width,uint64_t a,uint64_t b,uint64_t *flags) {
 switch(op){case 0:SIZES("add");case 1:SIZES("sub");case 2:SIZES("and");case 3:SIZES("or");case 4:SIZES("xor");default:__builtin_trap();}
}

uint64_t extend_native(int sign, int width, uint64_t value, int arch32) {
 uint64_t out=0;
 if(sign) {
  switch(width) {
  case 1: __asm__("movsbq %b1,%0":"=r"(out):"r"(value));break;
  case 2: __asm__("movswq %w1,%0":"=r"(out):"r"(value));break;
  case 4: __asm__("movslq %k1,%0":"=r"(out):"r"(value));break;
  case 8: out=value;break;
  default: __builtin_trap();
  }
 } else {
  switch(width) {
  case 1: __asm__("movzbq %b1,%0":"=r"(out):"r"(value));break;
  case 2: __asm__("movzwq %w1,%0":"=r"(out):"r"(value));break;
  case 4: __asm__("movl %k1,%k0":"=r"(out):"r"(value));break;
  case 8: out=value;break;
  default: __builtin_trap();
  }
 }
 if(arch32) { uint64_t truncated; __asm__("movl %k1,%k0":"=r"(truncated):"r"(out));return truncated; }
 return out;
}
