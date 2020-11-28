
#ifndef __BYTES_UTILS_H__
#define __BYTES_UTILS_H__

#include <stdio.h>
#include <stdint.h>
#include <string.h>

//#ifndef bytes_utiles_printf
//#define bytes_utiles_printf printf
//#endif
#ifndef bytes_utiles_printf
#define bytes_utiles_printf printf
#endif

//replace 0 by .
static void print_diff_byte(uint8_t d, const char *sep){
    unsigned int n=d>>4;
    if(0==n) bytes_utiles_printf("."); else bytes_utiles_printf("%X",n);
    n = d & 0xF;
    if(0==n) bytes_utiles_printf("."); else bytes_utiles_printf("%X",n);
    bytes_utiles_printf("%s",sep);
}
static void print_diff_bytes_sep(const char *msg,const void *vbuf, unsigned int size, const char *m2, const char *sep){
    const uint8_t*const buf = (const uint8_t*const)vbuf;
    bytes_utiles_printf("%s",msg);
    if(size){
        unsigned int i;
        for(i=0;i<size-1;i++) print_diff_byte(buf[i],sep);
        print_diff_byte(buf[i],"");
    }
    bytes_utiles_printf("%s", m2);
}

static void print_bytes_sep(const char *msg,const void *vbuf, unsigned int size, const char *m2, const char *sep){
    const uint8_t*const buf = (const uint8_t*const)vbuf;
    bytes_utiles_printf("%s",msg);
    if(size){
        unsigned int i;
        for(i=0;i<size-1;i++) bytes_utiles_printf("%02X%s",buf[i],sep);
        bytes_utiles_printf("%02X",buf[i]);
    }
    bytes_utiles_printf("%s", m2);
}
static void print_bytes(const char *m,const void *buf, unsigned int size, const char *m2){print_bytes_sep(m,buf,size,m2," ");}
static void println_bytes(const char *m,const void *buf, unsigned int size){print_bytes(m,buf,size,"\n");}
static void print_128(const char *m, const uint8_t a[16], const char *m2){
	print_bytes_sep( m,a   ,4,"_","");
	print_bytes_sep("",a+4 ,4,"_","");
	print_bytes_sep("",a+8 ,4,"_","");
	print_bytes_sep("",a+12,4,m2 ,"");
}
static void println_128(const char m[], const uint8_t a[16]){print_128(m,a,"\n");}

static void xor_bytes( uint8_t *d, const uint8_t *s, size_t size ){
    for(size_t i=0;i<size;i++)
		d[i] ^= s[i];
}

static int hexdigit_value(char c){
	int nibble = -1;
	if(('0'<=c) && (c<='9')) nibble = c-'0';
	if(('a'<=c) && (c<='f')) nibble = c-'a' + 10;
	if(('A'<=c) && (c<='F')) nibble = c-'A' + 10;
	return nibble;
}

static int is_hexdigit(char c){
	return -1!=hexdigit_value(c);
}

static size_t hexstr_to_bytes(uint8_t *dst, size_t dst_size, const char *const hexstr){
	unsigned int len = strlen(hexstr);
	if(dst_size>(len/2))
		dst_size = (len/2);
	memset(dst,0,dst_size);
	for(unsigned int i=0;i<dst_size*2;i++){
		unsigned int shift = 4 - 4*(i & 1);
		unsigned int charIndex = i;//len-1-i;
		char c = hexstr[charIndex];
		uint8_t nibble = hexdigit_value(c);
		dst[i/2] |= nibble << shift;
	}
	return dst_size;
}

static void bytes_to_hexstr(char *dst,uint8_t *bytes, unsigned int nBytes){
	unsigned int i;
	for(i=0;i<nBytes;i++){
		sprintf(dst+2*i,"%02X",bytes[i]);
	}
}
static size_t cleanup_hexstr(char *hexstr, size_t hexstr_size, char *str, size_t str_size){
	size_t cnt=0;
	int lastIs0=0;
	for(unsigned int j = 0;j<str_size;j++){
		char c = str[j];
		if(is_hexdigit(c)){
			if(cnt==hexstr_size-1){//need final char for null.
				printf("Too many hex digits. hexstr=%s\n",hexstr);
				hexstr[cnt]=0;
				return -1;
			}
			hexstr[cnt++]=c;
		} else if(lastIs0) {
			if('x'==c) cnt--;
			if('X'==c) cnt--;
		}
		lastIs0 = '0'==c;
	}
	hexstr[cnt]=0;
	return cnt;
}
static size_t user_hexstr_to_bytes(uint8_t*out, size_t out_size, char *str, size_t str_size){
	size_t hexstr_size = cleanup_hexstr(str,str_size,str,str_size);
	size_t conv_size = (hexstr_size/2) < out_size ? hexstr_size/2 : out_size;
	return hexstr_to_bytes(out,conv_size,str);
}

static void bytes_utils_remove_unused_warnings(void){
    (void)println_bytes;
    (void)println_128;
    (void)xor_bytes;
    (void)bytes_to_hexstr;
    (void)user_hexstr_to_bytes;
    (void)print_diff_bytes_sep;
}

#endif
