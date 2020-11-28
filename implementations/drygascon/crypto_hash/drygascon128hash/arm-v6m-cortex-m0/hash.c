#ifdef REDIRECT_DBG_TO_FILE
#include <stdio.h>
#include <stdarg.h>
#define bytes_utiles_printf append_to_log
static void append_to_log(const char *format, ...){
    static FILE *fp=0;
    if(0==fp) fp=fopen("/tmp/mylog", "w");
    va_list vargs;
    va_start(vargs, format);
    vfprintf(fp,format, vargs);
    va_end(vargs);
}
#endif

#include "crypto_hash.h"
#include "drygascon128k32.h"

int crypto_hash(
    unsigned char *out,
    const unsigned char *in,
    unsigned long long inlen
){
    drygascon128_hash(
        out,    //digest
        in,     // message,
        inlen  // mlen,
    );
    return 0;
}
