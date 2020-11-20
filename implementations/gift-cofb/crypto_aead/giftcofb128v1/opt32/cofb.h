#ifndef COFB_H_
#define COFB_H_

#define DOUBLE_HALF_BLOCK(x) ({                                             \
	tmp0 = (x)[0];                                                          \
    (x)[0] = (((x)[0] & 0x7f7f7f7f) << 1) | (((x)[0] & 0x80808080) >> 15);  \
    (x)[0] |= ((x)[1] & 0x80808080) << 17;                                  \
    (x)[1] = (((x)[1] & 0x7f7f7f7f) << 1) | (((x)[1] & 0x80808080) >> 15);  \
    (x)[1] ^= (((tmp0 >> 7) & 1) * 27) << 24;                               \
})

#define TRIPLE_HALF_BLOCK(x) ({                                             \
	tmp0 = (x)[0];															\
	tmp1 = (x)[1];															\
    (x)[0] = (((x)[0] & 0x7f7f7f7f) << 1) | (((x)[0] & 0x80808080) >> 15);	\
    (x)[0] |= ((x)[1] & 0x80808080) << 17;									\
    (x)[1] = (((x)[1] & 0x7f7f7f7f) << 1) | (((x)[1] & 0x80808080) >> 15);	\
    (x)[1] ^= (((tmp0 >> 7) & 1) * 27) << 24;								\
    (x)[0] ^= tmp0;															\
    (x)[1] ^= tmp1;															\
})

#define G(x) ({                                                             \
	tmp0 = (x)[0];                                                          \
	tmp1 = (x)[1];                                                          \
	(x)[0] = (x)[2];														\
	(x)[1] = (x)[3];														\
    (x)[2] = ((tmp0 & 0x7f7f7f7f) << 1) | ((tmp0 & 0x80808080) >> 15);      \
    (x)[2] |= ((tmp1 & 0x80808080) << 17);								    \
    (x)[3] = ((tmp1 & 0x7f7f7f7f) << 1) | ((tmp1 & 0x80808080) >> 15);      \
    (x)[3] |= ((tmp0 & 0x80808080) << 17);									\
})

#define XOR_BLOCK(x, y, z) ({       \
    (x)[0] = (y)[0] ^ (z)[0];       \
    (x)[1] = (y)[1] ^ (z)[1];       \
    (x)[2] = (y)[2] ^ (z)[2];       \
    (x)[3] = (y)[3] ^ (z)[3];       \
})

#define XOR_TOP_BAR_BLOCK(x, y) ({  \
    (x)[0] ^= (y)[0];               \
    (x)[1] ^= (y)[1];               \
})

#define RHO1(d, y, m, n) ({         \
    G(y);                           \
    padding(d,m,n);                 \
    XOR_BLOCK(d, d, y);             \
})

#define RHO(y, m, x, c, n) ({       \
    XOR_BLOCK(c, y, m);				\
    RHO1(x, y, m, n);				\
})

#define RHO_PRIME(y, c, x, m, n) ({ \
    XOR_BLOCK(m, y, c);             \
    RHO1(x, y, m, n);               \
})

#endif // COFB_H_