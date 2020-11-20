#ifndef ENDIAN_H_
#define ENDIAN_H_

#define U32BIG(x)											\
  ((((x) & 0x000000FF) << 24) | (((x) & 0x0000FF00) << 8) | \
   (((x) & 0x00FF0000) >> 8) | (((x) & 0xFF000000) >> 24))

#define U8BIG(x, y)											\
	(x)[0] = (y) >> 24; 									\
	(x)[1] = ((y) >> 16) & 0xff; 							\
	(x)[2] = ((y) >> 8) & 0xff; 							\
	(x)[3] = (y) & 0xff;

#endif  // ENDIAN_H_