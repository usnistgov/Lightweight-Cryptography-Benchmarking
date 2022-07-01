

void hirose_128_128_256 (unsigned char* h,
			 unsigned char* g,
			 const unsigned char* m);

void initialize (unsigned char* h,
		 unsigned char* g);

void ipad_256 (const unsigned char* m, unsigned char* mp, int l, int len8);

void ipad_128 (const unsigned char* m, unsigned char* mp, int l, int len8);
