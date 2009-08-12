#include "aes.h"
#include <string.h>
#include <stdio.h>

#define AES_C
#define SHA2_C


/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/*
 * 32-bit integer manipulation macros (big endian)
 */

#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif


/*
 * 32-bit integer manipulation macros (little endian)
 */
#ifndef GET_ULONG_LE
#define GET_ULONG_LE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ]       )        \
        | ( (unsigned long) (b)[(i) + 1] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 2] << 16 )        \
        | ( (unsigned long) (b)[(i) + 3] << 24 );       \
}
#endif

#ifndef PUT_ULONG_LE
#define PUT_ULONG_LE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n)       );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 24 );       \
}
#endif


//     ------------------------------  AES Tables ------------------------------------------


#if defined(AES_ROM_TABLES)
/*
 * Forward S-box
 */
static const unsigned char FSb[256] =
{
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

/*
 * Forward tables
 */
#define FT \
\
    V(A5,63,63,C6), V(84,7C,7C,F8), V(99,77,77,EE), V(8D,7B,7B,F6), \
    V(0D,F2,F2,FF), V(BD,6B,6B,D6), V(B1,6F,6F,DE), V(54,C5,C5,91), \
    V(50,30,30,60), V(03,01,01,02), V(A9,67,67,CE), V(7D,2B,2B,56), \
    V(19,FE,FE,E7), V(62,D7,D7,B5), V(E6,AB,AB,4D), V(9A,76,76,EC), \
    V(45,CA,CA,8F), V(9D,82,82,1F), V(40,C9,C9,89), V(87,7D,7D,FA), \
    V(15,FA,FA,EF), V(EB,59,59,B2), V(C9,47,47,8E), V(0B,F0,F0,FB), \
    V(EC,AD,AD,41), V(67,D4,D4,B3), V(FD,A2,A2,5F), V(EA,AF,AF,45), \
    V(BF,9C,9C,23), V(F7,A4,A4,53), V(96,72,72,E4), V(5B,C0,C0,9B), \
    V(C2,B7,B7,75), V(1C,FD,FD,E1), V(AE,93,93,3D), V(6A,26,26,4C), \
    V(5A,36,36,6C), V(41,3F,3F,7E), V(02,F7,F7,F5), V(4F,CC,CC,83), \
    V(5C,34,34,68), V(F4,A5,A5,51), V(34,E5,E5,D1), V(08,F1,F1,F9), \
    V(93,71,71,E2), V(73,D8,D8,AB), V(53,31,31,62), V(3F,15,15,2A), \
    V(0C,04,04,08), V(52,C7,C7,95), V(65,23,23,46), V(5E,C3,C3,9D), \
    V(28,18,18,30), V(A1,96,96,37), V(0F,05,05,0A), V(B5,9A,9A,2F), \
    V(09,07,07,0E), V(36,12,12,24), V(9B,80,80,1B), V(3D,E2,E2,DF), \
    V(26,EB,EB,CD), V(69,27,27,4E), V(CD,B2,B2,7F), V(9F,75,75,EA), \
    V(1B,09,09,12), V(9E,83,83,1D), V(74,2C,2C,58), V(2E,1A,1A,34), \
    V(2D,1B,1B,36), V(B2,6E,6E,DC), V(EE,5A,5A,B4), V(FB,A0,A0,5B), \
    V(F6,52,52,A4), V(4D,3B,3B,76), V(61,D6,D6,B7), V(CE,B3,B3,7D), \
    V(7B,29,29,52), V(3E,E3,E3,DD), V(71,2F,2F,5E), V(97,84,84,13), \
    V(F5,53,53,A6), V(68,D1,D1,B9), V(00,00,00,00), V(2C,ED,ED,C1), \
    V(60,20,20,40), V(1F,FC,FC,E3), V(C8,B1,B1,79), V(ED,5B,5B,B6), \
    V(BE,6A,6A,D4), V(46,CB,CB,8D), V(D9,BE,BE,67), V(4B,39,39,72), \
    V(DE,4A,4A,94), V(D4,4C,4C,98), V(E8,58,58,B0), V(4A,CF,CF,85), \
    V(6B,D0,D0,BB), V(2A,EF,EF,C5), V(E5,AA,AA,4F), V(16,FB,FB,ED), \
    V(C5,43,43,86), V(D7,4D,4D,9A), V(55,33,33,66), V(94,85,85,11), \
    V(CF,45,45,8A), V(10,F9,F9,E9), V(06,02,02,04), V(81,7F,7F,FE), \
    V(F0,50,50,A0), V(44,3C,3C,78), V(BA,9F,9F,25), V(E3,A8,A8,4B), \
    V(F3,51,51,A2), V(FE,A3,A3,5D), V(C0,40,40,80), V(8A,8F,8F,05), \
    V(AD,92,92,3F), V(BC,9D,9D,21), V(48,38,38,70), V(04,F5,F5,F1), \
    V(DF,BC,BC,63), V(C1,B6,B6,77), V(75,DA,DA,AF), V(63,21,21,42), \
    V(30,10,10,20), V(1A,FF,FF,E5), V(0E,F3,F3,FD), V(6D,D2,D2,BF), \
    V(4C,CD,CD,81), V(14,0C,0C,18), V(35,13,13,26), V(2F,EC,EC,C3), \
    V(E1,5F,5F,BE), V(A2,97,97,35), V(CC,44,44,88), V(39,17,17,2E), \
    V(57,C4,C4,93), V(F2,A7,A7,55), V(82,7E,7E,FC), V(47,3D,3D,7A), \
    V(AC,64,64,C8), V(E7,5D,5D,BA), V(2B,19,19,32), V(95,73,73,E6), \
    V(A0,60,60,C0), V(98,81,81,19), V(D1,4F,4F,9E), V(7F,DC,DC,A3), \
    V(66,22,22,44), V(7E,2A,2A,54), V(AB,90,90,3B), V(83,88,88,0B), \
    V(CA,46,46,8C), V(29,EE,EE,C7), V(D3,B8,B8,6B), V(3C,14,14,28), \
    V(79,DE,DE,A7), V(E2,5E,5E,BC), V(1D,0B,0B,16), V(76,DB,DB,AD), \
    V(3B,E0,E0,DB), V(56,32,32,64), V(4E,3A,3A,74), V(1E,0A,0A,14), \
    V(DB,49,49,92), V(0A,06,06,0C), V(6C,24,24,48), V(E4,5C,5C,B8), \
    V(5D,C2,C2,9F), V(6E,D3,D3,BD), V(EF,AC,AC,43), V(A6,62,62,C4), \
    V(A8,91,91,39), V(A4,95,95,31), V(37,E4,E4,D3), V(8B,79,79,F2), \
    V(32,E7,E7,D5), V(43,C8,C8,8B), V(59,37,37,6E), V(B7,6D,6D,DA), \
    V(8C,8D,8D,01), V(64,D5,D5,B1), V(D2,4E,4E,9C), V(E0,A9,A9,49), \
    V(B4,6C,6C,D8), V(FA,56,56,AC), V(07,F4,F4,F3), V(25,EA,EA,CF), \
    V(AF,65,65,CA), V(8E,7A,7A,F4), V(E9,AE,AE,47), V(18,08,08,10), \
    V(D5,BA,BA,6F), V(88,78,78,F0), V(6F,25,25,4A), V(72,2E,2E,5C), \
    V(24,1C,1C,38), V(F1,A6,A6,57), V(C7,B4,B4,73), V(51,C6,C6,97), \
    V(23,E8,E8,CB), V(7C,DD,DD,A1), V(9C,74,74,E8), V(21,1F,1F,3E), \
    V(DD,4B,4B,96), V(DC,BD,BD,61), V(86,8B,8B,0D), V(85,8A,8A,0F), \
    V(90,70,70,E0), V(42,3E,3E,7C), V(C4,B5,B5,71), V(AA,66,66,CC), \
    V(D8,48,48,90), V(05,03,03,06), V(01,F6,F6,F7), V(12,0E,0E,1C), \
    V(A3,61,61,C2), V(5F,35,35,6A), V(F9,57,57,AE), V(D0,B9,B9,69), \
    V(91,86,86,17), V(58,C1,C1,99), V(27,1D,1D,3A), V(B9,9E,9E,27), \
    V(38,E1,E1,D9), V(13,F8,F8,EB), V(B3,98,98,2B), V(33,11,11,22), \
    V(BB,69,69,D2), V(70,D9,D9,A9), V(89,8E,8E,07), V(A7,94,94,33), \
    V(B6,9B,9B,2D), V(22,1E,1E,3C), V(92,87,87,15), V(20,E9,E9,C9), \
    V(49,CE,CE,87), V(FF,55,55,AA), V(78,28,28,50), V(7A,DF,DF,A5), \
    V(8F,8C,8C,03), V(F8,A1,A1,59), V(80,89,89,09), V(17,0D,0D,1A), \
    V(DA,BF,BF,65), V(31,E6,E6,D7), V(C6,42,42,84), V(B8,68,68,D0), \
    V(C3,41,41,82), V(B0,99,99,29), V(77,2D,2D,5A), V(11,0F,0F,1E), \
    V(CB,B0,B0,7B), V(FC,54,54,A8), V(D6,BB,BB,6D), V(3A,16,16,2C)

#define V(a,b,c,d) 0x##a##b##c##d
static const unsigned long FT0[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##b##c##d##a
static const unsigned long FT1[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##c##d##a##b
static const unsigned long FT2[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##d##a##b##c
static const unsigned long FT3[256] = { FT };
#undef V

#undef FT

/*
 * Reverse S-box
 */
static const unsigned char RSb[256] =
{
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

/*
 * Reverse tables
 */
#define RT \
\
    V(50,A7,F4,51), V(53,65,41,7E), V(C3,A4,17,1A), V(96,5E,27,3A), \
    V(CB,6B,AB,3B), V(F1,45,9D,1F), V(AB,58,FA,AC), V(93,03,E3,4B), \
    V(55,FA,30,20), V(F6,6D,76,AD), V(91,76,CC,88), V(25,4C,02,F5), \
    V(FC,D7,E5,4F), V(D7,CB,2A,C5), V(80,44,35,26), V(8F,A3,62,B5), \
    V(49,5A,B1,DE), V(67,1B,BA,25), V(98,0E,EA,45), V(E1,C0,FE,5D), \
    V(02,75,2F,C3), V(12,F0,4C,81), V(A3,97,46,8D), V(C6,F9,D3,6B), \
    V(E7,5F,8F,03), V(95,9C,92,15), V(EB,7A,6D,BF), V(DA,59,52,95), \
    V(2D,83,BE,D4), V(D3,21,74,58), V(29,69,E0,49), V(44,C8,C9,8E), \
    V(6A,89,C2,75), V(78,79,8E,F4), V(6B,3E,58,99), V(DD,71,B9,27), \
    V(B6,4F,E1,BE), V(17,AD,88,F0), V(66,AC,20,C9), V(B4,3A,CE,7D), \
    V(18,4A,DF,63), V(82,31,1A,E5), V(60,33,51,97), V(45,7F,53,62), \
    V(E0,77,64,B1), V(84,AE,6B,BB), V(1C,A0,81,FE), V(94,2B,08,F9), \
    V(58,68,48,70), V(19,FD,45,8F), V(87,6C,DE,94), V(B7,F8,7B,52), \
    V(23,D3,73,AB), V(E2,02,4B,72), V(57,8F,1F,E3), V(2A,AB,55,66), \
    V(07,28,EB,B2), V(03,C2,B5,2F), V(9A,7B,C5,86), V(A5,08,37,D3), \
    V(F2,87,28,30), V(B2,A5,BF,23), V(BA,6A,03,02), V(5C,82,16,ED), \
    V(2B,1C,CF,8A), V(92,B4,79,A7), V(F0,F2,07,F3), V(A1,E2,69,4E), \
    V(CD,F4,DA,65), V(D5,BE,05,06), V(1F,62,34,D1), V(8A,FE,A6,C4), \
    V(9D,53,2E,34), V(A0,55,F3,A2), V(32,E1,8A,05), V(75,EB,F6,A4), \
    V(39,EC,83,0B), V(AA,EF,60,40), V(06,9F,71,5E), V(51,10,6E,BD), \
    V(F9,8A,21,3E), V(3D,06,DD,96), V(AE,05,3E,DD), V(46,BD,E6,4D), \
    V(B5,8D,54,91), V(05,5D,C4,71), V(6F,D4,06,04), V(FF,15,50,60), \
    V(24,FB,98,19), V(97,E9,BD,D6), V(CC,43,40,89), V(77,9E,D9,67), \
    V(BD,42,E8,B0), V(88,8B,89,07), V(38,5B,19,E7), V(DB,EE,C8,79), \
    V(47,0A,7C,A1), V(E9,0F,42,7C), V(C9,1E,84,F8), V(00,00,00,00), \
    V(83,86,80,09), V(48,ED,2B,32), V(AC,70,11,1E), V(4E,72,5A,6C), \
    V(FB,FF,0E,FD), V(56,38,85,0F), V(1E,D5,AE,3D), V(27,39,2D,36), \
    V(64,D9,0F,0A), V(21,A6,5C,68), V(D1,54,5B,9B), V(3A,2E,36,24), \
    V(B1,67,0A,0C), V(0F,E7,57,93), V(D2,96,EE,B4), V(9E,91,9B,1B), \
    V(4F,C5,C0,80), V(A2,20,DC,61), V(69,4B,77,5A), V(16,1A,12,1C), \
    V(0A,BA,93,E2), V(E5,2A,A0,C0), V(43,E0,22,3C), V(1D,17,1B,12), \
    V(0B,0D,09,0E), V(AD,C7,8B,F2), V(B9,A8,B6,2D), V(C8,A9,1E,14), \
    V(85,19,F1,57), V(4C,07,75,AF), V(BB,DD,99,EE), V(FD,60,7F,A3), \
    V(9F,26,01,F7), V(BC,F5,72,5C), V(C5,3B,66,44), V(34,7E,FB,5B), \
    V(76,29,43,8B), V(DC,C6,23,CB), V(68,FC,ED,B6), V(63,F1,E4,B8), \
    V(CA,DC,31,D7), V(10,85,63,42), V(40,22,97,13), V(20,11,C6,84), \
    V(7D,24,4A,85), V(F8,3D,BB,D2), V(11,32,F9,AE), V(6D,A1,29,C7), \
    V(4B,2F,9E,1D), V(F3,30,B2,DC), V(EC,52,86,0D), V(D0,E3,C1,77), \
    V(6C,16,B3,2B), V(99,B9,70,A9), V(FA,48,94,11), V(22,64,E9,47), \
    V(C4,8C,FC,A8), V(1A,3F,F0,A0), V(D8,2C,7D,56), V(EF,90,33,22), \
    V(C7,4E,49,87), V(C1,D1,38,D9), V(FE,A2,CA,8C), V(36,0B,D4,98), \
    V(CF,81,F5,A6), V(28,DE,7A,A5), V(26,8E,B7,DA), V(A4,BF,AD,3F), \
    V(E4,9D,3A,2C), V(0D,92,78,50), V(9B,CC,5F,6A), V(62,46,7E,54), \
    V(C2,13,8D,F6), V(E8,B8,D8,90), V(5E,F7,39,2E), V(F5,AF,C3,82), \
    V(BE,80,5D,9F), V(7C,93,D0,69), V(A9,2D,D5,6F), V(B3,12,25,CF), \
    V(3B,99,AC,C8), V(A7,7D,18,10), V(6E,63,9C,E8), V(7B,BB,3B,DB), \
    V(09,78,26,CD), V(F4,18,59,6E), V(01,B7,9A,EC), V(A8,9A,4F,83), \
    V(65,6E,95,E6), V(7E,E6,FF,AA), V(08,CF,BC,21), V(E6,E8,15,EF), \
    V(D9,9B,E7,BA), V(CE,36,6F,4A), V(D4,09,9F,EA), V(D6,7C,B0,29), \
    V(AF,B2,A4,31), V(31,23,3F,2A), V(30,94,A5,C6), V(C0,66,A2,35), \
    V(37,BC,4E,74), V(A6,CA,82,FC), V(B0,D0,90,E0), V(15,D8,A7,33), \
    V(4A,98,04,F1), V(F7,DA,EC,41), V(0E,50,CD,7F), V(2F,F6,91,17), \
    V(8D,D6,4D,76), V(4D,B0,EF,43), V(54,4D,AA,CC), V(DF,04,96,E4), \
    V(E3,B5,D1,9E), V(1B,88,6A,4C), V(B8,1F,2C,C1), V(7F,51,65,46), \
    V(04,EA,5E,9D), V(5D,35,8C,01), V(73,74,87,FA), V(2E,41,0B,FB), \
    V(5A,1D,67,B3), V(52,D2,DB,92), V(33,56,10,E9), V(13,47,D6,6D), \
    V(8C,61,D7,9A), V(7A,0C,A1,37), V(8E,14,F8,59), V(89,3C,13,EB), \
    V(EE,27,A9,CE), V(35,C9,61,B7), V(ED,E5,1C,E1), V(3C,B1,47,7A), \
    V(59,DF,D2,9C), V(3F,73,F2,55), V(79,CE,14,18), V(BF,37,C7,73), \
    V(EA,CD,F7,53), V(5B,AA,FD,5F), V(14,6F,3D,DF), V(86,DB,44,78), \
    V(81,F3,AF,CA), V(3E,C4,68,B9), V(2C,34,24,38), V(5F,40,A3,C2), \
    V(72,C3,1D,16), V(0C,25,E2,BC), V(8B,49,3C,28), V(41,95,0D,FF), \
    V(71,01,A8,39), V(DE,B3,0C,08), V(9C,E4,B4,D8), V(90,C1,56,64), \
    V(61,84,CB,7B), V(70,B6,32,D5), V(74,5C,6C,48), V(42,57,B8,D0)

#define V(a,b,c,d) 0x##a##b##c##d
static const unsigned long RT0[256] = { RT };
#undef V

#define V(a,b,c,d) 0x##b##c##d##a
static const unsigned long RT1[256] = { RT };
#undef V

#define V(a,b,c,d) 0x##c##d##a##b
static const unsigned long RT2[256] = { RT };
#undef V

#define V(a,b,c,d) 0x##d##a##b##c
static const unsigned long RT3[256] = { RT };
#undef V

#undef RT

/*
 * Round constants
 */
static const unsigned long RCON[10] =
{
    0x00000001, 0x00000002, 0x00000004, 0x00000008,
    0x00000010, 0x00000020, 0x00000040, 0x00000080,
    0x0000001B, 0x00000036
};

#else

/*
 * Forward S-box & tables
 */
static unsigned char FSb[256];
static unsigned long FT0[256]; 
static unsigned long FT1[256]; 
static unsigned long FT2[256]; 
static unsigned long FT3[256]; 

/*
 * Reverse S-box & tables
 */
static unsigned char RSb[256];
static unsigned long RT0[256];
static unsigned long RT1[256];
static unsigned long RT2[256];
static unsigned long RT3[256];

/*
 * Round constants
 */
static unsigned long RCON[10];

/*
 * Tables generation code     ------------------   generate tables   ----------------------------
 */
#define ROTL8(x) ( ( x << 8 ) & 0xFFFFFFFF ) | ( x >> 24 )
#define XTIME(x) ( ( x << 1 ) ^ ( ( x & 0x80 ) ? 0x1B : 0x00 ) )
#define MUL(x,y) ( ( x && y ) ? pow[(log[x]+log[y]) % 255] : 0 )

static int aes_init_done = 0;

static void aes_gen_tables( void )
{
    int i, x, y, z;
    int pow[256];
    int log[256];

    /*
     * compute pow and log tables over GF(2^8)
     */
    for( i = 0, x = 1; i < 256; i++ )
    {
        pow[i] = x;
        log[x] = i;
        x = ( x ^ XTIME( x ) ) & 0xFF;
    }

    /*
     * calculate the round constants
     */
    for( i = 0, x = 1; i < 10; i++ )
    {
        RCON[i] = (unsigned long) x;
        x = XTIME( x ) & 0xFF;
    }

    /*
     * generate the forward and reverse S-boxes
     */
    FSb[0x00] = 0x63;
    RSb[0x63] = 0x00;

    for( i = 1; i < 256; i++ )
    {
        x = pow[255 - log[i]];

        y  = x; y = ( (y << 1) | (y >> 7) ) & 0xFF;
        x ^= y; y = ( (y << 1) | (y >> 7) ) & 0xFF;
        x ^= y; y = ( (y << 1) | (y >> 7) ) & 0xFF;
        x ^= y; y = ( (y << 1) | (y >> 7) ) & 0xFF;
        x ^= y ^ 0x63;

        FSb[i] = (unsigned char) x;
        RSb[x] = (unsigned char) i;
    }

    /*
     * generate the forward and reverse tables
     */
    for( i = 0; i < 256; i++ )
    {
        x = FSb[i];
        y = XTIME( x ) & 0xFF;
        z =  ( y ^ x ) & 0xFF;

        FT0[i] = ( (unsigned long) y       ) ^
                 ( (unsigned long) x <<  8 ) ^
                 ( (unsigned long) x << 16 ) ^
                 ( (unsigned long) z << 24 );

        FT1[i] = ROTL8( FT0[i] );
        FT2[i] = ROTL8( FT1[i] );
        FT3[i] = ROTL8( FT2[i] );

        x = RSb[i];

        RT0[i] = ( (unsigned long) MUL( 0x0E, x )       ) ^
                 ( (unsigned long) MUL( 0x09, x ) <<  8 ) ^
                 ( (unsigned long) MUL( 0x0D, x ) << 16 ) ^
                 ( (unsigned long) MUL( 0x0B, x ) << 24 );

        RT1[i] = ROTL8( RT0[i] );
        RT2[i] = ROTL8( RT1[i] );
        RT3[i] = ROTL8( RT2[i] );
    }
}

#endif


//  ------------------------------------- encryption functions -----------------------


/*
 * AES key schedule (encryption)
 */
void aes_setkey_enc( aes_context *ctx, unsigned char *key, int keysize )
{
    int i;
    unsigned long *RK;

#if !defined(AES_ROM_TABLES)
    if( aes_init_done == 0 )
    {
        aes_gen_tables();
        aes_init_done = 1;
    }
#endif

    switch( keysize )
    {
        case 128: ctx->nr = 10; break;
        case 192: ctx->nr = 12; break;
        case 256: ctx->nr = 14; break;
        default : return;
    }

#if defined(PADLOCK_ALIGN16)
    ctx->rk = RK = PADLOCK_ALIGN16( ctx->buf );
#else
    ctx->rk = RK = ctx->buf;
#endif

    for( i = 0; i < (keysize >> 5); i++ )
    {
        GET_ULONG_LE( RK[i], key, i << 2 );
    }

    switch( ctx->nr )
    {
        case 10:

            for( i = 0; i < 10; i++, RK += 4 )
            {
                RK[4]  = RK[0] ^ RCON[i] ^
                ( (unsigned long) FSb[ ( RK[3] >>  8 ) & 0xFF ]       ) ^
                ( (unsigned long) FSb[ ( RK[3] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (unsigned long) FSb[ ( RK[3] >> 24 ) & 0xFF ] << 16 ) ^
                ( (unsigned long) FSb[ ( RK[3]       ) & 0xFF ] << 24 );

                RK[5]  = RK[1] ^ RK[4];
                RK[6]  = RK[2] ^ RK[5];
                RK[7]  = RK[3] ^ RK[6];
            }
            break;

        case 12:

            for( i = 0; i < 8; i++, RK += 6 )
            {
                RK[6]  = RK[0] ^ RCON[i] ^
                ( (unsigned long) FSb[ ( RK[5] >>  8 ) & 0xFF ]       ) ^
                ( (unsigned long) FSb[ ( RK[5] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (unsigned long) FSb[ ( RK[5] >> 24 ) & 0xFF ] << 16 ) ^
                ( (unsigned long) FSb[ ( RK[5]       ) & 0xFF ] << 24 );

                RK[7]  = RK[1] ^ RK[6];
                RK[8]  = RK[2] ^ RK[7];
                RK[9]  = RK[3] ^ RK[8];
                RK[10] = RK[4] ^ RK[9];
                RK[11] = RK[5] ^ RK[10];
            }
            break;

        case 14:

            for( i = 0; i < 7; i++, RK += 8 )
            {
                RK[8]  = RK[0] ^ RCON[i] ^
                ( (unsigned long) FSb[ ( RK[7] >>  8 ) & 0xFF ]       ) ^
                ( (unsigned long) FSb[ ( RK[7] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (unsigned long) FSb[ ( RK[7] >> 24 ) & 0xFF ] << 16 ) ^
                ( (unsigned long) FSb[ ( RK[7]       ) & 0xFF ] << 24 );

                RK[9]  = RK[1] ^ RK[8];
                RK[10] = RK[2] ^ RK[9];
                RK[11] = RK[3] ^ RK[10];

                RK[12] = RK[4] ^
                ( (unsigned long) FSb[ ( RK[11]       ) & 0xFF ]       ) ^
                ( (unsigned long) FSb[ ( RK[11] >>  8 ) & 0xFF ] <<  8 ) ^
                ( (unsigned long) FSb[ ( RK[11] >> 16 ) & 0xFF ] << 16 ) ^
                ( (unsigned long) FSb[ ( RK[11] >> 24 ) & 0xFF ] << 24 );

                RK[13] = RK[5] ^ RK[12];
                RK[14] = RK[6] ^ RK[13];
                RK[15] = RK[7] ^ RK[14];
            }
            break;

        default:

            break;
    }
}

/*
 * AES key schedule (decryption)    ---------------------- decryption function  -------------------
 */
void aes_setkey_dec( aes_context *ctx, unsigned char *key, int keysize )
{
    int i, j;
    aes_context cty;
    unsigned long *RK;
    unsigned long *SK;

    switch( keysize )
    {
        case 128: ctx->nr = 10; break;
        case 192: ctx->nr = 12; break;
        case 256: ctx->nr = 14; break;
        default : return;
    }

#if defined(PADLOCK_ALIGN16)
    ctx->rk = RK = PADLOCK_ALIGN16( ctx->buf );
#else
    ctx->rk = RK = ctx->buf;
#endif

    aes_setkey_enc( &cty, key, keysize );
    SK = cty.rk + cty.nr * 4;

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;

    for( i = ctx->nr - 1, SK -= 8; i > 0; i--, SK -= 8 )
    {
        for( j = 0; j < 4; j++, SK++ )
        {
            *RK++ = RT0[ FSb[ ( *SK       ) & 0xFF ] ] ^
                    RT1[ FSb[ ( *SK >>  8 ) & 0xFF ] ] ^
                    RT2[ FSb[ ( *SK >> 16 ) & 0xFF ] ] ^
                    RT3[ FSb[ ( *SK >> 24 ) & 0xFF ] ];
        }
    }

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;

    memset( &cty, 0, sizeof( aes_context ) );
}

#define AES_FROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    X0 = *RK++ ^ FT0[ ( Y0       ) & 0xFF ] ^   \
                 FT1[ ( Y1 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y2 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y3 >> 24 ) & 0xFF ];    \
                                                \
    X1 = *RK++ ^ FT0[ ( Y1       ) & 0xFF ] ^   \
                 FT1[ ( Y2 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y3 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y0 >> 24 ) & 0xFF ];    \
                                                \
    X2 = *RK++ ^ FT0[ ( Y2       ) & 0xFF ] ^   \
                 FT1[ ( Y3 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y0 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y1 >> 24 ) & 0xFF ];    \
                                                \
    X3 = *RK++ ^ FT0[ ( Y3       ) & 0xFF ] ^   \
                 FT1[ ( Y0 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y1 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y2 >> 24 ) & 0xFF ];    \
}

#define AES_RROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    X0 = *RK++ ^ RT0[ ( Y0       ) & 0xFF ] ^   \
                 RT1[ ( Y3 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y2 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y1 >> 24 ) & 0xFF ];    \
                                                \
    X1 = *RK++ ^ RT0[ ( Y1       ) & 0xFF ] ^   \
                 RT1[ ( Y0 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y3 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y2 >> 24 ) & 0xFF ];    \
                                                \
    X2 = *RK++ ^ RT0[ ( Y2       ) & 0xFF ] ^   \
                 RT1[ ( Y1 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y0 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y3 >> 24 ) & 0xFF ];    \
                                                \
    X3 = *RK++ ^ RT0[ ( Y3       ) & 0xFF ] ^   \
                 RT1[ ( Y2 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y1 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y0 >> 24 ) & 0xFF ];    \
}

/*
 * AES-ECB block encryption/decryption
 */
void aes_crypt_ecb( aes_context *ctx,
                    int mode,
                    unsigned char input[16],
                    unsigned char output[16] )
{
    int i;
    unsigned long *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;

#if defined(PADLOCK_C) && defined(HAVE_X86)
    if( padlock_supports( PADLOCK_ACE ) )
    {
        if( padlock_xcryptecb( ctx, mode, input, output ) == 0 )
            return;
    }
#endif

    RK = ctx->rk;

    GET_ULONG_LE( X0, input,  0 ); X0 ^= *RK++;
    GET_ULONG_LE( X1, input,  4 ); X1 ^= *RK++;
    GET_ULONG_LE( X2, input,  8 ); X2 ^= *RK++;
    GET_ULONG_LE( X3, input, 12 ); X3 ^= *RK++;

    if( mode == AES_DECRYPT )
    {
        for( i = (ctx->nr >> 1) - 1; i > 0; i-- )
        {
            AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );
            AES_RROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );
        }

        AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );

        X0 = *RK++ ^ \
                ( (unsigned long) RSb[ ( Y0       ) & 0xFF ]       ) ^
                ( (unsigned long) RSb[ ( Y3 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (unsigned long) RSb[ ( Y2 >> 16 ) & 0xFF ] << 16 ) ^
                ( (unsigned long) RSb[ ( Y1 >> 24 ) & 0xFF ] << 24 );

        X1 = *RK++ ^ \
                ( (unsigned long) RSb[ ( Y1       ) & 0xFF ]       ) ^
                ( (unsigned long) RSb[ ( Y0 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (unsigned long) RSb[ ( Y3 >> 16 ) & 0xFF ] << 16 ) ^
                ( (unsigned long) RSb[ ( Y2 >> 24 ) & 0xFF ] << 24 );

        X2 = *RK++ ^ \
                ( (unsigned long) RSb[ ( Y2       ) & 0xFF ]       ) ^
                ( (unsigned long) RSb[ ( Y1 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (unsigned long) RSb[ ( Y0 >> 16 ) & 0xFF ] << 16 ) ^
                ( (unsigned long) RSb[ ( Y3 >> 24 ) & 0xFF ] << 24 );

        X3 = *RK++ ^ \
                ( (unsigned long) RSb[ ( Y3       ) & 0xFF ]       ) ^
                ( (unsigned long) RSb[ ( Y2 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (unsigned long) RSb[ ( Y1 >> 16 ) & 0xFF ] << 16 ) ^
                ( (unsigned long) RSb[ ( Y0 >> 24 ) & 0xFF ] << 24 );
    }
    else /* AES_ENCRYPT */
    {
        for( i = (ctx->nr >> 1) - 1; i > 0; i-- )
        {
            AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );
            AES_FROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );
        }

        AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );

        X0 = *RK++ ^ \
                ( (unsigned long) FSb[ ( Y0       ) & 0xFF ]       ) ^
                ( (unsigned long) FSb[ ( Y1 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (unsigned long) FSb[ ( Y2 >> 16 ) & 0xFF ] << 16 ) ^
                ( (unsigned long) FSb[ ( Y3 >> 24 ) & 0xFF ] << 24 );

        X1 = *RK++ ^ \
                ( (unsigned long) FSb[ ( Y1       ) & 0xFF ]       ) ^
                ( (unsigned long) FSb[ ( Y2 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (unsigned long) FSb[ ( Y3 >> 16 ) & 0xFF ] << 16 ) ^
                ( (unsigned long) FSb[ ( Y0 >> 24 ) & 0xFF ] << 24 );

        X2 = *RK++ ^ \
                ( (unsigned long) FSb[ ( Y2       ) & 0xFF ]       ) ^
                ( (unsigned long) FSb[ ( Y3 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (unsigned long) FSb[ ( Y0 >> 16 ) & 0xFF ] << 16 ) ^
                ( (unsigned long) FSb[ ( Y1 >> 24 ) & 0xFF ] << 24 );

        X3 = *RK++ ^ \
                ( (unsigned long) FSb[ ( Y3       ) & 0xFF ]       ) ^
                ( (unsigned long) FSb[ ( Y0 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (unsigned long) FSb[ ( Y1 >> 16 ) & 0xFF ] << 16 ) ^
                ( (unsigned long) FSb[ ( Y2 >> 24 ) & 0xFF ] << 24 );
    }

    PUT_ULONG_LE( X0, output,  0 );
    PUT_ULONG_LE( X1, output,  4 );
    PUT_ULONG_LE( X2, output,  8 );
    PUT_ULONG_LE( X3, output, 12 );
}

/*
 * AES-CBC buffer encryption/decryption
 */
void aes_crypt_cbc( aes_context *ctx,
                    int mode,
                    int length,
                    unsigned char iv[16],
                    unsigned char *input,
                    unsigned char *output )
{
    int i;
    unsigned char temp[16];

#if defined(PADLOCK_C) && defined(HAVE_X86)
    if( padlock_supports( PADLOCK_ACE ) )
    {
        if( padlock_xcryptcbc( ctx, mode, length, iv, input, output ) == 0 )
            return;
    }
#endif

    if( mode == AES_DECRYPT )
    {
        while( length > 0 )
        {
            memcpy( temp, input, 16 );
            aes_crypt_ecb( ctx, mode, input, output );

            for( i = 0; i < 16; i++ )
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, 16 );

            input  += 16;
            output += 16;
            length -= 16;
        }
    }
    else
    {
        while( length > 0 )
        {
            for( i = 0; i < 16; i++ )
                output[i] = (unsigned char)( input[i] ^ iv[i] );

            aes_crypt_ecb( ctx, mode, output, output );
            memcpy( iv, output, 16 );

            input  += 16;
            output += 16;
            length -= 16;
        }
    }
}

/*
 * AES-CFB128 buffer encryption/decryption
 */
void aes_crypt_cfb128( aes_context *ctx,
                       int mode,
                       int length,
                       int *iv_off,
                       unsigned char iv[16],
                       unsigned char *input,
                       unsigned char *output )
{
    int c, n = *iv_off;

    if( mode == AES_DECRYPT )
    {
        while( length-- )
        {
            if( n == 0 )
                aes_crypt_ecb( ctx, AES_ENCRYPT, iv, iv );

            c = *input++;
            *output++ = (unsigned char)( c ^ iv[n] );
            iv[n] = (unsigned char) c;

            n = (n + 1) & 0x0F;
        }
    }
    else
    {
        while( length-- )
        {
            if( n == 0 )
                aes_crypt_ecb( ctx, AES_ENCRYPT, iv, iv );

            iv[n] = *output++ = (unsigned char)( iv[n] ^ *input++ );

            n = (n + 1) & 0x0F;
        }
    }

    *iv_off = n;
}

/* ======================== SHA2 ============================================================ */

/*
 * SHA-256 context setup
 */
void sha2_starts( sha2_context *ctx, int is224 )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    if( is224 == 0 )
    {
        /* SHA-256 */
        ctx->state[0] = 0x6A09E667;
        ctx->state[1] = 0xBB67AE85;
        ctx->state[2] = 0x3C6EF372;
        ctx->state[3] = 0xA54FF53A;
        ctx->state[4] = 0x510E527F;
        ctx->state[5] = 0x9B05688C;
        ctx->state[6] = 0x1F83D9AB;
        ctx->state[7] = 0x5BE0CD19;
    }
    else
    {
        /* SHA-224 */
        ctx->state[0] = 0xC1059ED8;
        ctx->state[1] = 0x367CD507;
        ctx->state[2] = 0x3070DD17;
        ctx->state[3] = 0xF70E5939;
        ctx->state[4] = 0xFFC00B31;
        ctx->state[5] = 0x68581511;
        ctx->state[6] = 0x64F98FA7;
        ctx->state[7] = 0xBEFA4FA4;
    }

    ctx->is224 = is224;
}

static void sha2_process( sha2_context *ctx, unsigned char data[64] )
{
    unsigned long temp1, temp2, W[64];
    unsigned long A, B, C, D, E, F, G, H;

    GET_ULONG_BE( W[ 0], data,  0 );
    GET_ULONG_BE( W[ 1], data,  4 );
    GET_ULONG_BE( W[ 2], data,  8 );
    GET_ULONG_BE( W[ 3], data, 12 );
    GET_ULONG_BE( W[ 4], data, 16 );
    GET_ULONG_BE( W[ 5], data, 20 );
    GET_ULONG_BE( W[ 6], data, 24 );
    GET_ULONG_BE( W[ 7], data, 28 );
    GET_ULONG_BE( W[ 8], data, 32 );
    GET_ULONG_BE( W[ 9], data, 36 );
    GET_ULONG_BE( W[10], data, 40 );
    GET_ULONG_BE( W[11], data, 44 );
    GET_ULONG_BE( W[12], data, 48 );
    GET_ULONG_BE( W[13], data, 52 );
    GET_ULONG_BE( W[14], data, 56 );
    GET_ULONG_BE( W[15], data, 60 );

#define  SHR(x,n) ((x & 0xFFFFFFFF) >> n)
#define ROTR(x,n) (SHR(x,n) | (x << (32 - n)))

#define S0(x) (ROTR(x, 7) ^ ROTR(x,18) ^  SHR(x, 3))
#define S1(x) (ROTR(x,17) ^ ROTR(x,19) ^  SHR(x,10))

#define S2(x) (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define S3(x) (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))

#define F0(x,y,z) ((x & y) | (z & (x | y)))
#define F1(x,y,z) (z ^ (x & (y ^ z)))

#define R(t)                                    \
(                                               \
    W[t] = S1(W[t -  2]) + W[t -  7] +          \
           S0(W[t - 15]) + W[t - 16]            \
)

#define P(a,b,c,d,e,f,g,h,x,K)                  \
{                                               \
    temp1 = h + S3(e) + F1(e,f,g) + K + x;      \
    temp2 = S2(a) + F0(a,b,c);                  \
    d += temp1; h = temp1 + temp2;              \
}

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

    P( A, B, C, D, E, F, G, H, W[ 0], 0x428A2F98 );
    P( H, A, B, C, D, E, F, G, W[ 1], 0x71374491 );
    P( G, H, A, B, C, D, E, F, W[ 2], 0xB5C0FBCF );
    P( F, G, H, A, B, C, D, E, W[ 3], 0xE9B5DBA5 );
    P( E, F, G, H, A, B, C, D, W[ 4], 0x3956C25B );
    P( D, E, F, G, H, A, B, C, W[ 5], 0x59F111F1 );
    P( C, D, E, F, G, H, A, B, W[ 6], 0x923F82A4 );
    P( B, C, D, E, F, G, H, A, W[ 7], 0xAB1C5ED5 );
    P( A, B, C, D, E, F, G, H, W[ 8], 0xD807AA98 );
    P( H, A, B, C, D, E, F, G, W[ 9], 0x12835B01 );
    P( G, H, A, B, C, D, E, F, W[10], 0x243185BE );
    P( F, G, H, A, B, C, D, E, W[11], 0x550C7DC3 );
    P( E, F, G, H, A, B, C, D, W[12], 0x72BE5D74 );
    P( D, E, F, G, H, A, B, C, W[13], 0x80DEB1FE );
    P( C, D, E, F, G, H, A, B, W[14], 0x9BDC06A7 );
    P( B, C, D, E, F, G, H, A, W[15], 0xC19BF174 );
    P( A, B, C, D, E, F, G, H, R(16), 0xE49B69C1 );
    P( H, A, B, C, D, E, F, G, R(17), 0xEFBE4786 );
    P( G, H, A, B, C, D, E, F, R(18), 0x0FC19DC6 );
    P( F, G, H, A, B, C, D, E, R(19), 0x240CA1CC );
    P( E, F, G, H, A, B, C, D, R(20), 0x2DE92C6F );
    P( D, E, F, G, H, A, B, C, R(21), 0x4A7484AA );
    P( C, D, E, F, G, H, A, B, R(22), 0x5CB0A9DC );
    P( B, C, D, E, F, G, H, A, R(23), 0x76F988DA );
    P( A, B, C, D, E, F, G, H, R(24), 0x983E5152 );
    P( H, A, B, C, D, E, F, G, R(25), 0xA831C66D );
    P( G, H, A, B, C, D, E, F, R(26), 0xB00327C8 );
    P( F, G, H, A, B, C, D, E, R(27), 0xBF597FC7 );
    P( E, F, G, H, A, B, C, D, R(28), 0xC6E00BF3 );
    P( D, E, F, G, H, A, B, C, R(29), 0xD5A79147 );
    P( C, D, E, F, G, H, A, B, R(30), 0x06CA6351 );
    P( B, C, D, E, F, G, H, A, R(31), 0x14292967 );
    P( A, B, C, D, E, F, G, H, R(32), 0x27B70A85 );
    P( H, A, B, C, D, E, F, G, R(33), 0x2E1B2138 );
    P( G, H, A, B, C, D, E, F, R(34), 0x4D2C6DFC );
    P( F, G, H, A, B, C, D, E, R(35), 0x53380D13 );
    P( E, F, G, H, A, B, C, D, R(36), 0x650A7354 );
    P( D, E, F, G, H, A, B, C, R(37), 0x766A0ABB );
    P( C, D, E, F, G, H, A, B, R(38), 0x81C2C92E );
    P( B, C, D, E, F, G, H, A, R(39), 0x92722C85 );
    P( A, B, C, D, E, F, G, H, R(40), 0xA2BFE8A1 );
    P( H, A, B, C, D, E, F, G, R(41), 0xA81A664B );
    P( G, H, A, B, C, D, E, F, R(42), 0xC24B8B70 );
    P( F, G, H, A, B, C, D, E, R(43), 0xC76C51A3 );
    P( E, F, G, H, A, B, C, D, R(44), 0xD192E819 );
    P( D, E, F, G, H, A, B, C, R(45), 0xD6990624 );
    P( C, D, E, F, G, H, A, B, R(46), 0xF40E3585 );
    P( B, C, D, E, F, G, H, A, R(47), 0x106AA070 );
    P( A, B, C, D, E, F, G, H, R(48), 0x19A4C116 );
    P( H, A, B, C, D, E, F, G, R(49), 0x1E376C08 );
    P( G, H, A, B, C, D, E, F, R(50), 0x2748774C );
    P( F, G, H, A, B, C, D, E, R(51), 0x34B0BCB5 );
    P( E, F, G, H, A, B, C, D, R(52), 0x391C0CB3 );
    P( D, E, F, G, H, A, B, C, R(53), 0x4ED8AA4A );
    P( C, D, E, F, G, H, A, B, R(54), 0x5B9CCA4F );
    P( B, C, D, E, F, G, H, A, R(55), 0x682E6FF3 );
    P( A, B, C, D, E, F, G, H, R(56), 0x748F82EE );
    P( H, A, B, C, D, E, F, G, R(57), 0x78A5636F );
    P( G, H, A, B, C, D, E, F, R(58), 0x84C87814 );
    P( F, G, H, A, B, C, D, E, R(59), 0x8CC70208 );
    P( E, F, G, H, A, B, C, D, R(60), 0x90BEFFFA );
    P( D, E, F, G, H, A, B, C, R(61), 0xA4506CEB );
    P( C, D, E, F, G, H, A, B, R(62), 0xBEF9A3F7 );
    P( B, C, D, E, F, G, H, A, R(63), 0xC67178F2 );

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
    ctx->state[5] += F;
    ctx->state[6] += G;
    ctx->state[7] += H;
}


/*
 * SHA-256 process buffer
 */
void sha2_update( sha2_context *ctx, unsigned char *input, int ilen )
{
    int fill;
    unsigned long left;

    if( ilen <= 0 )
        return;

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < (unsigned long) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, fill );
        sha2_process( ctx, ctx->buffer );
        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 64 )
    {
        sha2_process( ctx, input );
        input += 64;
        ilen  -= 64;
    }

    if( ilen > 0 )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, ilen );
    }
}



static const unsigned char sha2_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};




/*
 * SHA-256 final digest
 */
void sha2_finish( sha2_context *ctx, unsigned char output[32] )
{
    unsigned long last, padn;
    unsigned long high, low;
    unsigned char msglen[8];

    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_ULONG_BE( high, msglen, 0 );
    PUT_ULONG_BE( low,  msglen, 4 );

    last = ctx->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    sha2_update( ctx, (unsigned char *) sha2_padding, padn );
    sha2_update( ctx, msglen, 8 );

    PUT_ULONG_BE( ctx->state[0], output,  0 );
    PUT_ULONG_BE( ctx->state[1], output,  4 );
    PUT_ULONG_BE( ctx->state[2], output,  8 );
    PUT_ULONG_BE( ctx->state[3], output, 12 );
    PUT_ULONG_BE( ctx->state[4], output, 16 );
    PUT_ULONG_BE( ctx->state[5], output, 20 );
    PUT_ULONG_BE( ctx->state[6], output, 24 );

    if( ctx->is224 == 0 )
        PUT_ULONG_BE( ctx->state[7], output, 28 );
}



/*
 * output = SHA-256( input buffer )
 */
void sha2( unsigned char *input, int ilen,
           unsigned char output[32], int is224 )
{
    sha2_context ctx;

    sha2_starts( &ctx, is224 );
    sha2_update( &ctx, input, ilen );
    sha2_finish( &ctx, output );

    memset( &ctx, 0, sizeof( sha2_context ) );
}




/*
 * output = SHA-256( file contents )
 */
int sha2_file( char *path, unsigned char output[32], int is224 )
{
    FILE *f;
    size_t n;
    sha2_context ctx;
    unsigned char buf[1024];

    if( ( f = fopen( path, "rb" ) ) == NULL )
        return( 1 );

    sha2_starts( &ctx, is224 );

    while( ( n = fread( buf, 1, sizeof( buf ), f ) ) > 0 )
        sha2_update( &ctx, buf, (int) n );

    sha2_finish( &ctx, output );

    memset( &ctx, 0, sizeof( sha2_context ) );

    if( ferror( f ) != 0 )
    {
        fclose( f );
        return( 2 );
    }

    fclose( f );
    return( 0 );
}



/*
 * SHA-256 HMAC context setup
 */
void sha2_hmac_starts( sha2_context *ctx, unsigned char *key, int keylen,
                       int is224 )
{
    int i;
    unsigned char sum[32];

    if( keylen > 64 )
    {
        sha2( key, keylen, sum, is224 );
        keylen = ( is224 ) ? 28 : 32;
        key = sum;
    }

    memset( ctx->ipad, 0x36, 64 );
    memset( ctx->opad, 0x5C, 64 );

    for( i = 0; i < keylen; i++ )
    {
        ctx->ipad[i] = (unsigned char)( ctx->ipad[i] ^ key[i] );
        ctx->opad[i] = (unsigned char)( ctx->opad[i] ^ key[i] );
    }

    sha2_starts( ctx, is224 );
    sha2_update( ctx, ctx->ipad, 64 );

    memset( sum, 0, sizeof( sum ) );
}




/*
 * SHA-256 HMAC process buffer
 */
void sha2_hmac_update( sha2_context *ctx, unsigned char *input, int ilen )
{
    sha2_update( ctx, input, ilen );
}


/*
 * SHA-256 HMAC final digest
 */
void sha2_hmac_finish( sha2_context *ctx, unsigned char output[32] )
{
    int is224, hlen;
    unsigned char tmpbuf[32];

    is224 = ctx->is224;
    hlen = ( is224 == 0 ) ? 32 : 28;

    sha2_finish( ctx, tmpbuf );
    sha2_starts( ctx, is224 );
    sha2_update( ctx, ctx->opad, 64 );
    sha2_update( ctx, tmpbuf, hlen );
    sha2_finish( ctx, output );

    memset( tmpbuf, 0, sizeof( tmpbuf ) );
}



/*
 * output = HMAC-SHA-256( hmac key, input buffer )
 */
void sha2_hmac( unsigned char *key, int keylen,
                unsigned char *input, int ilen,
                unsigned char output[32], int is224 )
{
    sha2_context ctx;

    sha2_hmac_starts( &ctx, key, keylen, is224 );
    sha2_hmac_update( &ctx, input, ilen );
    sha2_hmac_finish( &ctx, output );

    memset( &ctx, 0, sizeof( sha2_context ) );
}


/* =============================== padlock ================================= */



#if defined(PADLOCK_C)
#if defined(HAVE_X86)



/*
 * PadLock detection routine
 */
int padlock_supports( int feature )
{
    static int flags = -1;
    int ebx, edx;

    if( flags == -1 )
    {
        asm( "movl  %%ebx, %0           \n"     \
             "movl  $0xC0000000, %%eax  \n"     \
             "cpuid                     \n"     \
             "cmpl  $0xC0000001, %%eax  \n"     \
             "movl  $0, %%edx           \n"     \
             "jb    unsupported         \n"     \
             "movl  $0xC0000001, %%eax  \n"     \
             "cpuid                     \n"     \
             "unsupported:              \n"     \
             "movl  %%edx, %1           \n"     \
             "movl  %2, %%ebx           \n"
             : "=m" (ebx), "=m" (edx)
             :  "m" (ebx)
             : "eax", "ecx", "edx" );

        flags = edx;
    }

    return( flags & feature );
}

/*
 * PadLock AES-ECB block en(de)cryption
 */
int padlock_xcryptecb( aes_context *ctx,
                       int mode,
                       unsigned char input[16],
                       unsigned char output[16] )
{
    int ebx;
    unsigned long *rk;
    unsigned long *blk;
    unsigned long *ctrl;
    unsigned char buf[256];

    rk  = ctx->rk;
    blk = PADLOCK_ALIGN16( buf );
    memcpy( blk, input, 16 );

    ctrl = blk + 4;
    *ctrl = 0x80 | ctx->nr | ( ( ctx->nr + ( mode^1 ) - 10 ) << 9 );

    asm( "pushfl; popfl         \n"     \
         "movl    %%ebx, %0     \n"     \
         "movl    $1, %%ecx     \n"     \
         "movl    %2, %%edx     \n"     \
         "movl    %3, %%ebx     \n"     \
         "movl    %4, %%esi     \n"     \
         "movl    %4, %%edi     \n"     \
         ".byte  0xf3,0x0f,0xa7,0xc8\n" \
         "movl    %1, %%ebx     \n"
         : "=m" (ebx)
         :  "m" (ebx), "m" (ctrl), "m" (rk), "m" (blk)
         : "ecx", "edx", "esi", "edi" );

    memcpy( output, blk, 16 );

    return( 0 );
}

/*
 * PadLock AES-CBC buffer en(de)cryption
 */
int padlock_xcryptcbc( aes_context *ctx,
                       int mode,
                       int length,
                       unsigned char iv[16],
                       unsigned char *input,
                       unsigned char *output )
{
    int ebx, count;
    unsigned long *rk;
    unsigned long *iw;
    unsigned long *ctrl;
    unsigned char buf[256];

    if( ( (long) input  & 15 ) != 0 ||
        ( (long) output & 15 ) != 0 )
        return( 1 );

    rk = ctx->rk;
    iw = PADLOCK_ALIGN16( buf );
    memcpy( iw, iv, 16 );

     ctrl = iw + 4;
    *ctrl = 0x80 | ctx->nr | ( ( ctx->nr + (mode^1) - 10 ) << 9 );

    count = (length + 15) >> 4;

    asm( "pushfl; popfl         \n"     \
         "movl    %%ebx, %0     \n"     \
         "movl    %2, %%ecx     \n"     \
         "movl    %3, %%edx     \n"     \
         "movl    %4, %%ebx     \n"     \
         "movl    %5, %%esi     \n"     \
         "movl    %6, %%edi     \n"     \
         "movl    %7, %%eax     \n"     \
         ".byte  0xf3,0x0f,0xa7,0xd0\n" \
         "movl    %1, %%ebx     \n"
         : "=m" (ebx)
         :  "m" (ebx), "m" (count), "m" (ctrl),
            "m"  (rk), "m" (input), "m" (output), "m" (iw)
         : "eax", "ecx", "edx", "esi", "edi" );

    memcpy( iv, iw, 16 );

    return( 0 );
}

#endif
#endif

void aes_enc_key_fn(char* aes_enc_key,char* key,char* password)
{
	aes_encrypt(key,aes_enc_key,password,32);}

void aes_dec_key_fn(char* key, char* buffer, char* password)
{
	aes_decrypt(buffer,key,password,32);}

//  -------------     aescrypt() - the main function that provides interface for encryption and decryption   ---------- //

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#if defined(WIN32)
#include <windows.h>
#include <io.h>
#else
#include <sys/types.h>
#include <unistd.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>


#define MODE_ENCRYPT    0
#define MODE_DECRYPT    1

int aescrypt(int mode, char* infile, char* outfile, char* pass_key, unsigned char key[16])
{

	printf("input pass_key : %s\n",pass_key);
    int ret = 1, i, n;
    int keylen, lastn;
    FILE *fkey, *fin, *fout;

    char *p;
    unsigned char IV[16];
    unsigned char digest[32];
    unsigned char buffer[1024];
    unsigned char aes_enc_key[256];
    unsigned char password[32];
    aes_context aes_ctx;
    sha2_context sha_ctx;
	off_t filesize, offset;
    
    if( mode != MODE_ENCRYPT && mode != MODE_DECRYPT )
    {
        fprintf( stderr, "invalide operation mode\n mode = 0 to encrypt ; mode = 1 to decrypt\n" );
        goto exit;
    }

    if( strcmp( infile, outfile ) == 0 )
    {
        fprintf( stderr, "input and output filenames must differ\n" );
        goto exit;
    }

	printf("pass en1 *  %s %s\n",password,pass_key);

	printf("pass envgf *  %s %s\n",password,pass_key);
	fin=fopen(infile,"rb");
    
	if( ( fout = fopen( outfile, "wb+" ) ) == NULL )
    {
        fprintf( stderr, "fopen(%s,wb+) failed\n", outfile );
        goto exit;
    }

	printf("pass en *  %s %s\n",password,pass_key);

    int lenkey = strlen(pass_key);
	printf("lenkey = %d\n",lenkey);
    
	for (i = 0; i < 31; i++)
		password[i] = pass_key[i%lenkey];
    password[31]='\0';

    printf("pass en-1 *  %s %s\n",password,pass_key);

    memset( pass_key, 0, strlen( pass_key ) );

#if defined(WIN32)
    /*
     * Support large files (> 2Gb) on Win32
     */
    li_size.QuadPart = 0;
    li_size.LowPart  =
        SetFilePointer( (HANDLE) _get_osfhandle( _fileno( fin ) ),
                        li_size.LowPart, &li_size.HighPart, FILE_END );

    if( li_size.LowPart == 0xFFFFFFFF && GetLastError() != NO_ERROR )
    {
        fprintf( stderr, "SetFilePointer(0,FILE_END) failed\n" );
        goto exit;
    }

    filesize = li_size.QuadPart;
#else
    if( ( filesize = lseek( fileno( fin ), 0, SEEK_END ) ) < 0 )
    {
        perror( "lseek" );
        goto exit;
    }
#endif

    if( fseek( fin, 0, SEEK_SET ) < 0 )
    {
        fprintf( stderr, "fseek(0,SEEK_SET) failed\n" );
        goto exit;
    }

	printf("pass en *  %s %s\n",password,pass_key);

    if( mode == MODE_ENCRYPT )
    {
        /*
         * Generate the initialization vector as:
         * IV = SHA-256( filesize || filename )[0..15]
         */
        for( i = 0; i < 8; i++ )
            buffer[i] = (unsigned char)( filesize >> ( i << 3 ) );

        p = infile;

        sha2_starts( &sha_ctx, 0 );
        sha2_update( &sha_ctx, buffer, 8 );
        sha2_update( &sha_ctx, (unsigned char *) p, strlen( p ) );
        sha2_finish( &sha_ctx, digest );

        memcpy( IV, digest, 16 );

        /*
         * The last four bits in the IV are actually used
         * to store the file size modulo the AES block size.
         */
        lastn = (int)( filesize & 0x0F );

        IV[15] = (unsigned char)
            ( ( IV[15] & 0xF0 ) | lastn );

        /*
         * Append the IV at the beginning of the output.
         */
        if( fwrite( IV, 1, 16, fout ) != 16 )
        {
            fprintf( stderr, "fwrite(%d bytes) failed\n", 16 );
            goto exit;
        }

        /*
         * Hash the IV and the secret key together 8192 times
         * using the result to setup the AES context and HMAC.
         */
        memset( digest, 0,  32 );
        memcpy( digest, IV, 16 );

		printf("ftyyyt  pass *  %s %s\n",password,pass_key);
		aes_enc_key_fn(aes_enc_key,key,password); 
		printf("key: %s \n encrypted key : %s",key,aes_enc_key);              // key encryption using password
		keylen = strlen(key);

        for( i = 0; i < 8192; i++ )
        {
            sha2_starts( &sha_ctx, 0 );
            sha2_update( &sha_ctx, digest, 32 );
            sha2_update( &sha_ctx, key, keylen );
            sha2_finish( &sha_ctx, digest );
        }
        memset( key, 0, sizeof( key ) );
		aes_setkey_enc( &aes_ctx, digest, 256 );
        sha2_hmac_starts( &sha_ctx, digest, 32, 0 );

        /*
         * Encrypt and write the ciphertext.
         */
        for( offset = 0; offset < filesize; offset += 16 )
        {
            n = ( filesize - offset > 16 ) ? 16 : (int)
                ( filesize - offset );

            if( fread( buffer, 1, n, fin ) != (size_t) n )
            {
                fprintf( stderr, "fread(%d bytes) failed\n", n );
                goto exit;
            }

            for( i = 0; i < 16; i++ )
                buffer[i] = (unsigned char)( buffer[i] ^ IV[i] );

            aes_crypt_ecb( &aes_ctx, AES_ENCRYPT, buffer, buffer );
            sha2_hmac_update( &sha_ctx, buffer, 16 );

            if( fwrite( buffer, 1, 16, fout ) != 16 )
            {
                fprintf( stderr, "fwrite(%d bytes) failed\n", 16 );
                goto exit;
            }

            memcpy( IV, buffer, 16 );
        }

        /*
         * Finally write the HMAC.
         */
        sha2_hmac_finish( &sha_ctx, digest );

        if( fwrite( digest, 1, 32, fout ) != 32 )
        {
            fprintf( stderr, "fwrite(%d bytes) failed\n", 16 );
            goto exit;
        }

		if( fwrite( aes_enc_key, 1, 16, fout ) != 16 )
        {
            fprintf( stderr, "Key write failed \nfwrite(%d bytes) failed\n", 16 );
            goto exit;
        }
    }
	printf("pass *  %s %s\n",password,pass_key);

    if( mode == MODE_DECRYPT )
    {
		printf("start pass:%s",password);
        unsigned char tmp[16];

        /*
         *  The encrypted file must be structured as follows:
         *
         *        00 .. 15              Initialization Vector
         *        16 .. 31              AES Encrypted Block #1
         *           ..
         *      N*16 .. (N+1)*16 - 1    AES Encrypted Block #N
         *  (N+1)*16 .. (N+1)*16 + 32   HMAC-SHA-256(ciphertext)
         */
        if( filesize < 48 + 16 )
        {
            fprintf( stderr, "Invalid Input File.\n(File too short to be decrypted.)\n" );
            goto exit;
        }

        if( ( filesize & 0x0F ) != 0 )
        {
            fprintf( stderr, "Invalid Input File.\n(File size not a multiple of 16.)\n" );
            goto exit;
        }
        /*
         * Substract the IV + HMAC length.
         */
        filesize -= ( 16 + 32 + 16);

        fseek( fin, filesize+48, SEEK_SET);            //    reading the password encrypted key

        if( fread( buffer, 1, 16, fin) != 16 )
		{
			fprintf(stderr, "fread failed - encrypted key could not be read\n");
			goto exit;
		}

		printf("buffer = %s\n",buffer);
		aes_dec_key_fn(key, buffer, password);
		printf("password = %s\n",password);
		keylen = strlen(key);
		fseek( fin, 0, SEEK_SET);

        /*
         * Read the IV and original filesize modulo 16.
         */
        if( fread( buffer, 1, 16, fin ) != 16 )
        {
            fprintf( stderr, "fread(%d bytes) failed\n", 16 );
            goto exit;
        }

        memcpy( IV, buffer, 16 );
        lastn = IV[15] & 0x0F;

        /*
         * Hash the IV and the secret key together 8192 times
         * using the result to setup the AES context and HMAC.
         */
        memset( digest, 0,  32 );
        memcpy( digest, IV, 16 );

        for( i = 0; i < 8192; i++ )
        {
            sha2_starts( &sha_ctx, 0 );
            sha2_update( &sha_ctx, digest, 32 );
            sha2_update( &sha_ctx, key, keylen );
            sha2_finish( &sha_ctx, digest );
        }

        memset( key, 0, sizeof( key ) );
          aes_setkey_dec( &aes_ctx, digest, 256 );
        sha2_hmac_starts( &sha_ctx, digest, 32, 0 );

        /*
         * Decrypt and write the plaintext.
         */
        for( offset = 0; offset < filesize; offset += 16 )
        {
            if( fread( buffer, 1, 16, fin ) != 16 )
            {
                fprintf( stderr, "fread(%d bytes) failed\n", 16 );
                goto exit;
            }

            memcpy( tmp, buffer, 16 );
 
            sha2_hmac_update( &sha_ctx, buffer, 16 );
            aes_crypt_ecb( &aes_ctx, AES_DECRYPT, buffer, buffer );
   
            for( i = 0; i < 16; i++ )
                buffer[i] = (unsigned char)( buffer[i] ^ IV[i] );

            memcpy( IV, tmp, 16 );

            n = ( lastn > 0 && offset == filesize - 16 )
                 ? lastn : 16;

            if( fwrite( buffer, 1, n, fout ) != (size_t) n )
            {
                fprintf( stderr, "Invalid file (fwrite(%d bytes) failed)\n", n );
                goto exit;
            }
        }

        /*
         * Verify the message authentication code.
         */
        sha2_hmac_finish( &sha_ctx, digest );

        if( fread( buffer, 1, 32, fin ) != 32 )
        {
            fprintf( stderr, "Invalid file (fread(%d bytes) failed)\n", 32 );
            goto exit;
        }

        if( memcmp( digest, buffer, 32 ) != 0 )
        {
            fprintf( stderr, "HMAC check failed: wrong key, "
                             "or file corrupted.\n" );
            goto exit;
        }
    }

    ret = 0;

exit:
    fclose(fin);
    fclose(fout);
    memset( buffer, 0, sizeof( buffer ) );
    memset( digest, 0, sizeof( digest ) );

    memset( &aes_ctx, 0, sizeof(  aes_context ) );
    memset( &sha_ctx, 0, sizeof( sha2_context ) );

    return( ret );
}


int change(char* infile, char* oldpass, char* newpass)
{
	unsigned char old[32], new[32];
	int oldlen = strlen(oldpass);
	int newlen = strlen(newpass);

	int i, size;
	unsigned char buffer[16], dec[16], newenc[16];
	printf("oldlen : %d , newlen : %d\n",oldlen, newlen);
    for(i=0;i<31;i++) {
		old[i] = oldpass[i%oldlen]; printf("old %d %c\n ",i,old[i]);
		new[i] = newpass[i%newlen]; printf("new %d %c\n ",i,new[i]);
	}
  
	old[31] = new[31] = 0;

	printf("change : oldpass : %s newpass = %s\n",old, new);

	FILE* fin = fopen(infile,"rb+");

	if(fin==NULL) {
		system("pwd");
		printf("change : error in opening  file : %s\n",infile);
		return 0;
	}
  	else {
		fseek(fin,0,SEEK_END);
		size = ftell(fin);
	}

	fseek(fin, size - 16, SEEK_SET);
  	if( fread( buffer, 1, 16, fin) != 16 )
	{
		fprintf(stderr, "change : fread failed - encrypted key could not be read\n");
		return 0;
	}

  	aes_dec_key_fn(dec, buffer, old);
  
	printf("change : dec = %s\nbuffer = --\noldpass = %s\n",dec,oldpass);

  	aes_enc_key_fn(newenc, dec, new);

  	printf("after change : newenc = %s\ndec = %s\nnewpass = %s\n",newenc,dec,newpass);

  	fseek(fin, size - 16, SEEK_SET);

  	if( fwrite( newenc, 1, 16, fin ) != 16 )
	{
		fprintf( stderr, "change : fwrite(%d bytes) failed\n", 16 );
		return 0;
	}

	fclose(fin);
	return 1;
}
