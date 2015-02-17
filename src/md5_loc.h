/*
 * Local defines for the md5 functions.
 *
 * $Id: md5_loc.h,v 1.5 2010-05-07 13:58:18 gray Exp $
 */

#ifndef __MD5_LOC_H__
#define __MD5_LOC_H__

namespace md5 {
    const char* HEX_STRING = "0123456789abcdef";    /* to convert to hex */
    const unsigned int BLOCK_SIZE_MASK = md5::BLOCK_SIZE - 1;

    /*
     * Define my endian-ness.  Could not do in a portable manner using the
     * include files -- grumble.
     */
    #if MD5_BIG_ENDIAN

    /*
     * big endian - big is better
     */
    #define MD5_SWAP(n) (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

    #else

    /*
     * little endian
     */
    #define MD5_SWAP(n) (n)

    #endif

    /*
     * These are the four functions used in the four steps of the md5
     * algorithm and defined in the RFC 1321.  The first function is a
     * little bit optimized (as found in Colin Plumbs public domain
     * implementation).
     */
    /* #define MD5_FF(b, c, d) ((b & c) | (~b & d)) */
    #define MD5_FF(b, c, d) (d ^ (b & (c ^ d)))
    #define MD5_FG(b, c, d) MD5_FF(d, b, c)
    #define MD5_FH(b, c, d) (b ^ c ^ d)
    #define MD5_FI(b, c, d) (c ^ (b | ~d))

    /*
     * It is unfortunate that C does not provide an operator for cyclic
     * rotation.  Hope the C compiler is smart enough.  -- Modified to
     * remove the w = at the front - Gray 2/97
     */
    #define MD5_CYCLIC(w, s) ((w << s) | (w >> (32 - s)))

    /*
     * First Round: using the given function, the context and a constant
     * the next context is computed.  Because the algorithms processing
     * unit is a 32-bit word and it is determined to work on words in
     * little endian byte order we perhaps have to change the byte order
     * before the computation.  To reduce the work for the next steps we
     * store the swapped words in the array CORRECT_WORDS. -- Modified to
     * fix the handling of unaligned buffer spaces - Gray 7/97
     */
    #define MD5_OP1(a, b, c, d, b_p, c_p, s, T) \
        do { \
            memcpy(c_p, b_p, sizeof(unsigned int)); \
            *c_p = MD5_SWAP(*c_p); \
            a += MD5_FF (b, c, d) + *c_p + T; \
            a = MD5_CYCLIC (a, s); \
            a += b; \
            b_p = (char *)b_p + sizeof(unsigned int); \
            c_p++; \
        } while (0)

    /*
     * Second to Fourth Round: we have the possibly swapped words in
     * CORRECT_WORDS.  Redefine the macro to take an additional first
     * argument specifying the function to use.
     */
    #define MD5_OP234(FUNC, a, b, c, d, k, s, T) \
        do { \
            a += FUNC (b, c, d) + k + T; \
            a = MD5_CYCLIC (a, s); \
            a += b; \
        } while (0)
}

#endif /* ! __MD5_LOC_H__ */
