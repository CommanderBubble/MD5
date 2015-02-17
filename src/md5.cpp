#include <cstdlib>
#include <cstring>

#include "../conf.h"
#include "md5.h"
#include "md5_loc.h"

namespace md5 {
    /****************************** Public Functions ******************************/

    /*
     * md5_t
     *
     * DESCRIPTION:
     *
     * Initialize structure containing state of MD5 computation. (RFC 1321,
     * 3.3: Step 3).  This is for progressive MD5 calculations only.  If
     * you have the complete string available, call it as below.
     * process should be called for each bunch of bytes and after the
     * last process call, finish should be called to get the signature.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * None.
     */
    md5_t::md5_t() {
        initialise();
    }

    /*
     * md5_t
     *
     * DESCRIPTION:
     *
     * This function is used to calculate a MD5 signature for a buffer of
     * bytes.  If you only have part of a buffer that you want to process
     * then md5_t, process, and finish should be used.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * buffer - A buffer of bytes whose MD5 signature we are calculating.
     *
     * buf_len - The length of the buffer.
     *
     * signature - A 16 byte buffer that will contain the MD5 signature.
     */
    md5_t::md5_t(const char* buffer, const unsigned int buf_len, void* signature) {
        /* initialize the computation context */
        initialise();

        /* process whole buffer but last buf_len % MD5_BLOCK bytes */
        process(buffer, buf_len);

        /* put result in desired memory area */
        finish(signature);
    }

    /*
     * process
     *
     * DESCRIPTION:
     *
     * This function is used to progressively calculate a MD5 signature some
     * number of bytes at a time.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * buffer - A buffer of bytes whose MD5 signature we are calculating.
     *
     * buf_len - The length of the buffer.
     */
    void md5_t::process(const void* buffer, const unsigned int buf_len) {
        if (!finished) {
            unsigned int len = buf_len;
            unsigned int in_block, add;

            /*
             * When we already have some bytes in our internal buffer, copy some
             * from the user to fill the block.
             */

            if (md_buf_len > 0) {
                in_block = md_buf_len;
                if (in_block + len > sizeof(md_buffer)) {
                    add = sizeof(md_buffer) - in_block;
                } else {
                    add = len;
                }

                memcpy(md_buffer + in_block, buffer, add);
                md_buf_len += add;
                in_block += add;

                if (in_block > md5::BLOCK_SIZE) {
                    process_block(md_buffer, in_block & ~md5::BLOCK_SIZE_MASK);
                    /* the regions in the following copy operation will not overlap. */
                    memcpy(md_buffer,
                    md_buffer + (in_block & ~md5::BLOCK_SIZE_MASK),
                    in_block & md5::BLOCK_SIZE_MASK);
                    md_buf_len = in_block & md5::BLOCK_SIZE_MASK;
                }

                buffer = (const char*)buffer + add;
                len -= add;
            }

            /* process available complete blocks right from the user buffer */
            if (len > md5::BLOCK_SIZE) {
                process_block(buffer, len & ~md5::BLOCK_SIZE_MASK);
                buffer = (const char*) buffer + (len & ~md5::BLOCK_SIZE_MASK);
                len &= md5::BLOCK_SIZE_MASK;
            }

            /* copy remaining bytes into the internal buffer */
            if (len > 0) {
                memcpy(md_buffer, buffer, len);
                md_buf_len = len;
            }
        } else {
            // add error?
        }
    }

    /*
     * finish
     *
     * DESCRIPTION:
     *
     * Finish a progressing MD5 calculation and copy the resulting MD5
     * signature into the result buffer which should be 16 bytes
     * (MD5_SIZE).  After this call, the MD5 structure cannot process
	 * additional bytes.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * signature - A 16 byte buffer that will contain the MD5 signature.
     */
    void md5_t::finish(void* signature_) {
        if (!finished) {
            unsigned int bytes, hold;
            int pad;

            /* take yet unprocessed bytes into account */
            bytes = md_buf_len;

            /*
             * Count remaining bytes.  Modified to do this to better avoid
             * overflows in the lower word -- Gray 10/97.
             */
            if (md_total[0] > UINT32_MAX - bytes) {
                md_total[1]++;
                md_total[0] -= (UINT32_MAX + 1 - bytes);
            } else {
                md_total[0] += bytes;
            }

            /*
             * Pad the buffer to the next MD5_BLOCK-byte boundary.  (RFC 1321,
             * 3.1: Step 1).  We need enough room for two size words and the
             * bytes left in the buffer.  For some reason even if we are equal
             * to the block-size, we add an addition block of pad bytes.
             */
            pad = md5::BLOCK_SIZE - (sizeof(unsigned int) * 2) - bytes;
            if (pad <= 0) {
                pad += md5::BLOCK_SIZE;
            }

            /*
             * Modified from a fixed array to this assignment and memset to be
             * more flexible with block-sizes -- Gray 10/97.
             */
            if (pad > 0) {
                /* some sort of padding start byte */
                md_buffer[bytes] = (unsigned char)0x80;
                if (pad > 1) {
                    memset(md_buffer + bytes + 1, 0, pad - 1);
                }
                bytes += pad;
            }

            /*
             * Put the 64-bit file length in _bits_ (i.e. *8) at the end of the
             * buffer.
             */
            hold = MD5_SWAP((md_total[0] & 0x1FFFFFFF) << 3);
            memcpy(md_buffer + bytes, &hold, sizeof(unsigned int));
            bytes += sizeof(unsigned int);

            /* shift the high word over by 3 and add in the top 3 bits from the low */
            hold = MD5_SWAP((md_total[1] << 3) | ((md_total[0] & 0xE0000000) >> 29));
            memcpy(md_buffer + bytes, &hold, sizeof(unsigned int));
            bytes += sizeof(unsigned int);

            /* process last bytes, the padding chars, and size words */
            process_block(md_buffer, bytes);

            get_result(static_cast<void*>(signature));

            sig_to_string(signature, str, 33);

            if (signature != NULL) {
                memcpy(signature_, static_cast<void*>(signature), MD5_SIZE);
            }

            finished = true;
        } else {
            // add error?
        }
    }

    /*
     * get_sig
     *
     * DESCRIPTION:
     *
     * Retrieves the previously calculated signature from the MD5 object.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * signature_ - A 16 byte buffer that will contain the MD5 signature.
     */
    void md5_t::get_sig(void* signature_) {
        if (finished) {
            memcpy(signature_, signature, MD5_SIZE);
        }
    }

    /*
     * get_string
     *
     * DESCRIPTION:
     *
     * Retrieves the previously calculated signature from the MD5 object in
     * printable format.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * str_ - a string of characters which should be at least 33 bytes long
     * (2 characters per MD5 byte and 1 for the \0).
     *
     * str_len - the length of the string.
     */
    void md5_t::get_string(void* str_, const unsigned int str_len) {
        if (finished) {
            memcpy(str_, str, str_len);
        }
    }

    /****************************** Private Functions ******************************/

    /*
     * initialise
     *
     * DESCRIPTION:
     *
     * Initialize structure containing state of MD5 computation. (RFC 1321,
     * 3.3: Step 3).
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * None.
     */
    void md5_t::initialise() {
        A = 0x67452301;
        B = 0xefcdab89;
        C = 0x98badcfe;
        D = 0x10325476;

//        md_total[0] = 0;
//        md_total[1] = 0;
//        md_buf_len = 0;

        finished = false;
    }

    void md5_t::process_block_new() {
    /* Process each 16-word block. */
//    For i = 0 to N/16-1 do

        /* Copy block i into X. */
        For j = 0 to 15 do
            Set X[j] to M[i*16+j].
        end /* of loop on j */

        /* Save A as AA, B as BB, C as CC, and D as DD. */
        unsigned int AA = A, BB = B, CC = C, DD = D;

        /* Round 1
         * Let [abcd k s i] denote the operation
         * a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s)
         * Do the following 16 operations
         * [ABCD  0  7  1]  [DABC  1 12  2]  [CDAB  2 17  3]  [BCDA  3 22  4]
         * [ABCD  4  7  5]  [DABC  5 12  6]  [CDAB  6 17  7]  [BCDA  7 22  8]
         * [ABCD  8  7  9]  [DABC  9 12 10]  [CDAB 10 17 11]  [BCDA 11 22 12]
         * [ABCD 12  7 13]  [DABC 13 12 14]  [CDAB 14 17 15]  [BCDA 15 22 16]
         */
        FF(A, B, C, D, X[0 ], , 0 );
        FF(D, A, B, C, X[1 ], , 1 );
        FF(C, D, A, B, X[2 ], , 2 );
        FF(B, C, D, A, X[3 ], , 3 );
        FF(A, B, C, D, X[4 ], , 4 );
        FF(D, A, B, C, X[5 ], , 5 );
        FF(C, D, A, B, X[6 ], , 6 );
        FF(B, C, D, A, X[7 ], , 7 );
        FF(A, B, C, D, X[8 ], , 8 );
        FF(D, A, B, C, X[9 ], , 9 );
        FF(C, D, A, B, X[10], , 10);
        FF(B, C, D, A, X[11], , 11);
        FF(A, B, C, D, X[12], , 12);
        FF(D, A, B, C, X[13], , 13);
        FF(C, D, A, B, X[14], , 14);
        FF(B, C, D, A, X[15], , 15);

        /* Round 2
         * Let [abcd k s i] denote the operation
         * a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s)
         * Do the following 16 operations
         * [ABCD  1  5 17]  [DABC  6  9 18]  [CDAB 11 14 19]  [BCDA  0 20 20]
         * [ABCD  5  5 21]  [DABC 10  9 22]  [CDAB 15 14 23]  [BCDA  4 20 24]
         * [ABCD  9  5 25]  [DABC 14  9 26]  [CDAB  3 14 27]  [BCDA  8 20 28]
         * [ABCD 13  5 29]  [DABC  2  9 30]  [CDAB  7 14 31]  [BCDA 12 20 32]
         */
        GG(A, B, C, D, 0,  X[], 16);
        GG(D, A, B, C, 1,  X[], 17);
        GG(C, D, A, B, 2,  X[], 18);
        GG(B, C, D, A, 3,  X[], 19);
        GG(A, B, C, D, 4,  X[], 20);
        GG(D, A, B, C, 5,  X[], 21);
        GG(C, D, A, B, 6,  X[], 22);
        GG(B, C, D, A, 7,  X[], 23);
        GG(A, B, C, D, 8,  X[], 24);
        GG(D, A, B, C, 9,  X[], 25);
        GG(C, D, A, B, 10, X[], 26);
        GG(B, C, D, A, 11, X[], 27);
        GG(A, B, C, D, 12, X[], 28);
        GG(D, A, B, C, 13, X[], 29);
        GG(C, D, A, B, 14, X[], 30);
        GG(B, C, D, A, 15, X[], 31);

        /* Round 3
         * Let [abcd k s i] denote the operation
         * a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s)
         * Do the following 16 operations
         * [ABCD  5  4 33]  [DABC  8 11 34]  [CDAB 11 16 35]  [BCDA 14 23 36]
         * [ABCD  1  4 37]  [DABC  4 11 38]  [CDAB  7 16 39]  [BCDA 10 23 40]
         * [ABCD 13  4 41]  [DABC  0 11 42]  [CDAB  3 16 43]  [BCDA  6 23 44]
         * [ABCD  9  4 45]  [DABC 12 11 46]  [CDAB 15 16 47]  [BCDA  2 23 48]
         */
        HH(A, B, C, D, 0,  X[], 32);
        HH(D, A, B, C, 1,  X[], 33);
        HH(C, D, A, B, 2,  X[], 34);
        HH(B, C, D, A, 3,  X[], 35);
        HH(A, B, C, D, 4,  X[], 36);
        HH(D, A, B, C, 5,  X[], 37);
        HH(C, D, A, B, 6,  X[], 38);
        HH(B, C, D, A, 7,  X[], 39);
        HH(A, B, C, D, 8,  X[], 40);
        HH(D, A, B, C, 9,  X[], 41);
        HH(C, D, A, B, 10, X[], 42);
        HH(B, C, D, A, 11, X[], 43);
        HH(A, B, C, D, 12, X[], 44);
        HH(D, A, B, C, 13, X[], 45);
        HH(C, D, A, B, 14, X[], 46);
        HH(B, C, D, A, 15, X[], 47);

        /* Round 4
         * Let [abcd k s i] denote the operation
         * a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s)
         * Do the following 16 operations
         * [ABCD  0  6 49]  [DABC  7 10 50]  [CDAB 14 15 51]  [BCDA  5 21 52]
         * [ABCD 12  6 53]  [DABC  3 10 54]  [CDAB 10 15 55]  [BCDA  1 21 56]
         * [ABCD  8  6 57]  [DABC 15 10 58]  [CDAB  6 15 59]  [BCDA 13 21 60]
         * [ABCD  4  6 61]  [DABC 11 10 62]  [CDAB  2 15 63]  [BCDA  9 21 64]
         */
        II(A, B, C, D, 0,  X[], 48);
        II(D, A, B, C, 1,  X[], 49);
        II(C, D, A, B, 2,  X[], 50);
        II(B, C, D, A, 3,  X[], 51);
        II(A, B, C, D, 4,  X[], 52);
        II(D, A, B, C, 5,  X[], 53);
        II(C, D, A, B, 6,  X[], 54);
        II(B, C, D, A, 7,  X[], 55);
        II(A, B, C, D, 8,  X[], 56);
        II(D, A, B, C, 9,  X[], 57);
        II(C, D, A, B, 10, X[], 58);
        II(B, C, D, A, 11, X[], 59);
        II(A, B, C, D, 12, X[], 60);
        II(D, A, B, C, 13, X[], 61);
        II(C, D, A, B, 14, X[], 62);
        II(B, C, D, A, 15, X[], 63);

        /* Then perform the following additions. (That is increment each
        of the four registers by the value it had before this block
        was started.) */
        A += AA;
        B += BB;
        C += CC;
        D += DD;

    end /* of loop on i */
    }

    /*
     * process_block
     *
     * DESCRIPTION:
     *
     * Process a block of bytes into a MD5 state structure.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * buffer - A buffer of bytes whose MD5 signature we are calculating.
     *
     * buf_len - The length of the buffer.
     */
    void md5_t::process_block(const void *buffer, const unsigned int buf_len) {
        unsigned int correct[16];
        const void* buf_p = buffer;
        const void* end_p;
        unsigned int words_n;
        unsigned int A, B, C, D;

        words_n = buf_len / sizeof(unsigned int);
        end_p = (char*)buf_p + words_n * sizeof(unsigned int);

        A = md_A;
        B = md_B;
        C = md_C;
        D = md_D;

        /*
         * First increment the byte count.  RFC 1321 specifies the possible
         * length of the file up to 2^64 bits.  Here we only compute the
         * number of bytes with a double word increment.  Modified to do
         * this to better avoid overflows in the lower word -- Gray 10/97.
         */
        if (md_total[0] > UINT32_MAX - buf_len) {
            md_total[1]++;
            md_total[0] -= (UINT32_MAX + 1 - buf_len);
        } else {
            md_total[0] += buf_len;
        }

        /*
         * Process all bytes in the buffer with MD5_BLOCK bytes in each
         * round of the loop.
         */
        while (buf_p < end_p) {
            unsigned int A_save, B_save, C_save, D_save;
            unsigned int* corr_p = correct;

            A_save = A;
            B_save = B;
            C_save = C;
            D_save = D;

            /*
             * Before we start, one word to the strange constants.  They are
             * defined in RFC 1321 as
             *
             * T[i] = (int) (4294967296.0 * fabs (sin (i))), i=1..64
             */

            /* Round 1. */
            MD5_OP1(A, B, C, D, buf_p, corr_p,  7, 0xd76aa478);
            MD5_OP1(D, A, B, C, buf_p, corr_p, 12, 0xe8c7b756);
            MD5_OP1(C, D, A, B, buf_p, corr_p, 17, 0x242070db);
            MD5_OP1(B, C, D, A, buf_p, corr_p, 22, 0xc1bdceee);
            MD5_OP1(A, B, C, D, buf_p, corr_p,  7, 0xf57c0faf);
            MD5_OP1(D, A, B, C, buf_p, corr_p, 12, 0x4787c62a);
            MD5_OP1(C, D, A, B, buf_p, corr_p, 17, 0xa8304613);
            MD5_OP1(B, C, D, A, buf_p, corr_p, 22, 0xfd469501);
            MD5_OP1(A, B, C, D, buf_p, corr_p,  7, 0x698098d8);
            MD5_OP1(D, A, B, C, buf_p, corr_p, 12, 0x8b44f7af);
            MD5_OP1(C, D, A, B, buf_p, corr_p, 17, 0xffff5bb1);
            MD5_OP1(B, C, D, A, buf_p, corr_p, 22, 0x895cd7be);
            MD5_OP1(A, B, C, D, buf_p, corr_p,  7, 0x6b901122);
            MD5_OP1(D, A, B, C, buf_p, corr_p, 12, 0xfd987193);
            MD5_OP1(C, D, A, B, buf_p, corr_p, 17, 0xa679438e);
            MD5_OP1(B, C, D, A, buf_p, corr_p, 22, 0x49b40821);

            /* Round 2. */
            MD5_OP234(MD5_FG, A, B, C, D, correct[  1],  5, 0xf61e2562);
            MD5_OP234(MD5_FG, D, A, B, C, correct[  6],  9, 0xc040b340);
            MD5_OP234(MD5_FG, C, D, A, B, correct[ 11], 14, 0x265e5a51);
            MD5_OP234(MD5_FG, B, C, D, A, correct[  0], 20, 0xe9b6c7aa);
            MD5_OP234(MD5_FG, A, B, C, D, correct[  5],  5, 0xd62f105d);
            MD5_OP234(MD5_FG, D, A, B, C, correct[ 10],  9, 0x02441453);
            MD5_OP234(MD5_FG, C, D, A, B, correct[ 15], 14, 0xd8a1e681);
            MD5_OP234(MD5_FG, B, C, D, A, correct[  4], 20, 0xe7d3fbc8);
            MD5_OP234(MD5_FG, A, B, C, D, correct[  9],  5, 0x21e1cde6);
            MD5_OP234(MD5_FG, D, A, B, C, correct[ 14],  9, 0xc33707d6);
            MD5_OP234(MD5_FG, C, D, A, B, correct[  3], 14, 0xf4d50d87);
            MD5_OP234(MD5_FG, B, C, D, A, correct[  8], 20, 0x455a14ed);
            MD5_OP234(MD5_FG, A, B, C, D, correct[ 13],  5, 0xa9e3e905);
            MD5_OP234(MD5_FG, D, A, B, C, correct[  2],  9, 0xfcefa3f8);
            MD5_OP234(MD5_FG, C, D, A, B, correct[  7], 14, 0x676f02d9);
            MD5_OP234(MD5_FG, B, C, D, A, correct[ 12], 20, 0x8d2a4c8a);

            /* Round 3. */
            MD5_OP234(MD5_FH, A, B, C, D, correct[  5],  4, 0xfffa3942);
            MD5_OP234(MD5_FH, D, A, B, C, correct[  8], 11, 0x8771f681);
            MD5_OP234(MD5_FH, C, D, A, B, correct[ 11], 16, 0x6d9d6122);
            MD5_OP234(MD5_FH, B, C, D, A, correct[ 14], 23, 0xfde5380c);
            MD5_OP234(MD5_FH, A, B, C, D, correct[  1],  4, 0xa4beea44);
            MD5_OP234(MD5_FH, D, A, B, C, correct[  4], 11, 0x4bdecfa9);
            MD5_OP234(MD5_FH, C, D, A, B, correct[  7], 16, 0xf6bb4b60);
            MD5_OP234(MD5_FH, B, C, D, A, correct[ 10], 23, 0xbebfbc70);
            MD5_OP234(MD5_FH, A, B, C, D, correct[ 13],  4, 0x289b7ec6);
            MD5_OP234(MD5_FH, D, A, B, C, correct[  0], 11, 0xeaa127fa);
            MD5_OP234(MD5_FH, C, D, A, B, correct[  3], 16, 0xd4ef3085);
            MD5_OP234(MD5_FH, B, C, D, A, correct[  6], 23, 0x04881d05);
            MD5_OP234(MD5_FH, A, B, C, D, correct[  9],  4, 0xd9d4d039);
            MD5_OP234(MD5_FH, D, A, B, C, correct[ 12], 11, 0xe6db99e5);
            MD5_OP234(MD5_FH, C, D, A, B, correct[ 15], 16, 0x1fa27cf8);
            MD5_OP234(MD5_FH, B, C, D, A, correct[  2], 23, 0xc4ac5665);

            /* Round 4. */
            MD5_OP234(MD5_FI, A, B, C, D, correct[  0],  6, 0xf4292244);
            MD5_OP234(MD5_FI, D, A, B, C, correct[  7], 10, 0x432aff97);
            MD5_OP234(MD5_FI, C, D, A, B, correct[ 14], 15, 0xab9423a7);
            MD5_OP234(MD5_FI, B, C, D, A, correct[  5], 21, 0xfc93a039);
            MD5_OP234(MD5_FI, A, B, C, D, correct[ 12],  6, 0x655b59c3);
            MD5_OP234(MD5_FI, D, A, B, C, correct[  3], 10, 0x8f0ccc92);
            MD5_OP234(MD5_FI, C, D, A, B, correct[ 10], 15, 0xffeff47d);
            MD5_OP234(MD5_FI, B, C, D, A, correct[  1], 21, 0x85845dd1);
            MD5_OP234(MD5_FI, A, B, C, D, correct[  8],  6, 0x6fa87e4f);
            MD5_OP234(MD5_FI, D, A, B, C, correct[ 15], 10, 0xfe2ce6e0);
            MD5_OP234(MD5_FI, C, D, A, B, correct[  6], 15, 0xa3014314);
            MD5_OP234(MD5_FI, B, C, D, A, correct[ 13], 21, 0x4e0811a1);
            MD5_OP234(MD5_FI, A, B, C, D, correct[  4],  6, 0xf7537e82);
            MD5_OP234(MD5_FI, D, A, B, C, correct[ 11], 10, 0xbd3af235);
            MD5_OP234(MD5_FI, C, D, A, B, correct[  2], 15, 0x2ad7d2bb);
            MD5_OP234(MD5_FI, B, C, D, A, correct[  9], 21, 0xeb86d391);

            /* Add the starting values of the context. */
            A += A_save;
            B += B_save;
            C += C_save;
            D += D_save;
        }

        /* Put checksum in context given as argument. */
        md_A = A;
        md_B = B;
        md_C = C;
        md_D = D;
    }

    /*
     * get_result
     *
     * DESCRIPTION:
     *
     * Copy the resulting MD5 signature into the first 16 bytes (MD5_SIZE)
     * of the result buffer.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * result - A 16 byte buffer that will contain the MD5 signature.
     */
    void md5_t::get_result(void *result) {
        unsigned int hold;
        void* res_p = result;

        hold = MD5_SWAP(md_A);
        memcpy(res_p, &hold, sizeof(unsigned int));
        res_p = (char*)res_p + sizeof(unsigned int);

        hold = MD5_SWAP(md_B);
        memcpy(res_p, &hold, sizeof(unsigned int));
        res_p = (char*)res_p + sizeof(unsigned int);

        hold = MD5_SWAP(md_C);
        memcpy(res_p, &hold, sizeof(unsigned int));
        res_p = (char*)res_p + sizeof(unsigned int);

        hold = MD5_SWAP(md_D);
        memcpy(res_p, &hold, sizeof(unsigned int));
    }

    /****************************** Exported Functions ******************************/

    /*
     * sig_to_string
     *
     * DESCRIPTION:
     *
     * Convert a MD5 signature in a 16 byte buffer into a hexadecimal string
     * representation.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * signature_ - a 16 byte buffer that contains the MD5 signature.
     *
     * str_ - a string of charactes which should be at least 33 bytes long (2
     * characters per MD5 byte and 1 for the \0).
     *
     * str_len - the length of the string.
     */
    void sig_to_string(const void* signature_, char* str_, const int str_len) {
        unsigned char* sig_p;
        char* str_p;
        char* max_p;
        unsigned int high, low;

        str_p = str_;
        max_p = str_ + str_len;

        for (sig_p = (unsigned char*)signature_; sig_p < (unsigned char*)signature_ + MD5_SIZE; sig_p++) {
            high = *sig_p / 16;
            low = *sig_p % 16;
            /* account for 2 chars */
            if (str_p + 1 >= max_p) {
                break;
            }
            *str_p++ = md5::HEX_STRING[high];
            *str_p++ = md5::HEX_STRING[low];
        }
        /* account for 2 chars */
        if (str_p < max_p) {
            *str_p++ = '\0';
        }
    }

    /*
     * sig_from_string
     *
     * DESCRIPTION:
     *
     * Convert a MD5 signature from a hexadecimal string representation into
     * a 16 byte buffer.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * signature_ - A 16 byte buffer that will contain the MD5 signature.
     *
     * str_ - A string of charactes which _must_ be at least 32 bytes long (2
     * characters per MD5 byte).
     */
    void sig_from_string(void* signature_, const char* str_) {
        unsigned char *sig_p;
        const char *str_p;
        char* hex;
        unsigned int high, low, val;

        hex = (char*)md5::HEX_STRING;
        sig_p = static_cast<unsigned char*>(signature_);

        for (str_p = str_; str_p < str_ + MD5_SIZE * 2; str_p += 2) {
            high = strchr(hex, *str_p) - hex;
            low = strchr(hex, *(str_p + 1)) - hex;
            val = high * 16 + low;
            *sig_p++ = val;
        }
    }
} // namespace md5

