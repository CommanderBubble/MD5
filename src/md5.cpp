#include <cstdlib>
#include <cstring>
#include <iostream>

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
     * buf_len_ - The length of the buffer.
     *
     * signature - A 16 byte buffer that will contain the MD5 signature.
     */
    md5_t::md5_t(const char* buffer_, const unsigned int buf_len_, void* signature) {
        /* initialize the computation context */
        initialise();

        /* process whole buffer but last buf_len_ % MD5_BLOCK bytes */
        process(buffer_, buf_len_);

        /* put result in desired memory area */
        finish(signature);
    }

    void md5_t::process_new(const void* buffer_, const unsigned int buffer_length) {
        if (!finished) {
            char block[md5::BLOCK_SIZE];
            unsigned int processed = 0;

            if (stored_size) {
                memcpy(block, stored, stored_size);
                memcpy(block + stored_size, buffer_, md5::BLOCK_SIZE - stored_size);
                processed = stored_size;
                process_block_new(block);
            }

            while (processed + md5::BLOCK_SIZE <= buffer_length) {
                memcpy(block, (char*)buffer_ + processed, md5::BLOCK_SIZE);
                processed += md5::BLOCK_SIZE;
                process_block_new(block);
            }

            if (processed != buffer_length) {
                stored_size = buffer_length - processed;
                memcpy(stored, (char*)buffer_ + processed, stored_size);
            } else {
                stored_size = 0;
            }
        } else {
            // throw error when trying to process after completion?
        }
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
     * buf_len_ - The length of the buffer.
     */
    void md5_t::process(const void* buffer_, const unsigned int buf_len_) {
        if (!finished) {
            unsigned int len = buf_len_;
            unsigned int in_block, add;

            /*
             * When we already have some bytes in our internal buffer, copy some
             * from the user to fill the block.
             */

            if (buf_len > 0) {
                in_block = buf_len;
                if (in_block + len > sizeof(buffer)) {
                    add = sizeof(buffer) - in_block;
                } else {
                    add = len;
                }

                memcpy(buffer + in_block, buffer_, add);
                buf_len += add;
                in_block += add;

                if (in_block > md5::BLOCK_SIZE) {
                    process_block(buffer, in_block & ~md5::BLOCK_SIZE_MASK);
                    /* the regions in the following copy operation will not overlap. */
                    memcpy(buffer,
                    buffer + (in_block & ~md5::BLOCK_SIZE_MASK),
                    in_block & md5::BLOCK_SIZE_MASK);
                    buf_len = in_block & md5::BLOCK_SIZE_MASK;
                }

                buffer_ = (const char*)buffer_ + add;
                len -= add;
            }

            /* process available complete blocks right from the user buffer */
            if (len > md5::BLOCK_SIZE) {
                process_block(buffer_, len & ~md5::BLOCK_SIZE_MASK);
                buffer_ = (const char*) buffer_ + (len & ~md5::BLOCK_SIZE_MASK);
                len &= md5::BLOCK_SIZE_MASK;
            }

            /* copy remaining bytes into the internal buffer */
            if (len > 0) {
                memcpy(buffer, buffer_, len);
                buf_len = len;
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
    void md5_t::finish_new(void* signature_) {
        if (!finished) {
            unsigned int bytes, hold;
            int pad;

            /* take yet unprocessed bytes into account */
            bytes = stored_size;

            /*
             * Count remaining bytes.  Modified to do this to better avoid
             * overflows in the lower word -- Gray 10/97.
             */

            std::cout << "length: " << message_length[1] << message_length[0] << std::endl;

            if (message_length[0] + bytes < message_length[0])
                message_length[1]++;
            message_length[0] += bytes;

            std::cout << "length: " << message_length[1] << message_length[0] << std::endl;

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
                stored[bytes] = (unsigned char)0x80;
                if (pad > 1) {
                    memset(stored + bytes + 1, 0, pad - 1);
                }
                bytes += pad;
            }

            /*
             * Put the 64-bit file length in _bits_ (i.e. *8) at the end of the
             * buffer.
             */
            hold = MD5_SWAP((message_length[0] & 0x1FFFFFFF) << 3);
            memcpy(stored + bytes, &hold, sizeof(unsigned int));
            bytes += sizeof(unsigned int);

            /* shift the high word over by 3 and add in the top 3 bits from the low */
            hold = MD5_SWAP((message_length[1] << 3) | ((message_length[0] & 0xE0000000) >> 29));
            memcpy(stored + bytes, &hold, sizeof(unsigned int));
            bytes += sizeof(unsigned int);

            unsigned int high = (message_length[1] << 3) | ((message_length[0] & 0xE0000000) >> 29);
            unsigned int low = ((message_length[0] & 0x1FFFFFFF) << 3);
            std::cout << "length: " << high << " " << low << std::endl;

            /* process last bytes, the padding chars, and size words */
            int counter = 0;
            while (counter < bytes) {
                char temp[md5::BLOCK_SIZE];
                memcpy(temp, stored + counter, md5::BLOCK_SIZE);
                counter += md5::BLOCK_SIZE;
                process_block_new(temp);
            }

            get_result(static_cast<void*>(signature));

            sig_to_string(signature, str, 33);

            if (signature_ != NULL) {
                memcpy(signature_, static_cast<void*>(signature), MD5_SIZE);
            }

            finished = true;
        } else {
            // add error?
        }
    }

    void md5_t::finish(void* signature_) {
        if (!finished) {
            unsigned int bytes, hold;
            int pad;

            /* take yet unprocessed bytes into account */
            bytes = buf_len;


            std::cout << "length: " << total[1] << total[0] << std::endl;

            /*
             * Count remaining bytes.  Modified to do this to better avoid
             * overflows in the lower word -- Gray 10/97.
             */
            if (total[0] > UINT32_MAX - bytes) {
                total[1]++;
                total[0] -= (UINT32_MAX + 1 - bytes);
            } else {
                total[0] += bytes;
            }

            std::cout << "length: " << total[1] << total[0] << std::endl;

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
                buffer[bytes] = (unsigned char)0x80;
                if (pad > 1) {
                    memset(buffer + bytes + 1, 0, pad - 1);
                }
                bytes += pad;
            }

            /*
             * Put the 64-bit file length in _bits_ (i.e. *8) at the end of the
             * buffer.
             */
            hold = MD5_SWAP((total[0] & 0x1FFFFFFF) << 3);
            memcpy(buffer + bytes, &hold, sizeof(unsigned int));
            bytes += sizeof(unsigned int);

            /* shift the high word over by 3 and add in the top 3 bits from the low */
            hold = MD5_SWAP((total[1] << 3) | ((total[0] & 0xE0000000) >> 29));
            memcpy(buffer + bytes, &hold, sizeof(unsigned int));
            bytes += sizeof(unsigned int);

            unsigned int high = (total[1] << 3) | ((total[0] & 0xE0000000) >> 29);
            unsigned int low = ((total[0] & 0x1FFFFFFF) << 3);
            std::cout << "length: " << high << " " << low << std::endl;

            /* process last bytes, the padding chars, and size words */
            process_block(buffer, bytes);

            get_result(static_cast<void*>(signature));

            sig_to_string(signature, str, 33);

            if (signature_ != NULL) {
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
        } else {
            //error?
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
        } else {
            // error?
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

        message_length[0] = 0;
        message_length[1] = 0;
        stored_size = 0;

        total[0] = 0;
        total[1] = 0;
        buf_len = 0;

        finished = false;
    }

    void md5_t::process_block_new(const void* block) {
    /* Process each 16-word block. */

        /*
         * we check for when the lower word rolls over, and increment the
         * higher word. we do not need to worry if the higher word rolls over
         * as only the two words we maintain are needed in the function later
         *
         */
        if (message_length[0] + md5::BLOCK_SIZE < message_length[0])
            message_length[1]++;
        message_length[0] += BLOCK_SIZE;

        char* temp = (char*)block;

        std::cout << "provided BLOCK: \"";

        for (unsigned int i = 0; i < 64; i++) {
            std::cout << temp[i];
        }

        std::cout << "\"\n";
        /* Copy block i into X. */
        //For j = 0 to 15 do
        //    Set X[j] to M[i*16+j].
        /* of loop on j */
        unsigned int X[16];
        for (unsigned int i = 0; i < 16; i++) {
            memcpy(X + i, (char*)block + 4 * i, 4);
        }

        /* Save A as AA, B as BB, C as CC, and D as DD. */
        unsigned int AA = A, BB = B, CC = C, DD = D;

        std::cout << "BEFORE:\n";
        std::cout << "A: " << A << std::endl
                  << "B: " << B << std::endl
                  << "C: " << C << std::endl
                  << "D: " << D << std::endl;

        /* Round 1
         * Let [abcd k s i] denote the operation
         * a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s)
         * Do the following 16 operations
         * [ABCD  0  7  1]  [DABC  1 12  2]  [CDAB  2 17  3]  [BCDA  3 22  4]
         * [ABCD  4  7  5]  [DABC  5 12  6]  [CDAB  6 17  7]  [BCDA  7 22  8]
         * [ABCD  8  7  9]  [DABC  9 12 10]  [CDAB 10 17 11]  [BCDA 11 22 12]
         * [ABCD 12  7 13]  [DABC 13 12 14]  [CDAB 14 17 15]  [BCDA 15 22 16]
         */
        md5::FF(A, B, C, D, X[0 ], 0, 0 );
        md5::FF(D, A, B, C, X[1 ], 1, 1 );
        md5::FF(C, D, A, B, X[2 ], 2, 2 );
        md5::FF(B, C, D, A, X[3 ], 3, 3 );
        md5::FF(A, B, C, D, X[4 ], 0, 4 );
        md5::FF(D, A, B, C, X[5 ], 1, 5 );
        md5::FF(C, D, A, B, X[6 ], 2, 6 );
        md5::FF(B, C, D, A, X[7 ], 3, 7 );
        md5::FF(A, B, C, D, X[8 ], 0, 8 );
        md5::FF(D, A, B, C, X[9 ], 1, 9 );
        md5::FF(C, D, A, B, X[10], 2, 10);
        md5::FF(B, C, D, A, X[11], 3, 11);
        md5::FF(A, B, C, D, X[12], 0, 12);
        md5::FF(D, A, B, C, X[13], 1, 13);
        md5::FF(C, D, A, B, X[14], 2, 14);
        md5::FF(B, C, D, A, X[15], 3, 15);

        /* Round 2
         * Let [abcd k s i] denote the operation
         * a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s)
         * Do the following 16 operations
         * [ABCD  1  5 17]  [DABC  6  9 18]  [CDAB 11 14 19]  [BCDA  0 20 20]
         * [ABCD  5  5 21]  [DABC 10  9 22]  [CDAB 15 14 23]  [BCDA  4 20 24]
         * [ABCD  9  5 25]  [DABC 14  9 26]  [CDAB  3 14 27]  [BCDA  8 20 28]
         * [ABCD 13  5 29]  [DABC  2  9 30]  [CDAB  7 14 31]  [BCDA 12 20 32]
         */
        md5::GG(A, B, C, D, X[1 ], 0, 16);
        md5::GG(D, A, B, C, X[6 ], 1, 17);
        md5::GG(C, D, A, B, X[11], 2, 18);
        md5::GG(B, C, D, A, X[0 ], 3, 19);
        md5::GG(A, B, C, D, X[5 ], 0, 20);
        md5::GG(D, A, B, C, X[10], 1, 21);
        md5::GG(C, D, A, B, X[15], 2, 22);
        md5::GG(B, C, D, A, X[4 ], 3, 23);
        md5::GG(A, B, C, D, X[9 ], 0, 24);
        md5::GG(D, A, B, C, X[14], 1, 25);
        md5::GG(C, D, A, B, X[3 ], 2, 26);
        md5::GG(B, C, D, A, X[8 ], 3, 27);
        md5::GG(A, B, C, D, X[13], 0, 28);
        md5::GG(D, A, B, C, X[2 ], 1, 29);
        md5::GG(C, D, A, B, X[7 ], 2, 30);
        md5::GG(B, C, D, A, X[12], 3, 31);

        /* Round 3
         * Let [abcd k s i] denote the operation
         * a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s)
         * Do the following 16 operations
         * [ABCD  5  4 33]  [DABC  8 11 34]  [CDAB 11 16 35]  [BCDA 14 23 36]
         * [ABCD  1  4 37]  [DABC  4 11 38]  [CDAB  7 16 39]  [BCDA 10 23 40]
         * [ABCD 13  4 41]  [DABC  0 11 42]  [CDAB  3 16 43]  [BCDA  6 23 44]
         * [ABCD  9  4 45]  [DABC 12 11 46]  [CDAB 15 16 47]  [BCDA  2 23 48]
         */
        md5::HH(A, B, C, D, X[5 ], 0, 32);
        md5::HH(D, A, B, C, X[8 ], 1, 33);
        md5::HH(C, D, A, B, X[11], 2, 34);
        md5::HH(B, C, D, A, X[14], 3, 35);
        md5::HH(A, B, C, D, X[1 ], 0, 36);
        md5::HH(D, A, B, C, X[4 ], 1, 37);
        md5::HH(C, D, A, B, X[7 ], 2, 38);
        md5::HH(B, C, D, A, X[10], 3, 39);
        md5::HH(A, B, C, D, X[13], 0, 40);
        md5::HH(D, A, B, C, X[0 ], 1, 41);
        md5::HH(C, D, A, B, X[3 ], 2, 42);
        md5::HH(B, C, D, A, X[6 ], 3, 43);
        md5::HH(A, B, C, D, X[9 ], 0, 44);
        md5::HH(D, A, B, C, X[12], 1, 45);
        md5::HH(C, D, A, B, X[15], 2, 46);
        md5::HH(B, C, D, A, X[2 ], 3, 47);

        /* Round 4
         * Let [abcd k s i] denote the operation
         * a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s)
         * Do the following 16 operations
         * [ABCD  0  6 49]  [DABC  7 10 50]  [CDAB 14 15 51]  [BCDA  5 21 52]
         * [ABCD 12  6 53]  [DABC  3 10 54]  [CDAB 10 15 55]  [BCDA  1 21 56]
         * [ABCD  8  6 57]  [DABC 15 10 58]  [CDAB  6 15 59]  [BCDA 13 21 60]
         * [ABCD  4  6 61]  [DABC 11 10 62]  [CDAB  2 15 63]  [BCDA  9 21 64]
         */
        md5::II(A, B, C, D, X[0 ], 0, 48);
        md5::II(D, A, B, C, X[7 ], 1, 49);
        md5::II(C, D, A, B, X[14], 2, 50);
        md5::II(B, C, D, A, X[5 ], 3, 51);
        md5::II(A, B, C, D, X[12], 0, 52);
        md5::II(D, A, B, C, X[3 ], 1, 53);
        md5::II(C, D, A, B, X[10], 2, 54);
        md5::II(B, C, D, A, X[1 ], 3, 55);
        md5::II(A, B, C, D, X[8 ], 0, 56);
        md5::II(D, A, B, C, X[15], 1, 57);
        md5::II(C, D, A, B, X[6 ], 2, 58);
        md5::II(B, C, D, A, X[13], 3, 59);
        md5::II(A, B, C, D, X[4 ], 0, 60);
        md5::II(D, A, B, C, X[11], 1, 61);
        md5::II(C, D, A, B, X[2 ], 2, 62);
        md5::II(B, C, D, A, X[9 ], 3, 63);

        /* Then perform the following additions. (That is increment each
        of the four registers by the value it had before this block
        was started.) */
        A += AA;
        B += BB;
        C += CC;
        D += DD;

        std::cout << "AFTER:\n";
        std::cout << "A: " << A << std::endl
                  << "B: " << B << std::endl
                  << "C: " << C << std::endl
                  << "D: " << D << std::endl;

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
    void md5_t::process_block(const void *buffer_, const unsigned int buf_len_) {
        std::cout << "provided BLOCK: \"";

        char* temp = (char*)buffer_;

        for (unsigned int i = 0; i < buf_len_; i++) {
            std::cout << temp[i];
        }

        std::cout << "\"\n";

        unsigned int correct[16];
        const void* buf_p = buffer_;
        const void* end_p;
        unsigned int words_n;

        words_n = buf_len_ / sizeof(unsigned int);
        end_p = (char*)buf_p + words_n * sizeof(unsigned int);

        /*
         * First increment the byte count.  RFC 1321 specifies the possible
         * length of the file up to 2^64 bits.  Here we only compute the
         * number of bytes with a double word increment.  Modified to do
         * this to better avoid overflows in the lower word -- Gray 10/97.
         */
        if (total[0] > UINT32_MAX - buf_len_) {
            total[1]++;
            total[0] -= (UINT32_MAX + 1 - buf_len_);
        } else {
            total[0] += buf_len_;
        }

        /*
         * Process all bytes in the buffer with MD5_BLOCK bytes in each
         * round of the loop.
         */
        while (buf_p < end_p) {
            unsigned int AA, BB, CC, DD;
            unsigned int* corr_p = correct;

            AA = A;
            BB = B;
            CC = C;
            DD = D;

            std::cout << "BEFORE:\n";
            std::cout << "A: " << A << std::endl
                      << "B: " << B << std::endl
                      << "C: " << C << std::endl
                      << "D: " << D << std::endl;


            /*
             * Before we start, one word to the strange constants.  They are
             * defined in RFC 1321 as
             *
             * T[i] = (int) (4294967296.0 * fabs (sin (i))), i=1..64
             */

            unsigned int place = 0;

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

            place = 0;

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

            place = 0;

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

            place = 0;

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
            A += AA;
            B += BB;
            C += CC;
            D += DD;

            std::cout << "AFTER:\n";
            std::cout << "A: " << A << std::endl
                      << "B: " << B << std::endl
                      << "C: " << C << std::endl
                      << "D: " << D << std::endl;

        }
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

        hold = MD5_SWAP(A);
        memcpy(res_p, &hold, sizeof(unsigned int));
        res_p = (char*)res_p + sizeof(unsigned int);

        hold = MD5_SWAP(B);
        memcpy(res_p, &hold, sizeof(unsigned int));
        res_p = (char*)res_p + sizeof(unsigned int);

        hold = MD5_SWAP(C);
        memcpy(res_p, &hold, sizeof(unsigned int));
        res_p = (char*)res_p + sizeof(unsigned int);

        hold = MD5_SWAP(D);
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

