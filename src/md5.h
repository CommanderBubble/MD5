/*
 * Declaration of functions and data types used for MD5 sum computing
 * library functions.  Copyright (C) 1995, 1996 Free Software
 * Foundation, Inc.  NOTE: The canonical source of this file is
 * maintained with the GNU C Library.  Bugs can be reported to
 * bug-glibc@prep.ai.mit.edu.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * $Id: md5.h,v 1.4 2000/03/09 04:06:41 gray Exp $
 */

/*
 * NOTE: during quick performance tests on a sun ultra and an alpha
 * 255 300, the md5 libraries performed upwards of 3mb/sec.  That
 * included disk i/o on bobcat and panther.
 */

#ifndef __MD5_H__
#define __MD5_H__

/*
 * Size of a standard MD5 signature in bytes.  This definition is for
 * external programs only.  The MD5 routines themselves reference the
 * signature as 4 unsigned 32-bit integers.
 */
#define MD5_SIZE	16

/*
 * NOTE: the following is assumed to generate a 32-bit unsigned data
 * type.
 */
#define MAX_MD5_UINT32		((unsigned int)4294967295U)

/*
 * The MD5 algorithm works on blocks of characters of 64 bytes.  This
 * is an internal value only and is not necessary for external use.
 */
#define MD5_BLOCK_SIZE		64

/*
 * Structure to save state of computation between the single steps.
 */

#include <string>

 namespace md5 {

//    typedef struct {
//      md5_uint32	md_A;			/* accumulater 1 */
//      md5_uint32	md_B;			/* accumulater 2 */
//      md5_uint32	md_C;			/* accumulater 3 */
//      md5_uint32	md_D;			/* accumulater 4 */

//      md5_uint32	md_total[2];		/* totaling storage */
//      md5_uint32	md_buf_len;		/* length of the storage buffer */
//      char		md_buffer[MD5_BLOCK_SIZE * 2];	/* character storage buffer */
//    } md5_t;

    class md5_t {
        public:
            /*
             * md5_t
             *
             * DESCRIPTION:
             *
             * Initialize structure containing state of MD5 computation. (RFC 1321,
             * 3.3: Step 3).  This is for progressive MD5 calculations only.  If
             * you have the complete string available, call it as below.
             * md5_t::process should be called for each bunch of bytes and after the
             * last process call, md5_t::finish should be called to get the signature.
             *
             * RETURNS:
             *
             * None.
             *
             * ARGUMENTS:
             *
             * None.
             */
            md5_t();

            /*
             * md5_t
             *
             * DESCRIPTION:
             *
             * This function is used to calculate a MD5 signature for a buffer of
             * bytes.  If you only have part of a buffer that you want to process
             * then md5_t::md5_t, md5_t::process, and md5_t::finish should be used.
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
             * signature_ - A 16 byte buffer that will contain the MD5 signature.
             */
            md5_t(const char* buffer, const unsigned int buf_len, void* signature_);

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
            void process(const void* buffer, const unsigned int buf_len);

            /*
             * finish
             *
             * DESCRIPTION:
             *
             * Finish a progressing MD5 calculation and copy the resulting MD5
             * signature into the result buffer which should be 16 bytes
             * (MD5_SIZE).  After this call, the MD5 structure cannot be used
             * to calculate a new md5, it can only return its signature.
             *
             * RETURNS:
             *
             * None.
             *
             * ARGUMENTS:
             *
             * signature_ - A 16 byte buffer that will contain the MD5 signature.
             */
            void finish(void* signature_);

            void get_signature(void* signature_);
            void get_string(void* str_);

        private:
            /* internal functions */
            void initialise();
            void process_block(const void*, const unsigned int);
            void get_result(void*);

            unsigned int md_A;                          /* accumulater 1 */
            unsigned int md_B;                          /* accumulater 2 */
            unsigned int md_C;                          /* accumulater 3 */
            unsigned int md_D;                          /* accumulater 4 */

            unsigned int md_total[2];                   /* totaling storage */
            unsigned int md_buf_len;                    /* length of the storage buffer */
            char md_buffer[MD5_BLOCK_SIZE * 2];         /* character storage buffer */

            bool finished;                              /* object state */

            char signature[4 * sizeof(unsigned int)];   /* stored signature */
            char str[33];                               /* stored plain text hash */
    };

    /*
     * md5_sig_to_string
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
     * signature - a 16 byte buffer that contains the MD5 signature.
     *
     * str - a string of charactes which should be at least 33 bytes long (2
     * characters per MD5 byte and 1 for the \0).
     *
     * str_len - the length of the string.
     */
    extern void sig_to_string(const void* signature, char* str, const int str_len);

    /*
     * md5_sig_from_string
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
     * signature - A 16 byte buffer that will contain the MD5 signature.
     *
     * str - A string of charactes which _must_ be at least 32 bytes long (2
     * characters per MD5 byte).
     */
    extern void sig_from_string(void* signature, const char* str);

} // namespace

#endif /* ! __MD5_H__ */
