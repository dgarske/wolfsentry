/*
 * centijson_sax.c
 *
 * Copyright (C) 2021-2023 wolfSSL Inc.
 *
 * This file is part of wolfSentry.
 *
 * wolfSentry is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSentry is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * CentiJSON
 * <http://github.com/mity/centijson>
 *
 * Copyright (c) 2018 Martin Mitas
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef NO_WOLFSENTRY
#include "wolfsentry/wolfsentry_json.h"
#else
#include "wolfsentry/centijson_sax.h"
#endif

#ifdef CENTIJSON_USE_LOCALE
#include <locale.h>     /* localeconv() */
#endif
#include <stdio.h>      /* snprintf() */
#include <stdlib.h>
#include <string.h>


#ifdef _MSC_VER
    /* MSVC does not understand "inline" when building as pure C (not C++).
     * However it understands "__inline" */
    #ifndef __cplusplus
        #define inline __inline
    #endif

    /* Older MSVC versions do not have snprintf() but _snprintf(). */
    #define snprintf _snprintf
#endif


static const JSON_CONFIG json_defaults = {
    10 * 1024 * 1024,       /* max_total_len */
    0,                      /* max_total_values */
    512,                    /* max_number_len */
    65536,                  /* max_string_len */
    512,                    /* max_key_len */
    512,                    /* max_nesting_level */
    0                       /* flags */
};


#define ABS(x)          ((x) >= 0 ? (x) : -(x))

#ifdef WOLFSENTRY

static void *json_malloc(JSON_PARSER *parser, size_t size) {
    if (parser->allocator)
        return parser->allocator->malloc(WOLFSENTRY_CONTEXT_ARGS_OUT_EX3(parser, allocator->context), size);
    else
        return NULL;
}
#define malloc(size) json_malloc(parser, size)
static void json_free(JSON_PARSER *parser, void *ptr) {
    if (parser->allocator)
        parser->allocator->free(WOLFSENTRY_CONTEXT_ARGS_OUT_EX3(parser, allocator->context), ptr);
    WOLFSENTRY_RETURN_VOID;
}
#define free(ptr) json_free(parser, ptr)
static void *json_realloc(JSON_PARSER *parser, void *ptr, size_t size) {
    if (ptr == NULL)
        return json_malloc(parser, size);
    if (parser->allocator)
        return parser->allocator->realloc(WOLFSENTRY_CONTEXT_ARGS_OUT_EX3(parser, allocator->context), ptr, size);
    else
        return NULL;
}
#define realloc(ptr, size) json_realloc(parser, ptr, size)

#endif

#ifndef WOLFSENTRY

#define WOLFSENTRY_RETURN_VALUE(x) return(x)
#define WOLFSENTRY_RETURN_VOID return

#endif

WOLFSENTRY_API_VOID
json_default_config(JSON_CONFIG* cfg)
{
    memcpy(cfg, &json_defaults, sizeof(JSON_CONFIG));
    WOLFSENTRY_RETURN_VOID;
}


#define FIRST_LINE_NUMBER       1
#define FIRST_COLUMN_NUMBER     1

/* Bits for JSON_PARSER::state. */
#define PARSER_STATE_UNINITED   0
#define CAN_SEE_VALUE           0x0001
#define CAN_SEE_KEY             0x0002
#define CAN_SEE_CLOSER          0x0004
#define CAN_SEE_COMMA           0x0008
#define CAN_SEE_COLON           0x0010
#define CAN_SEE_EOF             0x8000

int
json_init(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_PARSER* parser, const JSON_CALLBACKS* callbacks,
              const JSON_CONFIG* config, void* user_data)
{
    if(config == NULL)
        config = &json_defaults;

    memset(parser, 0, sizeof(JSON_PARSER));

    memcpy(&parser->callbacks, callbacks, sizeof(JSON_CALLBACKS));
    memcpy(&parser->config, config, sizeof(JSON_CONFIG));
#ifdef WOLFSENTRY
    parser->allocator = allocator;
#ifdef WOLFSENTRY_THREADSAFE
    parser->thread = thread;
#endif
#endif

    parser->user_data = user_data;

    parser->pos.line_number = FIRST_LINE_NUMBER;
    parser->pos.column_number = FIRST_COLUMN_NUMBER;

    parser->automaton = AUTOMATON_MAIN;
    parser->state = CAN_SEE_VALUE;

    parser->last_cl_offset = SIZE_MAX-1;

    WOLFSENTRY_RETURN_VALUE(0);
}

static void
json_raise_(JSON_PARSER* parser, int errcode, JSON_INPUT_POS* pos)
{
    /* Keep the primary error. */
    if(parser->errcode >= 0) {
        parser->errcode = errcode;
        memcpy(&parser->err_pos, pos, sizeof(JSON_INPUT_POS));
    }
}

static inline  void
json_raise(JSON_PARSER* parser, int errcode)
{
    json_raise_(parser, errcode, &parser->pos);
}

static inline void
json_raise_for_value(JSON_PARSER* parser, int errcode)
{
    json_raise_(parser, errcode, &parser->value_pos);
}

static void
json_raise_unexpected(JSON_PARSER* parser)
{
    int err;

    switch(parser->state) {
        case CAN_SEE_VALUE:                     err = JSON_ERR_EXPECTEDVALUE; break;
        case CAN_SEE_KEY:                       err = JSON_ERR_EXPECTEDKEY; break;
        case (CAN_SEE_VALUE | CAN_SEE_CLOSER):  err = JSON_ERR_EXPECTEDVALUEORCLOSER; break;
        case (CAN_SEE_KEY | CAN_SEE_CLOSER):    err = JSON_ERR_EXPECTEDKEYORCLOSER; break;
        case CAN_SEE_COLON:                     err = JSON_ERR_EXPECTEDCOLON; break;
        case (CAN_SEE_COMMA | CAN_SEE_CLOSER):  err = JSON_ERR_EXPECTEDCOMMAORCLOSER; break;
        case CAN_SEE_EOF:                       err = JSON_ERR_EXPECTEDEOF; break;

        /* Other combinations should never happen but lets be defensive. */
        default:                                err = JSON_ERR_SYNTAX; break;
    }

    json_raise(parser, err);
}

static inline void
json_switch_automaton(JSON_PARSER* parser, enum centijson_automaton automaton)
{
    memcpy(&parser->value_pos, &parser->pos, sizeof(JSON_INPUT_POS));

    parser->automaton = automaton;
    parser->substate = 0;
    parser->buf_used = 0;
}

static void
json_process(JSON_PARSER* parser, JSON_TYPE type, const unsigned char* data, size_t size)
{
    if(parser->errcode < 0)
        WOLFSENTRY_RETURN_VOID;

    if(type != JSON_ARRAY_END  &&  type != JSON_OBJECT_END) {
        if(parser->value_counter == 0) {
            switch(type) {
                case JSON_NULL:
                    if(parser->config.flags & JSON_NONULLASROOT)
                        json_raise_for_value(parser, JSON_ERR_BADROOTTYPE);
                    break;
                case JSON_FALSE:
                case JSON_TRUE:
                    if(parser->config.flags & JSON_NOBOOLASROOT)
                        json_raise_for_value(parser, JSON_ERR_BADROOTTYPE);
                    break;
                case JSON_NUMBER:
                    if(parser->config.flags & JSON_NONUMBERASROOT)
                        json_raise_for_value(parser, JSON_ERR_BADROOTTYPE);
                    break;
                case JSON_STRING:
                    if(parser->config.flags & JSON_NOSTRINGASROOT)
                        json_raise_for_value(parser, JSON_ERR_BADROOTTYPE);
                    break;
                case JSON_ARRAY_BEG:
                    if(parser->config.flags & JSON_NOARRAYASROOT)
                        json_raise_for_value(parser, JSON_ERR_BADROOTTYPE);
                    break;
                case JSON_OBJECT_BEG:
                    if(parser->config.flags & JSON_NOOBJECTASROOT)
                        json_raise_for_value(parser, JSON_ERR_BADROOTTYPE);
                    break;
                default:
                    break;
            }

            if(parser->errcode < 0)
                return;
        }

        if(parser->config.max_total_values != 0  &&
           parser->value_counter >= parser->config.max_total_values)
        {
            json_raise_for_value(parser, JSON_ERR_MAXTOTALVALUES);
            return;
        }
        parser->value_counter++;
    }

    parser->errcode = parser->callbacks.process(type, data, size, parser->user_data);

    /* Update what the main automaton may see next. */
    switch(type) {
        case JSON_ARRAY_BEG:
            parser->state = CAN_SEE_VALUE | CAN_SEE_CLOSER;
            break;

        case JSON_OBJECT_BEG:
            parser->state = CAN_SEE_KEY | CAN_SEE_CLOSER;
            break;

        case JSON_KEY:
            parser->state = CAN_SEE_COLON;
            break;

        default:
            if(parser->nesting_level > 0)
                parser->state = CAN_SEE_COMMA | CAN_SEE_CLOSER;
            else
                parser->state = CAN_SEE_EOF;
            break;
    }

    json_switch_automaton(parser, AUTOMATON_MAIN);

    WOLFSENTRY_RETURN_VOID;
}

static int
json_buf_append(JSON_PARSER* parser, const unsigned char* data, size_t size)
{
    if(parser->buf_used + size > parser->buf_alloced) {
        unsigned char* new_buf;
        size_t new_alloced = (parser->buf_used + size) * 2;

        new_buf = (unsigned char *)realloc(parser->buf, new_alloced);
        if(new_buf == NULL) {
            json_raise(parser, JSON_ERR_OUTOFMEMORY);
            WOLFSENTRY_RETURN_VALUE(-1);
        }

        parser->buf = new_buf;
        parser->buf_alloced = new_alloced;
    }

    memcpy(parser->buf + parser->buf_used, data, size);
    parser->buf_used += size;
    return 0;
}

static int
json_buf_append_codepoint(JSON_PARSER* parser, uint32_t codepoint)
{
    unsigned char tmp[4];
    size_t n;

    if(codepoint <= 0x7f) {
        tmp[0] = (unsigned char)codepoint;
        n = 1;
    } else if(codepoint <= 0x7ff) {
        tmp[0] = (unsigned char)(0xc0 | ((codepoint >> 6) & 0x1f));
        tmp[1] = (unsigned char)(0x80 | ((codepoint >> 0) & 0x3f));
        n = 2;
    } else if(codepoint <= 0xffff) {
        tmp[0] = (unsigned char)(0xe0 | ((codepoint >> 12) & 0x0f));
        tmp[1] = (unsigned char)(0x80 | ((codepoint >> 6) & 0x3f));
        tmp[2] = (unsigned char)(0x80 | ((codepoint >> 0) & 0x3f));
        n = 3;
    } else {
        tmp[0] = (unsigned char)(0xf0 | ((codepoint >> 18) & 0x07));
        tmp[1] = (unsigned char)(0x80 | ((codepoint >> 12) & 0x3f));
        tmp[2] = (unsigned char)(0x80 | ((codepoint >> 6) & 0x3f));
        tmp[3] = (unsigned char)(0x80 | ((codepoint >> 0) & 0x3f));
        n = 4;
    }

    return json_buf_append(parser, tmp, n);
}


/* Assuming ASCII compatibility here. */
#define IS_IN(ch, ch_min, ch_max)   ((unsigned char)(ch_min) <= (unsigned char)(ch) && (unsigned char)(ch) <= (unsigned char)(ch_max))
#define IS_WHITESPACE(ch)           ((ch) == ' ' || (ch) == '\t' || (ch) == '\r' || (ch) == '\n')
#define IS_CONTROL(ch)              ((unsigned char)(ch) <= 31)
#define IS_PUNCT(ch)                (IS_IN(ch, 33, 47) || IS_IN(ch, 58, 64) || IS_IN(ch, 91, 96) || IS_IN(ch, 123, 126))
#define IS_TOKEN_BOUNDARY(ch)       (IS_WHITESPACE(ch) || IS_CONTROL(ch) || IS_PUNCT(ch))
#define IS_ASCII(ch)                ((unsigned char)(ch) <= 127)
#define IS_DIGIT(ch)                (IS_IN(ch, '0', '9'))
#define IS_XDIGIT(ch)               (IS_DIGIT(ch) || IS_IN(ch, 'a', 'f') || IS_IN(ch, 'A', 'F'))

#define IS_HI_SURROGATE(codepoint)  (0xd800 <= (codepoint)  &&  (codepoint) <= 0xdbff)
#define IS_LO_SURROGATE(codepoint)  (0xdc00 <= (codepoint)  &&  (codepoint) <= 0xdfff)


static size_t
json_literal_automaton(JSON_PARSER* parser, const unsigned char* input, size_t size,
                       JSON_TYPE type, const char* literal, size_t literal_size)
{
    size_t off = 0;

    /* In this automaton, we use substate as a character count of the literal
     * we have already seen. */
    while(parser->substate < literal_size  &&  off < size) {
        int ch = input[off];

        if(ch != literal[parser->substate]) {
            json_raise_for_value(parser, JSON_ERR_SYNTAX);
            return 0;
        }

        off++;
        parser->pos.offset++;
        parser->pos.column_number++;
        parser->substate++;
    }

    /* Check the literal is really complete and there is not some unexpected
     * tail. (If so, we want to raise the problem for whole literal. */
    if(off < size  &&  !IS_TOKEN_BOUNDARY(input[off])) {
        memcpy(&parser->pos, &parser->value_pos, sizeof(JSON_INPUT_POS));
        json_raise(parser, JSON_ERR_SYNTAX);
    } else if(input == NULL  /* EOF */  ||
       (off < size  &&  IS_TOKEN_BOUNDARY(input[off]))) {
        json_process(parser, type, NULL, 0);
    }
    return off;
}

static size_t
json_number_automaton(JSON_PARSER* parser, const unsigned char* input, size_t size)
{
    static const unsigned can_see_m_sign        = 0x0001;   /* Mantissa */
    static const unsigned can_see_m_first_digit = 0x0002;
    static const unsigned can_see_m_digit       = 0x0004;
    static const unsigned can_see_f_delimeter   = 0x0010;   /* Fraction */
    static const unsigned can_see_f_digit       = 0x0020;
    static const unsigned can_see_e_delim       = 0x0100;   /* Exponent */
    static const unsigned can_see_e_sign        = 0x0200;
    static const unsigned can_see_e_digit       = 0x0400;
    static const unsigned can_see_end           = 0x1000;   /* End of number */

    size_t off = 0;
    size_t max_len = parser->config.max_number_len;

    if(max_len != 0  &&  parser->pos.offset - parser->value_pos.offset + size > max_len)
        size = max_len - (parser->pos.offset - parser->value_pos.offset) + 1;

    if(parser->substate == 0)
        parser->substate = can_see_m_sign | can_see_m_first_digit;

    while(off < size) {
        int ch = input[off];

        if((parser->substate & can_see_m_sign)  &&  ch == '-') {    /* '+' not allowed here. */
            parser->substate = can_see_m_first_digit;
        } else if((parser->substate & can_see_m_first_digit)  &&  IS_DIGIT(ch)) {
            parser->substate = can_see_m_digit | can_see_f_delimeter | can_see_e_delim | can_see_end;
            /* There cannot be any follow-up digit if mantissa begins with zero. */
            if(ch == '0')
                parser->substate &= ~can_see_m_digit;
        } else if((parser->substate & can_see_m_digit)  &&  IS_DIGIT(ch)) {
            parser->substate = can_see_m_digit | can_see_f_delimeter | can_see_e_delim | can_see_end;
        } else if((parser->substate & can_see_f_delimeter)  &&  ch == '.') {
            parser->substate = can_see_f_digit;
        } else if((parser->substate & can_see_f_digit)  &&  IS_DIGIT(ch)) {
            parser->substate = can_see_f_digit | can_see_e_delim | can_see_end;
        } else if((parser->substate & can_see_e_delim)  &&  (ch == 'e' || ch == 'E')) {
            parser->substate = can_see_e_sign | can_see_e_digit;
        } else if((parser->substate & can_see_e_sign)  &&  (ch == '+' || ch == '-')) {
            parser->substate = can_see_e_digit;
        } else if((parser->substate & can_see_e_digit)  &&  IS_DIGIT(ch)) {
            parser->substate = can_see_e_digit | can_see_end;
        } else if((parser->substate & can_see_end)  &&  IS_TOKEN_BOUNDARY(ch)) {
            /* Success. */
            if(parser->buf_used == 0) {
                json_process(parser, JSON_NUMBER, input, off);
            } else {
                if(json_buf_append(parser, input, off) < 0)
                    return 0;
                json_process(parser, JSON_NUMBER, parser->buf, parser->buf_used);
            }
            return off;
        } else {
            json_raise_for_value(parser, JSON_ERR_SYNTAX);
            return 0;
        }

        off++;
        parser->pos.offset++;
        parser->pos.column_number++;
    }

    if(max_len != 0  &&  parser->pos.offset - parser->value_pos.offset > max_len)
        json_raise_for_value(parser, JSON_ERR_MAXNUMBERLEN);

    if(input == NULL) {       /* EOF */
        if(parser->errcode >= 0  &&  (parser->substate & can_see_end))
            json_process(parser, JSON_NUMBER, parser->buf, parser->buf_used);
        else
            json_raise_for_value(parser, JSON_ERR_SYNTAX);
    } else {
        if((parser->errcode >= 0) && (off > 0)) {
            if(json_buf_append(parser, input, off) < 0)
                return 0;
        }
    }

    return off;
}

static inline unsigned
json_resolve_xdigit(unsigned char ch)
{
    if(IS_DIGIT(ch))
        return (unsigned)ch - (unsigned)'0';
    else if(IS_IN(ch, 'a', 'f'))
        return (unsigned)ch - (unsigned)'a' + 10U;
    else
        return (unsigned)ch - (unsigned)'A' + 10U;
}

/* U+fffd (Unicode replacement character), encoded in UTF-8.
 *
 * Note we sometimes need to use three, if we meet incorrect "\uABCD" escape
 * sequence corresponding to an orphan surrogate, due the "best practice" of
 * replacement character usage recommended in Unicode 10 standard:
 *
 * (Every orphan surrogate would be, in UTF-8, encoded as an 3-byte sequence.
 * The first (leading) byte forms longest good subsequence replaced by single
 * U+fffd. The two trailing bytes, who cannot really follow in well-formed
 * UTF-8, then are replaced with U+fffd each too.)
 */
static const unsigned char fffd[9] = { 0xef, 0xbf, 0xbd, 0xef, 0xbf, 0xbd, 0xef, 0xbf, 0xbd };
static const size_t fffd_size = 3;

static int
json_handle_ill_surrogate(JSON_PARSER* parser, uint32_t codepoint, int ignore, int fix)
{
    if(ignore)
        return json_buf_append_codepoint(parser, codepoint);

    if(fix)
        return json_buf_append(parser, fffd, 3 * fffd_size);

    json_raise(parser, JSON_ERR_INVALIDUTF8);
    return -1;
}

static size_t
json_string_automaton(JSON_PARSER* parser, const unsigned char* input, size_t size,
                      JSON_TYPE type)
{
    int ignore_ill_utf8;
    int fix_ill_utf8;
    size_t max_len;
    size_t off = 0;

    if(type == JSON_KEY) {
        ignore_ill_utf8 = (parser->config.flags & JSON_IGNOREILLUTF8KEY);
        fix_ill_utf8 = (parser->config.flags & JSON_FIXILLUTF8KEY);
        max_len = parser->config.max_key_len;
    } else {
        ignore_ill_utf8 = (parser->config.flags & JSON_IGNOREILLUTF8VALUE);
        fix_ill_utf8 = (parser->config.flags & JSON_FIXILLUTF8VALUE);
        max_len = parser->config.max_string_len;
    }

    if(max_len > 0)
        max_len++;  /* +1 for the final quotes. */

    if(max_len != 0  &&  parser->pos.offset - parser->value_pos.offset + size > max_len)
        size = max_len - (parser->pos.offset - parser->value_pos.offset) + 1;

    while(off < size) {
        unsigned char ch = input[off];

        if(parser->substate == 0) {
            if(ch == '\"') {
                /* End of string. */
                off++;
                parser->pos.offset++;
                parser->pos.column_number++;
                json_process(parser, type, parser->buf, parser->buf_used);
                break;
            } else if(IS_CONTROL(ch)) {
                /* Unescaped control char. */
                if(ch == '\r' || ch == '\n')
                    json_raise_for_value(parser, JSON_ERR_UNCLOSEDSTRING);
                else
                    json_raise(parser, JSON_ERR_UNESCAPEDCONTROL);
                break;
            } else if(ch == '\\') {
                /* Start of an escape sequence. */
                parser->substate = '\\';
            } else if(IS_ASCII(ch)  ||  ignore_ill_utf8) {
                /* ASCII char which needs no special care.
                 *
                 * This is likely the most common case. Use tight loop to
                 * handle as many chars as possible. */
                size_t off2 = off+1;
                while(off2 < size  &&  IS_ASCII(input[off2])  &&  !IS_CONTROL(input[off2])
                         &&  input[off2] != '\\'  &&  input[off2] != '\"')
                    off2++;

                /* Do we have complete simple string?
                 * Then we can just process it without using temp. buffer. */
                if(parser->buf_used + off == 0  &&  off2 < size  &&  input[off2] == '\"') {
                    parser->pos.offset += off2 + 1;
                    parser->pos.column_number += (unsigned)(off2 + 1);
                    off = off2 + 1;
                    json_process(parser, type, input, off2);
                    break;
                }

                if(json_buf_append(parser, input + off, off2 - off) < 0)
                    break;
                parser->pos.offset += off2 - off;
                parser->pos.column_number += (unsigned)(off2 - off);
                off = off2;
                continue;
            } else {
                /* Should be leading byte of multi-byte UTF-8 encoded character.
                 *
                 * Well-Formed UTF-8 Byte Sequences
                 * (From Unicode Standard 10.0, Table 3-7):
                 *
                 * | First Byte  | Second Byte | Third Byte  | Fourth Byte |
                 * |-------------|-------------|-------------|-------------|
                 * | 0x00...0x7f |    (ASCII: handled specially above)     |
                 * | 0xc2...0xdf | 0x80...0xbf |             |             |
                 * | 0xe0        | 0xa0...0xbf | 0x80...0xbf |             |
                 * | 0xe1...0xec | 0x80...0xbf | 0x80...0xbf |             |
                 * | 0xed        | 0x80...0x9f | 0x80...0xbf |             |
                 * | 0xee...0xef | 0x80...0xbf | 0x80...0xbf |             |
                 * | 0xf0        | 0x90...0xbf | 0x80...0xbf | 0x80...0xbf |
                 * | 0xf1...0xf3 | 0x80...0xbf | 0x80...0xbf | 0x80...0xbf |
                 * | 0xf4        | 0x80...0x8f | 0x80...0xbf | 0x80...0xbf |
                 *
                 * Note this table implicitly handles all the ill-formed stuff,
                 * i.e. code points encoded in an "over-long" way; as well as
                 * those reserved for UTF-16 surrogates.
                 */
                if(IS_IN(ch, 0xc2, 0xdf)) {
                    parser->substate = 1;
                } else if((unsigned char) ch == 0xe0) {
                    parser->substate = 4;
                } else if(IS_IN(ch, 0xe1, 0xec)) {
                    parser->substate = 2;
                } else if((unsigned char) ch == 0xed) {
                    parser->substate = 5;
                } else if(IS_IN(ch, 0xee, 0xef)) {
                    parser->substate = 2;
                } else if((unsigned char) ch == 0xf0) {
                    parser->substate = 6;
                } else if(IS_IN(ch, 0xf1, 0xf3)) {
                    parser->substate = 3;
                } else if((unsigned char) ch == 0xf4) {
                    parser->substate = 7;
                } else if(fix_ill_utf8) {
                    if(json_buf_append(parser, fffd, fffd_size) < 0)
                        break;
                } else {
                    json_raise(parser, JSON_ERR_INVALIDUTF8);
                    break;
                }

                if(parser->substate != 0) {
                    if(json_buf_append(parser, &ch, 1) < 0)
                        break;
                }
            }
        } else if(parser->substate <= 7) {
            /* Should be trailing UTF-8 byte. */
            if(parser->substate <= 3  &&  ((unsigned char)(ch) & 0xc0) == 0x80) {
                parser->substate--;
            } else if(parser->substate == 4  &&  IS_IN(ch, 0xa0, 0xbf)) {
                parser->substate = 1;
            } else if(parser->substate == 5  &&  IS_IN(ch, 0x80, 0x9f)) {
                parser->substate = 1;
            } else if(parser->substate == 6  &&  IS_IN(ch, 0x90, 0xbf)) {
                parser->substate = 2;
            } else if(parser->substate == 7  &&  IS_IN(ch, 0x80, 0x8f)) {
                parser->substate = 2;
            } else if(fix_ill_utf8) {
                /* From Unicode Standard 10.0, best practice for ill-formed
                 * UTF-8 sequence:
                 *
                 * > Whenever an unconvertible offset is reached during
                 * > conversion of a code unit sequence:
                 * >  1. The maximal subpart at that offset should be replaced
                 * >     by a single U+fffd.
                 * >  2. The conversion should proceed at the offset immediately
                 * >     after the maximal subpart.
                 *
                 * I.e. we want to emit U+fffd instead of the incorrect sequence
                 * BEFORE the current offset, because current byte is something
                 * different then the predecessor expected.
                 *
                 * I.e. we have to go back to the previous leading byte
                 * (including it).
                 */
                while(((unsigned char)(parser->buf[parser->buf_used-1]) & 0xc0) == 0x80)
                    parser->buf_used--; /* Cancel all the trailing bytes. */
                parser->buf_used--;     /* Cancel the leading byte. */
                if(json_buf_append(parser, fffd, fffd_size) < 0)
                    break;

                /* And now we have to replay the current byte in state == 0
                 * because it may be ASCII or correct leading byte of the
                 * following character or something. */
                parser->substate = 0;
                continue;
            } else {
                json_raise(parser, JSON_ERR_INVALIDUTF8);
                break;
            }

            if(json_buf_append(parser, &ch, 1) < 0)
                break;
        } else if(parser->substate == '\\') {
            /* Handle 2nd character of an escape sequence. */
            if(ch == 'u') {
                /* Expecting 4 hex digits. */
                parser->substate = 0xabcd + 4;
            } else {
                switch(ch) {
                    case '\"':  ch = '\"'; break;
                    case '\\':  ch = '\\'; break;
                    case '/':   ch = '/'; break;
                    case 'b':   ch = '\b'; break;
                    case 'f':   ch = '\f'; break;
                    case 'n':   ch = '\n'; break;
                    case 'r':   ch = '\r'; break;
                    case 't':   ch = '\t'; break;
                    default:    json_raise(parser, JSON_ERR_INVALIDESCAPE); return off;
                }

                if(json_buf_append(parser, &ch, 1) < 0)
                    break;
                parser->substate = 0;
            }
        } else if(parser->substate > 0xabcd) {
            /* Handle body of the '\uABCD' style escape.
             *
             * This is quite complex because JSON standard allows either
             * any non-surrogate codepoint <= U+ffff or two long escapes
             * forming UTF-16 surrogate pair for codepoints > U+ffff.
             *
             * Naturally, surrogate codepoints not forming the pair (e.g.
             * orphan or two hi surrogates) make ill-formed UTF-8 string.
             */
            if(!IS_XDIGIT(ch)) {
                json_raise(parser, JSON_ERR_INVALIDESCAPE);
                return off;
            }

            parser->codepoint[1] <<= 4;
            parser->codepoint[1] |= json_resolve_xdigit(ch);
            parser->substate--;

            if(parser->substate == 0xabcd) {
                /* We have completed the long escape. */
                if(parser->codepoint[0] != 0  &&  !IS_LO_SURROGATE(parser->codepoint[1])) {
                    /* parser->codepoint[0] is unexpected high surrogate. */
                    if(json_handle_ill_surrogate(parser, parser->codepoint[0], ignore_ill_utf8, fix_ill_utf8) < 0)
                        break;

                    /* Propagate below to handle parser->codepoint[1] as if no
                     * high surrogate precedes. */
                    parser->codepoint[0] = 0;
                }

                if(parser->codepoint[0] == 0  &&  IS_LO_SURROGATE(parser->codepoint[1])) {
                    /* parser->codepoint[1] is unexpected low surrogate. */
                    if(json_handle_ill_surrogate(parser, parser->codepoint[1], ignore_ill_utf8, fix_ill_utf8) < 0)
                        break;
                    parser->substate = 0;
                } else if(parser->codepoint[0] != 0  &&  IS_LO_SURROGATE(parser->codepoint[1])) {
                    /* parser->codepoint[0] & [1] form valid surrogate pair. */
                    uint32_t hi = parser->codepoint[0];
                    uint32_t lo = parser->codepoint[1];
                    uint32_t codepoint = 0x10000 + (hi - 0xd800) * 0x400 + (lo - 0xdc00);
                    if(json_buf_append_codepoint(parser, codepoint) < 0)
                        break;
                    parser->substate = 0;
                    parser->codepoint[0] = 0;
                    parser->codepoint[1] = 0;
                } else if(IS_HI_SURROGATE(parser->codepoint[1])) {
                    /* parser->codepoint[1] is high surrogate. Store it and we
                     * see later if low surrogate follows. */
                    parser->codepoint[0] = parser->codepoint[1];
                    parser->substate = 0xabcd - 2;
                } else {
                    /* parser->codepoint[1] is non-surrogate codepoint. */
                    if(json_buf_append_codepoint(parser, parser->codepoint[1]) < 0)
                        break;
                    parser->substate = 0;
                }

                parser->codepoint[1] = 0;
            }
        } else if(parser->substate >= 0xabcd - 2) {
            /* We are just after high surrogate and expect another long escape,
             * this time for the low surrogate. */
            if(parser->substate == 0xabcd - 2  &&  ch == '\\') {
                parser->substate = 0xabcd - 1;
            } else if(parser->substate == 0xabcd - 1  &&  ch == 'u') {
                parser->substate = 0xabcd + 4;
            } else {
                if(json_handle_ill_surrogate(parser, parser->codepoint[0], ignore_ill_utf8, fix_ill_utf8) < 0)
                    break;

                /* Replay the current byte as if no high surrogate precedes. */
                parser->codepoint[0] = 0;
                parser->substate = (parser->substate == 0xabcd - 1) ? '\\' : 0;
                continue;
            }
        } else {
            json_raise(parser, JSON_ERR_INTERNAL);
            break;
        }

        off++;
        parser->pos.offset++;
        parser->pos.column_number++;
    }

    if(max_len != 0  &&  parser->pos.offset - parser->value_pos.offset > max_len)
        json_raise_for_value(parser, (type == JSON_KEY)
                    ? JSON_ERR_MAXKEYLEN : JSON_ERR_MAXSTRINGLEN);

    if(input == NULL)   /* EOF */
        json_raise_for_value(parser, JSON_ERR_UNCLOSEDSTRING);

    return off;
}

static size_t
json_dispatch(JSON_PARSER* parser, const unsigned char* input, size_t size)
{
    switch(parser->automaton) {
        case AUTOMATON_NULL:    return json_literal_automaton(parser, input, size, JSON_NULL, "null", 4);
        case AUTOMATON_FALSE:   return json_literal_automaton(parser, input, size, JSON_FALSE, "false", 5);
        case AUTOMATON_TRUE:    return json_literal_automaton(parser, input, size, JSON_TRUE, "true", 4);
        case AUTOMATON_NUMBER:  return json_number_automaton(parser, input, size);
        case AUTOMATON_STRING:  return json_string_automaton(parser, input, size, JSON_STRING);
        case AUTOMATON_KEY:     return json_string_automaton(parser, input, size, JSON_KEY);
        case AUTOMATON_MAIN:    break;
    }

    json_raise(parser, JSON_ERR_INTERNAL);
    return 0;
}

static void
json_handle_new_line(JSON_PARSER* parser, unsigned char ch)
{
    if(ch == '\r') {
        parser->last_cl_offset = parser->pos.offset;
        parser->pos.line_number++;
        parser->pos.column_number = FIRST_COLUMN_NUMBER - 1;
    } else if(ch == '\n') {
        if(!(parser->pos.offset == parser->last_cl_offset + 1))
            parser->pos.line_number++;
        parser->pos.column_number = FIRST_COLUMN_NUMBER - 1;
    }
}

WOLFSENTRY_API int
json_feed(JSON_PARSER* parser, const unsigned char* input, size_t size)
{
    size_t off = 0;
    unsigned char ch;

    if(parser->config.max_total_len != 0  &&
       parser->pos.offset + size > parser->config.max_total_len)
    {
        /* Update parser->pos to point to the exact place. */
        while(parser->pos.offset < parser->config.max_total_len) {
            parser->pos.offset++;
            parser->pos.column_number++;
            off++;
            json_handle_new_line(parser, input[off]);
        }

        json_raise(parser, JSON_ERR_MAXTOTALLEN);
    }

    while(off < size  &&  parser->errcode >= 0) {
        ch = input[off];

        /* If we have active any sub-automaton, let it process the character. */
        if(parser->automaton != AUTOMATON_MAIN) {
            size_t n = json_dispatch(parser, input+off, size-off);

            if(parser->errcode < 0)
                WOLFSENTRY_RETURN_VALUE(parser->errcode);

            off += n;
            continue;
        }

        /* Main automaton. */
        if((parser->state & CAN_SEE_VALUE)  &&  (ch == '[' || ch == '{')) {
            /* Begin of array or object. */
            if(parser->config.max_nesting_level != 0  &&
               parser->nesting_level >= parser->config.max_nesting_level) {
                json_raise(parser, JSON_ERR_MAXNESTINGLEVEL);
                break;
            }

            if(parser->nesting_level >= parser->nesting_stack_size) {
                unsigned char* new_nesting_stack;
                size_t new_nesting_stack_size = parser->nesting_stack_size * 2;

                if(new_nesting_stack_size == 0)
                    new_nesting_stack_size = 32;
                new_nesting_stack = (unsigned char *)realloc(parser->nesting_stack, new_nesting_stack_size);
                if(new_nesting_stack == NULL) {
                    json_raise(parser, JSON_ERR_OUTOFMEMORY);
                    break;
                }

                parser->nesting_stack = new_nesting_stack;
                parser->nesting_stack_size = new_nesting_stack_size;
            }
            parser->nesting_stack[parser->nesting_level++] = (ch == '[') ? ']' : '}';
            json_process(parser, (ch == '[') ? JSON_ARRAY_BEG : JSON_OBJECT_BEG, NULL, 0);
        } else if((parser->state & CAN_SEE_CLOSER)  &&  (ch == ']' || ch == '}')) {
            /* End of array or object. */
            if(parser->nesting_stack[parser->nesting_level-1] != ch) {
                json_raise(parser, JSON_ERR_BADCLOSER);
                break;
            }
            parser->nesting_level--;
            json_process(parser, (ch == ']') ? JSON_ARRAY_END : JSON_OBJECT_END, NULL, 0);
        } else if((parser->state & CAN_SEE_COMMA)  &&  ch == ',') {
            if(parser->nesting_stack[parser->nesting_level - 1] == ']')
                parser->state = CAN_SEE_VALUE;
            else
                parser->state = CAN_SEE_KEY;
        } else if((parser->state & CAN_SEE_COLON)  &&  ch == ':') {
            parser->state = CAN_SEE_VALUE;
        } else if((parser->state & CAN_SEE_VALUE)  &&  ch == '"') {
            json_switch_automaton(parser, AUTOMATON_STRING);
        } else if((parser->state & CAN_SEE_KEY)  &&  ch == '"') {
            json_switch_automaton(parser, AUTOMATON_KEY);
        } else if((parser->state & CAN_SEE_VALUE)  &&
                  (('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z'))) {
            switch(ch) {
                case 'n':   json_switch_automaton(parser, AUTOMATON_NULL); break;
                case 'f':   json_switch_automaton(parser, AUTOMATON_FALSE); break;
                case 't':   json_switch_automaton(parser, AUTOMATON_TRUE); break;
                default:    json_raise(parser, JSON_ERR_SYNTAX); break;
            }
            continue;
        } else if((parser->state & CAN_SEE_VALUE)  &&  (IS_DIGIT(ch) || ch == '-')) {
            json_switch_automaton(parser, AUTOMATON_NUMBER);
            continue;
        } else if(!IS_WHITESPACE(ch)) {
            json_raise_unexpected(parser);
            break;
        }

        /* Advance to next char. */
        off++;
        parser->pos.offset++;
        parser->pos.column_number++;
        json_handle_new_line(parser, ch);
    }

    WOLFSENTRY_RETURN_VALUE(parser->errcode);
}

WOLFSENTRY_API int
json_fini(JSON_PARSER* parser, JSON_INPUT_POS* p_pos)
{
    if (parser->state == PARSER_STATE_UNINITED)
        WOLFSENTRY_RETURN_VALUE(JSON_ERR_NOT_INITED);

    /* Some automaton may need some flushing. */
    if(parser->errcode >= 0) {
        if(parser->automaton != AUTOMATON_MAIN) {
            parser->pos.offset += json_dispatch(parser, NULL, 0);

            if(parser->automaton != AUTOMATON_MAIN) {
                json_raise(parser, JSON_ERR_SYNTAX);
            }
        } else if(parser->nesting_level != 0  ||  !(parser->state & CAN_SEE_EOF)) {
            json_raise_unexpected(parser);
        }
    }

    if(p_pos != NULL) {
        memcpy(p_pos, (parser->errcode >= 0) ? &parser->pos : &parser->err_pos,
                sizeof(JSON_INPUT_POS));
    }

    free(parser->nesting_stack);
    free(parser->buf);
    parser->state = PARSER_STATE_UNINITED;
    WOLFSENTRY_RETURN_VALUE(parser->errcode);
}

WOLFSENTRY_API int
json_parse(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
           const unsigned char* input, size_t size,
           const JSON_CALLBACKS* callbacks, const JSON_CONFIG* config,
           void* user_data, JSON_INPUT_POS* p_pos)
{
    JSON_PARSER parser;
    int ret;

    ret = json_init(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        &parser, callbacks, config, user_data);
    if(ret < 0)
        WOLFSENTRY_RETURN_VALUE(ret);

    /* We rely on propagation of any error code into json_fini(). */
    if (json_feed(&parser, input, size) < 0) {
    }

    WOLFSENTRY_RETURN_VALUE(json_fini(&parser, p_pos));
}



/*****************
 *** Utilities ***
 *****************/

/* Compare numerically strings composed of positive integers. */
static inline int
intstrncmp_pos(const unsigned char* str1, size_t size1, const unsigned char* str2, size_t size2)
{
    if(size1 != size2)
        return (size1 < size2) ? -1 : +1;

    return strncmp((const char *)str1, (const char *)str2, size1);
}

/* Compare numerically strings composed of negative integers. */
static inline int
intstrncmp_neg(const unsigned char* str1, size_t size1, const unsigned char* str2, size_t size2)
{
    return -intstrncmp_pos(str1 + 1, size1 - 1, str2 + 1, size2 - 1);
}

static int
intstrncmp(const unsigned char* str1, size_t size1, const unsigned char* str2, size_t size2)
{
    int is_positive1 = (str1[0] != '-');
    int is_positive2 = (str2[0] != '-');

    if(is_positive1 == is_positive2) {
        if(is_positive1)
            return intstrncmp_pos(str1, size1, str2, size2);
        else
            return intstrncmp_neg(str1, size1, str2, size2);
    } else {
        if(is_positive1)
            return +1;
        else
            return -1;
    }
}

static int
intstr_is_between(const unsigned char* val_str, size_t val_size,
                  const char* min_str, size_t min_size,
                  const char* max_str, size_t max_size)
{
    return (intstrncmp((unsigned char *)min_str, min_size, val_str, val_size) <= 0  &&
            intstrncmp(val_str, val_size, (unsigned char *)max_str, max_size) <= 0);
}

WOLFSENTRY_API int
json_analyze_number(const unsigned char* num, size_t num_size,
                    int* p_is_int32_compatible,
                    int* p_is_uint32_compatible,
                    int* p_is_int64_compatible,
                    int* p_is_uint64_compatible)
{
    static const char int32_min[] =           "-2147483648";
    static const char int32_max[] =            "2147483647";
    static const char uint32_max[] =           "4294967295";
    static const char int64_min[] =  "-9223372036854775808";
    static const char int64_max[] =   "9223372036854775807";
    static const char uint64_max[] = "18446744073709551615";

    int is_int32_compatible = 0;
    int is_uint32_compatible = 0;
    int is_int64_compatible = 0;
    int is_uint64_compatible = 0;


    /* If the string is too long, then either it would overflow any integer
     * type or it contains some fraction and/or exponent part. In such case
     * it's probably good idea to not report it as an integer even when the
     * fraction and the exponent are zeros.
     *
     * And this pre-test is good to avoid scanning for '.' or 'e' in
     * potentially long strings.
     */
    if(num_size <= strlen(uint64_max)) {
        /* JSON syntax allows negative zero integer. Turn it to positive one
         * to simplify the comparison functions. */
        if(num_size == 2  &&  num[0] == '-'  &&  num[1] == '0') {
            num++;
            num_size--;
        }

        if(memchr(num, '.', num_size) == NULL  &&     /* No fraction? */
           memchr(num, 'e', num_size) == NULL  &&     /* No exponent? */
           memchr(num, 'E', num_size) == NULL)
        {
            if(intstr_is_between(num, num_size, int32_min, strlen(int32_min), int32_max, strlen(int32_max)))
                is_int32_compatible = 1;
            if(intstr_is_between(num, num_size, "0", 1, uint32_max, strlen(uint32_max)))
                is_uint32_compatible = 1;
            if(intstr_is_between(num, num_size, int64_min, strlen(int64_min), int64_max, strlen(int64_max)))
                is_int64_compatible = 1;
            if(intstr_is_between(num, num_size, "0", 1, uint64_max, strlen(uint64_max)))
                is_uint64_compatible = 1;
        }
    }

    if(p_is_int32_compatible != NULL)
        *p_is_int32_compatible = is_int32_compatible;
    if(p_is_uint32_compatible != NULL)
        *p_is_uint32_compatible = is_uint32_compatible;
    if(p_is_int64_compatible != NULL)
        *p_is_int64_compatible = is_int64_compatible;
    if(p_is_uint64_compatible != NULL)
        *p_is_uint64_compatible = is_uint64_compatible;

    return 0;
}

WOLFSENTRY_API int32_t
json_number_to_int32(const unsigned char* num, size_t num_size)
{
    return (int32_t) json_number_to_int64(num, num_size);
}

WOLFSENTRY_API uint32_t
json_number_to_uint32(const unsigned char* num, size_t num_size)
{
    return (uint32_t) json_number_to_uint64(num, num_size);
}

WOLFSENTRY_API int64_t
json_number_to_int64(const unsigned char* num, size_t num_size)
{
    size_t off = 0;
    int is_neg = 0;
    uint64_t val;

    if(num[off] == '-') {
        is_neg = 1;
        off++;
    }

    val = json_number_to_uint64(num + off, num_size - off);

    if(is_neg) {
        /* Trick to avoid underflow issues if the correct result is INT64_MIN. */
        return -(int64_t)(val - 1) - 1;
    }

    return (int64_t) val;
}

WOLFSENTRY_API uint64_t
json_number_to_uint64(const unsigned char* num, size_t num_size)
{
    size_t off = 0;
    uint64_t val = 0;

    while(off < num_size  &&  IS_DIGIT(num[off])) {
        val *= 10;
        val += num[off++] - (unsigned)'0';
    }

    return val;
}

WOLFSENTRY_API int
json_number_to_double(const unsigned char* num, size_t num_size, double* p_result)
{
#ifdef CENTIJSON_USE_LOCALE
    struct lconv* locale_info;
#endif
    unsigned char local_buffer[64];
    unsigned char* buffer;

    /* Unfortunately, AFAIK, there is no reasonably easy portable way how to
     * construct float or double by hand.
     *
     * The closest to that ideal is likely strtod() function (mandated by
     * the C89/90 standard, so hopefully, it is practically everywhere).
     *
     * However strtod() has (for us) two strong disadvantages we have to deal
     * with.
     *
     * (1) It expects the string is terminated by '\0' which we do not have
     *     here.
     *
     * (2) Instead of decimal period '.', it may expect other character as
     *     specified by the current locale.
     *
     *     That is an issue on its own since, on some platforms a locale is
     *     an attribute of thread; on other platforms it is a an attribute
     *     of process. Some platforms even have some hybrid solution.
     *
     *     This means, we (as a library) cannot afford changing the locale to
     *     "C", even temporarily, as we could easily break multi-threaded
     *     applications.
     *
     * Instead, we create the new string in a temp. buffer following those
     * requirements.
     */

    if(num_size + 1 < sizeof(local_buffer)) {
        /* The number is short enough so we can avoid heap allocation. */
        buffer = local_buffer;
    } else {
#ifdef WOLFSENTRY
            return JSON_ERR_OUTOFMEMORY;
#else        
        buffer = (unsigned char*) malloc(num_size + 1);
        if(buffer == NULL)
            return JSON_ERR_OUTOFMEMORY;
#endif
    }

    /* Make sure the string is zero-terminated. */
    memcpy(buffer, num, num_size);
    buffer[num_size] = '\0';

#ifdef CENTIJSON_USE_LOCALE
    /* Make sure we use the locale-dependent decimal point. */
    locale_info = localeconv();
    if(locale_info->decimal_point[0] != '.') {
        unsigned char* fp;

        fp = strchr(buffer, '.');
        if(fp != NULL)
            *fp = locale_info->decimal_point[0];
    }
#endif

    *p_result = strtod((const char *)buffer, NULL);

#ifndef WOLFSENTRY
    if(buffer != local_buffer)
        free(buffer);
#endif
    return 0;
}


WOLFSENTRY_API int
json_dump_int32(int32_t i32, JSON_DUMP_CALLBACK write_func, void* user_data)
{
    return json_dump_int64(i32, write_func, user_data);
}

WOLFSENTRY_API int
json_dump_uint32(uint32_t u32, JSON_DUMP_CALLBACK write_func, void* user_data)
{
    return json_dump_uint64(u32, write_func, user_data);
}

WOLFSENTRY_API int
json_dump_int64(int64_t i64, JSON_DUMP_CALLBACK write_func, void* user_data)
{
    char buffer[32];
    size_t off = sizeof(buffer);
    int is_neg = (i64 < 0);

    if(i64 != 0) {
        while(i64 != 0) {
            buffer[--off] = (char)('0' + ABS(i64 % 10));
            i64 /= 10;
        }

        if(is_neg)
            buffer[--off] = '-';
    } else {
        buffer[--off] = '0';
    }

    return write_func((const unsigned char *)buffer + off, sizeof(buffer) - off, user_data);
}

WOLFSENTRY_API int
json_dump_uint64(uint64_t u64, JSON_DUMP_CALLBACK write_func, void* user_data)
{
    char buffer[32];
    size_t off = sizeof(buffer);

    if(u64 != 0) {
        while(u64 != 0) {
            buffer[--off] = (char)('0' + (u64 % 10));
            u64 /= 10;
        }
    } else {
        buffer[--off] = '0';
    }

    return write_func((const unsigned char *)buffer + off, sizeof(buffer) - off, user_data);
}

WOLFSENTRY_API int
json_dump_double(double dbl, JSON_DUMP_CALLBACK write_func, void* user_data)
{
#if defined(FREERTOS) || (__STDC_VERSION__ < 199901L)
    static const char fmt[] = "%.16f";
#else
    static const char fmt[] = "%.16lg";
#endif
    static const size_t extra_bytes = 2;    /* Space reserved for ".0" */
#ifdef CENTIJSON_USE_LOCALE
    struct lconv* locale_info;
#endif
    int n;
    char local_buffer[64];
    size_t capacity = sizeof(local_buffer) - extra_bytes;
    char* buffer = local_buffer;
#ifndef WOLFSENTRY
    char* new_buffer;
#endif
    char* fp;
    int ret;

    while(1) {
        n = snprintf(buffer, capacity, fmt, dbl);
        if(n >= 0  &&  (size_t)n < capacity)
            break;

#ifdef WOLFSENTRY
        return JSON_ERR_OUTOFMEMORY;
#else
        /* If the buffer is insufficient, old snprintf() implementations
         * only report the buffer is too small and don't tell how large
         * the buffer has to be. So lets grow the buffer until it is large
         * enough. */
        if(n < 0)
            capacity *= 2;
        else
            capacity = n + 1;

        /* Make the terrain safe for realloc(). */
        if(buffer == local_buffer)
            buffer = NULL;

        new_buffer = (char *) realloc(buffer, capacity + extra_bytes);
        if(new_buffer == NULL) {
            free(buffer);
            return JSON_ERR_OUTOFMEMORY;
        }
        buffer = new_buffer;
#endif
    }

#ifdef CENTIJSON_USE_LOCALE
    /* Similar pain as above for strtod(). We need to fight with snprintf() and
     * undo the locale-dependent stuff. */
    locale_info = localeconv();

    /* Remove all potential locale-provided thousand separators. */
    if(locale_info->thousands_sep != NULL  &&  locale_info->thousands_sep[0]) {
        char* sep = locale_info->thousands_sep;
        size_t sep_len = strlen(sep);
        unsigned char* ptr = buffer;

        while(1) {
            ptr = strstr(ptr, sep);
            if(ptr == NULL)
                break;

            memmove(ptr, ptr + sep_len, n - (ptr - buffer));
            n -= sep_len;
        }
    }

    /* Replace the locale-provided decimal point with '.'. */
    fp = strchr(buffer, locale_info->decimal_point[0]);
    if(fp != NULL) {
        *fp = '.';
#else
    fp = strchr(buffer, ',');
    if(fp != NULL) {
        *fp = '.';
    } else if (strchr(buffer, '.') != NULL) {
        /* do nothing */
#endif

    } else if(strchr(buffer, 'e') == NULL) {
        /* There is no decimal point present and also no 'e', i.e. it's not
         * in the scientific notation, i.e. it looks too much as an integer
         * if we ever re-read the value back.
         *
         * For the sake of consistency, let's make sure that, if we ever
         * re-read the string again, we shall map it to double again, by
         * appending the decimal point.
         *
         * We may do this safely: We reserved few bytes in the buffer exactly
         * for this purpose.
         */
        memcpy(buffer + n, ".0", 2); /* NOLINT(bugprone-not-null-terminated-result) */
        n += 2;
    }

    ret = write_func((const unsigned char *)buffer, (size_t)n, user_data);

#ifndef WOLFSENTRY
    if(buffer != local_buffer)
        free(buffer);
#endif
    return ret;
}

static void
json_control_to_hex(char* buf, uint8_t ch)
{
    static const char xdigits[] = "0123456789ABCDEF";

    buf[0] = '\\';
    buf[1] = 'u';
    buf[2] = '0';
    buf[3] = '0';
    buf[4] = xdigits[((ch >> 4) & 0xf)];
    buf[5] = xdigits[(ch & 0xf)];
}

WOLFSENTRY_API int
json_dump_string(const unsigned char* str, size_t size, JSON_DUMP_CALLBACK write_func, void* user_data)
{
    size_t off = 0;
    int ret;

    ret = write_func((const unsigned char *)"\"", 1, user_data);
    if(ret < 0)
        return ret;

    while(off < size) {
        unsigned char ch = str[off];

        if(IS_CONTROL(ch)  ||  ch == '\"'  ||  ch == '\\') {
            char esc_buffer[8];
            const char* esc;
            size_t esc_size;

            switch(ch) {
                case '\"':  esc = "\\\""; esc_size = 2; break;
                case '\\':  esc = "\\\\"; esc_size = 2; break;
                case '\b':  esc = "\\b"; esc_size = 2; break;
                case '\f':  esc = "\\f"; esc_size = 2; break;
                case '\n':  esc = "\\n"; esc_size = 2; break;
                case '\r':  esc = "\\r"; esc_size = 2; break;
                case '\t':  esc = "\\t"; esc_size = 2; break;

                default:
                    json_control_to_hex(esc_buffer, ch);
                    esc = esc_buffer;
                    esc_size = 6;
                    break;
            }

            ret = write_func((const unsigned char *)esc, esc_size, user_data);
            if(ret < 0)
                return ret;

            off++;
        } else {
            size_t off2 = off + 1;

            /* Tight loop for non-control characters. */
            while(off2 < size  &&  !IS_CONTROL(str[off2])  &&  str[off2] != '\"'  &&  str[off2] != '\\')
                off2++;

            ret = write_func(str + off, off2 - off, user_data);
            if(ret < 0)
                return ret;

            off = off2;
        }
    }

    ret = write_func((const unsigned char *)"\"", 1, user_data);
    if(ret < 0)
        return ret;

    return 0;
}

WOLFSENTRY_API const char* json_error_str(int err_code)
{
    static const char unexpected_code[] = "Unexpected error code";
    static const char *const errs[] =
    {
        "Success", /* JSON_ERR_SUCCESS 0 */
        "Internal error", /* JSON_ERR_INTERNAL (-1) */
        "Out of memory", /* JSON_ERR_OUTOFMEMORY (-2) */
        unexpected_code,
        "Syntax error", /* JSON_ERR_SYNTAX (-4) */
        "Mismatch in brackets", /* JSON_ERR_BADCLOSER (-5) */
        "Root type not allowed by settings", /* JSON_ERR_BADROOTTYPE (-6) */
        "Expected value", /* JSON_ERR_EXPECTEDVALUE (-7) */
        "Expected key", /* JSON_ERR_EXPECTEDKEY (-8) */
        "Expected value or closer", /* JSON_ERR_EXPECTEDVALUEORCLOSER (-9) */
        "Expected key or closer", /* JSON_ERR_EXPECTEDKEYORCLOSER (-10) */
        "Expected colon", /* JSON_ERR_EXPECTEDCOLON (-11) */
        "Expected comma or closer",  /* JSON_ERR_EXPECTEDCOMMAORCLOSER (-12) */
        "Expected EOF", /* JSON_ERR_EXPECTEDEOF (-13) */
        "Exceeded max document length", /* JSON_ERR_MAXTOTALLEN (-14) */
        "Exceeded max total values", /* JSON_ERR_MAXTOTALVALUES (-15) */
        "Exceeded max nesting level", /* JSON_ERR_MAXNESTINGLEVEL (-16) */
        "Exceeded max number length", /* JSON_ERR_MAXNUMBERLEN (-17) */
        "Exceeded max string length", /* JSON_ERR_MAXSTRINGLEN (-18) */
        "Exceeded max key length", /* JSON_ERR_MAXKEYLEN (-19) */
        "Unclosed string", /* JSON_ERR_UNCLOSEDSTRING (-20) */
        "Unescaped control character", /* JSON_ERR_UNESCAPEDCONTROL (-21) */
        "Invalid escape sequence", /* JSON_ERR_INVALIDESCAPE (-22) */
        "Invalid UTF-8" /* JSON_ERR_INVALIDUTF8 (-23) */
    };
    const int array_size = sizeof errs / sizeof errs[0];
    if(-array_size < err_code && err_code <= 0)
        return errs[-err_code];
    return unexpected_code;
}

WOLFSENTRY_API const char* json_type_str(JSON_TYPE type)
{
    switch (type) {
    case JSON_NULL: return "NULL";
    case JSON_FALSE: return "FALSE";
    case JSON_TRUE: return "TRUE";
    case JSON_NUMBER: return "NUMBER";
    case JSON_STRING: return "STRING";
    case JSON_KEY: return "KEY";
    case JSON_ARRAY_BEG: return "ARRAY_BEG";
    case JSON_ARRAY_END: return "ARRAY_END";
    case JSON_OBJECT_BEG: return "OBJECT_BEG";
    case JSON_OBJECT_END: return "OBJECT_END";
    }
    return "Unexpected type";
}
