/*
 * centijson_dom.h
 *
 * Copyright (C) 2022-2025 wolfSSL Inc.
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

#ifndef JSON_DOM_H
#define JSON_DOM_H

#include "wolfsentry/centijson_sax.h"
#include "wolfsentry/centijson_value.h"

#ifdef __cplusplus
extern "C" {
#endif


/* DOM-specific error codes
 *
 * The DOM paring functions can return any from json.h and additionally these.
 */
#define JSON_DOM_ERR_DUPKEY             (-1000)


/* Flags for json_dom_init()
 */

/* Policy how to deal if the JSON contains object with duplicate key: */
#define JSON_DOM_DUPKEY_ABORT           0x0000U
#define JSON_DOM_DUPKEY_USEFIRST        0x0001U
#define JSON_DOM_DUPKEY_USELAST         0x0002U

#define JSON_DOM_DUPKEY_MASK                                            \
            (JSON_DOM_DUPKEY_ABORT | JSON_DOM_DUPKEY_USEFIRST | JSON_DOM_DUPKEY_USELAST)

/* When creating JSON_VALUE_DICT (for JSON_OBJECT), use flag JSON_VALUE_DICT_MAINTAINORDER. */
#define JSON_DOM_MAINTAINDICTORDER      0x0010U

/* Internal use */
#define JSON_DOM_FLAG_INITED            0x8000U

/* Structure holding parsing state. Do not access it directly.
 */
typedef struct JSON_DOM_PARSER {
    JSON_PARSER parser;
    JSON_VALUE** path;
    size_t path_size;
    size_t path_alloc;
    JSON_VALUE root;
    JSON_VALUE key;
    unsigned flags;
    unsigned dict_flags;
} JSON_DOM_PARSER;


/* Used internally by load_config.c:handle_user_value_clause() */
int json_dom_init_1(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_DOM_PARSER* dom_parser, unsigned dom_flags);

/* Used internally by load_config.c:handle_user_value_clause() */
int json_dom_process(JSON_TYPE type, const unsigned char* data, size_t data_size, void* user_data);

/* Used internally by load_config.c:handle_user_value_clause() */
int json_dom_fini_aux(JSON_DOM_PARSER* dom_parser, JSON_VALUE* p_root);

int json_dom_clean(JSON_DOM_PARSER* dom_parser);

/* Initialize the DOM parser structure.
 *
 * The parameter `config` is propagated into json_init().
 */
WOLFSENTRY_API int json_dom_init(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_DOM_PARSER* dom_parser, const JSON_CONFIG* config, unsigned dom_flags);

/* Feed the parser with more input.
 */
WOLFSENTRY_API int json_dom_feed(JSON_DOM_PARSER* dom_parser, const unsigned char* input, size_t size);

/* Finish the parsing and free any resources associated with the parser.
 *
 * On success, zero is returned and the JSON_VALUE pointed by `p_dom` is initialized
 * accordingly to the root of the data in the JSON input (typically array or
 * object), and it contains all the data from the JSON input.
 *
 * On failure, the error code is returned; info about position of the issue in
 * the input is filled in the structure pointed by `p_pos` (if `p_pos` is not
 * NULL and if it is a parsing kind of error); and the value pointed by `p_dom`
 * is initialized to JSON_VALUE_NULL.
 */
WOLFSENTRY_API int json_dom_fini(JSON_DOM_PARSER* dom_parser, JSON_VALUE* p_dom, JSON_INPUT_POS* p_pos);


/* Simple wrapper for json_dom_init() + json_dom_feed() + json_dom_fini(),
 * usable when the provided input contains complete JSON document.
 */
WOLFSENTRY_API int json_dom_parse(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
                   const unsigned char* input, size_t size, const JSON_CONFIG* config,
                   unsigned dom_flags, JSON_VALUE* p_root, JSON_INPUT_POS* p_pos);


/* Dump recursively all the DOM hierarchy out, via the provided writing
 * callback.
 *
 * The provided writing function must write all the data provided to it
 * and return zero to indicate success, or non-zero to indicate an error
 * and abort the operation.
 *
 * Returns zero on success, JSON_ERR_OUTOFMEMORY, or an error the code returned
 * from writing callback.
 */
#define JSON_DOM_DUMP_MINIMIZE          0x0001  /* Do not indent, do not use no extra whitespace including new lines. */
#define JSON_DOM_DUMP_FORCECLRF         0x0002  /* Use "\r\n" instead of just "\n". */
#define JSON_DOM_DUMP_INDENTWITHSPACES  0x0004  /* Indent with `tab_width` spaces instead of with '\t'. */
#define JSON_DOM_DUMP_PREFERDICTORDER   0x0008  /* Prefer original dictionary order, if available. */

WOLFSENTRY_API int json_dom_dump(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
                  const JSON_VALUE* root,
                  JSON_DUMP_CALLBACK write_func, void* user_data,
                  unsigned tab_width, unsigned flags);

WOLFSENTRY_API const char* json_dom_error_str(int err_code);

#ifdef __cplusplus
}  /* extern "C" { */
#endif

#endif  /* JSON_DOM_H */
