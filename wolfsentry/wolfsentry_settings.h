/*
 * wolfsentry_settings.h
 *
 * Copyright (C) 2022-2023 wolfSSL Inc.
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

#ifndef WOLFSENTRY_SETTINGS_H
#define WOLFSENTRY_SETTINGS_H

#ifdef WOLFSENTRY_USER_SETTINGS_FILE
#include WOLFSENTRY_USER_SETTINGS_FILE
#endif

#ifndef BUILDING_LIBWOLFSENTRY
#include <wolfsentry/wolfsentry_options.h>
#endif

#ifdef WOLFSENTRY_C89
    #define WOLFSENTRY_NO_INLINE
    #ifndef WOLFSENTRY_NO_POSIX_MEMALIGN
        #define WOLFSENTRY_NO_POSIX_MEMALIGN
    #endif
    #define WOLFSENTRY_NO_DESIGNATED_INITIALIZERS
    #define WOLFSENTRY_NO_LONG_LONG
    #if !defined(WOLFSENTRY_USE_NONPOSIX_SEMAPHORES) && !defined(WOLFSENTRY_SINGLETHREADED)
        /* sem_timedwait() was added in POSIX 200112L */
        #define WOLFSENTRY_SINGLETHREADED
    #endif
#endif

#ifndef __attribute_maybe_unused__
#if defined(__GNUC__)
#define __attribute_maybe_unused__ __attribute__((unused))
#else
#define __attribute_maybe_unused__
#endif
#endif

#ifdef WOLFSENTRY_NO_INLINE
#define inline __attribute_maybe_unused__
#endif

#ifndef DO_NOTHING
#define DO_NOTHING do {} while (0)
#endif

#ifdef FREERTOS
    #include <FreeRTOS.h>
    #define WOLFSENTRY_CALL_DEPTH_RETURNS_STRING
    #if !defined(WOLFSENTRY_NO_STDIO) && !defined(WOLFSENTRY_PRINTF_ERR)
        #define WOLFSENTRY_PRINTF_ERR(...) printf(__VA_ARGS__)
    #endif

    #define FREERTOS_NANOSECONDS_PER_SECOND     1000000000L
    #define FREERTOS_NANOSECONDS_PER_TICK       (FREERTOS_NANOSECONDS_PER_SECOND / configTICK_RATE_HZ)

    #if !defined(SIZE_T_32) && !defined(SIZE_T_64)
        /* size_t is "unsigned int" in STM32 FreeRTOS */
        #define SIZE_T_32
    #endif
#endif

#ifndef WOLFSENTRY_NO_INTTYPES_H
#include <inttypes.h>
#endif
#ifndef WOLFSENTRY_NO_STDINT_H
#include <stdint.h>
#endif

#if !defined(SIZE_T_32) && !defined(SIZE_T_64)
    #if defined(__WORDSIZE) && (__WORDSIZE == 64)
        #define SIZE_T_64
    #elif defined(INTPTR_MAX) && defined(INT64_MAX) && (INTPTR_MAX == INT64_MAX)
        #define SIZE_T_64
    #elif defined(__WORDSIZE) && (__WORDSIZE == 32)
        #define SIZE_T_32
    #elif defined(INTPTR_MAX) && defined(INT32_MAX) && (INTPTR_MAX == INT32_MAX)
        #define SIZE_T_32
    #else
        #error "must define SIZE_T_32 or SIZE_T_64 with user settings."
    #endif
#elif defined(SIZE_T_32) && defined(SIZE_T_64)
    #error "must define SIZE_T_32 xor SIZE_T_64."
#endif

#if !defined(WOLFSENTRY_NO_STDIO) && !defined(WOLFSENTRY_PRINTF_ERR)
    #define WOLFSENTRY_PRINTF_ERR(...) fprintf(stderr, __VA_ARGS__)
#endif

#ifndef WOLFSENTRY_SINGLETHREADED

#define WOLFSENTRY_THREADSAFE

#ifndef WOLFSENTRY_USE_NONPOSIX_SEMAPHORES
    #if defined(__MACH__) || defined(FREERTOS) || defined(_WIN32)
        #define WOLFSENTRY_USE_NONPOSIX_SEMAPHORES
    #endif
#endif

#ifndef WOLFSENTRY_USE_NONPOSIX_THREADS
    #if defined(FREERTOS) || defined(_WIN32)
        #define WOLFSENTRY_USE_NONPOSIX_THREADS
    #endif
#endif

#ifndef WOLFSENTRY_USE_NONPOSIX_SEMAPHORES
    #define WOLFSENTRY_USE_NATIVE_POSIX_SEMAPHORES
#endif

#ifndef WOLFSENTRY_USE_NONPOSIX_THREADS
    #define WOLFSENTRY_USE_NATIVE_POSIX_THREADS
#endif

#ifndef WOLFSENTRY_HAVE_NONGNU_ATOMICS
    #define WOLFSENTRY_HAVE_GNU_ATOMICS
#endif

#endif /* !WOLFSENTRY_SINGLETHREADED */

#ifndef WOLFSENTRY_NO_CLOCK_BUILTIN
    #define WOLFSENTRY_CLOCK_BUILTINS
#endif

#ifndef WOLFSENTRY_NO_MALLOC_BUILTIN
    #define WOLFSENTRY_MALLOC_BUILTINS
#endif

#ifndef WOLFSENTRY_NO_ERROR_STRINGS
    #define WOLFSENTRY_ERROR_STRINGS
#endif

#ifndef WOLFSENTRY_NO_PROTOCOL_NAMES
    #define WOLFSENTRY_PROTOCOL_NAMES
#endif

#if defined(WOLFSENTRY_USE_NATIVE_POSIX_SEMAPHORES) || defined(WOLFSENTRY_CLOCK_BUILTINS) || defined(WOLFSENTRY_MALLOC_BUILTINS)
#ifndef _XOPEN_SOURCE
#if __STDC_VERSION__ >= 201112L
#define _XOPEN_SOURCE 700
#elif __STDC_VERSION__ >= 199901L
#define _XOPEN_SOURCE 600
#else
#define _XOPEN_SOURCE 500
#endif /* __STDC_VERSION__ */
#endif
#endif

#if !defined(WOLFSENTRY_NO_POSIX_MEMALIGN) && (!defined(_POSIX_C_SOURCE) || (_POSIX_C_SOURCE < 200112L))
    #define WOLFSENTRY_NO_POSIX_MEMALIGN
#endif

#if defined(__STRICT_ANSI__)
#define WOLFSENTRY_FLEXIBLE_ARRAY_SIZE 1
#elif defined(__GNUC__) && !defined(__clang__)
#define WOLFSENTRY_FLEXIBLE_ARRAY_SIZE
#else
#define WOLFSENTRY_FLEXIBLE_ARRAY_SIZE 0
#endif

#ifndef WOLFSENTRY_NO_TIME_H
#ifndef __USE_POSIX199309
/* glibc needs this for struct timespec with -std=c99 */
#define __USE_POSIX199309
#endif
#endif

#ifdef SIZE_T_32
    #define SIZET_FMT "%u"
#elif __STDC_VERSION__ >= 199901L
    #define SIZET_FMT "%zu"
#else
    #define SIZET_FMT "%lu"
#endif

#ifndef WOLFSENTRY_NO_STDDEF_H
#include <stddef.h>
#endif
#ifndef WOLFSENTRY_NO_ASSERT_H
#include <assert.h>
#endif
#ifndef WOLFSENTRY_NO_STDIO
#ifndef __USE_ISOC99
/* kludge to make glibc snprintf() prototype visible even when -std=c89 */
#define __USE_ISOC99
#include <stdio.h>
#undef __USE_ISOC99
#else
#include <stdio.h>
#endif
#endif
#ifndef WOLFSENTRY_NO_STRING_H
#include <string.h>
#endif
#ifndef WOLFSENTRY_NO_STRINGS_H
#include <strings.h>
#endif
#ifndef WOLFSENTRY_NO_TIME_H
#include <time.h>
#endif

#if !defined(WOLFSENTRY_NO_GETPROTOBY) && (!defined(__GLIBC__) || !defined(__USE_MISC) || defined(WOLFSENTRY_C89))
    /* get*by*_r() is non-standard. */
    #define WOLFSENTRY_NO_GETPROTOBY
#endif

typedef unsigned char byte;

typedef uint16_t wolfsentry_addr_family_t;
#include <wolfsentry/wolfsentry_af.h>

typedef uint16_t wolfsentry_proto_t;
typedef uint16_t wolfsentry_port_t;
#ifdef WOLFSENTRY_ENT_ID_TYPE
typedef WOLFSENTRY_ENT_ID_TYPE wolfsentry_ent_id_t;
#else
typedef uint32_t wolfsentry_ent_id_t;
#define WOLFSENTRY_ENT_ID_FMT "%u"
#endif
#define WOLFSENTRY_ENT_ID_NONE 0
typedef uint16_t wolfsentry_addr_bits_t;
#ifdef WOLFSENTRY_HITCOUNT_TYPE
typedef WOLFSENTRY_HITCOUNT_TYPE wolfsentry_hitcount_t;
#else
typedef uint32_t wolfsentry_hitcount_t;
#define WOLFSENTRY_HITCOUNT_FMT "%u"
#endif
#ifdef WOLFSENTRY_TIME_TYPE
typedef WOLFSENTRY_TIME_TYPE wolfsentry_time_t;
#else
typedef int64_t wolfsentry_time_t;
#endif

#ifdef WOLFSENTRY_PRIORITY_TYPE
typedef WOLFSENTRY_PRIORITY_TYPE wolfsentry_priority_t;
#else
typedef uint16_t wolfsentry_priority_t;
#endif

#ifndef attr_align_to
#ifdef __GNUC__
#define attr_align_to(x) __attribute__((aligned(x)))
#elif defined(_MSC_VER)
/* disable align warning, we want alignment ! */
#pragma warning(disable: 4324)
#define attr_align_to(x) __declspec(align(x))
#else
#error must supply definition for attr_align_to() macro.
#endif
#endif

#ifndef __wolfsentry_wur
#ifdef __wur
#define __wolfsentry_wur __wur
#elif defined(__must_check)
#define __wolfsentry_wur __must_check
#elif defined(__GNUC__) && (__GNUC__ >= 4)
#define __wolfsentry_wur __attribute__((warn_unused_result))
#else
#define __wolfsentry_wur
#endif
#endif

#ifndef wolfsentry_static_assert
#if defined(__GNUC__) && defined(static_assert) && !defined(__STRICT_ANSI__)
/* note semicolon included in expansion, so that assert can completely disappear in ISO C builds. */
#define wolfsentry_static_assert(c) static_assert(c, #c);
#define wolfsentry_static_assert2(c, m) static_assert(c, m);
#else
#define wolfsentry_static_assert(c)
#define wolfsentry_static_assert2(c, m)
#endif
#endif /* !wolfsentry_static_assert */

#if defined(WOLFSENTRY_THREADSAFE)

#ifdef WOLFSENTRY_USE_NATIVE_POSIX_SEMAPHORES

#ifndef __USE_XOPEN2K
/* kludge to force glibc sem_timedwait() prototype visible with -std=c99 */
#define __USE_XOPEN2K
#include <semaphore.h>
#undef __USE_XOPEN2K
#else
#include <semaphore.h>
#endif

#elif defined(__MACH__)

#include <dispatch/dispatch.h>
#include <semaphore.h>
#define sem_t dispatch_semaphore_t

#elif defined(FREERTOS)

#include <semphr.h>
#include <atomic.h>

#define SEM_VALUE_MAX        0x7FFFU

#define sem_t StaticSemaphore_t

#else

#error semaphore shim set missing for target

#endif

    #ifdef WOLFSENTRY_THREAD_INCLUDE
        #include WOLFSENTRY_THREAD_INCLUDE
    #elif defined(WOLFSENTRY_USE_NATIVE_POSIX_THREADS)
        #include <pthread.h>
    #endif
    #ifdef WOLFSENTRY_THREAD_ID_T
        typedef WOLFSENTRY_THREAD_ID_T wolfsentry_thread_id_t;
    #elif defined(WOLFSENTRY_USE_NATIVE_POSIX_THREADS)
        typedef pthread_t wolfsentry_thread_id_t;
    #elif defined(FREERTOS)
        typedef TaskHandle_t wolfsentry_thread_id_t;
    #else
        #error Must supply WOLFSENTRY_THREAD_ID_T for WOLFSENTRY_THREADSAFE on non-POSIX targets.
    #endif
    /* note WOLFSENTRY_THREAD_GET_ID_HANDLER must return WOLFSENTRY_THREAD_NO_ID on failure. */
    #ifdef WOLFSENTRY_THREAD_GET_ID_HANDLER
    #elif defined(WOLFSENTRY_USE_NATIVE_POSIX_THREADS)
       #define WOLFSENTRY_THREAD_GET_ID_HANDLER pthread_self
    #elif defined(FREERTOS)
       #define WOLFSENTRY_THREAD_GET_ID_HANDLER xTaskGetCurrentTaskHandle
    #else
        #error Must supply WOLFSENTRY_THREAD_GET_ID_HANDLER for WOLFSENTRY_THREADSAFE on non-POSIX targets.
    #endif

    struct wolfsentry_thread_context;

    /* WOLFSENTRY_THREAD_NO_ID must be zero. */
    #define WOLFSENTRY_THREAD_NO_ID 0

    struct wolfsentry_thread_context_public {
        uint64_t opaque[9];
    };

    #define WOLFSENTRY_THREAD_CONTEXT_PUBLIC_INITIALIZER {0}
#endif

#ifdef BUILDING_LIBWOLFSENTRY
    #if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__) || \
        defined(_WIN32_WCE)
        #if defined(WOLFSENTRY_DLL)
            #define WOLFSENTRY_API_BASE __declspec(dllexport)
        #else
            #define WOLFSENTRY_API_BASE
        #endif
        #define WOLFSENTRY_LOCAL_BASE
    #elif defined(HAVE_VISIBILITY) && HAVE_VISIBILITY
        #define WOLFSENTRY_API_BASE   __attribute__ ((visibility("default")))
        #define WOLFSENTRY_LOCAL_BASE __attribute__ ((visibility("hidden")))
    #elif defined(__SUNPRO_C) && (__SUNPRO_C >= 0x550)
        #define WOLFSENTRY_API_BASE   __global
        #define WOLFSENTRY_LOCAL_BASE __hidden
    #else
        #define WOLFSENTRY_API_BASE
        #define WOLFSENTRY_LOCAL_BASE
    #endif /* HAVE_VISIBILITY */
#else /* !BUILDING_LIBWOLFSENTRY */
    #if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__) || \
        defined(_WIN32_WCE)
        #if defined(WOLFSENTRY_DLL)
            #define WOLFSENTRY_API_BASE __declspec(dllimport)
        #else
            #define WOLFSENTRY_API_BASE
        #endif
        #define WOLFSENTRY_LOCAL_BASE
    #else
        #define WOLFSENTRY_API_BASE
        #define WOLFSENTRY_LOCAL_BASE
    #endif
#endif /* !BUILDING_LIBWOLFSENTRY */

#define WOLFSENTRY_API_VOID WOLFSENTRY_API_BASE void
#define WOLFSENTRY_API WOLFSENTRY_API_BASE __wolfsentry_wur

#define WOLFSENTRY_LOCAL_VOID WOLFSENTRY_LOCAL_BASE void
#define WOLFSENTRY_LOCAL WOLFSENTRY_LOCAL_BASE __wolfsentry_wur

#ifndef WOLFSENTRY_NO_DESIGNATED_INITIALIZERS
#define WOLFSENTRY_HAVE_DESIGNATED_INITIALIZERS
#endif

#ifndef WOLFSENTRY_NO_LONG_LONG
#define WOLFSENTRY_HAVE_LONG_LONG
#endif

#ifndef WOLFSENTRY_MAX_ADDR_BYTES
#define WOLFSENTRY_MAX_ADDR_BYTES 16
#elif WOLFSENTRY_MAX_ADDR_BYTES * 8 > 0xffff
#error WOLFSENTRY_MAX_ADDR_BYTES * 8 must fit in a uint16_t.
#endif

#ifndef WOLFSENTRY_MAX_ADDR_BITS
#define WOLFSENTRY_MAX_ADDR_BITS (WOLFSENTRY_MAX_ADDR_BYTES*8)
#else
#if WOLFSENTRY_MAX_ADDR_BITS > (WOLFSENTRY_MAX_ADDR_BYTES*8)
#error WOLFSENTRY_MAX_ADDR_BITS is too large for given/default WOLFSENTRY_MAX_ADDR_BYTES
#endif
#endif

#ifndef WOLFSENTRY_MAX_LABEL_BYTES
#define WOLFSENTRY_MAX_LABEL_BYTES 32
#elif WOLFSENTRY_MAX_LABEL_BYTES > 0xff
#error WOLFSENTRY_MAX_LABEL_BYTES must fit in a byte.
#endif

#ifndef WOLFSENTRY_BUILTIN_LABEL_PREFIX
#define WOLFSENTRY_BUILTIN_LABEL_PREFIX "%"
#endif

#ifndef WOLFSENTRY_KV_MAX_VALUE_BYTES
#define WOLFSENTRY_KV_MAX_VALUE_BYTES 16384
#endif

#if defined(WOLFSENTRY_ENT_ID_TYPE) || \
    defined(WOLFSENTRY_HITCOUNT_TYPE) || \
    defined(WOLFSENTRY_TIME_TYPE) || \
    defined(WOLFSENTRY_PRIORITY_TYPE)
#define WOLFSENTRY_USER_DEFINED_TYPES
#endif

enum wolfsentry_build_flags {
    WOLFSENTRY_CONFIG_FLAG_ENDIANNESS_ONE = (1U << 0U),
    WOLFSENTRY_CONFIG_FLAG_USER_DEFINED_TYPES = (1U << 1U),
    WOLFSENTRY_CONFIG_FLAG_THREADSAFE = (1U << 2U),
    WOLFSENTRY_CONFIG_FLAG_CLOCK_BUILTINS = (1U << 3U),
    WOLFSENTRY_CONFIG_FLAG_MALLOC_BUILTINS = (1U << 4U),
    WOLFSENTRY_CONFIG_FLAG_ERROR_STRINGS = (1U << 5U),
    WOLFSENTRY_CONFIG_FLAG_PROTOCOL_NAMES = (1U << 6U),
    WOLFSENTRY_CONFIG_FLAG_NO_STDIO = (1U << 7U),
    WOLFSENTRY_CONFIG_FLAG_NO_JSON = (1U << 8U),
    WOLFSENTRY_CONFIG_FLAG_HAVE_JSON_DOM = (1U << 9U),
    WOLFSENTRY_CONFIG_FLAG_DEBUG_CALL_TRACE = (1U << 10U),
    WOLFSENTRY_CONFIG_FLAG_LWIP = (1U << 11U),
    WOLFSENTRY_CONFIG_FLAG_MAX = WOLFSENTRY_CONFIG_FLAG_LWIP,
    WOLFSENTRY_CONFIG_FLAG_ENDIANNESS_ZERO = (0U << 31U)
};

struct wolfsentry_build_settings {
    uint32_t version;
    uint32_t config;
};

#if !defined(BUILDING_LIBWOLFSENTRY) || defined(DEFINE_WOLFSENTRY_BUILD_SETTINGS)

static const __attribute_maybe_unused__ uint32_t __wolfsentry_config = WOLFSENTRY_CONFIG_FLAG_ENDIANNESS_ONE
#ifdef WOLFSENTRY_USER_DEFINED_TYPES
    | WOLFSENTRY_CONFIG_FLAG_USER_DEFINED_TYPES
#endif
#ifdef WOLFSENTRY_THREADSAFE
    | WOLFSENTRY_CONFIG_FLAG_THREADSAFE
#endif
#ifdef WOLFSENTRY_CLOCK_BUILTINS
    | WOLFSENTRY_CONFIG_FLAG_CLOCK_BUILTINS
#endif
#ifdef WOLFSENTRY_MALLOC_BUILTINS
    | WOLFSENTRY_CONFIG_FLAG_MALLOC_BUILTINS
#endif
#ifdef WOLFSENTRY_ERROR_STRINGS
    | WOLFSENTRY_CONFIG_FLAG_ERROR_STRINGS
#endif
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    | WOLFSENTRY_CONFIG_FLAG_PROTOCOL_NAMES
#endif
#ifdef WOLFSENTRY_NO_STDIO
    | WOLFSENTRY_CONFIG_FLAG_NO_STDIO
#endif
#ifdef WOLFSENTRY_NO_JSON
    | WOLFSENTRY_CONFIG_FLAG_NO_JSON
#endif
#ifdef WOLFSENTRY_HAVE_JSON_DOM
    | WOLFSENTRY_CONFIG_FLAG_HAVE_JSON_DOM
#endif
#ifdef WOLFSENTRY_DEBUG_CALL_TRACE
    | WOLFSENTRY_CONFIG_FLAG_DEBUG_CALL_TRACE
#endif
#ifdef WOLFSENTRY_LWIP
    | WOLFSENTRY_CONFIG_FLAG_LWIP
#endif
    ;

static __attribute_maybe_unused__ struct wolfsentry_build_settings wolfsentry_build_settings = {
#ifdef WOLFSENTRY_HAVE_DESIGNATED_INITIALIZERS
    .version =
#endif
    WOLFSENTRY_VERSION,
#ifdef WOLFSENTRY_HAVE_DESIGNATED_INITIALIZERS
    .config =
#endif
    __wolfsentry_config
};

#endif /* !BUILDING_LIBWOLFSENTRY || DEFINE_WOLFSENTRY_BUILD_SETTINGS */

#endif /* WOLFSENTRY_SETTINGS_H */
