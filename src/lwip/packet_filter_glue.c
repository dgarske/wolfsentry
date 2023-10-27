/*
 * lwip/packet_filter_glue.c
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

#include <wolfsentry/wolfsentry.h>
#include <wolfsentry/wolfsentry_lwip.h>
#include "lwip/sockets.h"

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_LWIP_PACKET_FILTER_GLUE_C

#ifndef __STRICT_ANSI__
#define __F__ __FUNCTION__
#endif

#if LWIP_PACKET_FILTER_API

#ifdef WOLFSENTRY_DEBUG_LWIP
    #define V4_FMT "%d.%d.%d.%d"
    #define V4_2_V4ARGS(x) (int)((x)->addr & 0xff), (int)(((x)->addr >> 8) & 0xff), (int)(((x)->addr >> 16) & 0xff), (int)(((x)->addr >> 24))
    #define V4V6_2_V4ARGS(x) (int)(ip_2_ip4(x)->addr & 0xff), (int)((ip_2_ip4(x)->addr >> 8) & 0xff), (int)((ip_2_ip4(x)->addr >> 16) & 0xff), (int)((ip_2_ip4(x)->addr >> 24))
    wolfsentry_static_assert(FILT_BINDING == 0)
    wolfsentry_static_assert(FILT_OUTBOUND_ERR == 13)
    static const char *lwip_event_reasons[] = {
        "BINDING",
        "DISSOCIATE",
        "LISTENING",
        "STOP_LISTENING",
        "CONNECTING",
        "ACCEPTING",
        "CLOSED",
        "REMOTE_RESET",
        "RECEIVING",
        "SENDING",
        "ADDR_UNREACHABLE",
        "PORT_UNREACHABLE",
        "INBOUND_ERR",
        "OUTBOUND_ERR"
    };
    static const char *lwip_event_reason(packet_filter_event_t reason) {
        if ((unsigned)reason < length_of_array(lwip_event_reasons))
            return lwip_event_reasons[reason];
        else
            return "(out-of-bounds reason!)";
    }
#endif

#if LWIP_ARP || LWIP_ETHERNET

#include "netif/ethernet.h"

#ifdef __STRICT_ANSI__
#undef __F__
#define __F__ "ethernet_filter_with_wolfsentry"
#endif
static err_t ethernet_filter_with_wolfsentry(
    void *arg,
    struct packet_filter_event *event,
    const struct eth_addr *laddr,
    const struct eth_addr *raddr,
    u16_t type)
{
    err_t ret;
    wolfsentry_errcode_t ws_ret;
    wolfsentry_route_flags_t route_flags =
        WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD; /* makes wolfsentry_route_event_dispatch*() tolerant of event_label values that can't be found in the event table. */
    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
    struct {
        struct wolfsentry_sockaddr sa;
        struct eth_addr addr_buf;
    } remote, local;
    struct wolfsentry_context *wolfsentry = (struct wolfsentry_context *)arg;
    WOLFSENTRY_THREAD_HEADER_DECLS
#ifdef WOLFSENTRY_DEBUG_LWIP
    wolfsentry_ent_id_t match_id = 0;
    wolfsentry_route_flags_t inexact_matches = 0;
#endif

    if (wolfsentry == NULL)
        WOLFSENTRY_RETURN_VALUE(ERR_OK);

    switch(event->reason) {
    case FILT_RECEIVING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_RECEIVED;
        break;
    case FILT_SENDING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SENDING;
        break;
    case FILT_INBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case FILT_OUTBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case FILT_ADDR_UNREACHABLE:
    case FILT_PORT_UNREACHABLE:
    case FILT_BINDING:
    case FILT_CONNECTING:
    case FILT_DISSOCIATE:
    case FILT_CLOSED:
    case FILT_ACCEPTING:
    case FILT_REMOTE_RESET:
    case FILT_LISTENING:
    case FILT_STOP_LISTENING:
        /* can't happen. */
        WOLFSENTRY_RETURN_VALUE(ERR_OK);
    }

    remote.sa.sa_family = WOLFSENTRY_AF_LINK;
    remote.sa.addr_len = sizeof(struct eth_addr) * 8;
    if (raddr)
        remote.addr_buf = *raddr;
    else
        memset(&remote.addr_buf, 0, sizeof remote.addr_buf);

    local.sa.sa_family = WOLFSENTRY_AF_LINK;
    local.sa.addr_len = sizeof(struct eth_addr) * 8;
    if (laddr)
        local.addr_buf = *laddr;
    else
        memset(&local.addr_buf, 0, sizeof local.addr_buf);

    remote.sa.sa_proto = type; /* see lwip/src/include/lwip/prot/ieee.h for map */
    remote.sa.sa_port = 0;

    local.sa.sa_proto = type; /* see lwip/src/include/lwip/prot/ieee.h for map */
    local.sa.sa_port = 0;

    if (event->netif)
        remote.sa.interface = local.sa.interface = netif_get_index(event->netif);
    else
        remote.sa.interface = local.sa.interface = NETIF_NO_INDEX; /* restricts matches to rules that have zero or wildcard interface ID. */

    if (WOLFSENTRY_THREAD_HEADER_INIT(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        WOLFSENTRY_RETURN_VALUE(ERR_MEM);

    ws_ret = wolfsentry_route_event_dispatch_with_inited_result(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            &remote.sa,
            &local.sa,
            route_flags,
            NULL /* event_label */,
            0,
            (void *)event,
#ifdef WOLFSENTRY_DEBUG_LWIP
            &match_id,
            &inexact_matches,
#else
            NULL,
            NULL,
#endif
            &action_results);

    if (ws_ret >= 0) {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT))
            ret = ERR_ABRT;
        else
            ret = ERR_OK;
    } else
        ret = ERR_OK;

    if (WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        WOLFSENTRY_RETURN_VALUE(ERR_MEM);

#ifdef WOLFSENTRY_DEBUG_LWIP
#define macargs(x) (unsigned)(x)->addr[0], (unsigned)(x)->addr[1], (unsigned)(x)->addr[2], (unsigned)(x)->addr[3], (unsigned)(x)->addr[4], (unsigned)(x)->addr[5]
    WOLFSENTRY_PRINTF_ERR("%s L %d %s, reason=%s, action_results=0x%x, route_flags=0x%x, ret=%d, ws_ret=" WOLFSENTRY_ERROR_FMT ", iface=%u, laddr=%02x:%02x:%02x:%02x:%02x:%02x %s-%s raddr=%02x:%02x:%02x:%02x:%02x:%02x, type=0x%X, match_id=%u, inexact_matches=0%o\n",__FILE__,__LINE__, __F__, lwip_event_reason(event->reason), action_results, route_flags, ret, WOLFSENTRY_ERROR_FMT_ARGS(ws_ret), local.sa.interface, macargs(laddr), route_flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN ? "<" : "", route_flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT ? ">" : "", macargs(raddr), (int)type, (unsigned int)match_id, (unsigned int)inexact_matches);
#endif

    WOLFSENTRY_RETURN_VALUE(ret);
}

#endif /* LWIP_ARP || LWIP_ETHERNET */

#if LWIP_IPV4

#include "lwip/ip4.h"

#ifdef __STRICT_ANSI__
#undef __F__
#define __F__ "ip4_filter_with_wolfsentry"
#endif
static err_t ip4_filter_with_wolfsentry(
    void *arg,
    struct packet_filter_event *event,
    const ip4_addr_t *laddr,
    const ip4_addr_t *raddr,
    u8_t proto)
{
    err_t ret;
    wolfsentry_errcode_t ws_ret;
    wolfsentry_route_flags_t route_flags =
        WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD; /* makes wolfsentry_route_event_dispatch*() tolerant of event_label values that can't be found in the event table. */
    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
    struct {
        struct wolfsentry_sockaddr sa;
        ip4_addr_t addr_buf;
    } remote, local;
    struct wolfsentry_context *wolfsentry = (struct wolfsentry_context *)arg;
    WOLFSENTRY_THREAD_HEADER_DECLS
#ifdef WOLFSENTRY_DEBUG_LWIP
    wolfsentry_ent_id_t match_id = 0;
    wolfsentry_route_flags_t inexact_matches = 0;
#endif

    if (wolfsentry == NULL)
        WOLFSENTRY_RETURN_VALUE(ERR_OK);

    switch(event->reason) {
    case FILT_RECEIVING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_RECEIVED;
        break;
    case FILT_SENDING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SENDING;
        break;
    case FILT_ADDR_UNREACHABLE:
    case FILT_PORT_UNREACHABLE:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_UNREACHABLE;
        break;
    case FILT_INBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case FILT_OUTBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case FILT_BINDING:
    case FILT_CONNECTING:
    case FILT_DISSOCIATE:
    case FILT_CLOSED:
    case FILT_ACCEPTING:
    case FILT_REMOTE_RESET:
    case FILT_LISTENING:
    case FILT_STOP_LISTENING:
        /* can't happen. */
        WOLFSENTRY_RETURN_VALUE(ERR_OK);
    }

    remote.sa.sa_family = WOLFSENTRY_AF_INET;
    remote.sa.addr_len = sizeof(ip4_addr_t) * 8;
    if (raddr)
        remote.addr_buf = *raddr;
    else
        memset(&remote.addr_buf, 0, sizeof remote.addr_buf);

    local.sa.sa_family = WOLFSENTRY_AF_INET;
    local.sa.addr_len = sizeof(ip4_addr_t) * 8;
    if (laddr)
        local.addr_buf = *laddr;
    else
        memset(&local.addr_buf, 0, sizeof local.addr_buf);

    remote.sa.sa_proto = proto;
    remote.sa.sa_port = 0; /* restricts matches to rules that have zero or wildcard ports. */

    local.sa.sa_proto = proto;
    local.sa.sa_port = 0; /* restricts matches to rules that have zero or wildcard ports. */

    if (event->netif)
        remote.sa.interface = local.sa.interface = netif_get_index(event->netif);
    else
        remote.sa.interface = local.sa.interface = NETIF_NO_INDEX; /* restricts matches to rules that have zero or wildcard interface ID. */

    if (WOLFSENTRY_THREAD_HEADER_INIT(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        WOLFSENTRY_RETURN_VALUE(ERR_MEM);

    ws_ret = wolfsentry_route_event_dispatch_with_inited_result(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            &remote.sa,
            &local.sa,
            route_flags,
            NULL /* event_label */,
            0,
            (void *)event,
#ifdef WOLFSENTRY_DEBUG_LWIP
            &match_id,
            &inexact_matches,
#else
            NULL,
            NULL,
#endif
            &action_results);

    if (ws_ret >= 0) {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT))
            ret = ERR_ABRT;
        else
            ret = ERR_OK;
    } else
        ret = ERR_OK;

    if (WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        WOLFSENTRY_RETURN_VALUE(ERR_MEM);

#ifdef WOLFSENTRY_DEBUG_LWIP
    WOLFSENTRY_PRINTF_ERR("%s L %d %s, reason=%s, action_results=0x%x, route_flags=0x%x, ret=%d, ws_ret=" WOLFSENTRY_ERROR_FMT ", iface=%u, laddr=" V4_FMT " %s-%s raddr=" V4_FMT " proto=%d, match_id=%u, inexact_matches=0%o\n",__FILE__,__LINE__, __F__, lwip_event_reason(event->reason), action_results, route_flags, ret, WOLFSENTRY_ERROR_FMT_ARGS(ws_ret), local.sa.interface, V4_2_V4ARGS(laddr), route_flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN ? "<" : "", route_flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT ? ">" : "", V4_2_V4ARGS(raddr), (int)proto, (unsigned int)match_id, (unsigned int)inexact_matches);
#endif

    WOLFSENTRY_RETURN_VALUE(ret);
}

#endif /* LWIP_IPV4 */

#if LWIP_IPV6

#include "lwip/ip6.h"

static err_t ip6_filter_with_wolfsentry(
    void *arg,
    struct packet_filter_event *event,
    const ip6_addr_t *laddr,
    const ip6_addr_t *raddr,
    u8_t proto)
{
    err_t ret;
    wolfsentry_errcode_t ws_ret;
    wolfsentry_route_flags_t route_flags =
        WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD; /* makes wolfsentry_route_event_dispatch*() tolerant of event_label values that can't be found in the event table. */
    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
    struct {
        struct wolfsentry_sockaddr sa;
        ip6_addr_t addr_buf; /* note, includes extra byte for zone. */
    } remote, local;
    struct wolfsentry_context *wolfsentry = (struct wolfsentry_context *)arg;
    WOLFSENTRY_THREAD_HEADER_DECLS
#ifdef WOLFSENTRY_DEBUG_LWIP
    wolfsentry_ent_id_t match_id = 0;
    wolfsentry_route_flags_t inexact_matches = 0;
#endif

    if (wolfsentry == NULL)
        WOLFSENTRY_RETURN_VALUE(ERR_OK);

    switch(event->reason) {
    case FILT_RECEIVING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_RECEIVED;
        break;
    case FILT_SENDING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SENDING;
        break;
    case FILT_ADDR_UNREACHABLE:
    case FILT_PORT_UNREACHABLE:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_UNREACHABLE;
        break;
    case FILT_INBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case FILT_OUTBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case FILT_BINDING:
    case FILT_CONNECTING:
    case FILT_DISSOCIATE:
    case FILT_CLOSED:
    case FILT_ACCEPTING:
    case FILT_REMOTE_RESET:
    case FILT_LISTENING:
    case FILT_STOP_LISTENING:
        /* can't happen. */
        WOLFSENTRY_RETURN_VALUE(ERR_OK);
    }

    remote.sa.sa_family = WOLFSENTRY_AF_INET6;
    remote.sa.addr_len = 128; /* ip6_addr_t includes an extra byte for the zone. */
    if (raddr)
        remote.addr_buf = *raddr;
    else
        memset(&remote.addr_buf, 0, sizeof remote.addr_buf);

    local.sa.sa_family = WOLFSENTRY_AF_INET6;
    local.sa.addr_len = 128; /* ip6_addr_t includes an extra byte for the zone. */
    if (laddr)
        local.addr_buf = *laddr;
    else
        memset(&local.addr_buf, 0, sizeof local.addr_buf);

    remote.sa.sa_proto = proto;
    remote.sa.sa_port = 0; /* restricts matches to rules that have zero or wildcard ports. */

    local.sa.sa_proto = proto;
    local.sa.sa_port = 0; /* restricts matches to rules that have zero or wildcard ports. */

    if (event->netif)
        remote.sa.interface = local.sa.interface = netif_get_index(event->netif);
    else
        remote.sa.interface = local.sa.interface = NETIF_NO_INDEX; /* restricts matches to rules that have zero or wildcard interface ID. */

    if (WOLFSENTRY_THREAD_HEADER_INIT(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        WOLFSENTRY_RETURN_VALUE(ERR_MEM);

    ws_ret = wolfsentry_route_event_dispatch_with_inited_result(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            &remote.sa,
            &local.sa,
            route_flags,
            NULL /* event_label */,
            0,
            (void *)event,
#ifdef WOLFSENTRY_DEBUG_LWIP
            &match_id,
            &inexact_matches,
#else
            NULL,
            NULL,
#endif
            &action_results);

    if (ws_ret >= 0) {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT))
            ret = ERR_ABRT;
        else
            ret = ERR_OK;
    } else
        ret = ERR_OK;

    if (WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        WOLFSENTRY_RETURN_VALUE(ERR_MEM);

    WOLFSENTRY_RETURN_VALUE(ret);
}

#endif /* LWIP_IP6 */

#if LWIP_TCP

#include "lwip/tcp.h"

#ifdef __STRICT_ANSI__
#undef __F__
#define __F__ "tcp_filter_with_wolfsentry"
#endif
static err_t tcp_filter_with_wolfsentry(
    void *arg,
    struct packet_filter_event *event,
    ip_addr_t *laddr,
    u16_t lport,
    ip_addr_t *raddr,
    u16_t rport)
{
    err_t ret;
    wolfsentry_errcode_t ws_ret;
    wolfsentry_route_flags_t route_flags =
        WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS |
        WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD; /* makes wolfsentry_route_event_dispatch*() tolerant of event_label values that can't be found in the event table. */
    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
    struct {
        struct wolfsentry_sockaddr sa;
#if LWIP_IPV6
        ip6_addr_t addr_buf; /* note, includes extra byte for zone. */
#else
        ip4_addr_t addr_buf;
#endif
    }
    remote, local;
    wolfsentry_static_assert2((void *)&remote.sa.addr == (void *)&remote.addr_buf, "unexpected layout in struct wolfsentry_sockaddr.")
    struct wolfsentry_context *wolfsentry = (struct wolfsentry_context *)arg;
    WOLFSENTRY_THREAD_HEADER_DECLS
#ifdef WOLFSENTRY_DEBUG_LWIP
    wolfsentry_ent_id_t match_id = 0;
    wolfsentry_route_flags_t inexact_matches = 0;
#endif

    if (wolfsentry == NULL)
        WOLFSENTRY_RETURN_VALUE(ERR_OK);

    switch(event->reason) {
    case FILT_ACCEPTING:
        action_results = WOLFSENTRY_ACTION_RES_CONNECT; /* lets wolfSentry increment the connection count for this peer. */
        route_flags |=
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        break;
    case FILT_REMOTE_RESET:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        /* fall through */
    case FILT_CLOSED:
        if (event->pcb.tcp_pcb->flags & TF_ACCEPTED) {
            route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
            action_results = WOLFSENTRY_ACTION_RES_DISCONNECT; /* lets wolfSentry decrement the connection count for this peer. */
        } else {
            /* connection wasn't accepted -- don't debit on disconnect. */
            route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
            action_results = WOLFSENTRY_ACTION_RES_CLOSED;
        }
        break;
    case FILT_PORT_UNREACHABLE:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_UNREACHABLE |
            WOLFSENTRY_ACTION_RES_DEROGATORY;
        break;
    case FILT_BINDING:
        route_flags |=
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        action_results = WOLFSENTRY_ACTION_RES_BINDING |
            WOLFSENTRY_ACTION_RES_EXCLUDE_REJECT_ROUTES;
        break;
    case FILT_LISTENING:
        route_flags |=
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        action_results = WOLFSENTRY_ACTION_RES_LISTENING |
            WOLFSENTRY_ACTION_RES_EXCLUDE_REJECT_ROUTES;
        break;
    case FILT_STOP_LISTENING:
        route_flags |=
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        action_results = WOLFSENTRY_ACTION_RES_STOPPED_LISTENING |
            WOLFSENTRY_ACTION_RES_EXCLUDE_REJECT_ROUTES;
        break;
    case FILT_RECEIVING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_RECEIVED;
        break;
    case FILT_CONNECTING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_CONNECTING_OUT;
        break;
    case FILT_SENDING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SENDING;
        break;
    case FILT_INBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case FILT_OUTBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case FILT_DISSOCIATE:
    case FILT_ADDR_UNREACHABLE:
        /* can't happen. */
        WOLFSENTRY_RETURN_VALUE(ERR_OK);
    }

#if LWIP_IPV6
    if (laddr->type == IPADDR_TYPE_V6) {
        remote.sa.sa_family = WOLFSENTRY_AF_INET6;
        remote.sa.addr_len = 128; /* ip6_addr_t includes an extra byte for the zone. */
        if (raddr)
            remote.addr_buf = *ip_2_ip6(raddr);
        else
            memset(&remote.addr_buf, 0, sizeof remote.addr_buf);

        local.sa.sa_family = WOLFSENTRY_AF_INET6;
        local.sa.addr_len = 128; /* ip6_addr_t includes an extra byte for the zone. */
        if (laddr)
            local.addr_buf = *ip_2_ip6(laddr);
        else
            memset(&local.addr_buf, 0, sizeof local.addr_buf);
    } else {
#endif
        remote.sa.sa_family = WOLFSENTRY_AF_INET;
        remote.sa.addr_len = sizeof(ip4_addr_t) * 8;
        if (raddr)
            *(struct ip4_addr *)&remote.addr_buf = *ip_2_ip4(raddr);
        else
            memset(&remote.addr_buf, 0, sizeof(struct ip4_addr));

        local.sa.sa_family = WOLFSENTRY_AF_INET;
        local.sa.addr_len = sizeof(ip4_addr_t) * 8;
        if (laddr)
            *(struct ip4_addr *)&local.addr_buf = *ip_2_ip4(laddr);
        else
            memset(&local.addr_buf, 0, sizeof(struct ip4_addr));
#if LWIP_IPV6
    }
#endif

    remote.sa.sa_proto = IPPROTO_TCP;
    remote.sa.sa_port = rport;

    local.sa.sa_proto = IPPROTO_TCP;
    local.sa.sa_port = lport;

    if (event->netif)
        remote.sa.interface = local.sa.interface = netif_get_index(event->netif);
    else
        remote.sa.interface = local.sa.interface = NETIF_NO_INDEX; /* restricts matches to rules that have zero or wildcard interface ID. */

    if (WOLFSENTRY_THREAD_HEADER_INIT(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        WOLFSENTRY_RETURN_VALUE(ERR_MEM);

    ws_ret = wolfsentry_route_event_dispatch_with_inited_result(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            &remote.sa,
            &local.sa,
            route_flags,
            NULL /* event_label */,
            0,
            (void *)&event,
#ifdef WOLFSENTRY_DEBUG_LWIP
            &match_id,
            &inexact_matches,
#else
            NULL,
            NULL,
#endif
            &action_results);

    if (ws_ret < 0)
        ret = ERR_OK;
    else {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_PORT_RESET))
            ret = ERR_RST;
        else if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT))
            ret = ERR_ABRT;
        else
            ret = ERR_OK;
    }

    if (WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        WOLFSENTRY_RETURN_VALUE(ERR_MEM);

#ifdef WOLFSENTRY_DEBUG_LWIP
#if LWIP_IPV6
    if (laddr->type == IPADDR_TYPE_V4) {
#endif
        WOLFSENTRY_PRINTF_ERR("%s L %d %s, reason=%s, action_results=0x%x, route_flags=0x%x, ret=%d, ws_ret=" WOLFSENTRY_ERROR_FMT ", iface=%u, lsock=" V4_FMT ":%d %s-%s rsock=" V4_FMT ":%d, match_id=%u, inexact_matches=0%o\n",__FILE__,__LINE__, __F__, lwip_event_reason(event->reason), action_results, route_flags, ret, WOLFSENTRY_ERROR_FMT_ARGS(ws_ret), local.sa.interface, V4V6_2_V4ARGS(laddr), lport, route_flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN ? "<" : "", route_flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT ? ">" : "", V4V6_2_V4ARGS(raddr), rport, (unsigned int)match_id, (unsigned int)inexact_matches);
#if LWIP_IPV6
    }
#endif
#endif

    WOLFSENTRY_RETURN_VALUE(ret);
}

#endif /* LWIP_TCP */

#if LWIP_UDP

#include "lwip/udp.h"

#ifdef __STRICT_ANSI__
#undef __F__
#define __F__ "udp_filter_with_wolfsentry"
#endif
static err_t udp_filter_with_wolfsentry(
    void *arg,
    struct packet_filter_event *event,
    const ip_addr_t *laddr,
    u16_t lport,
    const ip_addr_t *raddr,
    u16_t rport)
{
    err_t ret;
    wolfsentry_errcode_t ws_ret;
    wolfsentry_route_flags_t route_flags =
        WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS |
        WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD; /* makes wolfsentry_route_event_dispatch*() tolerant of event_label values that can't be found in the event table. */
    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
    struct {
        struct wolfsentry_sockaddr sa;
#if LWIP_IPV6
        ip6_addr_t addr_buf; /* note, includes extra byte for zone. */
#else
        ip4_addr_t addr_buf;
#endif
    } remote, local;
    struct wolfsentry_context *wolfsentry = (struct wolfsentry_context *)arg;
    WOLFSENTRY_THREAD_HEADER_DECLS
#ifdef WOLFSENTRY_DEBUG_LWIP
    wolfsentry_ent_id_t match_id = 0;
    wolfsentry_route_flags_t inexact_matches = 0;
#endif

    if (wolfsentry == NULL)
        WOLFSENTRY_RETURN_VALUE(ERR_OK);

    switch(event->reason) {
    case FILT_BINDING:
        route_flags |=
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        action_results = WOLFSENTRY_ACTION_RES_BINDING |
            WOLFSENTRY_ACTION_RES_EXCLUDE_REJECT_ROUTES;
        break;
    case FILT_CONNECTING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN | WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_CONNECTING_OUT;
        break;
    case FILT_DISSOCIATE:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN | WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_CLOSED;
        break;
    case FILT_CLOSED:
        route_flags |=
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        action_results = WOLFSENTRY_ACTION_RES_CLOSED |
            WOLFSENTRY_ACTION_RES_EXCLUDE_REJECT_ROUTES;
        break;
    case FILT_PORT_UNREACHABLE:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_UNREACHABLE |
            WOLFSENTRY_ACTION_RES_DEROGATORY;
        break;
    case FILT_RECEIVING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_RECEIVED;
        break;
    case FILT_SENDING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SENDING;
        break;
    case FILT_INBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case FILT_OUTBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case FILT_ACCEPTING:
    case FILT_REMOTE_RESET:
    case FILT_LISTENING:
    case FILT_STOP_LISTENING:
    case FILT_ADDR_UNREACHABLE:
        /* can't happen. */
        WOLFSENTRY_RETURN_VALUE(ERR_OK);
    }

#if LWIP_IPV6
    if (laddr->type == IPADDR_TYPE_V6) {
        remote.sa.sa_family = WOLFSENTRY_AF_INET6;
        remote.sa.addr_len = 128; /* ip6_addr_t includes an extra byte for the zone. */
        if (raddr)
            remote.addr_buf = *ip_2_ip6(raddr);
        else
            memset(&remote.addr_buf, 0, sizeof remote.addr_buf);

        local.sa.sa_family = WOLFSENTRY_AF_INET6;
        local.sa.addr_len = 128; /* ip6_addr_t includes an extra byte for the zone. */
        if (laddr)
            local.addr_buf = *ip_2_ip6(laddr);
        else
            memset(&local.addr_buf, 0, sizeof local.addr_buf);
    } else {
#endif
        remote.sa.sa_family = WOLFSENTRY_AF_INET;
        remote.sa.addr_len = sizeof(ip4_addr_t) * 8;
        if (raddr)
            *(struct ip4_addr *)&remote.addr_buf = *ip_2_ip4(raddr);
        else
            memset(&remote.addr_buf, 0, sizeof(struct ip4_addr));

        local.sa.sa_family = WOLFSENTRY_AF_INET;
        local.sa.addr_len = sizeof(ip4_addr_t) * 8;
        if (laddr)
            *(struct ip4_addr *)&local.addr_buf = *ip_2_ip4(laddr);
        else
            memset(&local.addr_buf, 0, sizeof(struct ip4_addr));
#if LWIP_IPV6
    }
#endif

    remote.sa.sa_proto = IPPROTO_UDP;
    remote.sa.sa_port = rport;

    local.sa.sa_proto = IPPROTO_UDP;
    local.sa.sa_port = lport;

    if (event->netif)
        remote.sa.interface = local.sa.interface = netif_get_index(event->netif);
    else
        remote.sa.interface = local.sa.interface = NETIF_NO_INDEX; /* restricts matches to rules that have zero or wildcard interface ID. */

    if (WOLFSENTRY_THREAD_HEADER_INIT(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        WOLFSENTRY_RETURN_VALUE(ERR_MEM);

    ws_ret = wolfsentry_route_event_dispatch_with_inited_result(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            &remote.sa,
            &local.sa,
            route_flags,
            NULL /* event_label */,
            0,
            (void *)event,
#ifdef WOLFSENTRY_DEBUG_LWIP
            &match_id,
            &inexact_matches,
#else
            NULL,
            NULL,
#endif
            &action_results);

    if (ws_ret >= 0) {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_PORT_RESET))
            ret = ERR_RST;
        else if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT))
            ret = ERR_ABRT;
        else
            ret = ERR_OK;
    } else
        ret = ERR_OK;

    if (WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        WOLFSENTRY_RETURN_VALUE(ERR_MEM);

#ifdef WOLFSENTRY_DEBUG_LWIP
#if LWIP_IPV6
    if (laddr->type == IPADDR_TYPE_V4) {
#endif
        WOLFSENTRY_PRINTF_ERR("%s L %d %s, reason=%s, action_results=0x%x, route_flags=0x%x, ret=%d, ws_ret=" WOLFSENTRY_ERROR_FMT ", iface=%u, lsock=" V4_FMT ":%d %s-%s rsock=" V4_FMT ":%d, match_id=%u, inexact_matches=0%o\n",__FILE__,__LINE__, __F__, lwip_event_reason(event->reason), action_results, route_flags, ret, WOLFSENTRY_ERROR_FMT_ARGS(ws_ret), local.sa.interface, V4V6_2_V4ARGS(laddr), lport, route_flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN ? "<" : "", route_flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT ? ">" : "", V4V6_2_V4ARGS(raddr), rport, (unsigned int)match_id, (unsigned int)inexact_matches);
#if LWIP_IPV6
    }
#endif
#endif

  WOLFSENTRY_RETURN_VALUE(ret);
}

#endif /* LWIP_UDP */

#if LWIP_ICMP

#include "lwip/icmp.h"

#ifdef __STRICT_ANSI__
#undef __F__
#define __F__ "icmp4_filter_with_wolfsentry"
#endif
static err_t icmp4_filter_with_wolfsentry(
    void *arg,
    struct packet_filter_event *event,
    const ip4_addr_t *laddr,
    const ip4_addr_t *raddr,
    u8_t icmp4_type)
{
    err_t ret;
    wolfsentry_errcode_t ws_ret;
    wolfsentry_route_flags_t route_flags =
        WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD; /* makes wolfsentry_route_event_dispatch*() tolerant of event_label values that can't be found in the event table. */
    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
    struct {
        struct wolfsentry_sockaddr sa;
        ip4_addr_t addr_buf;
    } remote, local;
    struct wolfsentry_context *wolfsentry = (struct wolfsentry_context *)arg;
    WOLFSENTRY_THREAD_HEADER_DECLS
#ifdef WOLFSENTRY_DEBUG_LWIP
    wolfsentry_ent_id_t match_id = 0;
    wolfsentry_route_flags_t inexact_matches = 0;
#endif

    if (wolfsentry == NULL)
        WOLFSENTRY_RETURN_VALUE(ERR_OK);

    switch(event->reason) {
    case FILT_RECEIVING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_RECEIVED;
        break;
    case FILT_SENDING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SENDING;
        break;
    case FILT_ADDR_UNREACHABLE:
    case FILT_PORT_UNREACHABLE:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_UNREACHABLE |
            WOLFSENTRY_ACTION_RES_DEROGATORY;
        break;
    case FILT_INBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case FILT_OUTBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case FILT_BINDING:
    case FILT_CONNECTING:
    case FILT_DISSOCIATE:
    case FILT_CLOSED:
    case FILT_ACCEPTING:
    case FILT_REMOTE_RESET:
    case FILT_LISTENING:
    case FILT_STOP_LISTENING:
        /* can't happen. */
        WOLFSENTRY_RETURN_VALUE(ERR_OK);
    }

    remote.sa.sa_family = WOLFSENTRY_AF_INET;
    remote.sa.addr_len = sizeof(ip4_addr_t) * 8;
    if (raddr)
        remote.addr_buf = *raddr;
    else
        memset(&remote.addr_buf, 0, sizeof remote.addr_buf);

    local.sa.sa_family = WOLFSENTRY_AF_INET;
    local.sa.addr_len = sizeof(ip4_addr_t) * 8;
    if (laddr)
        local.addr_buf = *laddr;
    else
        memset(&local.addr_buf, 0, sizeof local.addr_buf);

    remote.sa.sa_proto = IPPROTO_ICMP;
    remote.sa.sa_port = 0;

    local.sa.sa_proto = IPPROTO_ICMP;
    local.sa.sa_port = icmp4_type;

    if (event->netif)
        remote.sa.interface = local.sa.interface = netif_get_index(event->netif);
    else
        remote.sa.interface = local.sa.interface = NETIF_NO_INDEX; /* restricts matches to rules that have zero or wildcard interface ID. */

    if (WOLFSENTRY_THREAD_HEADER_INIT(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        WOLFSENTRY_RETURN_VALUE(ERR_MEM);

    ws_ret = wolfsentry_route_event_dispatch_with_inited_result(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            &remote.sa,
            &local.sa,
            route_flags,
            NULL /* event_label */,
            0,
            (void *)event,
#ifdef WOLFSENTRY_DEBUG_LWIP
            &match_id,
            &inexact_matches,
#else
            NULL,
            NULL,
#endif
            &action_results);

    if (ws_ret >= 0) {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT))
            ret = ERR_ABRT;
        else
            ret = ERR_OK;
    } else
        ret = ERR_OK;

    if (WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        WOLFSENTRY_RETURN_VALUE(ERR_MEM);

#ifdef WOLFSENTRY_DEBUG_LWIP
    WOLFSENTRY_PRINTF_ERR("%s L %d %s, reason=%s, action_results=0x%x, route_flags=0x%x, ret=%d, ws_ret=" WOLFSENTRY_ERROR_FMT ", iface=%u, laddr=%d.%d.%d.%d %s-%s raddr=%d.%d.%d.%d type=%d, match_id=%u, inexact_matches=0%o\n",__FILE__,__LINE__, __F__, lwip_event_reason(event->reason), action_results, route_flags, ret, WOLFSENTRY_ERROR_FMT_ARGS(ws_ret), local.sa.interface, V4_2_V4ARGS(laddr), route_flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN ? "<" : "", route_flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT ? ">" : "", V4_2_V4ARGS(raddr), (int)icmp4_type, (unsigned int)match_id, (unsigned int)inexact_matches);
#endif

    WOLFSENTRY_RETURN_VALUE(ret);
}

#endif /* LWIP_ICMP */

#if LWIP_ICMP6

#include "lwip/icmp6.h"

static err_t icmp6_filter_with_wolfsentry(
    void *arg,
    struct packet_filter_event *event,
    const ip6_addr_t *laddr,
    const ip6_addr_t *raddr,
    u8_t icmp6_type)
{
    err_t ret;
    wolfsentry_errcode_t ws_ret;
    wolfsentry_route_flags_t route_flags =
        WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD; /* makes wolfsentry_route_event_dispatch*() tolerant of event_label values that can't be found in the event table. */
    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
    struct {
        struct wolfsentry_sockaddr sa;
        ip6_addr_t addr_buf; /* note, includes extra byte for zone. */
    } remote, local;
    struct wolfsentry_context *wolfsentry = (struct wolfsentry_context *)arg;
    WOLFSENTRY_THREAD_HEADER_DECLS
#ifdef WOLFSENTRY_DEBUG_LWIP
    wolfsentry_ent_id_t match_id = 0;
    wolfsentry_route_flags_t inexact_matches = 0;
#endif

    if (wolfsentry == NULL)
        WOLFSENTRY_RETURN_VALUE(ERR_OK);

    switch(event->reason) {
    case FILT_RECEIVING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_RECEIVED;
        break;
    case FILT_SENDING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SENDING;
        break;
    case FILT_ADDR_UNREACHABLE:
    case FILT_PORT_UNREACHABLE:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_UNREACHABLE |
            WOLFSENTRY_ACTION_RES_DEROGATORY;
        break;
    case FILT_INBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case FILT_OUTBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case FILT_BINDING:
    case FILT_CONNECTING:
    case FILT_DISSOCIATE:
    case FILT_CLOSED:
    case FILT_ACCEPTING:
    case FILT_REMOTE_RESET:
    case FILT_LISTENING:
    case FILT_STOP_LISTENING:
        /* can't happen. */
        WOLFSENTRY_RETURN_VALUE(ERR_OK);
    }

    remote.sa.sa_family = WOLFSENTRY_AF_INET6;
    remote.sa.addr_len = 128; /* ip6_addr_t includes an extra byte for the zone. */
    if (raddr)
        remote.addr_buf = *raddr;
    else
        memset(&remote.addr_buf, 0, sizeof remote.addr_buf);

    local.sa.sa_family = WOLFSENTRY_AF_INET6;
    local.sa.addr_len = 128; /* ip6_addr_t includes an extra byte for the zone. */
    if (laddr)
        local.addr_buf = *laddr;
    else
        memset(&local.addr_buf, 0, sizeof local.addr_buf);

    remote.sa.sa_proto = IPPROTO_ICMP;
    remote.sa.sa_port = 0;

    local.sa.sa_proto = IPPROTO_ICMP;
    local.sa.sa_port = icmp6_type;

    if (event->netif)
        remote.sa.interface = local.sa.interface = netif_get_index(event->netif);
    else
        remote.sa.interface = local.sa.interface = NETIF_NO_INDEX; /* restricts matches to rules that have zero or wildcard interface ID. */

    if (WOLFSENTRY_THREAD_HEADER_INIT(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        WOLFSENTRY_RETURN_VALUE(ERR_MEM);

    ws_ret = wolfsentry_route_event_dispatch_with_inited_result(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            &remote.sa,
            &local.sa,
            route_flags,
            NULL /* event_label */,
            0,
            (void *)event,
#ifdef WOLFSENTRY_DEBUG_LWIP
            &match_id,
            &inexact_matches,
#else
            NULL,
            NULL,
#endif
            &action_results);

    if (ws_ret >= 0) {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT))
            ret = ERR_ABRT;
        else
            ret = ERR_OK;
    } else
        ret = ERR_OK;

    if (WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        WOLFSENTRY_RETURN_VALUE(ERR_MEM);

  WOLFSENTRY_RETURN_VALUE(ret);
}

#endif /* LWIP_ICMP6 */

WOLFSENTRY_API_VOID wolfsentry_cleanup_lwip_filter_callbacks(WOLFSENTRY_CONTEXT_ARGS_IN, void *cleanup_arg) {
    (void)cleanup_arg;
    WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_install_lwip_filter_callbacks(WOLFSENTRY_CONTEXT_ARGS_OUT, 0, 0, 0, 0, 0));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_lwip_filter_ethernet_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    packet_filter_event_mask_t ethernet_mask)
{
#if LWIP_ARP || LWIP_ETHERNET
    WOLFSENTRY_MUTEX_OR_RETURN();
    if (ethernet_mask) {
        wolfsentry_errcode_t ret = wolfsentry_cleanup_push(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry_cleanup_lwip_filter_callbacks, NULL);
        WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);
        ethernet_filter(ethernet_filter_with_wolfsentry);
        ethernet_filter_mask(ethernet_mask);
        ethernet_filter_arg((void *)wolfsentry);
    } else {
        ethernet_filter(NULL);
        ethernet_filter_mask(0);
        ethernet_filter_arg(NULL);
    }
    WOLFSENTRY_UNLOCK_AND_RETURN_OK;
#else
    if (ethernet_mask)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    else
        WOLFSENTRY_RETURN_OK;
#endif /* LWIP_ARP || LWIP_ETHERNET */
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_lwip_filter_ip_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    packet_filter_event_mask_t ip_mask)
{
#if LWIP_IPV4 || LWIP_IPV6
    WOLFSENTRY_MUTEX_OR_RETURN();
    if (ip_mask) {
        wolfsentry_errcode_t ret = wolfsentry_cleanup_push(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry_cleanup_lwip_filter_callbacks, NULL);
        WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);
    }
#endif
#if LWIP_IPV4
    if (ip_mask) {
        ip4_filter(ip4_filter_with_wolfsentry);
        ip4_filter_mask(ip_mask);
        ip4_filter_arg((void *)wolfsentry);
    } else {
        ip4_filter(NULL);
        ip4_filter_mask(0);
        ip4_filter_arg(NULL);
    }
#endif /* LWIP_IPV4 */

#if LWIP_IPV6
    if (ip_mask) {
        ip6_filter(ip6_filter_with_wolfsentry);
        ip6_filter_mask(ip_mask);
        ip6_filter_arg((void *)wolfsentry);
    } else {
        ip6_filter(NULL);
        ip6_filter_mask(0);
        ip6_filter_arg(NULL);
    }
#endif /* LWIP_IPV6 */

#if LWIP_IPV4 || LWIP_IPV6
    WOLFSENTRY_UNLOCK_AND_RETURN_OK;
#else
    if (ip_mask)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    else
        WOLFSENTRY_RETURN_OK;
#endif
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_lwip_filter_icmp_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    packet_filter_event_mask_t icmp_mask)
{
#if LWIP_ICMP || LWIP_ICMP6
    WOLFSENTRY_MUTEX_OR_RETURN();
    if (icmp_mask) {
        wolfsentry_errcode_t ret = wolfsentry_cleanup_push(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry_cleanup_lwip_filter_callbacks, NULL);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
    }
#endif
#if LWIP_ICMP
    if (icmp_mask) {
        icmp_filter(icmp4_filter_with_wolfsentry);
        icmp_filter_mask(icmp_mask);
        icmp_filter_arg((void *)wolfsentry);
    } else
        icmp_filter(NULL);
#endif /* LWIP_ICMP */

#if LWIP_ICMP6
    if (icmp_mask) {
        icmp6_filter(icmp6_filter_with_wolfsentry);
        icmp6_filter_mask(icmp_mask);
        icmp6_filter_arg((void *)wolfsentry);
    } else {
        icmp6_filter(NULL);
        icmp6_filter_mask(0);
        icmp6_filter_arg(NULL);
    }
#endif /* LWIP_ICMP6 */

#if LWIP_ICMP || LWIP_ICMP6
    WOLFSENTRY_UNLOCK_AND_RETURN_OK;
#else
    if (icmp_mask)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    else
        WOLFSENTRY_RETURN_OK;
#endif
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_lwip_filter_tcp_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    packet_filter_event_mask_t tcp_mask)
{
#if LWIP_TCP
    WOLFSENTRY_MUTEX_OR_RETURN();
    if (tcp_mask) {
        wolfsentry_errcode_t ret = wolfsentry_cleanup_push(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry_cleanup_lwip_filter_callbacks, NULL);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        tcp_filter(tcp_filter_with_wolfsentry);
        /* make sure wolfSentry sees the close/reset events that balance earlier
         * accepts, for concurrent-connection accounting purposes.
         */
        if (tcp_mask & (FILT_MASK(ACCEPTING) | FILT_MASK(CLOSED) | FILT_MASK(REMOTE_RESET)))
            tcp_mask |= FILT_MASK(ACCEPTING) | FILT_MASK(CLOSED) | FILT_MASK(REMOTE_RESET);
        tcp_filter_mask(tcp_mask);
        tcp_filter_arg((void *)wolfsentry);
    } else {
        tcp_filter(NULL);
        tcp_filter_mask(0);
        tcp_filter_arg(NULL);
    }
    WOLFSENTRY_UNLOCK_AND_RETURN_OK;
#else
    if (tcp_mask)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    else
        WOLFSENTRY_RETURN_OK;
#endif /* LWIP_TCP */
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_lwip_filter_udp_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    packet_filter_event_mask_t udp_mask)
{
#if LWIP_UDP
    WOLFSENTRY_MUTEX_OR_RETURN();
    if (udp_mask) {
        wolfsentry_errcode_t ret = wolfsentry_cleanup_push(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry_cleanup_lwip_filter_callbacks, NULL);
        WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);
        udp_filter(udp_filter_with_wolfsentry);
        udp_filter_mask(udp_mask);
        udp_filter_arg((void *)wolfsentry);
    } else {
        udp_filter(NULL);
        udp_filter_mask(0);
        udp_filter_arg(NULL);
    }
    WOLFSENTRY_UNLOCK_AND_RETURN_OK;
#else
    if (udp_mask)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    else
        WOLFSENTRY_RETURN_OK;
#endif /* LWIP_UDP */

}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_lwip_filter_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    packet_filter_event_mask_t ethernet_mask,
    packet_filter_event_mask_t ip_mask,
    packet_filter_event_mask_t icmp_mask,
    packet_filter_event_mask_t tcp_mask,
    packet_filter_event_mask_t udp_mask)
{
    wolfsentry_errcode_t ret;

    WOLFSENTRY_MUTEX_OR_RETURN();

    if ((ret = wolfsentry_install_lwip_filter_ethernet_callback(WOLFSENTRY_CONTEXT_ARGS_OUT, ethernet_mask)) < 0)
        goto out;
    if ((ret = wolfsentry_install_lwip_filter_ip_callbacks(WOLFSENTRY_CONTEXT_ARGS_OUT, ip_mask)) < 0)
        goto out;
    if ((ret = wolfsentry_install_lwip_filter_icmp_callbacks(WOLFSENTRY_CONTEXT_ARGS_OUT, icmp_mask)) < 0)
        goto out;
    if ((ret = wolfsentry_install_lwip_filter_tcp_callback(WOLFSENTRY_CONTEXT_ARGS_OUT, tcp_mask)) < 0)
        goto out;
    if ((ret = wolfsentry_install_lwip_filter_udp_callback(WOLFSENTRY_CONTEXT_ARGS_OUT, udp_mask)) < 0)
        goto out;

    ret = WOLFSENTRY_ERROR_ENCODE(OK);

out:
    if (ret < 0) {
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_install_lwip_filter_ethernet_callback(WOLFSENTRY_CONTEXT_ARGS_OUT, 0));
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_install_lwip_filter_ip_callbacks(WOLFSENTRY_CONTEXT_ARGS_OUT, 0));
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_install_lwip_filter_icmp_callbacks(WOLFSENTRY_CONTEXT_ARGS_OUT, 0));
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_install_lwip_filter_tcp_callback(WOLFSENTRY_CONTEXT_ARGS_OUT, 0));
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_install_lwip_filter_udp_callback(WOLFSENTRY_CONTEXT_ARGS_OUT, 0));
    }

    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

#endif /* LWIP_PACKET_FILTER_API */
