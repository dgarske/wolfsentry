// SPDX-License-Identifier: GPL-2.0-or-later

#define DEBUG_TLS
//#define DEBUG_WOLFSENTRY

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_USER_BASE

#include "sentry.h"
#include "log_server.h"

struct wolfsentry_context *wolfsentry = NULL;
static int wolfsentry_data_index = -1;

/* Callback that is fired when an action is taken, this can be used for
 * debugging for now */
static wolfsentry_errcode_t wolfsentry_test_action(
    struct wolfsentry_context *ws_ctx,
    const struct wolfsentry_action *action,
    void *handler_arg,
    void *caller_arg,
    const struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *target_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results)
{
    const struct wolfsentry_event *parent_event;
    (void)ws_ctx;
    (void)handler_arg;
    (void)route_table;
    (void)action_results;

    if (rule_route == NULL) {
#ifdef DEBUG_WOLFSENTRY
        fprintf(stderr, "null rule_route, target_route=%p\n",target_route);
#else
        (void)target_route;
#endif
        return 0;
    }

    parent_event = wolfsentry_route_parent_event(rule_route);

#ifdef DEBUG_WOLFSENTRY
    printf("action callback: a=\"%s\" parent_event=\"%s\" trigger=\"%s\" t=%u r_id=%u caller_arg=%p\n",
           wolfsentry_action_get_label(action),
           wolfsentry_event_get_label(parent_event),
           wolfsentry_event_get_label(trigger_event),
           action_type,
           wolfsentry_get_object_id(rule_route),
           caller_arg);
#else
    (void)action;
    (void)parent_event;
    (void)trigger_event;
    (void)action_type;
    (void)rule_route;
    (void)caller_arg;
#endif

    return 0;
}

/* Check a TCP connection with wolfSentry. This is called for connect and
 * disconnect so wolfSentry can count the simultaneous connections */
int sentry_action(ip_addr_t *local_ip, ip_addr_t *remote_ip, in_port_t local_port, in_port_t remote_port, sentry_action_type action)
{
    wolfsentry_errcode_t ret;
    wolfsentry_action_res_t action_results;
    /* Note that sa.addr is 0 bytes, addr_buf essentially enlarges this to the correct size */
    struct {
        struct wolfsentry_sockaddr sa;
        byte addr_buf[4];
    } remote, local;
#ifdef BUILD_FOR_FREERTOS_LWIP
    u32_t remoteip = remote_ip->addr;
    u32_t localip = local_ip->addr;
#elif defined(BUILD_FOR_LINUX) || defined(BUILD_FOR_MACOSX)
    u32_t remoteip = remote_ip->s_addr;
    u32_t localip = local_ip->s_addr;
#else
#error only know how to build for FreeRTOS-LWIP, Linux, and MacOSX
#endif

    /* Connect will increment the connection count in wolfSentry, disconnect
     * will decrement it */
    switch(action) {
        case SENTRY_ACTION_CONNECT:
            action_results = WOLFSENTRY_ACTION_RES_CONNECT;
            break;
        case SENTRY_ACTION_DISCONNECT:
            action_results = WOLFSENTRY_ACTION_RES_DISCONNECT;
            break;
        case SENTRY_ACTION_NONE:
        default:
            action_results = WOLFSENTRY_ACTION_RES_NONE;
            break;
    }

    /* Setup sockaddr information to send to wolfSentry */
    remote.sa.sa_family = WOLFSENTRY_AF_INET;
    remote.sa.sa_proto = IPPROTO_TCP;
    remote.sa.sa_port = remote_port;
    /* Essentially a prefix size, wolfSentry uses the lesser of this and the
     * rule in JSON as to how much of the IP address to compare */
    remote.sa.addr_len = 32; // prefix size
    remote.sa.interface = 0;
    memcpy(remote.sa.addr, &remoteip, 4);

    local.sa.sa_family = WOLFSENTRY_AF_INET;
    local.sa.sa_proto = IPPROTO_TCP;
    local.sa.sa_port = local_port;
    local.sa.addr_len = 32;
    local.sa.interface = 0;
    memcpy(local.sa.addr, &localip, 4);

    /* Send the details of this to wolfSentry and get the result */
    ret = wolfsentry_route_event_dispatch_with_inited_result(
            wolfsentry,
            &remote.sa,
            &local.sa,
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
            "call-in-from-echo",
            strlen("call-in-from-echo"),
            NULL,
            NULL,
            NULL,
            &action_results);

    if (ret < 0) {
#ifdef DEBUG_WOLFSENTRY
        fprintf(stderr, "TCP Sentry action returned " WOLFSENTRY_ERROR_FMT "\n",
                WOLFSENTRY_ERROR_FMT_ARGS(ret));
#endif
    }

    /* Check the result, if it contains "reject" then notify the caller */
    if (WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT)) {
            return -1;
        }
    }

    return 0;
}



/* ############################################################################ */

static void free_wolfsentry_data(struct wolfsentry_data *data) {
    XFREE(data, data->heap, data->alloctype);
}

int wolfsentry_store_endpoints(
    WOLFSSL *ssl,
    struct sockaddr_in *remote,
    struct sockaddr_in *local,
    int proto,
    wolfsentry_route_flags_t flags,
    struct wolfsentry_data **wolfsentry_data_out)
{
    struct wolfsentry_data *wolfsentry_data = (struct wolfsentry_data *)XMALLOC(
        sizeof *wolfsentry_data, NULL, DYNAMIC_TYPE_SOCKADDR);
    if (wolfsentry_data == NULL)
        return WOLFSSL_FAILURE;
    memset(wolfsentry_data, 0, sizeof *wolfsentry_data);

    wolfsentry_data->heap = NULL;
    wolfsentry_data->alloctype = DYNAMIC_TYPE_SOCKADDR;

#ifdef TEST_IPV6
    if ((sizeof wolfsentry_data->remote.addr < sizeof remote->sin6_addr) ||
        (sizeof wolfsentry_data->local.addr < sizeof local->sin6_addr))
        return WOLFSSL_FAILURE;
    wolfsentry_data->remote.sa_family = wolfsentry_data->local.sa_family = remote->sin6_family;
    wolfsentry_data->remote.sa_port = ntohs(remote->sin6_port);
    wolfsentry_data->local.sa_port = ntohs(local->sin6_port);
    if (WOLFSENTRY_MASKIN_BITS(flags, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD)) {
        wolfsentry_data->remote.addr_len = 0;
        XMEMSET(wolfsentry_data->remote.addr, 0, sizeof remote->sin6_addr);
    } else {
        wolfsentry_data->remote.addr_len = sizeof remote->sin6_addr * BITS_PER_BYTE;
        XMEMCPY(wolfsentry_data->remote.addr, &remote->sin6_addr, sizeof remote->sin6_addr);
    }
    if (WOLFSENTRY_MASKIN_BITS(flags, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD)) {
        wolfsentry_data->local.addr_len = 0;
        XMEMSET(wolfsentry_data->local.addr, 0, sizeof local->sin6_addr);
    } else {
        wolfsentry_data->local.addr_len = sizeof local->sin6_addr * BITS_PER_BYTE;
        XMEMCPY(wolfsentry_data->local.addr, &local->sin6_addr, sizeof local->sin6_addr);
    }
#else
    if ((sizeof wolfsentry_data->remote.addr < sizeof remote->sin_addr) ||
        (sizeof wolfsentry_data->local.addr < sizeof local->sin_addr))
        return WOLFSSL_FAILURE;
    wolfsentry_data->remote.sa_family = wolfsentry_data->local.sa_family = remote->sin_family;
    wolfsentry_data->remote.sa_port = ntohs(remote->sin_port);
    wolfsentry_data->local.sa_port = ntohs(local->sin_port);
    if (WOLFSENTRY_MASKIN_BITS(flags, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD)) {
        wolfsentry_data->remote.addr_len = 0;
        XMEMSET(wolfsentry_data->remote.addr, 0, sizeof remote->sin_addr);
    } else {
        wolfsentry_data->remote.addr_len = sizeof remote->sin_addr * BITS_PER_BYTE;
        XMEMCPY(wolfsentry_data->remote.addr, &remote->sin_addr, sizeof remote->sin_addr);
    }
    if (WOLFSENTRY_MASKIN_BITS(flags, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD)) {
        wolfsentry_data->local.addr_len = 0;
        XMEMSET(wolfsentry_data->local.addr, 0, sizeof local->sin_addr);
    } else {
        wolfsentry_data->local.addr_len = sizeof local->sin_addr * BITS_PER_BYTE;
        XMEMCPY(wolfsentry_data->local.addr, &local->sin_addr, sizeof local->sin_addr);
    }
#endif
    wolfsentry_data->remote.sa_proto = wolfsentry_data->local.sa_proto = proto;
    wolfsentry_data->remote.interface = wolfsentry_data->local.interface = 0;
    wolfsentry_data->flags = flags;

    if (wolfSSL_set_ex_data_with_cleanup(
            ssl, wolfsentry_data_index, wolfsentry_data,
            (wolfSSL_ex_data_cleanup_routine_t)free_wolfsentry_data) !=
        WOLFSSL_SUCCESS) {
        free_wolfsentry_data(wolfsentry_data);
        return WOLFSSL_FAILURE;
    }

    if (wolfsentry_data_out != NULL)
        *wolfsentry_data_out = wolfsentry_data;

    return WOLFSSL_SUCCESS;
}

int wolfSentry_NetworkFilterCallback(
    WOLFSSL *ssl,
    struct wolfsentry_context *_wolfsentry,
    wolfSSL_netfilter_decision_t *decision)
{
    struct wolfsentry_data *data;
#ifdef DEBUG_WOLFSENTRY
    char inet_ntop_buf[INET6_ADDRSTRLEN], inet_ntop_buf2[INET6_ADDRSTRLEN];
#endif
    wolfsentry_errcode_t ret;

    if ((data = wolfSSL_get_ex_data(ssl, wolfsentry_data_index)) == NULL)
        return WOLFSSL_FAILURE;

    ret = wolfsentry_route_event_dispatch(
        _wolfsentry,
        (const struct wolfsentry_sockaddr *)&data->remote,
        (const struct wolfsentry_sockaddr *)&data->local,
        data->flags,
        "event-on-connect",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        data /* caller_context */,
        &data->rule_route_id /* id */,
        NULL /* inexact_matches */,
        &data->action_results);

    if (ret >= 0) {
        if (WOLFSENTRY_MASKIN_BITS(data->action_results, WOLFSENTRY_ACTION_RES_REJECT))
            *decision = WOLFSSL_NETFILTER_REJECT;
        else if (WOLFSENTRY_MASKIN_BITS(data->action_results, WOLFSENTRY_ACTION_RES_ACCEPT))
            *decision = WOLFSSL_NETFILTER_ACCEPT;
        else
            *decision = WOLFSSL_NETFILTER_PASS;
    } else {
        fprintf(stderr, "wolfsentry_route_event_dispatch error "
               WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        *decision = WOLFSSL_NETFILTER_PASS;
    }

#ifdef DEBUG_WOLFSENTRY
    printf("wolfSentry got network filter callback: family=%d proto=%d rport=%d"
           " lport=%d raddr=%s laddr=%s interface=%d; decision=%d (%s)\n",
           data->remote.sa_family,
           data->remote.sa_proto,
           data->remote.sa_port,
           data->local.sa_port,
           inet_ntop(data->remote.sa_family, data->remote.addr, inet_ntop_buf,
                     sizeof inet_ntop_buf),
           inet_ntop(data->local.sa_family, data->local.addr, inet_ntop_buf2,
                     sizeof inet_ntop_buf2),
           data->remote.interface,
           *decision,
           *decision == WOLFSSL_NETFILTER_REJECT ? "REJECT" :
           *decision == WOLFSSL_NETFILTER_ACCEPT ? "ACCEPT" :
           *decision == WOLFSSL_NETFILTER_PASS ? "PASS" :
           "???");
#endif

    return WOLFSSL_SUCCESS;
}


static wolfsentry_errcode_t wolfsentry_notify_via_UDP_JSON(
    struct wolfsentry_context *ws_ctx,
    const struct wolfsentry_action *action,
    void *handler_arg,
    void *caller_arg,
    const struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *trigger_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results)
{
    unsigned int res_bit;
    unsigned int n_res_bits = 0;
    const char *res_string;
    wolfsentry_errcode_t ret;
    struct wolfsentry_route_exports trigger_route_exports, rule_route_exports;
    const char *family_name;
    struct wolfsentry_addr_family_bynumber *addr_family;
    const char *notification_dest_addr;
    int notification_dest_addr_len;
    struct wolfsentry_kv_pair_internal *notification_dest_addr_record = NULL;
    uint64_t notification_dest_port;
    struct sockaddr_in sa;
    int pton_ret;
    int sockfd;
    wolfsentry_time_t when;
    struct timespec ts;
    struct tm tm;
    char timebuf[32];
    char msgbuf[1024], *msgbuf_ptr = msgbuf;
    int msgbuf_space_left = (int)sizeof msgbuf;
    int msgbuf_len;

    (void)handler_arg;
    (void)route_table;
    (void)action_type;

    if (trigger_route == NULL)
        WOLFSENTRY_RETURN_OK;

    if (caller_arg != NULL) {
        if (wolfsentry_object_checkout(rule_route) >= 0)
            ((struct wolfsentry_data *)caller_arg)->rule_route = rule_route;
    }

    ret = wolfsentry_route_export(ws_ctx, trigger_route, &trigger_route_exports);
    if (ret < 0)
        return ret;

    ret = wolfsentry_route_export(ws_ctx, rule_route, &rule_route_exports);
    if (ret < 0)
        return ret;
    ret = wolfsentry_user_value_get_uint(
        ws_ctx,
        "notification-dest-port",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        &notification_dest_port);

    if (ret < 0)
        return ret;

    ret = wolfsentry_user_value_get_string(
        ws_ctx,
        "notification-server-addr",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        &notification_dest_addr,
        &notification_dest_addr_len,
        &notification_dest_addr_record);

    if (ret < 0)
        return ret;

    sa.sin_family = AF_INET;

    pton_ret = inet_pton(AF_INET, notification_dest_addr, &sa.sin_addr);

    ret = wolfsentry_user_value_release_record(ws_ctx, &notification_dest_addr_record);
    if (ret < 0) {
        fprintf(stderr,
                "wolfsentry_user_value_release_record: " WOLFSENTRY_ERROR_FMT,
                WOLFSENTRY_ERROR_FMT_ARGS(ret));
        return ret;
    }

    switch (pton_ret) {
    case 1:
        break;
    case 0:
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    case -1:
    default:
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FAILED);
    }

    sa.sin_port = htons(notification_dest_port);

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 17 /* UDP */)) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FAILED);

    addr_family = NULL;
    family_name = wolfsentry_addr_family_ntop(ws_ctx, trigger_route_exports.sa_family, &addr_family, &ret);

    ret = wolfsentry_time_now_plus_delta(ws_ctx, 0 /* td */, &when);
    if (ret < 0)
        return ret;
    ret = wolfsentry_time_to_timespec(ws_ctx, when, &ts);
    if (ret < 0)
        return ret;
    if (gmtime_r(&ts.tv_sec, &tm) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FAILED);
    msgbuf_len = strftime(timebuf, sizeof timebuf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    if (msgbuf_len == 0)
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);

    /* note that strings, and ideally numbers, should use helpers in
     * centijson_sax.h, mainly json_dump_uint64() and json_dump_string(), which
     * furthermore take a JSON_DUMP_CALLBACK
     */
    msgbuf_len = snprintf(
        msgbuf_ptr,
        (size_t)msgbuf_space_left,
        "{ \"timestamp\" : \"%s\", \"action\" : \"%s\", \"trigger\" : %s%s%s, \"parent\" : %s%s%s, \"rule-id\" : " WOLFSENTRY_ENT_ID_FMT ", \"rule-hitcount\" : " WOLFSENTRY_HITCOUNT_FMT ", \"af\" : \"%s\", \"proto\" : %d, \"remote\" : { \"address\" : \"",
        timebuf,
        wolfsentry_action_get_label(action),
        trigger_event ? "\"" : "", trigger_event ? wolfsentry_event_get_label(trigger_event) : "null", trigger_event ? "\"" : "",
        trigger_route_exports.parent_event_label ? "\"" : "", trigger_route_exports.parent_event_label ? trigger_route_exports.parent_event_label : "null", trigger_route_exports.parent_event_label ? "\"" : "",
        wolfsentry_get_object_id(rule_route),
        rule_route_exports.meta.hit_count,
        family_name,
        trigger_route_exports.sa_proto);

    msgbuf_space_left -= msgbuf_len;
    if (msgbuf_space_left < 0) {
        fprintf(stderr,"out of space at L%d, msgbuf_len = %d, msgbuf_space_left = %d\n",
                __LINE__, msgbuf_len, msgbuf_space_left);
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
    }
    msgbuf_ptr += msgbuf_len;

    if (addr_family) {
        if ((ret = wolfsentry_addr_family_drop_reference(ws_ctx, addr_family, NULL /* action_results */ )) < 0) {
            fprintf(stderr, "wolfsentry_addr_family_drop_reference: " WOLFSENTRY_ERROR_FMT,
                    WOLFSENTRY_ERROR_FMT_ARGS(ret));
            return ret;
        }
    }

    msgbuf_len = msgbuf_space_left;
    ret = wolfsentry_route_format_address(
        ws_ctx,
        trigger_route_exports.sa_family,
        trigger_route_exports.remote_address,
        trigger_route_exports.remote.addr_len,
        msgbuf_ptr,
        &msgbuf_len);
    if (ret < 0) {
        fprintf(stderr, "wolfsentry_route_format_address: " WOLFSENTRY_ERROR_FMT,
                WOLFSENTRY_ERROR_FMT_ARGS(ret));
        return ret;
    }

    msgbuf_space_left -= msgbuf_len;
    if (msgbuf_space_left < 0) {
        fprintf(stderr,"out of space at L%d, msgbuf_len = %d, msgbuf_space_left = %d\n",
                __LINE__, msgbuf_len, msgbuf_space_left);
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
    }
    msgbuf_ptr += msgbuf_len;

    msgbuf_len = snprintf(
        msgbuf_ptr,
        (size_t)msgbuf_space_left,
        "\", \"port\" : %u }, \"local\" : { \"address\" : \"",
        trigger_route_exports.remote.sa_port);

    msgbuf_space_left -= msgbuf_len;
    if (msgbuf_space_left < 0) {
        fprintf(stderr,"out of space at L%d, msgbuf_len = %d, msgbuf_space_left = %d\n",
                __LINE__, msgbuf_len, msgbuf_space_left);
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
    }
    msgbuf_ptr += msgbuf_len;

    msgbuf_len = (int)msgbuf_space_left;
    ret = wolfsentry_route_format_address(
        ws_ctx,
        trigger_route_exports.sa_family,
        trigger_route_exports.local_address,
        trigger_route_exports.local.addr_len,
        msgbuf_ptr,
        &msgbuf_len);
    if (ret < 0) {
        fprintf(stderr, "wolfsentry_route_format_address: " WOLFSENTRY_ERROR_FMT,
                WOLFSENTRY_ERROR_FMT_ARGS(ret));
        return ret;
    }

    msgbuf_space_left -= msgbuf_len;
    if (msgbuf_space_left < 0) {
        fprintf(stderr,"out of space at L%d, msgbuf_len = %d, msgbuf_space_left = %d\n",
                __LINE__, msgbuf_len, msgbuf_space_left);
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
    }
    msgbuf_ptr += msgbuf_len;

    msgbuf_len = snprintf(
        msgbuf_ptr,
        (size_t)msgbuf_space_left,
        "\", \"port\" : %u }, \"decision\" : [",
        trigger_route_exports.local.sa_port);

    msgbuf_space_left -= msgbuf_len;
    if (msgbuf_space_left < 0) {
        fprintf(stderr,"out of space at L%d, msgbuf_len = %d, msgbuf_space_left = %d\n",
                __LINE__, msgbuf_len, msgbuf_space_left);
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
    }
    msgbuf_ptr += msgbuf_len;

    for (res_bit = 0; res_bit < 32U; ++res_bit) {
        if ((res_string = wolfsentry_action_res_decode(*action_results, res_bit)) != NULL) {
            ++n_res_bits;
            if (n_res_bits > 1) {
                *msgbuf_ptr++ = ',';
                --msgbuf_space_left;
                if (msgbuf_space_left < 0)
                    WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
            }
            msgbuf_len = snprintf(msgbuf_ptr, (size_t)msgbuf_space_left, "\"%s\"", res_string);
            msgbuf_space_left -= msgbuf_len;
            if (msgbuf_space_left < 0)
                WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
            msgbuf_ptr += msgbuf_len;
        }
    }

    msgbuf_len = snprintf(msgbuf_ptr, msgbuf_space_left, "]}");
    msgbuf_space_left -= msgbuf_len;
    if (msgbuf_space_left < 0) {
        fprintf(stderr,"out of space at L%d, msgbuf_len = %d, msgbuf_space_left = %d\n",
                __LINE__, msgbuf_len, msgbuf_space_left);
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
    }
    msgbuf_ptr += msgbuf_len;

    /* squelch code can go around here, but the squelch thresh for the circlog should be higher. */

    if (sendto(
            sockfd,
            msgbuf,
            sizeof msgbuf - (size_t)msgbuf_space_left,
            0 /* flags */,
            (const struct sockaddr *)&sa, sizeof sa) < 0)
        perror("sendto");
    close(sockfd);

    {
        char *circlog_buf;
        ret = circlog_enqueue_one(sizeof msgbuf - (size_t)msgbuf_space_left, &circlog_buf);
        if (ret < 0) {
            fprintf(stderr, " %s L%d circlog failed: " WOLFSENTRY_ERROR_FMT "\n", __FILE__, __LINE__, WOLFSENTRY_ERROR_FMT_ARGS(ret));
        } else
            memcpy(circlog_buf, msgbuf, sizeof msgbuf - (size_t)msgbuf_space_left);
    }

    return 0;
}

static wolfsentry_errcode_t handle_commendable(
    struct wolfsentry_context *ws_ctx,
    const struct wolfsentry_action *action,
    void *handler_arg,
    void *caller_arg,
    const struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *trigger_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results)
{
    struct wolfsentry_route_exports rule_route_exports;
    wolfsentry_errcode_t ret;

    (void)action;
    (void)handler_arg;
    (void)caller_arg;
    (void)trigger_route;
    (void)route_table;

#ifdef DEBUG_WOLFSENTRY
    fprintf(stderr,"called action %s for event %s and action type %u\n", wolfsentry_action_get_label(action), wolfsentry_event_get_label(trigger_event), action_type);
#else
    (void)trigger_event;
    (void)action_type;
#endif

    /* if the rule_route is a netblock, add a new route for
     * wolfsentry_data.remote.s_addr, wildcard ports, wildcard dest, and
     * increment its commendable count.
     */

    ret = wolfsentry_route_export(ws_ctx, rule_route, &rule_route_exports);
    if (ret < 0)
        return ret;

    if (rule_route_exports.remote.addr_len == 32)
        *action_results |= WOLFSENTRY_ACTION_RES_COMMENDABLE;

    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t handle_transaction_successful(
    struct wolfsentry_context *ws_ctx,
    const struct wolfsentry_action *action,
    void *handler_arg,
    void *caller_arg,
    const struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *trigger_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results)
{
    return handle_commendable(ws_ctx, action, handler_arg, caller_arg, trigger_event, action_type, trigger_route, route_table, rule_route, action_results);
}

static wolfsentry_errcode_t handle_derogatory(
    struct wolfsentry_context *ws_ctx,
    const struct wolfsentry_action *action,
    void *handler_arg,
    void *caller_arg,
    const struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *trigger_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results)
{
    struct wolfsentry_route_exports rule_route_exports;
    wolfsentry_errcode_t ret;
    int new_derogatory_count;

    (void)action;
    (void)handler_arg;
    (void)caller_arg;
    (void)trigger_route;
    (void)route_table;
    (void)action_results;

    ret = wolfsentry_route_export(ws_ctx, rule_route, &rule_route_exports);
    if (ret < 0)
        return ret;

#ifdef DEBUG_WOLFSENTRY
    fprintf(stderr,"called action %s for event %s and action type %u\n", wolfsentry_action_get_label(action), wolfsentry_event_get_label(trigger_event), action_type);
#else
    (void)trigger_event;
    (void)action_type;
#endif

    /* if the rule_route is a netblock, add a new route for
     * wolfsentry_data.remote.s_addr, wildcard ports, wildcard dest, and
     * increment its derogatory count.
     */

    if (rule_route_exports.remote.addr_len == 32)
        *action_results |= WOLFSENTRY_ACTION_RES_DEROGATORY;
    else {
        struct wolfsentry_sockaddr *remote_addr = (struct wolfsentry_sockaddr *)&((struct wolfsentry_data *)caller_arg)->remote;
        char addr_buffer[128];
        int addr_buffer_len = sizeof addr_buffer;
        struct wolfsentry_route *new_route = NULL;
        wolfsentry_action_res_t action_results_2;

        ret = wolfsentry_route_format_address(
            ws_ctx,
            remote_addr->sa_family,
            remote_addr->addr,
            remote_addr->addr_len,
            addr_buffer,
            &addr_buffer_len);

        if (ret < 0)
            return ret;

        ret = wolfsentry_route_insert_and_check_out(
            ws_ctx,
            NULL /* void *caller_arg*/, /* passed to action callback(s) as the caller_arg. */
            (struct wolfsentry_sockaddr *)&((struct wolfsentry_data *)caller_arg)->remote,
            (struct wolfsentry_sockaddr *)&((struct wolfsentry_data *)caller_arg)->local,
            WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD|
            WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD|
            WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD|
            WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD|
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD|
            WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD|
            WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS|
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN|
            WOLFSENTRY_ROUTE_FLAG_GREENLISTED, /* greenlist the peer until it exceeds the derogatory threshold. */
            "dynamic-within-netblock",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            &new_route,
            &action_results_2);

        if (ret < 0) {
            fprintf(stderr, "wolfsentry_route_insert_and_check_out() returned " WOLFSENTRY_ERROR_FMT "\n",
                    WOLFSENTRY_ERROR_FMT_ARGS(ret));
            return ret;
        }

        ret = wolfsentry_route_increment_derogatory_count(ws_ctx, new_route, 1 /* count_to_add */, &new_derogatory_count);
        if (ret < 0) {
            fprintf(stderr, "wolfsentry_route_increment_derogatory_count() returned " WOLFSENTRY_ERROR_FMT "\n",
                    WOLFSENTRY_ERROR_FMT_ARGS(ret));
        } else {
#ifdef DEBUG_WOLFSENTRY
            fprintf(stderr, "%s L%d new derogatory count for new route %u: %d\n", __FILE__, __LINE__, wolfsentry_get_object_id(new_route), new_derogatory_count);
#endif
        }

        ret = wolfsentry_route_drop_reference(ws_ctx, new_route, NULL /* action_results */);
        if (ret < 0) {
            fprintf(stderr, "wolfsentry_route_drop_reference() returned "
                    WOLFSENTRY_ERROR_FMT "\n",
                    WOLFSENTRY_ERROR_FMT_ARGS(ret));
        }

    }

    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t handle_transaction_failed(
    struct wolfsentry_context *ws_ctx,
    const struct wolfsentry_action *action,
    void *handler_arg,
    void *caller_arg,
    const struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *trigger_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results)
{
    return handle_derogatory(ws_ctx, action, handler_arg, caller_arg, trigger_event, action_type, trigger_route, route_table, rule_route, action_results);
}

static wolfsentry_errcode_t handle_handshake_failed(
    struct wolfsentry_context *ws_ctx,
    const struct wolfsentry_action *action,
    void *handler_arg,
    void *caller_arg,
    const struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *trigger_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results)
{
    return handle_derogatory(ws_ctx, action, handler_arg, caller_arg, trigger_event, action_type, trigger_route, route_table, rule_route, action_results);
}

static wolfsentry_errcode_t my_addr_family_parser(
    struct wolfsentry_context *ws_ctx,
    const char *addr_text,
    const int addr_text_len,
    byte *addr_internal,
    wolfsentry_addr_bits_t *addr_internal_len)
{
    uint32_t a[3];
    char abuf[32];
    int n_octets, parsed_len = 0, i;

    (void)ws_ctx;

    if (snprintf(abuf,sizeof abuf,"%.*s",addr_text_len,addr_text) >= (int)sizeof abuf)
        WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
    if ((n_octets = sscanf(abuf,"%o/%o/%o%n",&a[0],&a[1],&a[2],&parsed_len)) < 1)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    if (parsed_len != addr_text_len) {
        if ((n_octets = sscanf(abuf,"%o/%o/%n",&a[0],&a[1],&parsed_len)) < 1)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    }
    if (parsed_len != addr_text_len) {
        if ((n_octets = sscanf(abuf,"%o/%n",&a[0],&parsed_len)) < 1)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    }
    if (parsed_len != addr_text_len)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    for (i = 0; i < n_octets; ++i) {
        if (a[i] > MAX_UINT_OF(byte))
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        addr_internal[i] = (byte)a[i];
    }
    *addr_internal_len = (wolfsentry_addr_bits_t)(n_octets * 8);
    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t my_addr_family_formatter(
    struct wolfsentry_context *ws_ctx,
    const byte *addr_internal,
    const unsigned int addr_internal_len,
    char *addr_text,
    int *addr_text_len)
{
    int out_len;
    int ret;

    (void)ws_ctx;

    if (addr_internal_len <= 8)
        out_len = snprintf(addr_text, (size_t)*addr_text_len,
                           "%o/",(unsigned int)addr_internal[0]);
    else if (addr_internal_len <= 16)
        out_len = snprintf(addr_text, (size_t)*addr_text_len,
                           "%o/%o/",(unsigned int)addr_internal[0],(unsigned int)addr_internal[1]);
    else
        out_len = snprintf(addr_text, (size_t)*addr_text_len,
                           "%o/%o/%o",(unsigned int)addr_internal[0],(unsigned int)addr_internal[1],(unsigned int)addr_internal[2]);
    if (out_len >= *addr_text_len)
        ret = WOLFSENTRY_ERROR_ENCODE(BUFFER_TOO_SMALL);
    else
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
    *addr_text_len = out_len;
    return ret;
}

int sentry_init(
    WOLFSSL_CTX *wolfssl_ctx,
    struct wolfsentry_host_platform_interface *hpi,
    const char *json_config)
{
    wolfsentry_errcode_t ret;
    static const struct wolfsentry_eventconfig ws_init_config = { .route_private_data_size = 32, .route_private_data_alignment = 16 };
    char err_buf[512];
    int errline;
    wolfsentry_ent_id_t id;

    if (json_config == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    ret =  wolfsentry_init(hpi, &ws_init_config,
                           &wolfsentry);
    if (ret < 0) {
        fprintf(stderr, "wolfsentry_init() returned " WOLFSENTRY_ERROR_FMT "\n",
                WOLFSENTRY_ERROR_FMT_ARGS(ret));
        errline = __LINE__;
        goto out;
    }

    ret = wolfsentry_addr_family_handler_install(
        wolfsentry,
        WOLFSENTRY_AF_USER_OFFSET,
        "my_AF",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        my_addr_family_parser,
        my_addr_family_formatter,
        24 /* max_addr_bits */);
    if (ret < 0) {
        errline = __LINE__;
        goto out;
    }

    ret = wolfsentry_action_insert(
        wolfsentry,
        "handle-insert",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        wolfsentry_test_action,
        NULL,
        &id);
    if (ret < 0) {
        errline = __LINE__;
        goto out;
    }

    ret = wolfsentry_action_insert(
        wolfsentry,
        "handle-delete",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        wolfsentry_test_action,
        NULL,
        &id);
    if (ret < 0) {
        errline = __LINE__;
        goto out;
    }

    ret = wolfsentry_action_insert(
        wolfsentry,
        "handle-match",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        wolfsentry_test_action,
        NULL,
        &id);
    if (ret < 0) {
        errline = __LINE__;
        goto out;
    }

    ret = wolfsentry_action_insert(
        wolfsentry,
        "notify-on-match",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        wolfsentry_test_action,
        NULL,
        &id);
    if (ret < 0) {
        errline = __LINE__;
        goto out;
    }

    ret = wolfsentry_action_insert(
        wolfsentry,
        "handle-update",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        wolfsentry_test_action,
        NULL,
        &id);
    if (ret < 0) {
        errline = __LINE__;
        goto out;
    }

    ret = wolfsentry_action_insert(
        wolfsentry,
        "notify-on-decision",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        wolfsentry_notify_via_UDP_JSON,
        NULL,
        &id);
    if (ret < 0) {
        errline = __LINE__;
        goto out;
    }

    ret = wolfsentry_action_insert(
        wolfsentry,
        "handle-transaction-successful",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        handle_transaction_successful,
        NULL,
        &id);
    if (ret < 0) {
        errline = __LINE__;
        goto out;
    }

    ret = wolfsentry_action_insert(
        wolfsentry,
        "handle-transaction-failed",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        handle_transaction_failed,
        NULL,
        &id);
    if (ret < 0) {
        errline = __LINE__;
        goto out;
    }

    ret = wolfsentry_action_insert(
        wolfsentry,
        "handle-handshake-failed",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        handle_handshake_failed,
        NULL,
        &id);
    if (ret < 0) {
        errline = __LINE__;
        goto out;
    }

    ret = wolfsentry_action_insert(
        wolfsentry,
        "handle-connect",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        wolfsentry_test_action,
        NULL,
        &id);
    if (ret < 0) {
        errline = __LINE__;
        goto out;
    }

    ret = wolfsentry_action_insert(
        wolfsentry,
        "handle-connect2",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        wolfsentry_test_action,
        NULL,
        &id);
    if (ret < 0) {
        errline = __LINE__;
        goto out;
    }

    ret = wolfsentry_config_json_oneshot(
        wolfsentry,
        json_config,
        strlen(json_config),
        WOLFSENTRY_CONFIG_LOAD_FLAG_NONE,
        err_buf,
        sizeof err_buf);

    if (ret < 0) {
        fprintf(stderr, "wolfsentry_config_json_init() failed: %s\n", err_buf);
        errline = __LINE__;
        goto out;
    }

    if (wolfsentry_data_index < 0)
        wolfsentry_data_index = wolfSSL_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_SSL, NULL, NULL, NULL,
                                                         NULL);

    ret = wolfSSL_CTX_set_AcceptFilter(
            wolfssl_ctx,
            (NetworkFilterCallback_t)wolfSentry_NetworkFilterCallback,
            wolfsentry);
    if (ret < 0) {
        fprintf(stderr, "wolfSSL_CTX_set_AcceptFilter() failed with code %d \"%s\".\n", ret, wolfSSL_ERR_reason_error_string(ret));
        errline = __LINE__;
        goto out;
    }

out:

    if (ret < 0) {
        fprintf(stderr, "fatal error at line %d.\n", errline);
        if (wolfsentry != NULL)
            (void)wolfsentry_shutdown(&wolfsentry);
    }

    return ret;
}




#ifdef BUILD_FOR_FREERTOS_LWIP

/* Check / validate ICMP traffic */
int sentry_action_ping(const ip_addr_t *addr, u8_t type)
{
    wolfsentry_errcode_t ret;
    wolfsentry_action_res_t action_results;
    /* As above, pad the struct to make addr 4 bytes */
    struct {
        struct wolfsentry_sockaddr sa;
        byte addr_buf[4];
    } remote;

    /* ICMP protocol check. The ICMP packet type is the port number for this
     * check */
    remote.sa.sa_family = WOLFSENTRY_AF_INET;
    remote.sa.sa_proto = IPPROTO_ICMP;
    remote.sa.sa_port = type;
    remote.sa.addr_len = 32;
    remote.sa.interface = 0;
    memcpy(remote.sa.addr, &addr->addr, 4);

    ret = wolfsentry_route_event_dispatch(
            wolfsentry,
            &remote.sa,
            &remote.sa, // Reuse for now
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
            "call-in-from-echo",
            strlen("call-in-from-echo"),
            NULL,
            NULL,
            NULL,
            &action_results);
    printf("PING Sentry action returned " WOLFSENTRY_ERROR_FMT "\n",
                WOLFSENTRY_ERROR_FMT_ARGS(ret));
    fflush(stdout);
    if (WOLFSENTRY_ERROR_DECODE_ERROR_CODE(ret) >= 0) {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT)) {
            return -1;
        }
    }

    return 0;
}

/* Check MAC address */
int sentry_action_mac(struct eth_addr *addr)
{
    wolfsentry_errcode_t ret;
    wolfsentry_action_res_t action_results;
    /* Pad addr to 6 bytes for the hardware address */
    struct {
        struct wolfsentry_sockaddr sa;
        byte addr_buf[6];
    } remote;

    /* We only really care about the data and length, the family is AF_LINK */
    remote.sa.sa_family = WOLFSENTRY_AF_LINK;
    remote.sa.addr_len = 48;
    remote.sa.interface = 0;
    // MAC addresses are 6 bytes (48 bits)
    memcpy(remote.sa.addr, &addr->addr, 6);

    ret = wolfsentry_route_event_dispatch(
            wolfsentry,
            &remote.sa,
            &remote.sa, // Reuse for now
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
            "call-in-from-echo",
            strlen("call-in-from-echo"),
            NULL,
            NULL,
            NULL,
            &action_results);

    printf("MAC Sentry action returned " WOLFSENTRY_ERROR_FMT "\n",
                WOLFSENTRY_ERROR_FMT_ARGS(ret));
    fflush(stdout);
    if (WOLFSENTRY_ERROR_DECODE_ERROR_CODE(ret) >= 0) {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT)) {
            return -1;
        }
    }

    return 0;
}

#endif /* BUILD_FOR_FREERTOS_LWIP */
