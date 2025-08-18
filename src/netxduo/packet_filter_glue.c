/**
 * @file packet_filter_glue.c
 * @brief NetX Duo packet filter glue code for WolfSentry integration
 *
 * This file provides network address conversion functions and packet filter
 * integration for WolfSentry with NetX Duo TCP/IP stack. It includes
 * implementations of inet_ntop and inet_pton functions compatible with
 * NetX Duo data structures, supporting both IPv4 and IPv6 addresses.
 *
 * @author wolfSSL Inc.
 * @date 2021-2025
 *
 * Copyright (C) 2021-2025 wolfSSL Inc.
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
#include <wolfsentry/wolfsentry_netxduo.h>
#include <string.h>


/* Constants for address conversion */
#define MAX_UINT32_DECIMAL_LEN  12    /* Max for 32-bit: 4294967295 (10 digits) + null + extra */
#define MAX_UINT32_HEX_LEN      8     /* Max for 32-bit: 8 hex digits */
#define IPV4_OCTETS             4     /* Number of octets in IPv4 address */
#define IPV6_GROUPS             8     /* Number of 16-bit groups in IPv6 address */
#define IPV4_MAPPED_PREFIX_LEN  10    /* Length of zero prefix in IPv4-mapped IPv6 */
#define IPV4_MAPPED_MARKER_POS  10    /* Position of 0xFF markers in IPv4-mapped IPv6 */
#define IPV4_MAPPED_ADDR_POS    12    /* Position of IPv4 address in IPv4-mapped IPv6 */
#define IPV4_MAPPED_PREFIX_STR  "::ffff:"
#define IPV4_MAPPED_PREFIX_STR_LEN  (sizeof(IPV4_MAPPED_PREFIX_STR) - 1)

/* Buffer size constants */
#define MIN_IPV4_STRING_LEN     16    /* Min size for "255.255.255.255\0" */
#define MIN_IPV6_STRING_LEN     40    /* Min size for full IPv6 address */
#define MIN_IPV4_MAPPED_LEN     23    /* Min size for "::ffff:255.255.255.255\0" */

/* Network constants */
#define MAX_IPV4_OCTET_VALUE    255
#define MAX_IPV6_GROUP_VALUE    0xFFFF
#define IPV4_MAPPED_MARKER      0xFF
#define DECIMAL_BASE            10
#define HEXADECIMAL_BASE        16


/**
 * @brief Convert unsigned integer to string representation (decimal or hexadecimal)
 *
 * @param val The unsigned integer value to convert
 * @param buf Buffer to store the resulting string
 * @param buf_size Size of the buffer in bytes
 * @param base Number base for conversion (10 for decimal, 16 for hexadecimal)
 *
 * @return Length of the resulting string on success, -1 on error (buffer too small)
 */
static int uint_to_string(unsigned int val, char *buf, int buf_size, int base)
{
    char temp[MAX_UINT32_DECIMAL_LEN];
    int i = 0, j = 0;
    int result = -1;

    if (buf_size >= 1) {
        if (val == 0) {
            if (buf_size >= 2) {
                buf[0] = '0';
                buf[1] = '\0';
                result = 1;
            }
        } else {
            while (val > 0) {
                int digit = val % base;
                if (digit < 10)
                    temp[i++] = '0' + digit;
                else
                    temp[i++] = 'a' + (digit - 10);
                val /= base;
            }

            while (i > 0 && j < buf_size - 1) {
                buf[j++] = temp[--i];
            }

            if (i == 0) {
                buf[j] = '\0';
                result = j;
            }
        }
    }

    return result;
}

/**
 * @brief Append string or single character to buffer with bounds checking
 *
 * @param p Pointer to current position in buffer (updated after append)
 * @param end Pointer to end of buffer (one past last valid position)
 * @param str String to append (if not NULL), or NULL to append single character
 * @param single_char Character to append when str is NULL
 *
 * @return 0 on success, -1 on error (buffer overflow)
 */
static int append_content(char **p, char *end, const char *str, char single_char)
{
    int result = 0;

    if (str) {
        while (*str && result == 0) {
            if (*p >= end) {
                result = -1;
            } else {
                *(*p)++ = *str++;
            }
        }
    } else {
        if (*p >= end) {
            result = -1;
        } else {
            *(*p)++ = single_char;
        }
    }

    return result;
}

/**
 * @brief Parse IPv4 address string into byte array
 *
 * @param src IPv4 address string in dotted decimal notation (e.g., "192.168.1.1")
 * @param bytes Output buffer for 4 bytes representing the IPv4 address
 *
 * @return 1 on success, 0 on error (invalid format or octet value > 255)
 */
static int parse_ipv4(const char *src, unsigned char *bytes)
{
    const char *p = src;
    int i;
    int result = 0;

    for (i = 0; i < IPV4_OCTETS && result == 0; i++) {
        unsigned long val = 0;
        int digit = 0;

        while (*p >= '0' && *p <= '9' && result == 0) {
            val = val * DECIMAL_BASE + (*p - '0');
            if (val > MAX_IPV4_OCTET_VALUE) {
                result = 0;
                break;
            }
            digit = 1;
            p++;
        }

        if (!digit) {
            result = 0;
            break;
        }

        bytes[i] = (unsigned char)val;

        if (i < IPV4_OCTETS - 1) {
            if (*p != '.') {
                result = 0;
                break;
            }
            p++;
        } else {
            if (*p != '\0') {
                result = 0;
                break;
            }
        }
    }

    if (result == 0 && i == IPV4_OCTETS) {
        result = 1;
    }

    return result;
}

/**
 * @brief Convert network address from binary to presentation format
 *
 * This function converts a network address from binary format to a string
 * representation suitable for presentation. It supports both IPv4 and IPv6
 * addresses, including IPv4-mapped IPv6 addresses.
 *
 * @param af Address family (AF_INET for IPv4, AF_INET6 for IPv6)
 * @param src Pointer to binary network address structure
 * @param dst Buffer to store the resulting string representation
 * @param size Size of the destination buffer
 *
 * @return Pointer to dst on success, NULL on error
 *         Returns NULL if:
 *         - Invalid parameters (dst is NULL, size is 0)
 *         - Unsupported address family
 *         - Buffer too small for the address string
 *         - Internal conversion error
 */
const char *wolfsentry_inet_ntop(int af, const void *src, char *dst, size_t size)
{
    const char *result = NULL;

    if (dst != NULL && size > 0) {
        switch (af) {
        case AF_INET:
        {
            const struct nx_bsd_in_addr *addr4 = (const struct nx_bsd_in_addr *)src;
            const unsigned char *bytes = (const unsigned char *)&addr4->s_addr;
            char *p = dst;
            char *end = dst + size;
            char temp_buf[MAX_UINT32_DECIMAL_LEN];
            int len, i;
            int success = 1;

            if (size >= MIN_IPV4_STRING_LEN) {
                /* Process bytes in network byte order */
                for (i = 0; i < IPV4_OCTETS && success; i++) {
                    if (i > 0 && append_content(&p, end, NULL, '.') < 0) {
                        success = 0;
                        break;
                    }

#ifdef __BIG_ENDIAN__
                    len = uint_to_string(bytes[i], temp_buf, sizeof(temp_buf), DECIMAL_BASE);
#else
                    len = uint_to_string(bytes[IPV4_OCTETS - 1 - i], temp_buf, sizeof(temp_buf), DECIMAL_BASE);
#endif
                    if (len < 0 || append_content(&p, end, temp_buf, 0) < 0) {
                        success = 0;
                        break;
                    }
                }

                if (success && append_content(&p, end, NULL, '\0') >= 0) {
                    result = dst;
                }
            }
            break;
        }

        case AF_INET6:
        {
            const struct nx_bsd_in6_addr *addr6 = (const struct nx_bsd_in6_addr *)src;
            const unsigned char *bytes = addr6->_S6_un._S6_u8;
            char *p = dst, *end = dst + size;
            int best_base = -1, best_len = 0, cur_base = -1, cur_len = 0;
            int i;
            int is_ipv4_mapped = 1;
            char temp_buf[MAX_UINT32_DECIMAL_LEN];
            int len;
            unsigned int val;
            char hex_buf[MAX_UINT32_HEX_LEN];
            int hex_len;
            int success = 1;

            if (size >= MIN_IPV6_STRING_LEN) {
                /* Check for IPv4-mapped IPv6 address */
                for (i = 0; i < IPV4_MAPPED_PREFIX_LEN; i++) {
                    if (bytes[i] != 0) {
                        is_ipv4_mapped = 0;
                        break;
                    }
                }

                if (is_ipv4_mapped && bytes[IPV4_MAPPED_MARKER_POS] == IPV4_MAPPED_MARKER
                    && bytes[IPV4_MAPPED_MARKER_POS + 1] == IPV4_MAPPED_MARKER) {

                    if (size >= MIN_IPV4_MAPPED_LEN) {
                        if (append_content(&p, end, IPV4_MAPPED_PREFIX_STR, 0) >= 0) {
                            for (i = 0; i < IPV4_OCTETS && success; i++) {
                                if (i > 0 && append_content(&p, end, NULL, '.') < 0) {
                                    success = 0;
                                    break;
                                }

                                len = uint_to_string(bytes[IPV4_MAPPED_ADDR_POS + i], temp_buf, sizeof(temp_buf), DECIMAL_BASE);
                                if (len < 0 || append_content(&p, end, temp_buf, 0) < 0) {
                                    success = 0;
                                    break;
                                }
                            }

                            if (success && append_content(&p, end, NULL, '\0') >= 0) {
                                result = dst;
                            }
                        }
                    }
                } else {
                    /* Find longest sequence of zeros for :: compression */
                    for (i = 0; i < IPV6_GROUPS; i++) {
                        if (bytes[i * 2] == 0 && bytes[i * 2 + 1] == 0) {
                            if (cur_base == -1) {
                                cur_base = i;
                                cur_len = 1;
                            } else {
                                cur_len++;
                            }
                        } else {
                            if (cur_base != -1) {
                                if (cur_len > best_len) {
                                    best_base = cur_base;
                                    best_len = cur_len;
                                }
                                cur_base = -1;
                            }
                        }
                    }

                    if (cur_base != -1 && cur_len > best_len) {
                        best_base = cur_base;
                        best_len = cur_len;
                    }

                    if (best_len < 2) {
                        best_base = -1;
                        best_len = 0;
                    }

                    for (i = 0; i < IPV6_GROUPS && success; i++) {
                        if (best_base != -1 && i >= best_base && i < best_base + best_len) {
                            if (i == best_base) {
                                if (p + 2 >= end) {
                                    success = 0;
                                    break;
                                }
                                *p++ = ':';
                                *p++ = ':';
                            }
                            continue;
                        }

                        if (i > 0 && !(best_base != -1 && i == best_base + best_len)) {
                            if (p + 1 >= end) {
                                success = 0;
                                break;
                            }
                            *p++ = ':';
                        }

                        val = (bytes[i * 2] << 8) | bytes[i * 2 + 1];
                        hex_len = uint_to_string(val, hex_buf, sizeof(hex_buf), HEXADECIMAL_BASE);

                        if (hex_len < 0 || append_content(&p, end, hex_buf, 0) < 0) {
                            success = 0;
                            break;
                        }
                    }

                    if (success) {
                        *p = '\0';
                        result = dst;
                    }
                }
            }
            break;
        }

        default:
            break;
        }
    }

    return result;
}

/**
 * @brief Convert network address from presentation to binary format
 *
 * This function converts a network address from string representation to
 * binary format. It supports both IPv4 and IPv6 addresses, including
 * IPv4-mapped IPv6 addresses (::ffff:w.x.y.z format).
 *
 * @param af Address family (AF_INET for IPv4, AF_INET6 for IPv6)
 * @param src String representation of the network address
 * @param dst Buffer to store the resulting binary address structure
 *
 * @return 1 on success (valid address converted)
 *         0 on invalid address format
 *         -1 on error (invalid parameters or unsupported address family)
 */
int wolfsentry_inet_pton(int af, const char* src, void* dst)
{
    int result = -1;

    if (src != NULL && dst != NULL) {
        switch (af) {
        case AF_INET:
        {
            struct nx_bsd_in_addr *addr4 = (struct nx_bsd_in_addr *)dst;
            unsigned char bytes[4];

            if (parse_ipv4(src, bytes)) {
                addr4->s_addr = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
                result = 1;
            } else {
                result = 0;
            }
            break;
        }

        case AF_INET6:
        {
            struct nx_bsd_in6_addr *addr6 = (struct nx_bsd_in6_addr *)dst;
            const char *p = src;
            unsigned short groups[IPV6_GROUPS] = {0};
            int group_count = 0, double_colon_pos = -1;
            int i;
            unsigned char ipv4_bytes[IPV4_OCTETS];
            unsigned long val;
            int digit;
            int hex_val;
            int parse_success = 1;

            /* Check for IPv4-mapped IPv6 address */
            if (strncmp(p, IPV4_MAPPED_PREFIX_STR, IPV4_MAPPED_PREFIX_STR_LEN) == 0) {
                if (parse_ipv4(p + IPV4_MAPPED_PREFIX_STR_LEN, ipv4_bytes)) {
                    /* Set IPv4-mapped IPv6 address */
                    for (i = 0; i < IPV4_MAPPED_PREFIX_LEN; i++)
                        addr6->_S6_un._S6_u8[i] = 0;
                    addr6->_S6_un._S6_u8[IPV4_MAPPED_MARKER_POS] = IPV4_MAPPED_MARKER;
                    addr6->_S6_un._S6_u8[IPV4_MAPPED_MARKER_POS + 1] = IPV4_MAPPED_MARKER;
                    for (i = 0; i < IPV4_OCTETS; i++)
                        addr6->_S6_un._S6_u8[IPV4_MAPPED_ADDR_POS + i] = ipv4_bytes[i];
                    result = 1;
                } else {
                    result = 0;
                }
            } else {
                /* Handle leading :: */
                if (*p == ':') {
                    if (*(p + 1) != ':') {
                        parse_success = 0;
                    } else {
                        double_colon_pos = 0;
                        p += 2;
                    }
                }

                while (*p != '\0' && parse_success) {
                    if (*p == ':') {
                        if (double_colon_pos != -1) {
                            parse_success = 0;
                            break;
                        }
                        double_colon_pos = group_count;
                        p++;
                        if (*p == '\0')
                            break;
                        continue;
                    }

                    /* Parse hexadecimal group */
                    val = 0;
                    digit = 0;

                    while ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) {
                        if (*p >= '0' && *p <= '9')
                            hex_val = *p - '0';
                        else if (*p >= 'a' && *p <= 'f')
                            hex_val = *p - 'a' + DECIMAL_BASE;
                        else
                            hex_val = *p - 'A' + DECIMAL_BASE;

                        val = val * HEXADECIMAL_BASE + hex_val;
                        if (val > MAX_IPV6_GROUP_VALUE) {
                            parse_success = 0;
                            break;
                        }
                        digit = 1;
                        p++;
                    }

                    if (!digit || group_count >= IPV6_GROUPS) {
                        parse_success = 0;
                        break;
                    }

                    groups[group_count++] = (unsigned short)val;

                    if (*p == ':') {
                        p++;
                        if (*p == ':') {
                            if (double_colon_pos != -1) {
                                parse_success = 0;
                                break;
                            }
                            double_colon_pos = group_count;
                            p++;
                            if (*p == '\0')
                                break;
                        } else if (*p == '\0') {
                            parse_success = 0;
                            break;
                        }
                    }
                }

                if (parse_success) {
                    /* Handle :: compression */
                    if (double_colon_pos != -1) {
                        int zeros_needed = IPV6_GROUPS - group_count;
                        if (zeros_needed >= 0) {
                            for (i = group_count - 1; i >= double_colon_pos; i--)
                                groups[i + zeros_needed] = groups[i];

                            for (i = double_colon_pos; i < double_colon_pos + zeros_needed; i++)
                                groups[i] = 0;
                        } else {
                            parse_success = 0;
                        }
                    } else {
                        if (group_count != IPV6_GROUPS) {
                            parse_success = 0;
                        }
                    }

                    if (parse_success) {
                        /* Store in network byte order */
                        for (i = 0; i < IPV6_GROUPS; i++) {
                            addr6->_S6_un._S6_u8[i * 2] = (unsigned char)(groups[i] >> 8);
                            addr6->_S6_un._S6_u8[i * 2 + 1] = (unsigned char)(groups[i] & 0xFF);
                        }
                        result = 1;
                    } else {
                        result = 0;
                    }
                } else {
                    result = 0;
                }
            }
            break;
        }

        default:
            break;
        }
    }

    return result;
}

#ifndef PACKED_STRUCT
#define PACKED_STRUCT __attribute__((__packed__))
#endif

struct PACKED_STRUCT netx_ip_header {
    struct {
        uint8_t  version : 4;
        uint8_t  ihl     : 4;
    };
    struct {
        uint8_t  dscp : 6;
        uint8_t  ecn  : 2;
    };
    uint16_t     total_length;
    uint16_t     identification;
    struct {
        uint16_t flags           :  3;
        uint16_t fragment_offset : 13;
    };
    uint8_t      time_to_live;
    uint8_t      protocol;
    uint16_t     header_checksum;
    uint32_t     source_ip;
    uint32_t     dest_ip;
};

struct PACKED_STRUCT netx_udp_header {
    uint16_t    source_port;
    uint16_t    dest_port;
    uint16_t    length;
    uint16_t    checksum;
};

struct PACKED_STRUCT netx_tcp_header
{
    uint16_t     source_port;
    uint16_t     dest_port;
    uint32_t     sequence_number;
    uint32_t     acknowledgement_number;
    struct {
        uint16_t data_offset : 4;
        uint16_t reserved    : 3;
        uint16_t ns          : 1;
        uint16_t cwr         : 1;
        uint16_t ece         : 1;
        uint16_t urg         : 1;
        uint16_t ack         : 1;
        uint16_t psh         : 1;
        uint16_t rst         : 1;
        uint16_t syn         : 1;
        uint16_t fin         : 1;
    };
    uint16_t     window_size;
    uint16_t     checksum;
    uint16_t     urgent_pointer;
};

struct PACKED_STRUCT netx_arp_header
{
    uint16_t arp_htype;
    uint16_t arp_ptype;
    uint8_t  arp_hlen;
    uint8_t  arp_plen;
    uint16_t arp_oper;
    uint8_t  arp_sha[6];
    uint32_t arp_spa;
    uint8_t  arp_tha[6];
    uint32_t arp_tpa;
};

struct PACKED_STRUCT netx_icmp_header
{
    uint8_t  icmp_type;
    uint8_t  icmp_code;
    uint16_t icmp_checksum;
    uint32_t icmp_header_extra;
};



/**
 * @brief Parse IP packet and extract endpoint information
 *
 * @param packet_ptr Pointer to the NetX packet
 * @param local_addr Buffer for local address (4 bytes for IPv4)
 * @param remote_addr Buffer for remote address (4 bytes for IPv4)
 * @param local_port Pointer to store local port
 * @param remote_port Pointer to store remote port
 * @param protocol Pointer to store protocol
 * @param is_outbound Flag indicating if packet is outbound
 *
 * @return 0 on success, -1 on error
 */
static int parse_ip_packet(unsigned char *packet_data, unsigned long data_length,
    unsigned char *local_addr, unsigned char *remote_addr,
    unsigned short *local_port, unsigned short *remote_port,
    unsigned char *protocol, int is_outbound)
{
    struct netx_ip_header *ip;
    struct netx_tcp_header *tcp;
    struct netx_udp_header *udp;
    unsigned long ip_addr;

    if (!packet_data || !local_addr || !remote_addr || !local_port ||
        !remote_port || !protocol) {
        return -1;
    }

    /* Check minimum size for IP header */
    if (data_length < sizeof(struct netx_ip_header)) {
        return -1;
    }

    ip = (struct netx_ip_header*)packet_data;

    /* Check IP version (IPv4 only) */
    if (ip->version != 4) {
        return -1;
    }

    /* Extract protocol */
    *protocol = ip->protocol;

    /* Extract IP addresses (NetX uses host byte order) */
    if (is_outbound) {
        /* For outbound packets: source is local, destination is remote */
        ip_addr = ip->source_ip;
        local_addr[0] = (ip_addr >> 24) & 0xFF;
        local_addr[1] = (ip_addr >> 16) & 0xFF;
        local_addr[2] = (ip_addr >> 8) & 0xFF;
        local_addr[3] = ip_addr & 0xFF;

        ip_addr = ip->dest_ip;
        remote_addr[0] = (ip_addr >> 24) & 0xFF;
        remote_addr[1] = (ip_addr >> 16) & 0xFF;
        remote_addr[2] = (ip_addr >> 8) & 0xFF;
        remote_addr[3] = ip_addr & 0xFF;
    } else {
        /* For inbound packets: destination is local, source is remote */
        ip_addr = ip->dest_ip;
        local_addr[0] = (ip_addr >> 24) & 0xFF;
        local_addr[1] = (ip_addr >> 16) & 0xFF;
        local_addr[2] = (ip_addr >> 8) & 0xFF;
        local_addr[3] = ip_addr & 0xFF;

        ip_addr = ip->source_ip;
        remote_addr[0] = (ip_addr >> 24) & 0xFF;
        remote_addr[1] = (ip_addr >> 16) & 0xFF;
        remote_addr[2] = (ip_addr >> 8) & 0xFF;
        remote_addr[3] = ip_addr & 0xFF;
    }

    /* Initialize ports to 0 (for non-port based protocols) */
    *local_port = 0;
    *remote_port = 0;

    /* Extract port numbers for TCP and UDP */
    if (*protocol == IPPROTO_TCP || *protocol == IPPROTO_UDP) {
        unsigned int ip_header_len = ip->ihl * 4; /* number of 32-bits */

        if (data_length < ip_header_len + sizeof(struct netx_tcp_header)) {
            return -1;
        }

        if (*protocol == IPPROTO_TCP) {
            tcp = (struct netx_tcp_header*)(packet_data + ip_header_len);
            if (is_outbound) {
                *local_port = ntohs(tcp->source_port);
                *remote_port = ntohs(tcp->dest_port);
            } else {
                *local_port = ntohs(tcp->dest_port);
                *remote_port = ntohs(tcp->source_port);
            }
        } else if (*protocol == IPPROTO_UDP) {
            udp = (struct netx_udp_header*)(packet_data + ip_header_len);
            if (is_outbound) {
                *local_port = ntohs(udp->source_port);
                *remote_port = ntohs(udp->dest_port);
            } else {
                *local_port = ntohs(udp->dest_port);
                *remote_port = ntohs(udp->source_port);
            }
        }
    }

    return 0;
}

/**
 * @brief Build wolfSentry sockaddr structure
 *
 * @param sockaddr Pointer to sockaddr structure to populate
 * @param addr_bytes IP address bytes (4 bytes for IPv4)
 * @param port Port number
 * @param protocol Protocol number
 *
 * @return 0 on success, -1 on error
 */
static int build_wolfsentry_sockaddr(struct wolfsentry_sockaddr *sockaddr,
                                    const unsigned char *addr_bytes,
                                    unsigned short port, unsigned char protocol,
                                    unsigned char interface_id)
{
    if (!sockaddr || !addr_bytes) {
        return -1;
    }

    sockaddr->sa_family = AF_INET;
    sockaddr->sa_proto = protocol;
    sockaddr->sa_port = (wolfsentry_port_t)port;
    sockaddr->addr_len = 32; /* IPv4 address length in bits */
    sockaddr->interface = interface_id; /* 0=Default interface */

    /* Copy IPv4 address (4 bytes) */
    memcpy(sockaddr->addr, addr_bytes, 4);

    return 0;
}

/**
 * @brief NetX Duo raw packet filter callback using wolfSentry
 *
 * This function is called with the IP packet to determine
 * whether the packet should be accepted or rejected based on wolfSentry rules.
 *
 * @param packet_data Pointer to the packet data buffer
 * @param data_length Length of the packet data in bytes
 *
 * @return NX_SUCCESS to accept packet, NX_NOT_SUCCESSFUL to reject packet
 */
int wolfsentry_netx_ip_packet_filter(struct wolfsentry_context* ctx, unsigned char interface_id,
    unsigned char *packet_data, unsigned long data_length)
{
    unsigned char local_addr[4], remote_addr[4];
    unsigned short local_port, remote_port;
    unsigned char protocol;
    int parse_result;
    wolfsentry_errcode_t ret;
    wolfsentry_action_res_t action_results;
    wolfsentry_route_flags_t route_flags;
    wolfsentry_ent_id_t rule_id;
    wolfsentry_route_flags_t inexact_matches;

    /* Define sockaddr structures for local and remote endpoints */
    WOLFSENTRY_SOCKADDR(32) local_sockaddr_buf, remote_sockaddr_buf; /* 32 bits for IPv4 address */
    struct wolfsentry_sockaddr *local_sockaddr, *remote_sockaddr;

    /* Initialize sockaddr structures */
    memset(&local_sockaddr_buf, 0, sizeof(local_sockaddr_buf));
    memset(&remote_sockaddr_buf, 0, sizeof(remote_sockaddr_buf));

    local_sockaddr  = (struct wolfsentry_sockaddr*)&local_sockaddr_buf;
    remote_sockaddr = (struct wolfsentry_sockaddr*)&remote_sockaddr_buf;

    /* Parse the packet to extract connection information */
    parse_result = parse_ip_packet(packet_data, data_length,
        local_addr, remote_addr, &local_port, &remote_port, &protocol, 0);
    if (parse_result != 0) {
        /* If we can't parse the packet, accept it by default */
        return NX_NOT_SUCCESSFUL;
    }

    /* Build wolfSentry sockaddr structures */
    if (build_wolfsentry_sockaddr(local_sockaddr,  local_addr,  local_port,  protocol, interface_id) != 0 ||
        build_wolfsentry_sockaddr(remote_sockaddr, remote_addr, remote_port, protocol, interface_id) != 0) {
        /* If we can't build sockaddr structures, accept packet by default */
        return NX_NOT_SUCCESSFUL;
    }

    /* Set route flags for inbound packet */
    route_flags = WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
        WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD |
        WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;

    /* Initialize action results */
    action_results = WOLFSENTRY_ACTION_RES_NONE;

    /* Call wolfSentry to evaluate the packet */
    ret = wolfsentry_route_event_dispatch(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(ctx),
        remote_sockaddr,
        local_sockaddr,
        route_flags,
        NULL, 0, /* label */
        NULL, /* caller_arg */
        &rule_id,
        &inexact_matches,
        &action_results
    );

    /* Handle wolfSentry errors */
    if (ret < 0) {
        /* On error, reject packet by default */
        return NX_NOT_SUCCESSFUL;
    }

    /* Check action results */
    if (action_results & WOLFSENTRY_ACTION_RES_ACCEPT) {
        return NX_SUCCESS;
    }
    else if (action_results & WOLFSENTRY_ACTION_RES_REJECT) {
        return NX_NOT_SUCCESSFUL;
    }

    /* If no explicit action, use default policy (reject) */
    return NX_NOT_SUCCESSFUL;
}
