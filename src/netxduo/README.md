# WolfSentry NetX Duo Integration

This directory contains the NetX Duo integration layer for WolfSentry, providing packet filtering and security policy enforcement for embedded systems using the NetX Duo TCP/IP stack.

## Overview

The NetX Duo integration enables WolfSentry to intercept and evaluate network packets at the IP layer, allowing for real-time security policy enforcement. This implementation provides:

- **Packet Filtering**: Intercepts all IP packets (TCP, UDP, ICMP) for security evaluation
- **Address Conversion**: Implements `inet_ntop` and `inet_pton` functions compatible with NetX Duo
- **Protocol Support**: Supports IPv4 addresses with extensible architecture for IPv6
- **Fail-Open Policy**: Accepts packets by default if WolfSentry is not initialized or encounters errors

## Files

- `packet_filter_glue.c` - Main implementation file containing packet filtering logic and address conversion functions

## NetX Duo IP Callback Mechanism

### Overview

The integration uses NetX Duo's raw packet filtering mechanism to intercept all IP packets before they are processed by the TCP/IP stack. This allows WolfSentry to evaluate each packet against configured security policies.

### Callback Function

The main callback function is `wolfsentry_netx_packet_filter()`, which is registered with NetX Duo using `nx_ip_raw_packet_filter_set()`. This function:

1. **Parses IP Headers**: Extracts source/destination addresses, ports, and protocol information
2. **Builds WolfSentry Structures**: Converts NetX packet data to WolfSentry sockaddr structures
3. **Evaluates Security Policy**: Calls WolfSentry's route event dispatch to check against configured rules
4. **Returns Decision**: Accepts or rejects the packet based on WolfSentry's evaluation

### Packet Processing Flow

```
NetX Duo IP Stack
       ↓
Raw Packet Filter Callback
       ↓
Parse IP/TCP/UDP Headers
       ↓
Build WolfSentry sockaddr
       ↓
Call WolfSentry Route Event Dispatch
       ↓
Return Accept/Reject Decision
       ↓
NetX Duo Continues/Blocks Packet
```

### Installation

To install the packet filter callbacks:

```c
#include <wolfsentry/wolfsentry_netxduo.h>

// Initialize WolfSentry context
struct wolfsentry_context *ctx = /* your wolfSentry context */;

// Set the context for NetX Duo integration
wolfsentry_set_netx_context(ctx);

// Install the packet filter callbacks
int result = wolfsentry_install_netx_filter_callbacks(ip_ptr);
if (result != 0) {
    // Handle installation error
}
```

## Address Conversion Functions

The implementation provides custom `inet_ntop` and `inet_pton` functions that are compatible with NetX Duo's data structures:

### wolfsentry_inet_ntop()

Converts binary network addresses to string representation:

```c
const char *wolfsentry_inet_ntop(int af, const void *src, char *dst, size_t size);
```

- Supports IPv4 (AF_INET) addresses
- Handles IPv4-mapped IPv6 addresses
- Returns NULL on error, pointer to dst on success

### wolfsentry_inet_pton()

Converts string network addresses to binary format:

```c
int wolfsentry_inet_pton(int af, const char* src, void* dst);
```

- Supports IPv4 (AF_INET) addresses
- Handles IPv4-mapped IPv6 addresses (::ffff:w.x.y.z format)
- Returns 1 on success, 0 on invalid format, -1 on error

## Security Features

### Default Policy

The implementation follows a **fail-open** security policy:
- If WolfSentry is not initialized, all packets are accepted
- If packet parsing fails, packets are accepted by default
- If WolfSentry evaluation fails, packets are accepted

### Action Results

WolfSentry can return the following actions:
- `WOLFSENTRY_ACTION_RES_ACCEPT`: Packet is allowed through
- `WOLFSENTRY_ACTION_RES_REJECT`: Packet is blocked
- `WOLFSENTRY_ACTION_RES_NONE`: No explicit action (defaults to accept)
