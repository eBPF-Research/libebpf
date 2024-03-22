#ifndef _ENDS_CONVERSION_H
#define _ENDS_CONVERSION_H

#include <stdint.h>
static inline uint16_t htobe16(uint16_t v) {
    return ((v >> 8) & 0xff) | ((v & 0xff) << 8);
}

static inline uint32_t htobe32(uint32_t v) {
    return ((v >> 24) & 0xff) | (((v >> 16) & 0xff) << 8) | (((v >> 8) & 0xff) << 16) | ((v & 0xff) << 24);
}

static inline uint64_t htobe64(uint64_t v) {
    return ((v >> 56) & 0xff) | (((v >> 48) & 0xff) << 8) | (((v >> 40) & 0xff) << 16) | (((v >> 32) & 0xff) << 24) | (((v >> 24) & 0xff) << 32) |
           (((v >> 16) & 0xff) << 40) | (((v >> 8) & 0xff) << 48) | ((v & 0xff) << 56);
}

static uint16_t htole16(uint16_t v) {
    return v;
}

static uint32_t htole32(uint32_t v) {
    return v;
}
static uint64_t htole64(uint64_t v) {
    return v;
}

static uint16_t bswap16(uint16_t v) {
    return ((v >> 8) & 0xff) | ((v & 0xff) << 8);
}

static uint32_t bswap32(uint32_t v) {
    return ((v >> 24) & 0xff) | (((v >> 16) & 0xff) << 8) | (((v >> 8) & 0xff) << 16) | ((v & 0xff) << 24);
}

static uint64_t bswap64(uint64_t v) {
    return ((v >> 56) & 0xff) | (((v >> 48) & 0xff) << 8) | (((v >> 40) & 0xff) << 16) | (((v >> 32) & 0xff) << 24) | (((v >> 24) & 0xff) << 32) |
           (((v >> 16) & 0xff) << 40) | (((v >> 8) & 0xff) << 48) | ((v & 0xff) << 56);
}

#endif
