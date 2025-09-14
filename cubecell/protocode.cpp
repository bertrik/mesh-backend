#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef enum {
    WIRE_VARINT = 0,            // int32, int64, uint32, uint64, sint32, sint64, bool, enum
    WIRE_I64 = 1,               // fixed64, sfixed64, double
    WIRE_LEN = 2,               // string, bytes, embedded messages, packed repeated fields
    WIRE_I32 = 5                // fixed32, sfixed32, float
} wiretype_t;

// writes a varint to the buffer, do not use directly
static size_t pb_write_varint(uint8_t *buf, uint32_t value)
{
    size_t i = 0;
    while (value >= 0x80) {
        buf[i++] = 0x80 | (value & 0x7F);
        value >>= 7;
    }
    buf[i++] = value;
    return i;
}

// converts a signed number into a zig-zag encoded number
static uint32_t encode_signed(int32_t n)
{
    return (n << 1) ^ (n >> 31);
}

static size_t pb_write_tag(uint8_t *buf, int fieldnr, wiretype_t type)
{
    return pb_write_varint(buf, (fieldnr << 3) | type);
}

size_t pb_write_u32(uint8_t *buf, int fieldnr, uint32_t u32)
{
    uint8_t *p = buf;
    p += pb_write_tag(p, fieldnr, WIRE_VARINT);
    p += pb_write_varint(p, u32);
    return (p - buf);
}

size_t pb_write_bool(uint8_t *buf, int fieldnr, bool b)
{
    return pb_write_u32(buf, fieldnr, b ? 1 : 0);
}

size_t pb_write_s32(uint8_t *buf, int fieldnr, int32_t s32)
{
    uint8_t *p = buf;
    p += pb_write_tag(p, fieldnr, WIRE_VARINT);
    p += pb_write_varint(p, encode_signed(s32));
    return (p - buf);
}

size_t pb_write_bytes(uint8_t *buf, int fieldnr, const uint8_t *data, size_t len)
{
    uint8_t *p = buf;
    p += pb_write_tag(p, fieldnr, WIRE_LEN);
    p += pb_write_varint(p, len);
    for (size_t i = 0; i < len; i++) {
        *p++ = data[i];
    }
    return (p - buf);
}

size_t pb_write_string(uint8_t *buf, int fieldnr, const char *string)
{
    return pb_write_bytes(buf, fieldnr, (const uint8_t *) string, strlen(string));
}

size_t le_write_u32(uint8_t *buf, uint32_t u32)
{
    *buf++ = (u32 >> 0) & 0xFF;
    *buf++ = (u32 >> 8) & 0xFF;
    *buf++ = (u32 >> 16) & 0xFF;
    *buf++ = (u32 >> 24) & 0xFF;
    return 4;
}

size_t pb_write_float(uint8_t *buf, int fieldnr, float f)
{
    uint8_t *p = buf;
    p += pb_write_tag(p, fieldnr, WIRE_I32);

    uint32_t u32 = *(uint32_t *) & f;
    p += le_write_u32(buf, *(uint32_t *) & f);
    return (p - buf);
}
