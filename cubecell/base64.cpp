#include "base64.h"

static int b64_index(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

size_t base64_decode(const char *in, uint8_t *out)
{
    size_t len = 0;             // number of output bytes
    int val = 0;                // working accumulator
    int bits = -8;              // bit position

    for (; *in && *in != '='; in++) {
        int idx = b64_index(*in);
        if (idx < 0)
            continue;           // skip invalid chars

        val = (val << 6) | idx;
        bits += 6;

        if (bits >= 0) {
            out[len++] = uint8_t((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    return len;
}
