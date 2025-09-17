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
    int len = 0;
    int val = 0, valb = -8;
    for (int i = 0; in[i] && in[i] != '='; i++) {
        int idx = b64_index(in[i]);
        if (idx == -1) {
            continue;
        }
        val = (val << 6) + idx;
        valb += 6;
        if (valb >= 0) {
            out[len++] = uint8_t((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return len;
}
