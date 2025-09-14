#include <stdint.h>
#include <stddef.h>

size_t pb_write_float(uint8_t *buf, int fieldnr, float f);

size_t pb_write_string(uint8_t *buf, int fieldnr, const char *string);

size_t pb_write_bytes(uint8_t *buf, int fieldnr, const uint8_t *bytes, size_t len);

size_t pb_write_s32(uint8_t *buf, int fieldnr, int32_t s32);

size_t pb_write_bool(uint8_t *buf, int fieldnr, bool b);

size_t pb_write_u32(uint8_t *buf, int fieldnr, uint32_t u32);

