#include <Arduino.h>
#include <mbedtls/aes.h>

#include <MiniShell.h>
#include <SPI.h>
#include <LoRa.h>

#define printf Serial.printf

static MiniShell shell(&Serial);
static uint32_t packet_cnt = 0x12345678;

static const uint8_t DEFAULT_KEY[] = {
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
    0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01
};

static void show_help(const cmd_t *cmds)
{
    for (const cmd_t * cmd = cmds; cmd->cmd != NULL; cmd++) {
        printf("%10s: %s\r\n", cmd->name, cmd->help);
    }
}

static int do_help(int argc, char *argv[]);

static int do_reboot(int argc, char *argv[])
{
    ESP.restart();
    return 0;
}

static void printhex(const uint8_t *data, size_t len)
{
    for (int i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            printf("\n%04X:", i);
        }
        printf(" %02X", data[i]);
    }
    printf("\n");
}

static bool lora_init(void)
{
    SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_CS);
    LoRa.setSPI(SPI);
    LoRa.setSPIFrequency(100000L);
    LoRa.setPins(LORA_CS, LORA_RST, LORA_IRQ);
    bool result = LoRa.begin(869525000L);
    if (result) {
        LoRa.setSpreadingFactor(11);
        LoRa.setSignalBandwidth(250E3);
        LoRa.setCodingRate4(5);
        LoRa.setSyncWord(0x2B);
        LoRa.setPreambleLength(16);
        LoRa.enableCrc();
        LoRa.disableInvertIQ();
    }
    return result;
}

static size_t put_u32_le(uint8_t *buffer, uint32_t value)
{
    *buffer++ = (value >> 0) & 0xFF;
    *buffer++ = (value >> 8) & 0xFF;
    *buffer++ = (value >> 16) & 0xFF;
    *buffer++ = (value >> 24) & 0xFF;
    return 4;
}

static size_t put_u8(uint8_t *buffer, uint8_t value)
{
    *buffer = value;
    return 1;
}

static size_t fill_header(uint8_t *buffer, uint32_t source, uint32_t packet_id, uint8_t hop)
{
    uint8_t *p = buffer;
    p += put_u32_le(p, 0xFFFFFFFF);     // destination
    p += put_u32_le(p, source);
    p += put_u32_le(p, packet_id);
    p += put_u8(p, hop | (hop << 5));   // flags
    p += put_u8(p, 8);          // hash
    p += put_u8(p, 0);          // next-hop
    p += put_u8(p, source & 0xFF);      // relay-node
    return p - buffer;
}

static size_t wrap_protobuf(uint8_t *buffer, uint8_t portnum, const uint8_t *data, size_t len)
{
    uint8_t *p = buffer;
    *p++ = 0x08;                // portnum
    *p++ = portnum;
    *p++ = 0x12;                // payload = byte array
    *p++ = len;
    memcpy(p, data, len);
    p += len;
    *p++ = 0x48;                // bitfield = OK-to-MQTT
    *p++ = 0x01;
    return p - buffer;
}

static void build_nonce(uint8_t *nonce, uint32_t packet_id, uint32_t source, uint32_t extra)
{
    nonce += put_u32_le(nonce, packet_id);
    nonce += put_u32_le(nonce, 0);
    nonce += put_u32_le(nonce, source);
    nonce += put_u32_le(nonce, extra);
}

static size_t encrypt(uint8_t *output, const uint8_t *input, size_t len, const uint8_t *aes_key,
                      const uint8_t *nonce)
{
    uint8_t stream_block[16];
    size_t nc_off = 0;

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, aes_key, 128);
    mbedtls_aes_crypt_ctr(&aes, len, &nc_off, (unsigned char *) nonce, stream_block,
                          (unsigned char *) input, output);
    mbedtls_aes_free(&aes);

    return len;
}

static bool send_data(const uint8_t *data, size_t data_len, uint32_t source, uint32_t packet_id)
{
    uint8_t packet[256];
    uint8_t nonce[16];
    uint8_t pb_buf[256];

    printf("Raw data:");
    printhex(data, data_len);

    // build protobuf payload
    size_t pb_len = wrap_protobuf(pb_buf, 1, data, data_len);
    printf("Protobuf:");
    printhex(pb_buf, pb_len);

    // build header
    uint8_t *p = packet;
    p += fill_header(p, source, packet_id, 3);

    // append encrypted protobuf 
    build_nonce(nonce, packet_id, source, 0);
    p += encrypt(p, pb_buf, pb_len, DEFAULT_KEY, nonce);

    // send buffer
    size_t len = p - packet;
    printf("Radio buffer:");
    printhex(packet, len);
    if (LoRa.beginPacket(false)) {
        LoRa.write(packet, len);
        LoRa.endPacket(true);
        return true;
    }
    printf("beginPacket failed!\n");
    return false;
}

static int do_init(int argc, char *argv[])
{
    bool result = lora_init();
    printf("LoRa init: %s\n", result ? "OK" : "FAILED");
    return 0;
}

static int do_text(int argc, char *argv[])
{
    char message[128];

    const char *text;
    uint32_t packet_id = packet_cnt++;
    if (argc > 1) {
        text = argv[1];
    } else {
        sprintf(message, "Test 0x%X!", packet_id);
        text = message;
    }

    size_t len = strlen(text);
    uint32_t source = 0xDA639BBB;
    return send_data((const uint8_t *) text, len, source, packet_id) ? 0 : -1;
}

static int do_dump(int argc, char *argv[])
{
    LoRa.dumpRegisters(Serial);
    return 0;
}

const cmd_t commands[] = {
    { "init", do_init, "Initialize hardware" },
    { "dump", do_dump, "Dump registers" },
    { "text", do_text, "<text> send a text message" },
    { "reboot", do_reboot, "Reboot" },
    { "help", do_help, "Show help" },
    { NULL, NULL, NULL }
};

static int do_help(int argc, char *argv[])
{
    show_help(commands);
    return 0;
}

void setup(void)
{
    Serial.begin(115200);
    Serial.println("Hello ESP32!");
    lora_init();
}

void loop(void)
{
    uint8_t packet[256];

    int packetSize = LoRa.parsePacket();
    if (packetSize > 0) {
        int index = 0;
        while (LoRa.available()) {
            if (index < sizeof(packet)) {
                packet[index++] = LoRa.read();
            }
        }
        int rssi = LoRa.packetRssi();
        printf("Received packet with RSSI %d:", rssi);
        printhex(packet, index);
    }

    shell.process(">", commands);
}
