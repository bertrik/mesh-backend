#include <Arduino.h>
#include "board-config.h"

#include <MiniShell.h>
#include <RadioLib.h>
#include <CRC.h>

#include <Crypto.h>
#include <AES.h>
#include <CTR.h>

#define printf Serial.printf

static MiniShell shell(&Serial);
static uint32_t packet_cnt = 0x12345678;
static uint32_t node_id;

static const uint8_t DEFAULT_KEY[] = {
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
    0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01
};

// Use SX1262 radio (used in CubeCell), with SPI pins configured for CubeCell
static SX1262 radio = new Module(RADIO_NSS,     // NSS pin (e.g. 18)
                                 RADIO_DIO_1,   // DIO1 pin
                                 RADIO_RESET,   // Reset pin
                                 RADIO_BUSY     // Busy pin
    );

static uint32_t get_node_id(void)
{
    return getID() & 0xFFFFFFFFL;
}

static bool lora_init(void)
{
    radio.setDio2AsRfSwitch(true);
    int16_t result = radio.begin(869.525);
    if (result < 0) {
        return false;
    }
    radio.setSpreadingFactor(11);
    radio.setBandwidth(250);
    radio.setCodingRate(5);
    radio.setSyncWord(0x2B);
    radio.setPreambleLength(16);
    radio.setCRC(1);
    radio.invertIQ(false);
    return true;
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

static void show_help(const cmd_t *cmds)
{
    for (const cmd_t * cmd = cmds; cmd->cmd != NULL; cmd++) {
        printf("%10s: %s\r\n", cmd->name, cmd->help);
    }
}

static int do_help(int argc, char *argv[]);

static int do_init(int argc, char *argv[])
{
    return lora_init()? 0 : -1;
}

static size_t put_u32_le(uint8_t *buffer, uint32_t value)
{
    *buffer++ = (value >> 0) & 0xFF;
    *buffer++ = (value >> 8) & 0xFF;
    *buffer++ = (value >> 16) & 0xFF;
    *buffer++ = (value >> 24) & 0xFF;
    return 4;
}

static size_t put_u32_be(uint8_t *buffer, uint32_t value)
{
    *buffer++ = (value >> 24) & 0xFF;
    *buffer++ = (value >> 16) & 0xFF;
    *buffer++ = (value >> 8) & 0xFF;
    *buffer++ = (value >> 0) & 0xFF;
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

static size_t pbwrap_text(uint8_t *buffer, const char *text)
{
    uint8_t len = strlen(text);

    uint8_t *p = buffer;
    *p++ = 0x08;                // portnum = 1
    *p++ = 0x01;
    *p++ = 0x12;                // payload = byte array
    *p++ = len;
    memcpy(p, text, len);
    p += len;
    *p++ = 0x48;                // bitfield = OK-to-MQTT
    *p++ = 0x01;
    return p - buffer;
}

static size_t pbwrap_data(uint8_t *buffer, const uint8_t *data, size_t len)
{
    uint8_t *p = buffer;
    *p++ = 0x08;                // portnum = 256
    *p++ = 0x80;
    *p++ = 0x02;
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
    CTR<AES128> ctr;
    ctr.setKey(aes_key, 16);
    ctr.setIV(nonce, 16);
    ctr.decrypt(output, input, len);
    return len;
}

static bool send_data(const uint8_t *pb_data, size_t pb_len, uint32_t packet_id)
{
    uint8_t packet[256];
    uint8_t nonce[16];

    printf("Protobuf data:");
    printhex(pb_data, pb_len);

    // build header
    uint8_t *p = packet;
    p += fill_header(p, node_id, packet_id, 3);

    // append encrypted protobuf
    build_nonce(nonce, packet_id, node_id, 0);
    p += encrypt(p, pb_data, pb_len, DEFAULT_KEY, nonce);

    // send buffer
    size_t len = p - packet;
    printf("Radio data:");
    printhex(packet, len);
    int16_t result = radio.transmit(packet, len);
    if (result < 0) {
        printf("transmit() failed!\n");
    }
    // return to read mode
    radio.startReceive();

    return result >= 0;
}

static int do_text(int argc, char *argv[])
{
    uint8_t pb_buf[256];
    char message[128];

    const char *text;
    uint32_t packet_id = packet_cnt++;
    if (argc > 1) {
        text = argv[1];
    } else {
        sprintf(message, "Test 0x%X!", packet_id);
        text = message;
    }

    size_t pb_len = pbwrap_text(pb_buf, text);

    return send_data(pb_buf, pb_len, packet_id) ? 0 : -1;
}

static int do_data(int argc, char *argv[])
{
    uint8_t data[200];
    uint8_t pb_buf[256];
    size_t len = (argc > 1) ? atoi(argv[1]) : 16;

    // prefix "secret" (to be replaced by CRC)
    uint32_t initial = 0x12345678;
    uint8_t *p = data;
    p += put_u32_be(p, initial);

    // append arbitrary byte data
    uint8_t v = 0;
    for (int i = 0; i < len; i++) {
        *p++ = v;
        v += 0x11;
    }
    len = p - data;

    // calculate and overwrite secret with CRC
    CRC32 crc = CRC32();
    crc.add(data, len);
    put_u32_be(data, crc.calc());

    printf("Raw data:");
    printhex(data, len);

    size_t pb_len = pbwrap_data(pb_buf, data, len);
    uint32_t packet_id = packet_cnt++;
    return send_data(pb_buf, pb_len, packet_id) ? 0 : -1;
}

const cmd_t commands[] = {
    { "help", do_help, "Show help" },
    { "text", do_text, "Send text message" },
    { "data", do_data, "[len] Send data packet" },
    { "init", do_init, "Initialise hardware" },
    { NULL, NULL, NULL }
};

static int do_help(int argc, char *argv[])
{
    show_help(commands);
    return 0;
}

static volatile bool recv_flag = false;
static uint8_t recv_buf[256];

static void packet_received(void)
{
    recv_flag = true;
}

void setup(void)
{
    Serial.begin(115200);

    node_id = get_node_id();
    printf("Node id: 0x%08X\n", node_id);
    if (!lora_init()) {
        printf("lora_init failed!\n");
    }
    radio.setPacketReceivedAction(packet_received);
    radio.startReceive();
}

void loop(void)
{
    if (recv_flag) {
        recv_flag = false;
        size_t len = radio.getPacketLength();
        if (len > 0) {
            int rssi = radio.getRSSI();
            printf("Received packet (RSSI: %d):", rssi);
            radio.readData(recv_buf, len);
            printhex(recv_buf, len);
        }
    }

    // process command line
    shell.process(">", commands);
}
