#include <Arduino.h>
#include <mbedtls/aes.h>

#include <MiniShell.h>
#include <SPI.h>
#include <LoRa.h>

#include <Crypto.h>
#include <BLAKE2s.h>

#include "base64.h"
#include "protocode.h"

#define printf Serial.printf

static MiniShell shell(&Serial);
static uint32_t packet_cnt = 0x12345678;
static uint32_t node_id;

static const uint8_t DEFAULT_KEY[] = {
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
    0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01
};
static uint8_t meshtastic_key[16];

static const char PASSPHRASE[] = "secret";

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

static uint32_t get_node_id(void)
{
    uint8_t mac[6];

    esp_efuse_mac_get_default(mac);
    uint32_t id = 0;
    for (int i = 2; i < 6; i++) {
        id = (id << 8) | mac[i];
    }
    return id;
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

// see https://buf.build/meshtastic/protobufs/docs/master:meshtastic#meshtastic.Data
static size_t pbwrap_data(uint8_t *buffer, int portnum, const uint8_t *data, size_t len)
{
    uint8_t *p = buffer;
    p += pb_write_u32(p, 1, portnum);   // portnum
    p += pb_write_bytes(p, 2, data, len);       // payload
    p += pb_write_u32(p, 9, 1); // bitfield = OK-to-MQTT
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

static bool send_data(const uint8_t *pb_data, size_t pb_len, uint32_t node_id, uint32_t packet_id)
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
    p += encrypt(p, pb_data, pb_len, meshtastic_key, nonce);

    // send buffer
    size_t len = p - packet;
    printf("Radio data:");
    printhex(packet, len);
    if (LoRa.beginPacket(false)) {
        LoRa.write(packet, len);
        LoRa.endPacket(true);
        return true;
    }
    printf("beginPacket failed!\n");
    return false;
}

static int do_key(int argc, char *argv[])
{
    uint8_t buffer[16];

    if (argc > 1) {
        memcpy(meshtastic_key, DEFAULT_KEY, 16);
        size_t len = base64_decode(argv[1], buffer);
        if ((len > 0) && (len <= 16)) {
            memcpy(meshtastic_key + 16 - len, buffer, len);
        }
    }

    printf("Meshtastic key is now:");
    printhex(meshtastic_key, 16);

    return 0;
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

    size_t pb_len = pbwrap_data(pb_buf, 1, (uint8_t *)text, strlen(text));
    return send_data(pb_buf, pb_len, node_id, packet_id) ? 0 : -1;
}

static int do_data(int argc, char *argv[])
{
    uint8_t data[200];
    uint8_t pb_buf[256];
    uint8_t header[16];
    size_t len = (argc > 1) ? atoi(argv[1]) : 16;
    uint32_t packet_id = packet_cnt++;

    // create arbitrary byte data
    uint8_t *p = data;
    uint8_t v = 0;
    for (int i = 0; i < len; i++) {
        *p++ = v;
        v += 0x11;
    }

    // calculate hash: passphrase + header data + payload
    BLAKE2s blake;
    fill_header(header, node_id, packet_id, 0);
    blake.update(PASSPHRASE, strlen(PASSPHRASE));
    blake.update(header + 4, 8);
    blake.update(data, len);

    // append hash to data
    blake.finalize(p, 4);
    p += 4;
    len = p - data;

    printf("Raw data:");
    printhex(data, len);

    size_t pb_len = pbwrap_data(pb_buf, 256, data, len);
    return send_data(pb_buf, pb_len, node_id, packet_id) ? 0 : -1;
}

static int do_user(int argc, char *argv[])
{
    uint8_t user_buf[128];
    uint8_t pkt_buf[256];
    char id[16];
    char longname[16];

    if (argc > 1) {
        strlcpy(longname, argv[1], sizeof(longname));
    } else {
        strcpy(longname, "ESP32 proto");
    }

    // build 'user' protobuf
    sprintf(id, "!%x", node_id);
    uint8_t *p = user_buf;
    p += pb_write_string(p, 1, id);     // node id
    p += pb_write_string(p, 2, longname);
    p += pb_write_string(p, 3, "ESP!"); // short name
    p += pb_write_u32(p, 5, 255);       // hardware model = private
    p += pb_write_u32(p, 7, 1); // role = client-mute
    p += pb_write_bool(p, 9, 1);        // unmessageable
    size_t user_len = p - user_buf;

    // wrap in packet structure, for port NODEINFO
    size_t pkt_len = pbwrap_data(pkt_buf, 4, user_buf, user_len);

    // send with header
    uint32_t packet_id = packet_cnt++;
    return send_data(pkt_buf, pkt_len, node_id, packet_id) ? 0 : -1;
}

// see https://buf.build/meshtastic/protobufs/docs/master:meshtastic#meshtastic.Telemetry
static int do_tele(int argc, char *argv[])
{
    float voltage = (argc > 1) ? atof(argv[1]) : 1.2345;

    // build 'DeviceMetrics' protobuf
    uint8_t metrics_buf[16];
    size_t metrics_len = pb_write_float(metrics_buf, 2, voltage); // 2 = voltage

    // build 'Telemetry' protobuf
    uint8_t tele_buf[128];
    uint8_t *p = tele_buf;
    p += pb_write_bytes(p, 2, metrics_buf, metrics_len);        // 2 = device metrics
    size_t tele_len = p - tele_buf;

    // wrap in packet structure, for port TELEMETRY
    uint8_t pkt_buf[256];
    size_t pkt_len = pbwrap_data(pkt_buf, 67, tele_buf, tele_len);

    // send with header
    uint32_t packet_id = packet_cnt++;
    return send_data(pkt_buf, pkt_len, node_id, packet_id) ? 0 : -1;
}

const cmd_t commands[] = {
    { "key", do_key, "<base64> Set custom key" },
    { "text", do_text, "[text] send a text message" },
    { "data", do_data, "<len> sends len bytes" },
    { "user", do_user, "[user] Send user info" },
    { "tele", do_tele, "[voltage] Send telemetry" },
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
    memcpy(meshtastic_key, DEFAULT_KEY, 16);
    node_id = get_node_id();
    printf("Hello, this is %X!\n", node_id);
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
