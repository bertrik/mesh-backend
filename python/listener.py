#!/usr/bin/env python3
import argparse
import base64
import binascii
import logging
import struct

import google.protobuf
import meshtastic
import paho.mqtt.client as mqtt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from meshtastic.protobuf.mesh_pb2 import MeshPacket
from meshtastic.protobuf.mqtt_pb2 import ServiceEnvelope
from meshtastic.protobuf.portnums_pb2 import PortNum

# actually d4f1bb3a20290759f0bcffabcf4e6901 in hex
DEFAULT_KEY = "1PG7OiApB1nwvP+rz05pAQ=="
logger = logging.getLogger(__name__)


class PacketHandler:
    def __init__(self, message_type: str, base64key: str):
        self.message_type = message_type
        self.key = self.create_key(base64key)
        logger.info(f'Decryption key = {self.key.hex():032s}')

    @staticmethod
    def create_key(base64key: str) -> bytes:
        default_key_bytes = base64.b64decode(DEFAULT_KEY)
        key_bytes = base64.b64decode(base64key)
        return default_key_bytes[0:16 - len(key_bytes)] + key_bytes

    def decrypt(self, data: bytes, packet_id: int, source_id: int, extra_nonce: int) -> bytes:
        nonce = struct.pack("<IIII", packet_id, 0, source_id, extra_nonce)
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(data) + decryptor.finalize()
        return decrypted_bytes

    def decode_packet(self, packet: MeshPacket) -> meshtastic.mesh_pb2.Data:
        if packet.encrypted:
            # print(f"(encrypted): {packet.encrypted}")
            source_id = getattr(packet, "from")
            decrypted = self.decrypt(packet.encrypted, packet.id, source_id, 0)
            data = meshtastic.mesh_pb2.Data()
            try:
                data.ParseFromString(decrypted)
            except google.protobuf.message.DecodeError as e:
                logger.warning(f"Decode error '{e}', data: {packet.encrypted.hex()}")
                data = None
            return data
        # print(f"(plaintext): {packet.decoded.payload}")
        return packet.decoded

    def log_meshdata(self, packet: meshtastic.protobuf.mesh_pb2.MeshPacket, meshdata: meshtastic.mesh_pb2.Data) -> None:
        payload = meshdata.payload
        match meshdata.portnum:
            case PortNum.TEXT_MESSAGE_APP:
                print(f"TEXT_MESSAGE_APP={payload}")
            case PortNum.POSITION_APP:
                position = meshtastic.mesh_pb2.Position()
                position.ParseFromString(payload)
                print(f"POSITION_APP={position}")
            case PortNum.NODEINFO_APP:
                user = meshtastic.mesh_pb2.User()
                user.ParseFromString(payload)
                print(f"NODEINFO_APP={user}")
            case PortNum.ROUTING_APP:
                routing = meshtastic.mesh_pb2.Routing()
                routing.ParseFromString(payload)
                print(f"ROUTING_APP={routing}")
            case PortNum.PAXCOUNTER_APP:
                paxcount = meshtastic.paxcount_pb2.Paxcount()
                paxcount.ParseFromString(payload)
                print(f"PAXCOUNTER_APP={paxcount}")
            case PortNum.STORE_FORWARD_APP:
                store_forward = meshtastic.storeforward_pb2.StoreAndForward()
                store_forward.ParseFromString(payload)
                print(f"STORE_FORWARD_APP={store_forward}")
            case PortNum.TELEMETRY_APP:
                telemetry = meshtastic.telemetry_pb2.Telemetry()
                telemetry.ParseFromString(payload)
                print(f"TELEMETRY_APP={telemetry}")
            case PortNum.TRACEROUTE_APP:
                route = meshtastic.protobuf.mesh_pb2.RouteDiscovery()
                route.ParseFromString(payload)
                print(f"TRACEROUTE_APP={route}")
            case PortNum.NEIGHBORINFO_APP:
                neighbour = meshtastic.mesh_pb2.Neighbor()
                neighbour.ParseFromString(payload)
                print(f"NEIGHBORINFO_APP={neighbour}")
            case _:
                print(f"meshdata={meshdata}")

    def handle_packet(self, data: bytes) -> None:
        se = ServiceEnvelope()
        se.ParseFromString(data)
        packet = se.packet
        meshdata = self.decode_packet(packet)
        if meshdata:
            if self.message_type == '*' or int(self.message_type) == meshdata.portnum:
                logger.info(f"Got packet: id={packet.id:08X}, {getattr(packet, "from"):08X} -> {packet.to:08X}")
                self.log_meshdata(packet, meshdata)
            if meshdata.portnum == PortNum.PRIVATE_APP:
                codes = [0x0, 0x12345678]
                for code in codes:
                    payload = self.attempt_decode(meshdata.payload, code)
                    if payload:
                        print(f"Private data for code '{code:08X}': {payload.hex()}")

    def attempt_decode(self, data: bytes, code: int) -> bytes | None:
        # from message
        crc = struct.unpack(">I", data[:4])[0]
        payload = data[4:]
        # calculated
        crcbuf = struct.pack(">I", code) + payload
        calculated = binascii.crc32(crcbuf)
        return payload if crc == calculated else None


class MqttListener:
    def __init__(self, broker: str, username: str, password: str, channel: str, callback):
        self.broker = broker
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.client.username_pw_set(username, password)
        self.channel = channel
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.handle_packet = callback

    def on_connect(self, client, _userdata, _flags, _rc, _properties):
        try:
            # msh/REGION/2/e/CHANNELNAME/USERID
            # see https://meshtastic.org/docs/software/integrations/mqtt/#mqtt-topics
            topic = f"msh/+/2/e/{self.channel}/+"
            logger.info(f"Connected, subscribing to uplink topic {topic}...")
            client.subscribe(topic)
        except Exception as e:
            print(e)

    def on_message(self, client, _userdata, msg):
        try:
            print(f"{msg.topic}")
            self.handle_packet(msg.payload)
        except Exception as e:
            logger.warning(f"Caught exception: {e}")

    def run(self):
        logger.info(f"Connecting to '{self.broker}' ...")
        self.client.connect(self.broker)
        self.client.loop_forever()


def main():
    """ The main entry point """
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-b", "--broker", help="The MQTT broker URL",
                        default="mqtt.meshnet.nl")
    parser.add_argument("-u", "--username", help="The MQTT user name",
                        default="boreft")
    parser.add_argument("-p", "--password", help="The MQTT password",
                        default="meshboreft")
    parser.add_argument("-f", "--filter", help="Message type to log (portnum)",
                        default="*")
    parser.add_argument("-k", "--key", help="Decryption key (base64)",
                        default="AQ==")
    parser.add_argument("-c", "--channel", help="Channel to listen on ('+' for all)",
                        default="LongFast")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)-8s: %(message)s")

    handler = PacketHandler(args.filter, args.key)
    listener = MqttListener(args.broker, args.username, args.password, args.channel, handler.handle_packet)
    listener.run()


if __name__ == "__main__":
    main()
