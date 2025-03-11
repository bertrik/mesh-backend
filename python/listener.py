#!/usr/bin/env python3
import argparse
import base64
import struct

import meshtastic
import paho.mqtt.client
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from meshtastic.protobuf.portnums_pb2 import PortNum

# actually d4f1bb3a20290759f0bcffabcf4e6901 in hex
DEFAULT_KEY = "1PG7OiApB1nwvP+rz05pAQ=="


class PacketHandler:
    def __init__(self, message_type: str):
        self.message_type = message_type

    @staticmethod
    def decrypt(data: bytes, packet_id: int, source_id: int, key: str) -> bytes:
        # Expand the default key
        if key == "AQ==":
            key = DEFAULT_KEY

        # Convert key to bytes
        key_bytes = base64.b64decode(key)
        nonce = struct.pack("<IIII", packet_id, 0, source_id, 0)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(data) + decryptor.finalize()
        return decrypted_bytes

    def decode_packet(self, packet: meshtastic.mesh_pb2.MeshPacket) -> meshtastic.mesh_pb2.Data:
        if packet.encrypted:
            # print(f"(encrypted): {packet.encrypted}")
            source_id = getattr(packet, "from")
            decrypted = self.decrypt(packet.encrypted, packet.id, source_id, "AQ==")
            data = meshtastic.mesh_pb2.Data()
            data.ParseFromString(decrypted)
            return data
        # print(f"(plaintext): {packet.decoded.payload}")
        return packet.decoded

    def log_meshdata(self, packet, meshdata):
        payload = meshdata.payload
        print(f"id: {packet.id:08X}, {getattr(packet, "from"):08X} -> {packet.to:08X}")
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
                routing = meshtastic.mesh_pb2.Routing
                routing.ParseFromString(payload)
                print(f"ROUTING_APP={routing}")
            case PortNum.STORE_FORWARD_APP:
                store_forward = meshtastic.storeforward_pb2.StoreAndForward()
                store_forward.ParseFromString(payload)
                print(f"STORE_FORWARD_APP={store_forward}")
            case PortNum.TELEMETRY_APP:
                telemetry = meshtastic.telemetry_pb2.Telemetry()
                telemetry.ParseFromString(payload)
                print(f"TELEMETRY_APP={telemetry}")
            case PortNum.NEIGHBORINFO_APP:
                neighbour = meshtastic.mesh_pb2.Neighbor()
                neighbour.ParseFromString(payload)
                print(f"NEIGHBORINFO_APP={neighbour}")
            case _:
                print(f"meshdata={meshdata}")

    def handle_packet(self, data: bytes) -> None:
        se = meshtastic.mqtt_pb2.ServiceEnvelope()
        se.ParseFromString(data)
        meshdata = self.decode_packet(se.packet)
        if meshdata:
            if self.message_type == '*' or int(self.message_type) == meshdata.portnum:
                self.log_meshdata(se.packet, meshdata)


class MqttListener:
    def __init__(self, broker: str, username: str, password: str, callback):
        self.broker = broker
        self.client = paho.mqtt.client.Client()
        self.client.username_pw_set(username, password)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.handle_packet = callback

    @staticmethod
    def on_connect(client, _userdata, _flags, _rc):
        try:
            # msh/REGION/2/e/CHANNELNAME/USERID
            # see https://meshtastic.org/docs/software/integrations/mqtt/#mqtt-topics
            topic = "msh/+/2/e/+/+"
            print(f"Subscribing to uplink topic {topic}...")
            client.subscribe(topic)
        except Exception as e:
            print(e)

    def on_message(self, _client, _userdata, msg):
        try:
            self.handle_packet(msg.payload)
        except Exception as e:
            print(f"Caught exception: {e}")

    def run(self):
        print(f"Connecting to '{self.broker}' ...")
        self.client.connect(self.broker)
        while True:
            self.client.loop()


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
    args = parser.parse_args()

    handler = PacketHandler(args.filter)
    listener = MqttListener(args.broker, args.username, args.password, handler.handle_packet)
    listener.run()


if __name__ == "__main__":
    main()
