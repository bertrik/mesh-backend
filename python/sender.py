#!/usr/bin/env python3
import argparse
import json
import logging

import paho.mqtt.client as mqtt

logger = logging.getLogger(__name__)


class MqttSendPacket:
    def __init__(self, source: int, msg_type: str):
        self.message = {"from": source, "type": msg_type}

    @staticmethod
    def text(source: int, text: str):
        packet = MqttSendPacket(source, "sendtext")
        packet.message["payload"] = text
        return packet

    def set_destination(self, destination: int):
        self.message["to"] = destination

    def set_channel(self, channel: int):
        self.message["channel"] = channel

    def serialize(self) -> str:
        return json.dumps(self.message)


class MqttSender:
    def __init__(self, broker: str, username: str, password: str):
        self.broker = broker
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.client.username_pw_set(username, password)

    def connect(self):
        logger.info("Connecting to %s", self.broker)
        self.client.connect(self.broker)

    def send(self, topic: str, payload: str):
        logger.info("Sending '%s' on topic '%s'", payload, topic)
        self.client.publish(topic, payload)


# https://meshtastic.org/docs/software/integrations/mqtt/#json-downlink-to-instruct-a-node-to-send-a-message
def main():
    """ The main entry point """
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-b", "--broker", help="The MQTT broker URL",
                        default="mqtt.meshnet.nl")
    parser.add_argument("-u", "--username", help="The MQTT user name",
                        default="boreft")
    parser.add_argument("-p", "--password", help="The MQTT password",
                        default="meshboreft")
    parser.add_argument("-r", "--root", help="MQTT root topic",
                        default="msh/gouda")
    parser.add_argument("-d", "--destination", help="Destination node id (hex)",
                        default="da639b54")
    parser.add_argument("text", help="Text payload")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)-8s: %(message)s")

    destination = int(args.destination, 16)
    packet = MqttSendPacket.text(destination, args.text)
    payload = packet.serialize()

    sender = MqttSender(args.broker, args.username, args.password)
    sender.connect()
    # NOTE: firmware subscribes to ROOT/2/e/CHANNELNAME/+ and ROOT/2/json/CHANNELNAME/+ for downlink
    # where ROOT is typically msh/REGION, e.g. msh/gouda
    # so we could use a topic like: msh/gouda/2/json/LongFast/!da639b54
    topic = f"{args.root}/2/json/mqtt/"
    sender.send(topic, payload)


if __name__ == "__main__":
    main()
