#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
ethernet.py: Ethernet frame input interfaces of PyNADS.

PyNADS - Python based Network Anomaly Detection System
Copyright (C) 2023  Philipp Meyer

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import timemachine
import labelManager


import binascii
import queue
import socket
import struct
import threading
from collections import namedtuple
import sys
import platform
import datetime
import psutil
import pyshark
import scapy.all as scapy


ETH_HEADER_BYTES = 14
ETH_Q_HEADER_BYTES = 18
ETH_MIN_PAYLOAD_BYTES = 46
ETH_MAX_PAYLOAD_BYTES = 1500
ETH_MAX_FRAME_BYTES = 1518
ETH_Q_MAX_FRAME_BYTES = 1526
ETH_P_ALL = 3  # All Ethernet protocols
ETH_TYPE_REPORT = 'FFAD'

SIM_DATA_HEADER_SIZE = 12
simdata_fields = ('simtime_ns',
                  'frame_length_byte')
SIM_DATA_TYPES_STRING = 'qi'
Simdata_t = namedtuple('SimData', simdata_fields)
# Followed by an Ethernet frame

PCAP_LABEL_FIELD_NAME = 'PKT_COMMENT'


def print_interfaces():
    iflist = scapy.get_working_ifaces()
    for iface in iflist:
        if iface.name == iface.description:
            print("{:<3}{:<35}{:<3}{:<4}{:<10}{:<10}".format(" - ", iface.name, " - ", " IPs: ", str(iface.ips[4]), str(iface.ips[6])))
        else:
            print("{:<3}{:<35}{:<3}{:<45}{:<3}{:<4}{:<10}{:<10}".format(" - ", iface.name, " - ", iface.description, " - ", " IPs: ", str(iface.ips[4]), str(iface.ips[6])))


def test_if_interface_exists(interface_name):
    iflist = scapy.get_working_ifaces()
    for iface in iflist:
        if iface.name == interface_name:
            return True
    return False


class _Socket:
    def __init__(self):
        self.sock = None
        self.interface_speed = None

    def set_interface_speed(self, interface_speed):
        self.interface_speed = interface_speed

    def get_interface_speed(self):
        if self.interface_speed:
            return self.interface_speed
        else:
            return psutil.net_if_stats()[self.interface].speed

    @staticmethod
    def get_destination_address(frame):
        return binascii.hexlify(frame[0:6]).decode()

    @staticmethod
    def set_destination_address(frame, address):
        if len(address) != 12:
            raise ValueError('address size is not 6')
        frame[0:6] = bytearray.fromhex(address)

    @staticmethod
    def get_source_address(frame):
        return binascii.hexlify(frame[6:12]).decode()

    @staticmethod
    def set_source_address(frame, address):
        if len(address) != 12:
            raise ValueError('address size is not 6')
        frame[6:12] = bytearray.fromhex(address)

    @staticmethod
    def get_ethertype(frame):
        return binascii.hexlify(frame[12:14]).decode()

    @staticmethod
    def set_ethertype(frame, ethertype):
        frame[12:14] = bytearray.fromhex(ethertype)

    @staticmethod
    def get_payload(frame):
        return binascii.hexlify(frame[14:]).decode()

    @staticmethod
    def get_number_of_bytes(frame):
        return len(frame)

    @staticmethod
    def encapsulate(payload):
        if len(payload) > ETH_MAX_PAYLOAD_BYTES:
            raise ValueError('payload size to large (max: 1500)')
        frame = bytearray(ETH_HEADER_BYTES + len(payload))
        frame[ETH_HEADER_BYTES:ETH_HEADER_BYTES + len(payload)] = payload
        return frame

    def print_frame(self, frame, now, message):
        print(message, len(frame), "bytes  time:", now, "\n  SMAC:", self.get_source_address(frame), " DMAC:",
              self.get_destination_address(frame), " Type:", self.get_ethertype(frame), "\n  Payload:", self.get_payload(frame))


class RawSocket(_Socket):
    def __init__(self, interface=None):
        super().__init__()
        self.interface = interface
        self.host = socket.gethostbyname(socket.gethostname())
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.sock.bind((self.interface, ETH_P_ALL))
        self.sock.setblocking(True)

    def receive(self, timeout=None):
        try:
            frame = bytearray(self.sock.recv(ETH_Q_MAX_FRAME_BYTES))
        except socket.error:
            pass
        else:
            return frame

    def send(self, frame):
        try:
            self.sock.send(frame)
        except socket.error:
            pass

    def to_string(self):
        return "RawSocket (Interface: " + self.interface + ", Interface speed: " + str(self.get_interface_speed()) + ")"


class SimSocket(_Socket):
    __default_interface_speed = 100  # Mbit per second

    def __init__(self, ip="127.0.0.1", port=2144):
        super().__init__()
        self.ip = ip
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.ip, self.port))
        self.sock.setblocking(True)

    def receive(self, timeout=None):
        try:
            data = self.sock.recv(SIM_DATA_HEADER_SIZE)
            simdata = Simdata_t._make(struct.unpack(SIM_DATA_TYPES_STRING, data))
            timemachine.set_simtime_ns(simdata.simtime_ns)
            frame = bytearray(self.sock.recv(simdata.frame_length_byte))
        except socket.error:
            pass
        else:
            return frame

    def send(self, frame):
        try:
            simdata = Simdata_t(int(timemachine.get_simtime_ns()), self.get_number_of_bytes(frame))
            data = bytearray(struct.pack(SIM_DATA_TYPES_STRING, simdata.simtime_ns, simdata.frame_length_byte))
            self.sock.send(data)
            self.sock.send(frame)
        except socket.error:
            pass

    def get_interface_speed(self):
        if self.interface_speed:
            return self.interface_speed
        else:
            return self.__default_interface_speed

    def to_string(self):
        return "SimSocket (IP: " + self.ip + ", Port: " + str(self.port) + ")"


class ScapySocket(_Socket):
    def _queue(self, packet):
        self.packet_queue.put(packet)

    def _sniff(self):
        scapy.conf.use_pcap = True
        interface = self.interface
        sniffer = scapy.sniff(iface=interface, prn=self._queue, filter=self.filter, store=0, stop_filter=lambda p: self.stop.is_set())

    def __init__(self, interface, filter=""): # Berkeley Packet Filter syntax
        super().__init__()
        self.stop = threading.Event()
        self.interface = interface
        self.filter = filter
        self.packet_queue = queue.Queue()
        self.sniffing_thread = threading.Thread(target=self._sniff)
        self.sniffing_thread.start()

    def receive(self, timeout=None):
        try:
            return scapy.raw(self.packet_queue.get(block=True, timeout=timeout))
        except queue.Empty:
            return bytes(0)
        except KeyboardInterrupt:
            self.stop.set()
            raise KeyboardInterrupt

    def send(self, frame):
        try:
            packet = scapy.Raw(frame)
            interface = self.interface
            scapy.sendp(packet, iface=interface, verbose=False)         
        except KeyboardInterrupt:
            self.stop.set()
            raise KeyboardInterrupt

    def to_string(self):
        return "ScapySocket (Interface: " + self.interface + ", Interface speed: " + str(self.get_interface_speed()) + ", Filter: " + self.filter + ")"


class PySharkSocket(ScapySocket):
    def _sniff(self):
        capture = pyshark.LiveCapture(interface=self.interface, bpf_filter=self.filter, use_json=True, include_raw=True)
        capture.apply_on_packets(callback=self._queue)

    def receive(self, timeout=None):
        try:
            packet = self.packet_queue.get(block=True, timeout=timeout)
            d_date = datetime.datetime.strptime(packet.sniff_timestamp[0:27] , "%b %d, %Y %H:%M:%S.%f")
            timemachine.set_tsharktime(d_date.timestamp())
            return bytearray.fromhex(packet.frame_raw.value)
        except queue.Empty:
            return bytes(0)
        except KeyboardInterrupt:
            self.stop.set()
            raise KeyboardInterrupt

    def to_string(self):
        return "PySharkSocket (Interface: " + self.interface + ", Interface speed: " + str(self.get_interface_speed()) + ", Filter: " + self.filter + ")"


class PcapFileSocket(_Socket):
    __default_interface_speed = 100  # Mbit per second

    def __init__(self, filename, filter=""): # Display Filter
        super().__init__()
        self.filename = filename
        self.pcap = pyshark.FileCapture(input_file=self.filename, display_filter=filter, keep_packets=False, use_json=True, include_raw=True)

    def receive(self, timeout=None):
        try:
            packet = self.pcap.next()
            d_date = datetime.datetime.strptime(packet.sniff_timestamp[0:27] , "%b %d, %Y %H:%M:%S.%f")
            d_date = d_date.replace(year=d_date.year + 1) # Workaround for https://bugs.python.org/issue29097
            timemachine.set_pcaptime(d_date.timestamp())
            if PCAP_LABEL_FIELD_NAME in packet:
                labelManager.add_label(packet[PCAP_LABEL_FIELD_NAME].comment)
            return bytearray.fromhex(packet.frame_raw.value)
        except KeyboardInterrupt:
            self.stop.set()
            raise KeyboardInterrupt

    def get_interface_speed(self):
        if self.interface_speed:
            return self.interface_speed
        else:
            return self.__default_interface_speed

    def send(self, frame):
        pass

    def to_string(self):
        return "PcapFileSocket (Filename: " + self.filename + ", Interface speed: " + str(self.get_interface_speed()) + ")"


# Dev Test:
if __name__ == "__main__":
    # import argparse
    # parser = argparse.ArgumentParser()
    # parser.add_argument("-I", "--interface", dest="interface", type=str, help="Interface", required=True)
    # parser.add_argument("--sim", dest="sim", action='store_true', default=False)
    # parser.add_argument("-f", "--filter", dest="filter", type=str, default="")
    # args = parser.parse_args()
    # if args.sim:
    #     sock = SimSocket()
    # elif len(args.filter) > 0 or platform == "win32":
    #     sock = PySharkSocket(args.interface, args.filter)
    # else:
    #     sock = RawSocket(args.interface)
    # print(sock.to_string())
    # while True:
    #     frame = sock.receive()
    #     now = timemachine.time()
    #     sock.print_frame(frame, now, "Received:")
    #sock = ScapySocket("eno1", "udp[8:4]=0x0000039f")
    # sock = PySharkSocket(interface="WLAN")
    sock = PcapFileSocket(filename="c:/Users/phili/git.inet.haw-hamburg.de/nads/PyNADS/poc/switchRearRight_200ms.all.pcap")
    while True:
        frame = sock.receive()
        if sock.get_number_of_bytes(frame) > 0:
            sock.print_frame(frame, timemachine.time(), "Received: ")
        else:
            print("Nothing")
