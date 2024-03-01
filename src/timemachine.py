#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
timemachine.py: Time representations of PyNADS.

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


import datetime
import time as computer_time


class _TimeMachine:
    __is_sim = False
    __sim_time = 0.0
    __is_tshark_time = False
    __tshark_time = computer_time.time()
    __is_pcap_time = False
    __pcap_time = datetime.datetime(1971, 1, 1, 1, 0).timestamp() # init to 1971-01-01 to workaround https://bugs.python.org/issue29097
    __train_interval = 0.0

    @staticmethod
    def get_time():
        if _TimeMachine.__is_sim:
            return _TimeMachine.__sim_time
        if _TimeMachine.__is_tshark_time:
            return _TimeMachine.__tshark_time
        if _TimeMachine.__is_pcap_time:
            return _TimeMachine.__pcap_time
        return computer_time.time()

    @staticmethod
    def get_ctime(*args, **kwargs):
        if _TimeMachine.__is_sim or _TimeMachine.__is_pcap_time:
            return time()
        else:
            return computer_time.ctime(*args, **kwargs)

    @staticmethod
    def get_train_interval():
        return _TimeMachine.__train_interval

    @staticmethod
    def travel_to_reality():
        _TimeMachine.__is_sim = False
        _TimeMachine.__is_tshark_time = False
        _TimeMachine.__is_pcap_time = False
    
    @staticmethod
    def travel_to_simulation():
        _TimeMachine.__is_sim = True
        _TimeMachine.__is_tshark_time = False
        _TimeMachine.__is_pcap_time = False

    @staticmethod
    def travel_to_tshark():
        _TimeMachine.__is_sim = False
        _TimeMachine.__is_tshark_time = True
        _TimeMachine.__is_pcap_time = False

    @staticmethod
    def travel_to_pcap():
        _TimeMachine.__is_sim = False
        _TimeMachine.__is_tshark_time = False
        _TimeMachine.__is_pcap_time = True

    @staticmethod
    def set_simtime(simtime):
        _TimeMachine.travel_to_simulation()
        _TimeMachine.__sim_time = simtime

    @staticmethod
    def set_tsharktime(tsharktime):
        _TimeMachine.travel_to_tshark()
        _TimeMachine.__tshark_time = tsharktime

    @staticmethod
    def set_pcaptime(pcaptime):
        _TimeMachine.travel_to_pcap()
        _TimeMachine.__pcap_time = pcaptime

    @staticmethod
    def set_train_interval(train_interval):
        _TimeMachine.__train_interval = train_interval


def time():
    return _TimeMachine.get_time()


def ctime(*args, **kwargs):
    return _TimeMachine.get_ctime(*args, **kwargs)


def train_interval():
    return _TimeMachine.get_train_interval()


def travel_to_simulation():
    _TimeMachine.travel_to_simulation()


def travel_to_reality():
    _TimeMachine.travel_to_reality()


def travel_to_tshark():
    _TimeMachine.travel_to_tshark()


def travel_to_pcap():
    _TimeMachine.travel_to_pcap()


def get_simtime_ns():
    return time() * 1000000000


def set_simtime_ns(simtime):
    _TimeMachine.set_simtime(simtime / 1000000000)


def set_simtime(simtime):
    _TimeMachine.set_simtime(simtime)


def set_tsharktime(tsharktime):
    _TimeMachine.set_tsharktime(tsharktime)


def set_pcaptime(pcaptime):
    _TimeMachine.set_pcaptime(pcaptime)


def set_train_interval(train_interval):
    _TimeMachine.set_train_interval(train_interval)


# Dev Test:
if __name__ == "__main__":
    timestamp = time()
    print(timestamp)
    set_simtime(2)
    print(time())
    set_tsharktime(3100100100)
    print(time())
    _TimeMachine.__sim_time = 0
    print(ctime())
    travel_to_reality()
    computer_time.sleep(1)
    print(ctime())
    print(ctime(timestamp))
    travel_to_pcap()
    print(time())
    set_pcaptime(31532400.1)
    print(time())
