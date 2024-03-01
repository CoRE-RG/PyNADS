#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
metrics.py: Input metirc calculations of PyNADS.

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


from enum import Enum


class METRIC(Enum):
    BANDWIDTH = 'Bandwidth'
    AVG_FRAME_SIZE = 'AverageFrameSize'
    AVG_FRAME_GAP = 'AverageFrameGAP'
    JITTER = 'Jitter'


class _Metric:
    def __init__(self, metricMin, metricMax):
        self._name = self.__class__.__name__
        self.metricMin = metricMin
        self.metricMax = metricMax

    def get_name(self):
        return self._name

    def get_metricMin(self):
        return self.metricMin

    def get_metricMax(self):
        return self.metricMax

    def to_string(self):
        return self._name


class Bandwidth(_Metric):
    def __init__(self, metricMax):
        super().__init__(0, metricMax)
        self.bits = 0
        self.lastGet = timemachine.time()

    def get_duration(self):
        now = timemachine.time()
        return now - self.lastGet

    def get_bit_per_second(self):
        now = timemachine.time()
        duration = now - self.lastGet
        if duration > 0:
            bit_per_second = self.bits / duration
        else:
            bit_per_second = 0
        self.lastGet = now
        self.bits = 0
        return bit_per_second

    def get_mbit_per_second(self):
        return self.get_bit_per_second() / 1000000

    def add_bits(self, bits):
        self.bits += bits

    def add_bytes(self, bytes):
        self.bits += (bytes * 8)

    def get_result(self):
        mBits = self.get_mbit_per_second()
        return mBits


class Jitter(_Metric):
    def __init__(self, metricMax):
        super().__init__(0, metricMax)
        self.maxArrival = 0
        self.minArrival = 0
        self.hadfirstValue = False

    def add_seconds(self, seconds):
        if self.hadfirstValue == True:
            if(seconds > self.maxArrival or self.maxArrival == 0):
                self.maxArrival = seconds
            if(seconds < self.minArrival or self.minArrival == 0):
                self.minArrival = seconds
        else:
            self.hadfirstValue = True

    def get_result(self):
        result = self.maxArrival - self.minArrival
        self.maxArrival = 0
        self.minArrival = 0
        return result


class AverageFrameSize(_Metric):
    def __init__(self, metricMax):
        super().__init__(0, metricMax)
        self.averageSize = 0
        self.sampleCount = 0

    def get_bytes(self):
        result = self.averageSize
        self.averageSize = 0
        self.sampleCount = 0
        return result

    def add_bytes(self, bytes):
        self.sampleCount += 1
        self.averageSize = self.averageSize + (bytes - self.averageSize) / self.sampleCount

    def get_result(self):
        bytes = self.get_bytes()
        return bytes


class AverageFrameGAP(_Metric):
    def __init__(self, metricMax):
        super().__init__(0, metricMax)
        self.averageGAP = 0
        self.sampleCount = 0

    def get_seconds(self):
        result = self.averageGAP
        self.averageGAP = 0
        self.sampleCount = 0
        return result

    def add_seconds(self, seconds):
        self.sampleCount += 1
        self.averageGAP = self.averageGAP + (seconds - self.averageGAP) / self.sampleCount

    def get_result(self):
        seconds = self.get_seconds()
        return seconds


# Dev Test:
if __name__ == "__main__":
    bw = Bandwidth()
    print(bw.get_name())
