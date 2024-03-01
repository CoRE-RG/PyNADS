import sys
import os
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
import unittest
import time

import metrics


class TestBandwidth(unittest.TestCase):
    def test_calculation(self):
        repeat = 100
        number_of_bytes = 1500000
        interval = 0.125
        cnt = 0
        start = time.time()
        bandwidth = metrics.Bandwidth()
        while cnt < repeat:
            bandwidth.add_bytes(number_of_bytes)
            time.sleep(interval)
            cnt += 1
        end = time.time()
        bandwidth_metric = bandwidth.get_mbit_per_second()
        bandwidth_calculation = ((repeat * 8 * number_of_bytes) / (end - start) / 1000000)
        print("AlmostEqual: " + str(bandwidth_metric) + ", " + str(bandwidth_calculation))
        self.assertAlmostEqual(bandwidth_metric, bandwidth_calculation, delta=0.1)


if __name__ == '__main__':
    unittest.main()
