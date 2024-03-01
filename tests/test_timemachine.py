import sys
import os
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
import unittest

import timemachine


class TestTimeMachine(unittest.TestCase):
    def test_time_travel(self):
        timemachine.travel_to_reality()
        reality1 = timemachine.time()
        timemachine.travel_to_simulation()
        timemachine.set_simtime(0)
        simulation1 = timemachine.time()
        self.assertEqual(simulation1, 0)
        timemachine.travel_to_reality()
        reality2 = timemachine.time()
        self.assertAlmostEqual(reality1, reality2, 3)

    def test_simulation_sync(self):
        timemachine.set_simtime(2)
        simulation1 = timemachine.time()
        self.assertEqual(simulation1, 2)
        timemachine.set_simtime_ns(3100100100)
        simulation2 = timemachine.time()
        self.assertEqual(simulation2, 3.1001001)

    def test_privacy(self):
        timemachine.set_simtime(2)
        simulation1 = timemachine.time()
        timemachine._TimeMachine.__simTime = 0
        simulation2 = timemachine.time()
        self.assertEqual(simulation2, simulation1)


if __name__ == '__main__':
    unittest.main()
