#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
PyNADS.py: Main file of PyNADS.

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


import anomalydetection
import confusionManager
import ethernet
import labelManager
import metrics
import timemachine


import argparse
import logging
import multiprocessing
import os
import platform
import progressbar
import subprocess
import sys
import textwrap
import traceback
from collections import namedtuple
if sys.platform == "win32":
    import winsound


__author__      = "Philipp Meyer, Wilhelm Schumacher"
__copyright__   = "Copyright (C) 2023  Philipp Meyer"

__license__     = "GPL"
__version__     = "1.2024.02.29.0" # <Major Version>.<Year>.<Month>.<Day>.<Minor Version>
__maintainer__  = "Philipp Meyer"
__email__       = "philipp.meyer@haw-hamburg.de"


NUMBER_SKIP_TRAIN_VALUES = 1
NUMBER_SKIP_PREDICT_VALUES = 10
RECEIVE_TIMEOUT_INTERVAL_FACTOR = 10

ANOMALY_CODE_ZERO = 0
ANOMALY_CODE_UNSPECIFIED = 1
ANOMALY_CODE_HEARTBEAT = 3


reportdata_fields = ('rep_code',
                     'rep_seq_num',
                     'report_id')
REPORT_DATA_TYPES_STRING = 'QQ'
Reportdata_t = namedtuple('ReportData', reportdata_fields)


class PyNADS:

    def __init__(self):
        self.name = "PyNADS"
        self.Running = True
        self.processes = []
        self.parser = None
        self.args = None
        self.logger = None
        self.frame_cnt = 0
        self.undefined_cnt = 0
        self.report_cnt = 0

    def print_copyright(self):
        print("PyNADS  " + __copyright__)
        print("This program comes with ABSOLUTELY NO WARRANTY.")
        print("This is free software, and you are welcome to redistribute it")
        print("under certain conditions.\n")

    def print_version(self):
        print("\nPython based Network Anomaly Detection System (PyNADS)\n")
        print("Version: " + __version__ + "\n")
        self.print_copyright()

    def print_help(self):
        self.print_version()
        self.parser.print_help(sys.stdout)
        print("\nlokal interfaces:")
        ethernet.print_interfaces()

    def print_version_and_exit(self):
        self.print_version()
        os._exit(1)

    def print_help_and_exit(self, quiet=False):
        if not quiet:
            self.print_help()
        os._exit(1)

    def print_interfaces_and_exit(self):
        print("\nlokal interfaces:")
        ethernet.print_interfaces()
        os._exit(1)

    def parse_arguments(self):
        self.parser = argparse.ArgumentParser(add_help=False, formatter_class=argparse.RawTextHelpFormatter)
        # A
        self.parser.add_argument("-a", "--ada", "--adalgorithm",
                                 dest="adalgorithm",
                                 type=str,
                                 help="Anomaly detection algorithm {SVM, EE, IF, KM<number_of_clusters>, MS, HBO, AE}",
                                 default=anomalydetection.ALGORITHM.KM.value)
        self.parser.add_argument("--a-border-enlargement-factor",
                                 dest="a_border_enlargement_factor",
                                 type=float,
                                 help="The portion clusters are enlarged with after learning. (USED FOR KM and MS algorithms) | default=1.1",
                                 default=1.1)
        self.parser.add_argument("--a-contamination",
                                 dest="a_contamination",
                                 type=float,
                                 help="The amount of contamination of the learn data set, i.e. the proportion of outliers in the data set. (USED FOR SVM, EE, and IF algorithms) | default=0.1",
                                 default=0.1)
        # B
        self.parser.add_argument("--beep",
                                 dest="beep",
                                 action='store_true',
                                 help="Sound feedback (experimental)",
                                 default=False)
        # F
        self.parser.add_argument("-f", "--filter",
                                 dest="filter",
                                 type=str,
                                 help=textwrap.dedent('''\
                                    If Default or Pyshark socket: Berkeley Packet Filter (BPF) syntax (EXAMPLES: http://biot.com/capstats/bpf.html)
                                    If Pcap file: Display Filter syntax (EXAMPLES: https://gitlab.com/wireshark/wireshark/-/wikis/DisplayFilters)'''),
                                 default="")
        # H
        self.parser.add_argument("-h", "-?", "--help",
                                 dest="help",
                                 action="store_true",
                                 help="Print help",
                                 default=False)
        # I
        self.parser.add_argument("-i", "--train-interval",
                                 dest="traininterval",
                                 type=float,
                                 help="Train interval in seconds",
                                 default=1)  
        self.parser.add_argument("-I", "--interface",
                                 dest="interface",
                                 type=str,
                                 help="Interface name",
                                 default="")
        # L
        self.parser.add_argument("-l", "--load",
                                 dest="load",
                                 type=str,
                                 help="Load train data from a file (skips training phase)",
                                 default="")
        self.parser.add_argument("--log-level",
                                 dest="log_level",
                                 type=str,
                                 help="Log level {DEBUG, INFO, WARNING, ERROR, CRITICAL} | default=INFO",
                                 default="INFO")
        self.parser.add_argument("--log-file",
                                 dest="logFile",
                                 type=str,
                                 help="Write output to a logging file",
                                 default="")
        self.parser.add_argument("--log-summary-interval",
                                 dest="logSummaryInterval",
                                 type=float,
                                 help="Summary logging interval in seconds | default=60",
                                 default=60)
        # M
        self.parser.add_argument("-m", "--metrics",
                                 dest="metrics_definition",
                                 type=str,
                                 nargs='+',
                                 help="Selection of metrics",
                                 choices=tuple(t.name for t in metrics.METRIC))
        # N
        self.parser.add_argument("-n", "--name",
                                 dest="name",
                                 type=str,
                                 help="Name of the PyNADS instance",
                                 default="PyNADS")
        # P
        self.parser.add_argument("--pcapFile",
                                 dest="pcap_file",
                                 type=str,
                                 help="Use a pcap file instead of a network interface",
                                 default="")
        self.parser.add_argument("--plot",
                                 dest="plot",
                                 action='store_true',
                                 help="Show plot",
                                 default=False)
        self.parser.add_argument("--pyshark",
                                 dest="pyshark",
                                 action='store_true',
                                 help="Use a Pysharksocket",
                                 default=False)                                 
        # Q
        self.parser.add_argument("-q", "--quiet",
                                 dest="quiet",
                                 action="store_true",
                                 help="No output on command line",
                                 default=False)
        # R
        self.parser.add_argument("-r", "--r-dst", "--report-destination",
                                 dest="reportAddress",
                                 type=str,
                                 help="MAC address a report should be forwarded to",
                                 default="")
        self.parser.add_argument("--r-heartbeat-interval", "--report-heartbeat-interval",
                                 dest="reportHeartbeatInterval",
                                 type=float,
                                 help="Interval of heartbeat reports in seconds | default=60",
                                 default=60)
        self.parser.add_argument("--r-id", "--report-id",
                                 dest="reportID",
                                 type=str,
                                 help="ID of the NADS in report",
                                 default="")
        # S
        self.parser.add_argument("-s", "--save",
                                 dest="save",
                                 type=str,
                                 help="Save train data to file",
                                 default="")
        self.parser.add_argument("-S", "--Is", "--interfaceSpeed",
                                 dest="interface_speed",
                                 type=int,
                                 help="Interface speed in Mbit per second",
                                 default=0)
        self.parser.add_argument("--sim",
                                 dest="sim",
                                 action='store_true',
                                 help="Use data from an OMNeT++ simulation instead of an interface (filter not working)",
                                 default=False)
        self.parser.add_argument("--simIP",
                                 dest="simIP",
                                 type=str,
                                 help="IP of the location of the running simulation",
                                 default="127.0.0.1")
        self.parser.add_argument("--simPort",
                                 dest="simPort",
                                 type=int,
                                 help="Port configured for the ExternalConnection of the simulation",
                                 default=2144)
        self.parser.add_argument("--speak",
                                 dest="speak",
                                 action='store_true',
                                 help="Spoken feedback (experimental)",
                                 default=False)
        # T
        self.parser.add_argument("-t", "--trainTime",
                                 dest="traintime",
                                 type=float,
                                 help="Train time in seconds",
                                 default=60.)
        # V
        self.parser.add_argument("-v", "--version",
                                 dest="version",
                                 action="store_true",
                                 help="Print version",
                                 default=False)
        # X
        self.parser.add_argument("-x", "--mx", "--metricx",
                                 dest="metricx",
                                 type=str,
                                 help="Metric for x axis",
                                 choices=tuple(t.name for t in metrics.METRIC),
                                 default=metrics.METRIC.AVG_FRAME_SIZE.name)
        # Y
        self.parser.add_argument("-y", "--my", "--metricy",
                                 dest="metricy",
                                 type=str,
                                 help="Metric for y axis",
                                 choices=tuple(t.name for t in metrics.METRIC),
                                 default=metrics.METRIC.BANDWIDTH.name)
        # Process arguments
        self.args = self.parser.parse_args()
        if not len(sys.argv) > 1 or self.args.help:
            self.print_help_and_exit(quiet=(self.args.quiet and not self.args.help))
        elif self.args.version:
            self.print_version_and_exit()
        elif len(self.args.interface) > 0:
            if not ethernet.test_if_interface_exists(self.args.interface):
                print("Interface " + self.args.interface + " does not exist!")
                self.print_interfaces_and_exit()

    def init_logging(self):
        # Set up logging
        self.logger = logging.getLogger(self.args.name)
        self.logger.setLevel(getattr(logging, self.args.log_level.upper()))
        # Logging to file
        if len(self.args.logFile) > 0:
            self.logger.addHandler(logging.FileHandler(self.args.logFile))
        # Logging to console
        if not self.args.quiet:
            self.logger.addHandler(logging.StreamHandler())

    def beep(self, duration=1, frequency=440):
        if sys.platform == "linux" or sys.platform == "linux2":
            subprocess.Popen(['play', '--no-show-progress', '--null', '--channels', '1', '-t', 'alsa','synth', str(duration), 'sine', str(frequency)])
        elif sys.platform == "win32":
            winsound.Beep(frequency, duration * 1000)
        else:
            raise OSError("Beeping not supported on this Platform")

    def say(self, text):
        if sys.platform == "linux" or sys.platform == "linux2":
            subprocess.Popen(['spd-say', text])
        else:
            raise OSError("Speaking not supported on this Platform")

    def feedback(self, text):
        self.logger.info(text)
        if self.args.speak:
            self.say(text)
        if self.args.beep:
            self.beep(1, 440)

    def log_summary(self):
        self.logger.info("### " + self.name + " Summary ###")
        self.logger.info("Training start:                  " + str(self.start_train_datetime))
        self.logger.info("Training end / Prediction start: " + str(self.end_train_datetime))
        self.logger.info("Now:                             " + str(timemachine.ctime()))
        self.logger.info("Received frames:                 " + str(self.frame_cnt))
        # self.logger.info("Number of normal data:           " + str(confusionManager.normal_cnt()))
        # self.logger.info("Number of outlier data:          " + str(confusionManager.accumulated_outliers()))
        # for outlier_type in confusionManager.outlier_types():
        #     self.logger.info("    " + f"{outlier_type + ':': <29}" + str(confusionManager.outliers(outlier_type)))
        self.logger.info("Number of undefined data:        " + str(self.undefined_cnt))
        self.logger.info("####################")
        self.logger.info(confusionManager.confusion_matrix_string())

    def cleanup(self):
        for process in self.processes:
            process.terminate()
            process.join(5)

    def init_socket(self):
        if len(self.args.pcap_file) > 0:
            sock = ethernet.PcapFileSocket(self.args.pcap_file, self.args.filter)
            timemachine.travel_to_pcap()    
        elif self.args.sim:
            sock = ethernet.SimSocket(self.args.simIP, self.args.simPort)
            timemachine.travel_to_simulation()
        elif self.args.pyshark:
            sock = ethernet.PySharkSocket(self.args.interface, self.args.filter)
            timemachine.travel_to_tshark()
        elif len(self.args.filter) > 0 or platform.system() == "Windows":
            sock = ethernet.ScapySocket(self.args.interface, self.args.filter)
        else:
            sock = ethernet.RawSocket(self.args.interface)
        if self.args.interface_speed > 0:
            sock.set_interface_speed(self.args.interface_speed)
        return sock

    def init_metric(self, metricArgs, interfaceSpeed):
        if metricArgs == metrics.METRIC.BANDWIDTH.name:
            return metrics.Bandwidth(interfaceSpeed)
        elif metricArgs == metrics.METRIC.AVG_FRAME_SIZE.name:
            return metrics.AverageFrameSize(ethernet.ETH_MAX_FRAME_BYTES)
        elif metricArgs == metrics.METRIC.AVG_FRAME_GAP.name:
            return  metrics.AverageFrameGAP(self.args.traininterval)
        elif metricArgs == metrics.METRIC.JITTER.name:
            return  metrics.Jitter(self.args.traininterval)
        else:
            self.print_help_and_exit()

    def init_metrics(self, socket):
        metricx = self.init_metric(self.args.metricx, socket.get_interface_speed())
        metricy = self.init_metric(self.args.metricy, socket.get_interface_speed())
        self.metrics = [metricx, metricy]
        if self.args.metrics_definition:
            for i in range(len(self.args.metrics_definition)):
                if i < 2:
                    self.metrics[i] = self.init_metric(self.args.metrics_definition[i], socket.get_interface_speed())
                else:
                    self.metrics.append(self.init_metric(self.args.metrics_definition[i], socket.get_interface_speed()))
        for i in range(len(self.metrics)):
            self.logger.info("Metric [" + str(i) + "]: " + self.metrics[i].get_name())

    def init_algorithm(self):
        if self.args.adalgorithm == anomalydetection.ALGORITHM.SVM.value:
            self.ad = anomalydetection.SVM(self.metrics,
                                           contamination=self.args.a_contamination)
        elif self.args.adalgorithm == anomalydetection.ALGORITHM.EE.value:
            self.ad = anomalydetection.EE(self.metrics,
                                          contamination=self.args.a_contamination)
        elif self.args.adalgorithm == anomalydetection.ALGORITHM.IF.value:
            self.ad = anomalydetection.IF(self.metrics,
                                          contamination=self.args.a_contamination)
        elif anomalydetection.ALGORITHM.KM.value in self.args.adalgorithm:
            number_of_cluster_str = self.args.adalgorithm.replace("KM", "")
            if number_of_cluster_str == "":
                number_of_cluster_str = "1"
            self.ad = anomalydetection.KM(self.metrics,
                                          number_of_clusters=int(number_of_cluster_str),
                                          border_enlargement_factor=self.args.a_border_enlargement_factor)
        elif self.args.adalgorithm == anomalydetection.ALGORITHM.MS.value:
            self.ad = anomalydetection.MS(self.metrics,
                                          border_enlargement_factor=self.args.a_border_enlargement_factor)
        elif self.args.adalgorithm == anomalydetection.ALGORITHM.HBO.value:
            self.ad =  anomalydetection.HBO(self.metrics)
        elif self.args.adalgorithm == anomalydetection.ALGORITHM.AE.value:
            self.ad = anomalydetection.AE(self.metrics)
        else:
             self.print_help_and_exit()
        self.logger.info("Algorithm: " + self.ad.to_string())

    def add_data_to_metric(self, metric, timeSinceLastPackage, bytesOfPackage):
        if metric.get_name() == metrics.METRIC.BANDWIDTH.value or metric.get_name() == metrics.METRIC.AVG_FRAME_SIZE.value:
            metric.add_bytes(bytesOfPackage)
        elif metric.get_name() == metrics.METRIC.AVG_FRAME_GAP.value or metric.get_name() == metrics.METRIC.JITTER.value:
            metric.add_seconds(timeSinceLastPackage)

    def start_plotter_process(self, predicted_normal_data_queue, predicted_outlier_data_queue):
        plotter_process = None
        if self.args.adalgorithm == anomalydetection.ALGORITHM.AE.value:
            plotter_process = self.ad.Plotter(self.name, self.ad.get_train_data(), predicted_normal_data_queue, predicted_outlier_data_queue)
        elif anomalydetection.ALGORITHM.KM.value in self.args.adalgorithm or self.args.adalgorithm == anomalydetection.ALGORITHM.MS.value:
                 plotter_process = self.ad.Plotter(self.name, self.ad.get_train_data(), self.ad.get_cluster_centers(),
                                              self.ad.get_dist_train_data_max(),
                                              predicted_normal_data_queue,
                                              predicted_outlier_data_queue)
        else:
            plotter_process = self.ad.Plotter(self.name, self.ad.get_train_data(), predicted_normal_data_queue, predicted_outlier_data_queue, self.ad.get_clf(), self.ad.get_contamination())
        plotter_process.set_xlabel(self.metrics[0].to_string())
        plotter_process.set_ylabel(self.metrics[1].to_string())
        self.processes.append(plotter_process)
        plotter_process.start()
    

    def send_report(self, sock, address, code, report_id):
        reportdata = Reportdata_t(rep_code=code, rep_seq_num=self.report_cnt, report_id=report_id)
        frame = sock.encapsulate(reportdata.rep_code.to_bytes(8, byteorder="big", signed=False) + reportdata.rep_seq_num.to_bytes(8, byteorder="big", signed=False) + bytes(reportdata.report_id, 'utf-8'))
        sock.set_ethertype(frame, ethernet.ETH_TYPE_REPORT)
        sock.set_destination_address(frame, address)
        sock.send(frame)
        self.report_cnt += 1

    def run(self):
        try:
            # Initialize program
            self.parse_arguments()
            self.init_logging()
            self.name = self.args.name
            if len(self.args.reportID) > 0:
                report_id = self.args.reportID
            else:
                report_id = self.name
            train = True
            if len(self.args.load) > 0:
                train = False
            sock = self.init_socket()
            self.logger.info("##############################")
            self.logger.info(self.name + " | " + sock.to_string() + ":")         
            self.init_metrics(sock)
            self.init_algorithm()
            # Initialize state variables
            skipped_train_values = 0
            skipped_predict_values = 0
            last_heartbeat_report = 0
            predicted_normal_data_queue = multiprocessing.Queue()
            predicted_outlier_data_queue = multiprocessing.Queue()
            start_train = timemachine.time()
            past_train = timemachine.time()
            past_frame = timemachine.time()
            self.start_train_datetime = timemachine.ctime()
            timemachine.set_train_interval(self.args.traininterval)
            trained = False
            bar = progressbar.ProgressBar(maxval=100, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()]).start()
            if train:
                self.logger.info("Started a " + str(timemachine.train_interval()) + " seconds interval training with a " + str(self.args.traintime) + " seconds duration at " + str(self.start_train_datetime))
            # Start of program loop
            while self.Running:
                frame = sock.receive(timeout=timemachine.train_interval() * RECEIVE_TIMEOUT_INTERVAL_FACTOR)
                now = timemachine.time()
                self.frame_cnt += 1
                for metric in self.metrics:
                    self.add_data_to_metric(metric, (now - past_frame), sock.get_number_of_bytes(frame))
                past_frame = now
                if (now - past_train) > timemachine.train_interval():
                    data = []
                    data_is_zero = True
                    for metric in self.metrics:
                        value = metric.get_result()
                        if value > 0:
                            data_is_zero = False
                        data.append(value)
                    # Start of train data recording               
                    if ((now - start_train) < self.args.traintime) and train:
                        bar.update(int((now - start_train) / self.args.traintime * 100))
                        if not data_is_zero and skipped_train_values >= NUMBER_SKIP_TRAIN_VALUES: # Don't train if all values are zero or first values
                            self.ad.add_data(data)
                        else:
                            skipped_train_values += 1
                    # End of train data recording
                    else:
                        # Training
                        if not trained:
                            bar.finish()
                            if len(self.args.load) > 0:
                                self.logger.info("Load data from File: " + self.args.load)
                                self.ad.load_data(self.args.load)
                            if len(self.args.save) > 0:
                                self.ad.save_data(self.args.save)
                            self.ad.fit_data() 
                            last_summary_log = timemachine.time()
                            self.end_train_datetime = timemachine.ctime()
                            self.logger.info("System trained with " + str(self.ad.get_train_data().size) + " (Skipped " + str(skipped_train_values*2) + ")" + " elements at " + str(self.end_train_datetime))
                            if self.args.plot:
                                if len(self.metrics) == 2:
                                    self.start_plotter_process(predicted_normal_data_queue, predicted_outlier_data_queue)
                                else:
                                    self.logger.warning("Plotting is only supported with 2 metrics!")
                            self.logger.info("Reporting outliers:")
                            trained = True  
                        # Prediction
                        if skipped_predict_values > NUMBER_SKIP_PREDICT_VALUES: # Don't predict first values
                            prediction = self.ad.predict_data(data)
                        else:
                            prediction = 0
                            skipped_predict_values += 1
                        if prediction == 1:
                            if self.args.plot and len(self.metrics) == 2:
                                predicted_normal_data_queue.put(self.ad.get_newest_predicted_normal_data())
                            confusionManager.increment_normal_cnt()
                        elif prediction == -1:
                            if data_is_zero:
                                anomaly_code = confusionManager.ANOMALY_CODE[confusionManager.OUTLIER_ZERO]
                                confusionManager.increment_outlier_cnt(confusionManager.OUTLIER_ZERO)
                            else:
                                anomaly_code = confusionManager.ANOMALY_CODE[confusionManager.OUTLIER_UNSPECIFIED]
                                confusionManager.increment_outlier_cnt(confusionManager.OUTLIER_UNSPECIFIED)
                            self.logger.info("### Outlier ###")
                            if labelManager.in_scenario():
                                self.feedback("Active Scenario: " + labelManager.scenario())
                            self.feedback("Outlier detected at " + str(timemachine.ctime(int(now))) + ":")
                            for i in range(len(data)):
                                self.feedback(self.metrics[i].get_name() + ": " + str(data[i]))
                            self.feedback("CODE: " + str(anomaly_code))
                            self.logger.info("####################")
                            if self.args.plot and len(self.metrics) == 2:
                                predicted_outlier_data_queue.put(self.ad.get_newest_predicted_outlier_data())
                            if len(self.args.reportAddress) > 0:
                                self.send_report(sock, self.args.reportAddress, anomaly_code, report_id)   
                        if timemachine.time() - last_heartbeat_report > self.args.reportHeartbeatInterval:
                            if len(self.args.reportAddress) > 0:
                                self.send_report(sock, self.args.reportAddress, ANOMALY_CODE_HEARTBEAT, report_id)
                            last_heartbeat_report = timemachine.time()
                        if timemachine.time() - last_summary_log > self.args.logSummaryInterval:
                            self.log_summary()
                            last_summary_log = timemachine.time()
                    past_train = now
        except StopIteration:
            self.log_summary()
            self.logger.info("No more data available")
            input("Press Enter to exit...") 
            self.logger.info("Shutdown requested....exiting")
        except KeyboardInterrupt:
            self.logger.info("Shutdown requested....exiting")
            self.log_summary()
        except Exception:
            traceback.print_exc(file=sys.stderr)
        finally:   
            self.cleanup()
            print("PyNADS shutdown finished!")
            print("##############################")


if __name__ == "__main__":
    nads = PyNADS()
    nads.run()
