#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
anomalydetection.py: Anmomaly detection algorithms of PyNADS.

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


import logging
import multiprocessing
import os
import sys
import queue
from enum import Enum
from scipy import stats
from pyod.models.hbos import HBOS

# Tensorflow loglevel:
#  Level | Level for Humans | Level Description
# -------|------------------|------------------------------------
#  0     | DEBUG            | [Default] Print all messages
#  1     | INFO             | Filter out INFO messages
#  2     | WARNING          | Filter out INFO & WARNING messages
#  3     | ERROR            | Filter out all messages
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import sklearn.preprocessing as pre

stderr = sys.stderr
sys.stderr = open(os.devnull, 'w')
import tensorflow as tf
from tensorflow.keras.layers import Dense, Input
from tensorflow.keras.models import Model
sys.stderr = stderr

from sklearn import svm
from sklearn.cluster import KMeans, MeanShift
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.metrics.pairwise import euclidean_distances

#matplotlib.use('TkAgg')


class ALGORITHM(Enum):
    SVM = 'SVM'  # One-Class SVM
    EE = 'EE'  # Elliptic Envelope
    IF = 'IF'  # Isolation Forest
    KM = "KM"  # KMeans
    MS = "MS"  # MeanShift
    HBO = 'HBO' # Histogram-based Outlier Detection
    AE = 'AE'  # Autoencoder

rng = np.random.RandomState(42)


class _AnomalyDetectionAlgorithm:
    def __init__(self):
        self._name = self.__class__.__name__
        self.train_data = None

    def save_data(self, filename):
        np.save(filename, self.train_data)

    def load_data(self, filename):
        self.train_data = np.load(filename)

    def to_string(self):
        return self._name


class _Plotter(multiprocessing.Process):

    def __init__(self, name):
        multiprocessing.Process.__init__(self)
        self.Running = True
        self.name = name
        self.xlabel = ""
        self.ylabel = ""

    def set_name(self, name):
        self.name = name

    def set_xlabel(self, label):
        self.xlabel = label

    def set_ylabel(self, label):
        self.ylabel = label

    def pause(self, interval):
        backend = plt.rcParams['backend']
        if backend in matplotlib.rcsetup.interactive_bk:
            figManager = matplotlib._pylab_helpers.Gcf.get_active()
            if figManager is not None:
                canvas = figManager.canvas
                if canvas.figure.stale:
                    canvas.draw()
                canvas.start_event_loop(interval)
                return

    def terminate(self):
        self.Running = False
        multiprocessing.Process.terminate(self)


class SVM(_AnomalyDetectionAlgorithm):
    def __init__(self, metrics, contamination=0.0):
        super().__init__()
        self.contamination = contamination
        self.train_data = np.array([[]]).astype(float)
        self.plot_started = False
        self.predicted_normal_data = None
        self.predicted_outlier_data = None
        self.scaler = pre.MinMaxScaler(copy=True, feature_range=(0, 1))
        self.scaler.fit([[metric.get_metricMin() for metric in metrics], [metric.get_metricMax() for metric in metrics]])
        self.clf = svm.OneClassSVM(nu=0.95 * self.contamination + 0.0005, kernel="rbf", gamma="auto")

    def add_data(self, data):
        scaled_data = self.scaler.transform(np.array([data]).astype(float))
        if self.train_data.size > 0:
            self.train_data = np.append(self.train_data, scaled_data, axis=0)
        else:
            self.train_data = scaled_data

    def fit_data(self):
        self.clf.fit(self.train_data)

    def predict_data(self, data):
        scaled_data = self.scaler.transform(np.array([data]).astype(float))
        prediction = self.clf.predict(scaled_data)
        if prediction == -1:
            if self.predicted_outlier_data is None:
                self.predicted_outlier_data = scaled_data
            else:
                self.predicted_outlier_data = np.append(self.predicted_outlier_data, scaled_data, axis=0)
        else:
            if self.predicted_normal_data is None:
                self.predicted_normal_data = scaled_data
            else:
                self.predicted_normal_data = np.append(self.predicted_normal_data, scaled_data, axis=0)
        return prediction

    def get_train_data(self):
        return self.train_data

    def get_newest_predicted_normal_data(self):
        result = self.predicted_normal_data
        self.predicted_normal_data = None
        return result

    def get_newest_predicted_outlier_data(self):
        result = self.predicted_outlier_data
        self.predicted_outlier_data = None
        return result

    def get_clf(self):
        return self.clf

    def get_contamination(self):
        return self.contamination

    class Plotter(_Plotter):

        def __init__(self, name, train_data, predicted_normal_data_queue, predicted_outlier_data_queue, clf, contamination):
            super().__init__(name)
            self.train_data = train_data
            self.predicted_normal_data_queue = predicted_normal_data_queue
            self.predicted_outlier_data_queue = predicted_outlier_data_queue
            self.clf = clf
            self.contamination = contamination

        def run(self):
            plt.ion()
            plt.show()
            plt.figure(num=self.name)
            plt.title("Support Vector Machine")
            xx, yy = np.meshgrid(np.linspace(0, 1, 100), np.linspace(0, 1, 100))
            z = self.clf.decision_function(np.c_[xx.ravel(), yy.ravel()])
            z = z.reshape(xx.shape)
            plt.contourf(xx, yy, z, cmap=plt.cm.Blues_r)
            plt.contour(xx, yy, z, levels=[0], linewidths=1, colors='green')
            plt.scatter(self.train_data[:, 0], self.train_data[:, 1], c="white", s=20, edgecolor='k')
            plt.axis('tight')
            plt.xlim((0, 1))
            plt.ylim((0, 1))
            plt.xlabel(self.xlabel)
            plt.ylabel(self.ylabel)
            plt.draw()
            plt.pause(0.001)
            while self.Running:
                try:
                    predicted_normal_data = self.predicted_normal_data_queue.get(block=False)
                    plt.scatter(predicted_normal_data[:, 0], predicted_normal_data[:, 1], c="green", s=20, edgecolor='k')
                except queue.Empty:
                    pass
                try:
                    predicted_outlier_data = self.predicted_outlier_data_queue.get(block=False)
                    plt.scatter(predicted_outlier_data[:, 0], predicted_outlier_data[:, 1], c="red", s=20, edgecolor='k')
                except queue.Empty:
                    pass
                plt.draw()
                self.pause(0.001)
            plt.close()


class EE(_AnomalyDetectionAlgorithm):
    def __init__(self, metrics, contamination=0):
        super().__init__()
        self.contamination = contamination
        self.plot_started = False
        self.predicted_normal_data = None
        self.predicted_outlier_data = None
        self.train_data = np.array([[]]).astype(float)
        self.scaler = pre.MinMaxScaler(copy=True, feature_range=(0, 1))
        self.scaler.fit([[metric.get_metricMin() for metric in metrics], [metric.get_metricMax() for metric in metrics]])
        self.clf = EllipticEnvelope(contamination=contamination)

    def add_data(self, data):
        scaled_data = self.scaler.transform(np.array([data]).astype(float))
        if self.train_data.size > 0:
            self.train_data = np.append(self.train_data, scaled_data, axis=0)
        else:
            self.train_data = scaled_data

    def fit_data(self):
        self.clf.fit(self.train_data)

    def predict_data(self, data):
        scaled_data = self.scaler.transform(np.array([data]).astype(float))
        prediction = self.clf.predict(scaled_data)
        if prediction == -1:
            if self.predicted_outlier_data is None:
                self.predicted_outlier_data = scaled_data
            else:
                self.predicted_outlier_data = np.append(self.predicted_outlier_data, scaled_data, axis=0)
        else:
            if self.predicted_normal_data is None:
                self.predicted_normal_data = scaled_data
            else:
                self.predicted_normal_data = np.append(self.predicted_normal_data, scaled_data, axis=0)
        return prediction

    def get_train_data(self):
        return self.train_data

    def get_newest_predicted_normal_data(self):
        result = self.predicted_normal_data
        self.predicted_normal_data = None
        return result

    def get_newest_predicted_outlier_data(self):
        result = self.predicted_outlier_data
        self.predicted_outlier_data = None
        return result

    def get_clf(self):
        return self.clf

    def get_contamination(self):
        return self.contamination

    class Plotter(_Plotter):

        def __init__(self, name, train_data, predicted_normal_data_queue, predicted_outlier_data_queue, clf, contamination):
            super().__init__(name)
            self.train_data = train_data
            self.predicted_normal_data_queue = predicted_normal_data_queue
            self.predicted_outlier_data_queue = predicted_outlier_data_queue
            self.clf = clf
            self.contamination = contamination

        def setContamination(self,contamination):
            self.contamination=contamination;

        def run(self):
            plt.ion()
            plt.show()
            plt.figure(num=self.name)
            plt.title("Elliptic Envelope")
            xx, yy = np.meshgrid(np.linspace(0, 1, 100), np.linspace(0, 1, 100))
            z = self.clf.decision_function(np.c_[xx.ravel(), yy.ravel()])
            z = z.reshape(xx.shape)
            scores_pred = self.clf.decision_function(self.train_data)
            threshold = stats.scoreatpercentile(scores_pred, 100 * self.contamination)
            plt.contourf(xx, yy, z, levels=np.linspace(z.min(), threshold, 7),
                        cmap=plt.cm.Blues_r)
            plt.contour(xx, yy, z, levels=[threshold], linewidths=2, colors='red')
            plt.contourf(xx, yy, z, levels=[threshold, z.max()],
                     colors='orange')
            plt.scatter(self.train_data[:, 0], self.train_data[:, 1], c="white", s=20, edgecolor='k')
            plt.axis('tight')
            plt.xlim((-1, 1))
            plt.ylim((-1, 1))
            plt.xlabel(self.xlabel)
            plt.ylabel(self.ylabel)
            plt.draw()
            plt.pause(0.001)
            while self.Running:
                try:
                    predicted_normal_data = self.predicted_normal_data_queue.get(block=False)
                    plt.scatter(predicted_normal_data[:, 0], predicted_normal_data[:, 1], c="green", s=20, edgecolor='k')
                except queue.Empty:
                    pass
                try:
                    predicted_outlier_data = self.predicted_outlier_data_queue.get(block=False)
                    plt.scatter(predicted_outlier_data[:, 0], predicted_outlier_data[:, 1], c="red", s=20, edgecolor='k')
                except queue.Empty:
                    pass
                plt.draw()
                self.pause(0.001)
            plt.close()


class IF(_AnomalyDetectionAlgorithm):
    def __init__(self, metrics, contamination=0):
        super().__init__()
        self.contamination = contamination
        self.plot_started = False
        self.predicted_normal_data = None
        self.predicted_outlier_data = None
        self.train_data = np.array([[]]).astype(float)
        self.scaler = pre.MinMaxScaler(copy=True, feature_range=(0, 1))
        self.scaler.fit([[metric.get_metricMin() for metric in metrics], [metric.get_metricMax() for metric in metrics]])
        self.clf = IsolationForest(max_samples="auto", contamination=self.contamination, random_state=rng)

    def add_data(self, data):
        scaled_data = self.scaler.transform(np.array([data]).astype(float))
        if self.train_data.size > 0:
            self.train_data = np.append(self.train_data, scaled_data, axis=0)
        else:
            self.train_data = scaled_data

    def fit_data(self):
        self.clf.fit(self.train_data)

    def predict_data(self, data):
        scaled_data = self.scaler.transform(np.array([data]).astype(float))
        prediction = self.clf.predict(scaled_data)
        if prediction == -1:
            if self.predicted_outlier_data is None:
                self.predicted_outlier_data = scaled_data
            else:
                self.predicted_outlier_data = np.append(self.predicted_outlier_data, scaled_data, axis=0)
        else:
            if self.predicted_normal_data is None:
                self.predicted_normal_data = scaled_data
            else:
                self.predicted_normal_data = np.append(self.predicted_normal_data, scaled_data, axis=0)
        return prediction

    def get_train_data(self):
        return self.train_data

    def get_newest_predicted_normal_data(self):
        result = self.predicted_normal_data
        self.predicted_normal_data = None
        return result

    def get_newest_predicted_outlier_data(self):
        result = self.predicted_outlier_data
        self.predicted_outlier_data = None
        return result

    def get_clf(self):
        return self.clf

    def get_contamination(self):
        return self.contamination

    class Plotter(_Plotter):

        def __init__(self, name, train_data, predicted_normal_data_queue, predicted_outlier_data_queue, clf, contamination):
            super().__init__(name)
            self.train_data = train_data
            self.predicted_normal_data_queue = predicted_normal_data_queue
            self.predicted_outlier_data_queue = predicted_outlier_data_queue
            self.clf = clf
            self.contamination = contamination

        def setContamination(self,contamination):
            self.contamination=contamination;

        def run(self):
            plt.ion()
            plt.show()
            plt.figure(num=self.name)
            plt.title("IsolationForest")
            xx, yy = np.meshgrid(np.linspace(0, 1, 100), np.linspace(0, 1, 100))
            z = self.clf.decision_function(np.c_[xx.ravel(), yy.ravel()])
            z = z.reshape(xx.shape)
            plt.contourf(xx, yy, z, cmap=plt.cm.Blues_r)
            plt.contour(xx, yy, z, levels=[0], linewidths=2, colors='green')
            plt.scatter(self.train_data[:, 0], self.train_data[:, 1], c="white", s=20, edgecolor='k')
            plt.axis('tight')
            plt.xlim((0, 1))
            plt.ylim((0, 1))
            plt.xlabel(self.xlabel)
            plt.ylabel(self.ylabel)
            plt.draw()
            plt.pause(0.001)
            while self.Running:
                try:
                    predicted_normal_data = self.predicted_normal_data_queue.get(block=False)
                    plt.scatter(predicted_normal_data[:, 0], predicted_normal_data[:, 1], c="green", s=20, edgecolor='k')
                except queue.Empty:
                    pass
                try:
                    predicted_outlier_data = self.predicted_outlier_data_queue.get(block=False)
                    plt.scatter(predicted_outlier_data[:, 0], predicted_outlier_data[:, 1], c="red", s=20, edgecolor='k')
                except queue.Empty:
                    pass
                plt.draw()
                self.pause(0.001)
            plt.close()


class KM(_AnomalyDetectionAlgorithm):
    def __init__(self, metrics, border_enlargement_factor=0, number_of_clusters=1):
        super().__init__()
        self.plot_started = False
        self.border_enlargement_factor = border_enlargement_factor
        self.predicted_normal_data = None
        self.predicted_outlier_data = None
        self.scaler = pre.MinMaxScaler(copy=True, feature_range=(0, 1))
        self.scaler.fit([[metric.get_metricMin() for metric in metrics], [metric.get_metricMax() for metric in metrics]])
        self.number_of_clusters = number_of_clusters
        self.dist_train_data_max = np.empty([self.number_of_clusters])
        self.clf = KMeans(n_clusters=self.number_of_clusters, random_state=rng)

    def add_data(self, data):
        scaled_data = self.scaler.transform(np.array([data]).astype(float))
        if self.train_data is None:
            self.train_data = scaled_data
        else:
            self.train_data = np.append(self.train_data, scaled_data, axis=0)

    def fit_data(self):
        self.clf.fit(self.train_data)
        train_data_cluster = self.clf.predict(self.train_data)
        dist_train_data = self.clf.transform(self.train_data)
        cluster_index = 0
        while cluster_index < self.number_of_clusters:
            cluster_dist_train_data = dist_train_data[:, cluster_index]
            cluster_points_dist_train_data = np.select([train_data_cluster == cluster_index], [ cluster_dist_train_data ])
            cluster_points_dist_train_data_max = np.amax(cluster_points_dist_train_data)
            self.dist_train_data_max[cluster_index] = cluster_points_dist_train_data_max * self.border_enlargement_factor
            cluster_index += 1

    def predict_data(self, data):
        scaled_data = self.scaler.transform(np.array([data]).astype(float))
        cluster = self.clf.predict(scaled_data)
        dist_test_data = self.clf.transform(scaled_data)
        outlier = True
        cluster_index = 0
        while cluster_index < self.number_of_clusters:
            if dist_test_data.item(cluster_index) <= self.dist_train_data_max.item(cluster_index):
                outlier = False
                break
            cluster_index += 1
        if outlier:
            if self.predicted_outlier_data is None:
                self.predicted_outlier_data = scaled_data
            else:
                self.predicted_outlier_data = np.append(self.predicted_outlier_data, scaled_data, axis=0)
            return -1
        else:
            if self.predicted_normal_data is None:
                self.predicted_normal_data = scaled_data
            else:
                self.predicted_normal_data = np.append(self.predicted_normal_data, scaled_data, axis=0)
            return 1

    def get_train_data(self):
        return self.train_data

    def get_cluster_centers(self):
        return self.clf.cluster_centers_

    def get_dist_train_data_max(self):
        return self.dist_train_data_max

    def get_newest_predicted_normal_data(self):
        result = self.predicted_normal_data
        self.predicted_normal_data = None
        return result

    def get_newest_predicted_outlier_data(self):
        result = self.predicted_outlier_data
        self.predicted_outlier_data = None
        return result

    def to_string(self):
        return super().to_string() + str(self.number_of_clusters)

    class Plotter(_Plotter):

        def __init__(self, name, train_data, cluster_centers, dist_train_data_max, predicted_normal_data_queue, predicted_outlier_data_queue):
            super().__init__(name)
            self.train_data = train_data
            self.cluster_centers = cluster_centers
            self.dist_train_data_max = dist_train_data_max
            self.predicted_normal_data_queue = predicted_normal_data_queue
            self.predicted_outlier_data_queue = predicted_outlier_data_queue

        def run(self):
            plt.ion()
            plt.show()
            plt.figure(num=self.name)
            plt.title("KMeans (" + str(len(self.cluster_centers)) + " cluster)")
            plt.scatter(self.train_data[:, 0], self.train_data[:, 1], c="white", s=20, edgecolor='k')
            for index, center in enumerate(self.cluster_centers):
                circle = plt.Circle(center, self.dist_train_data_max.item(index), linewidth=2, color='green', fill=False, hatch='\\')
                ax = plt.gca()
                ax.add_patch(circle)
            plt.axis('tight')
            plt.xlim((0, 1))
            plt.ylim((0, 1))
            plt.xlabel(self.xlabel)
            plt.ylabel(self.ylabel)
            plt.draw()
            plt.pause(0.001)
            while self.Running:
                try:
                    predicted_normal_data = self.predicted_normal_data_queue.get(block=False)
                    plt.scatter(predicted_normal_data[:, 0], predicted_normal_data[:, 1], c="green", s=20, edgecolor='k')
                except queue.Empty:
                    pass
                try:
                    predicted_outlier_data = self.predicted_outlier_data_queue.get(block=False)
                    plt.scatter(predicted_outlier_data[:, 0], predicted_outlier_data[:, 1], c="red", s=20, edgecolor='k')
                except queue.Empty:
                    pass
                plt.draw()
                self.pause(0.001)
            plt.close()


class MS(_AnomalyDetectionAlgorithm):

    def __init__(self, metrics, border_enlargement_factor=0):
        super().__init__()
        self.plot_started = False
        self.border_enlargement_factor = border_enlargement_factor
        self.predicted_normal_data = None
        self.predicted_outlier_data = None
        self.scaler = pre.MinMaxScaler(copy=True, feature_range=(0, 1))
        self.scaler.fit([[metric.get_metricMin() for metric in metrics], [metric.get_metricMax() for metric in metrics]])
        self.number_of_clusters = 0
        self.dist_train_data_max = None
        self.clf = MeanShift(n_jobs=-1)

    def add_data(self, data):
        scaled_data = self.scaler.transform(np.array([data]).astype(float))
        if self.train_data is None:
            self.train_data = scaled_data
        else:
            self.train_data = np.append(self.train_data, scaled_data, axis=0)

    def fit_data(self):
        self.clf.fit(self.train_data)
        labels = self.clf.labels_
        labels_unique = np.unique(labels)
        self.number_of_clusters = len(labels_unique)
        self.dist_train_data_max = np.empty([self.number_of_clusters])
        train_data_cluster = self.clf.predict(self.train_data)
        dist_train_data = euclidean_distances(self.train_data, self.clf.cluster_centers_)
        cluster_index = 0
        while cluster_index < self.number_of_clusters:
            cluster_dist_train_data = dist_train_data[:, cluster_index]
            cluster_points_dist_train_data = np.select([train_data_cluster == cluster_index], [cluster_dist_train_data])
            cluster_points_dist_train_data_max = np.amax(cluster_points_dist_train_data)
            self.dist_train_data_max[cluster_index] = cluster_points_dist_train_data_max * self.border_enlargement_factor
            cluster_index += 1

    def predict_data(self, data):
        scaled_data = self.scaler.transform(np.array([data]).astype(float))
        cluster = self.clf.predict(scaled_data)
        dist_test_data = euclidean_distances(scaled_data, self.clf.cluster_centers_)
        outlier = True
        cluster_index = 0
        while cluster_index < self.number_of_clusters:
            if dist_test_data.item(cluster_index) <= self.dist_train_data_max.item(cluster_index):
                outlier = False
                break
            cluster_index += 1
        if outlier:
            if self.predicted_outlier_data is None:
                self.predicted_outlier_data = scaled_data
            else:
                self.predicted_outlier_data = np.append(self.predicted_outlier_data, scaled_data, axis=0)
            return -1
        else:
            if self.predicted_normal_data is None:
                self.predicted_normal_data = scaled_data
            else:
                self.predicted_normal_data = np.append(self.predicted_normal_data, scaled_data, axis=0)
            return 1

    def get_train_data(self):
        return self.train_data

    def get_cluster_centers(self):
        return self.clf.cluster_centers_

    def get_dist_train_data_max(self):
        return self.dist_train_data_max

    def get_newest_predicted_normal_data(self):
        result = self.predicted_normal_data
        self.predicted_normal_data = None
        return result

    def get_newest_predicted_outlier_data(self):
        result = self.predicted_outlier_data
        self.predicted_outlier_data = None
        return result

    class Plotter(_Plotter):

        def __init__(self, name, train_data, cluster_centers, dist_train_data_max, predicted_normal_data_queue, predicted_outlier_data_queue):
            super().__init__(name)
            self.train_data = train_data
            self.cluster_centers = cluster_centers
            self.dist_train_data_max = dist_train_data_max
            self.predicted_normal_data_queue = predicted_normal_data_queue
            self.predicted_outlier_data_queue = predicted_outlier_data_queue

        def run(self):
            plt.ion()
            plt.show(block=False)
            plt.figure(num=self.name)
            plt.title("MeanShift (" + str(len(self.cluster_centers)) + " cluster)")
            plt.scatter(self.train_data[:, 0], self.train_data[:, 1], c="white", s=20, edgecolor='k')
            for index, center in enumerate(self.cluster_centers):
                circle = plt.Circle(center, self.dist_train_data_max.item(index), linewidth=2, color='green', fill=False, hatch='\\')
                ax = plt.gca()
                ax.add_patch(circle)
            plt.axis('tight')
            plt.xlim((0, 1))
            plt.ylim((0, 1))
            plt.xlabel(self.xlabel)
            plt.ylabel(self.ylabel)
            plt.draw()
            plt.pause(0.001)
            while self.Running:
                try:
                    predicted_normal_data = self.predicted_normal_data_queue.get(block=False)
                    plt.scatter(predicted_normal_data[:, 0], predicted_normal_data[:, 1], c="green", s=20, edgecolor='k')
                except queue.Empty:
                    pass
                try:
                    predicted_outlier_data = self.predicted_outlier_data_queue.get(block=False)
                    plt.scatter(predicted_outlier_data[:, 0], predicted_outlier_data[:, 1], c="red", s=20, edgecolor='k')
                except queue.Empty:
                    pass
                plt.draw()
                self.pause(0.001)
            plt.close()


class HBO(_AnomalyDetectionAlgorithm):
    def __init__(self, metrics, contamination=0.1):
        super().__init__()
        self.contamination = contamination
        self.train_data = np.array([[]]).astype(float)
        self.plot_started = False
        self.predicted_normal_data = None
        self.predicted_outlier_data = None
        self.scaler = pre.MinMaxScaler(copy=True, feature_range=(0, 1))
        self.scaler.fit([[metric.get_metricMin() for metric in metrics], [metric.get_metricMax() for metric in metrics]])
        self.clf = HBOS(contamination=contamination)

    def add_data(self, data):
        scaled_data = self.scaler.transform(np.array([data]).astype(float))
        if self.train_data.size > 0:
            self.train_data = np.append(self.train_data, scaled_data, axis=0)
        else:
            self.train_data = scaled_data

    def fit_data(self):
        self.clf.fit(self.train_data)

    def predict_data(self, data):
        scaled_data = self.scaler.transform(np.array([data]).astype(float))
        prediction = self.clf.predict(scaled_data)[0]
        if prediction == 0:
            outlier = False
        else:
            outlier = True
        if outlier:
            if self.predicted_outlier_data is None:
                self.predicted_outlier_data = scaled_data
            else:
                self.predicted_outlier_data = np.append(self.predicted_outlier_data, scaled_data, axis=0)
            return -1
        else:
            if self.predicted_normal_data is None:
                self.predicted_normal_data = scaled_data
            else:
                self.predicted_normal_data = np.append(self.predicted_normal_data, scaled_data, axis=0)
            return 1


    def get_train_data(self):
        return self.train_data

    def get_newest_predicted_normal_data(self):
        result = self.predicted_normal_data
        self.predicted_normal_data = None
        return result

    def get_newest_predicted_outlier_data(self):
        result = self.predicted_outlier_data
        self.predicted_outlier_data = None
        return result

    def getClf(self):
        return self.clf

    class Plotter(_Plotter):

        def __init__(self, name, train_data, predicted_normal_data_queue, predicted_outlier_data_queue,clf):
            super().__init__(name)
            self.train_data = train_data
            self.predicted_normal_data_queue = predicted_normal_data_queue
            self.predicted_outlier_data_queue = predicted_outlier_data_queue
            self.clf=clf

        def setContamination(self,contamination):
            self.contamination=contamination;

        def run(self):
            plt.ion()
            plt.show()
            scores_pred = self.clf.decision_function(self.train_data)
            threshold = stats.scoreatpercentile(scores_pred, 100 * self.clf.contamination)
            plt.figure(num=self.name)
            plt.title("Anomaly Detection Histogram Based (-1: Anormal | 1: Normal)")
            plt.axis('tight')
            plt.xlim((0, 1))
            plt.ylim((0, 1))
            plt.xlabel(self.xlabel)
            plt.ylabel(self.ylabel)
            xx, yy = np.meshgrid(np.linspace(0, 1, 100), np.linspace(0, 1, 100))
            Z = self.clf.decision_function(np.c_[xx.ravel(), yy.ravel()])
            Z = Z.reshape(xx.shape)
            plt.contourf(xx, yy, Z, cmap=plt.cm.Blues_r)
            plt.contour(xx, yy, Z, levels=[threshold], linewidths=2, colors='red')
            plt.scatter(self.train_data[:, 0], self.train_data[:, 1], c="white", s=20, edgecolor='k')
            plt.draw()
            plt.pause(0.001)
            while self.Running:
                try:
                    predicted_normal_data = self.predicted_normal_data_queue.get(block=False)
                    plt.scatter(predicted_normal_data[:, 0], predicted_normal_data[:, 1], c="green", s=20, edgecolor='k')
                except queue.Empty:
                    pass
                try:
                    predicted_outlier_data = self.predicted_outlier_data_queue.get(block=False)
                    plt.scatter(predicted_outlier_data[:, 0], predicted_outlier_data[:, 1], c="red", s=20, edgecolor='k')
                except queue.Empty:
                    pass
                plt.draw()
                plt.pause(0.001)
            plt.close()


class AE(_AnomalyDetectionAlgorithm):

    def __init__(self, metrics):
        super().__init__()
        self.predicted_normal_data = None
        self.predicted_outlier_data = None
        self.scaler = pre.MinMaxScaler(copy=True, feature_range=(0, 1))
        self.scaler.fit([[metric.get_metricMin() for metric in metrics], [metric.get_metricMax() for metric in metrics]])
        input_size=len(metrics)
        hidden_size=32
        code_size=4
        input = Input(shape=(input_size,))
        hidden_1 = Dense(hidden_size, activation='relu')(input)
        code = Dense(code_size, activation='relu')(hidden_1)
        hidden_2 = Dense(hidden_size, activation='relu')(code)
        output = Dense(input_size, activation='sigmoid')(hidden_2)
        self.autoencoder = Model(input, output)
        self.autoencoder.compile(optimizer='adam', loss='binary_crossentropy') # losses:https://www.tensorflow.org/api_docs/python/tf/keras/losses
        self.threshold = None

    def add_data(self, data):
        scaled_data = self.scaler.transform(np.array([data]).astype(float))
        if self.train_data is None:
            self.train_data = scaled_data
        else:
            self.train_data = np.append(self.train_data, scaled_data, axis=0)

    def fit_data(self):
        history = self.autoencoder.fit(self.train_data, self.train_data, epochs=3, batch_size=1, shuffle=True, verbose=0)
        reconstructions = self.autoencoder.predict(self.train_data)
        train_loss = tf.keras.losses.mae(reconstructions, self.train_data)
        self.threshold = np.mean(train_loss) + np.std(train_loss)

    def predict_data(self, data):
        scaled_data = self.scaler.transform(np.array([data]).astype(float))
        reconstructions = self.autoencoder(scaled_data)
        loss = tf.keras.losses.mae(reconstructions, scaled_data)
        if tf.math.less(loss, self.threshold):
            if self.predicted_normal_data is None:
                self.predicted_normal_data = scaled_data
            else:
                self.predicted_normal_data = np.append(self.predicted_normal_data, scaled_data, axis=0)
            return 1
        else:
            if self.predicted_outlier_data is None:
                self.predicted_outlier_data = scaled_data
            else:
                self.predicted_outlier_data = np.append(self.predicted_outlier_data, scaled_data, axis=0)
            return -1

    def get_train_data(self):
        return self.train_data

    def get_newest_predicted_normal_data(self):
        result = self.predicted_normal_data
        self.predicted_normal_data = None
        return result

    def get_newest_predicted_outlier_data(self):
        result = self.predicted_outlier_data
        self.predicted_outlier_data = None
        return result

    class Plotter(_Plotter):

        def __init__(self, name, train_data, predicted_normal_data_queue, predicted_outlier_data_queue):
            super().__init__(name)
            self.train_data = train_data
            self.predicted_normal_data_queue = predicted_normal_data_queue
            self.predicted_outlier_data_queue = predicted_outlier_data_queue

        def run(self):
            plt.ion()
            plt.show(block=False)
            plt.figure(num=self.name)
            plt.title("Autoencoder")
            plt.scatter(self.train_data[:, 0], self.train_data[:, 1], c="white", s=20, edgecolor='k')
            plt.axis('tight')
            plt.xlim((0, 1))
            plt.ylim((0, 1))
            plt.xlabel(self.xlabel)
            plt.ylabel(self.ylabel)
            plt.draw()
            plt.pause(0.001)
            while self.Running:
                try:
                    predicted_normal_data = self.predicted_normal_data_queue.get(block=False)
                    plt.scatter(predicted_normal_data[:, 0], predicted_normal_data[:, 1], c="green", s=20, edgecolor='k')
                except queue.Empty:
                    pass
                try:
                    predicted_outlier_data = self.predicted_outlier_data_queue.get(block=False)
                    plt.scatter(predicted_outlier_data[:, 0], predicted_outlier_data[:, 1], c="red", s=20, edgecolor='k')
                except queue.Empty:
                    pass
                plt.draw()
                self.pause(0.001)
            plt.close()


# Dev Test:
if __name__ == "__main__":
    from random import randrange
    clf = AE(100, 100)
    for i in range(10000):
        clf.add_data(randrange(0,100), randrange(50,60))
    # clf.add_data(55, 55)
    # clf.add_data(66, 66)
    # clf.save_data("Test.npy")
    # clf.add_data(77, 77)
    # clf.load_data("Test.npy")
    print(clf.train_data)
    clf.fit_data()
    for i in range(20):
        x = randrange(0,100)
        y = randrange(0,100)
        print([x, y])
        clf.predict_data(x, y)
    
