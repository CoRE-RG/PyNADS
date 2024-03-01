#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
labelManager.py: Label manager of PyNADS.

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


LABEL_BENIGN = "BENIGN"


class _LabelManager:
	__labels = {}
	__scenario_label = ""

	@staticmethod
	def get_labels():
		# remove old labels
		timestamps = list(_LabelManager.__labels.keys())
		for timestamp in timestamps:
			if timestamp < timemachine.time() - timemachine.train_interval():
				del _LabelManager.__labels[timestamp]
		return _LabelManager.__labels

	@staticmethod
	def get_scenario_label():
		return _LabelManager.__scenario_label

	@staticmethod
	def get_number_of_labels():
		return len(_LabelManager.__labels)

	@staticmethod
	def add_label(label):
		sublabels = label.split(" - ")
		_LabelManager.__labels[timemachine.time()] = sublabels[0]
		if len(sublabels) > 1:
			_LabelManager.__scenario_label = sublabels[1]
		else:
			_LabelManager.__scenario_label = ""
	

def has_label():
	return _LabelManager.get_number_of_labels() > 0


def label():
	for value in labels().values():
		if value != LABEL_BENIGN:
			return value
	return LABEL_BENIGN


def labels():
	return _LabelManager.get_labels()


def in_scenario():
	return _LabelManager.get_scenario_label() != ""


def scenario():
	return _LabelManager.get_scenario_label()


def is_benign():
	for value in labels().values():
		if value != LABEL_BENIGN:
			return False
	return True


def is_abnormal():
	return not is_benign()


def add_label(label):
	_LabelManager.add_label(label)


# Dev Test:
if __name__ == "__main__":
	add_label(LABEL_BENIGN)
	print("Label: {}".format(label()))
	print("isBenign: {}".format(isBenign()))
	print("isAbnormal: {}".format(isAbnormal()))
	add_label("ABNORMAL")
	print("Label: {}".format(label()))
	print("isBenign: {}".format(isBenign()))
	print("isAbnormal: {}".format(isAbnormal()))
