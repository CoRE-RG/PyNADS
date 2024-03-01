#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
confusionManager.py: Performance metrics calculations of PyNADS.

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


import labelManager


OUTLIER_UNSPECIFIED = "UNSPECIFIED"
OUTLIER_ZERO = "ZERO"

ANOMALY_CODE = {
	OUTLIER_ZERO: 0,
	OUTLIER_UNSPECIFIED: 1,
}


class _ConfusionManager:
	__normal_cnt = 0
	__outlier_cnts = {
		OUTLIER_UNSPECIFIED: 0,
		OUTLIER_ZERO: 0
	}
	__true_positives = {}
	__true_negatives = {}
	__false_positives = {}
	__false_negatives = {}

	@staticmethod
	def get_normal_cnt():
		return _ConfusionManager.__normal_cnt

	@staticmethod
	def get_outlier_types():
		return _ConfusionManager.__outlier_cnts.keys()

	@staticmethod
	def get_outliers(outlier_type):
		if outlier_type not in _ConfusionManager.__outlier_cnts:
			return 0
		return _ConfusionManager.__outlier_cnts[outlier_type]

	@staticmethod
	def get_accumulated_outliers():
		return sum(_ConfusionManager.__outlier_cnts.values())

	@staticmethod
	def get_true_positive_labels():
		return _ConfusionManager.__true_positives.keys()

	@staticmethod
	def get_true_positives(label):
		if label not in _ConfusionManager.__true_positives:
			return 0
		return _ConfusionManager.__true_positives[label]

	@staticmethod
	def get_accumulated_true_positives():
		return sum(_ConfusionManager.__true_positives.values())

	@staticmethod
	def get_true_negative_labels():
		return _ConfusionManager.__true_negatives.keys()

	@staticmethod
	def get_true_negatives(label):
		if label not in _ConfusionManager.__true_negatives:
			return 0
		return _ConfusionManager.__true_negatives[label]

	@staticmethod
	def get_accumulated_true_negatives():
		return sum(_ConfusionManager.__true_negatives.values())

	@staticmethod
	def get_false_positive_labels():
		return _ConfusionManager.__false_positives.keys()

	@staticmethod
	def get_false_positives(label):
		if label not in _ConfusionManager.__false_positives:
			return 0
		return _ConfusionManager.__false_positives[label]

	@staticmethod
	def get_accumulated_false_positives():
		return sum(_ConfusionManager.__false_positives.values())

	@staticmethod
	def get_false_negative_labels():
		return _ConfusionManager.__false_negatives.keys()

	@staticmethod
	def get_false_negatives(label):
		if label not in _ConfusionManager.__false_negatives:
			return 0
		return _ConfusionManager.__false_negatives[label]

	@staticmethod
	def get_accumulated_false_negatives():
		return sum(_ConfusionManager.__false_negatives.values())

	@staticmethod
	def get_precision(label):
		if label not in _ConfusionManager.__true_positives:
			return 0
		if label not in _ConfusionManager.__false_positives:
			return 0
		return _ConfusionManager.__true_positives[label] / (_ConfusionManager.__true_positives[label] + _ConfusionManager.__false_positives[label])

	@staticmethod
	def get_accumulated_precision():
		if _ConfusionManager.get_accumulated_true_positives() == 0 and _ConfusionManager.get_accumulated_false_positives() == 0:
			return 1
		return _ConfusionManager.get_accumulated_true_positives() / (_ConfusionManager.get_accumulated_true_positives() + _ConfusionManager.get_accumulated_false_positives())

	@staticmethod
	def get_recall(label):
		if label not in _ConfusionManager.__true_positives:
			return 0
		if label not in _ConfusionManager.__false_negatives:
			return 0
		return _ConfusionManager.__true_positives[label] / (_ConfusionManager.__true_positives[label] + _ConfusionManager.__false_negatives[label])

	@staticmethod
	def get_accumulated_recall():
		if _ConfusionManager.get_accumulated_true_positives() == 0 and _ConfusionManager.get_accumulated_false_negatives() == 0:
			return 1
		return _ConfusionManager.get_accumulated_true_positives() / (_ConfusionManager.get_accumulated_true_positives() + _ConfusionManager.get_accumulated_false_negatives())

	@staticmethod
	def increment_normal_cnt():
		_ConfusionManager.__normal_cnt += 1
		if labelManager.has_label():
			if labelManager.is_benign():
				if labelManager.label() not in _ConfusionManager.__true_negatives:
					_ConfusionManager.__true_negatives[labelManager.label()] = 0
				_ConfusionManager.__true_negatives[labelManager.label()] += 1
			else:
				if labelManager.label() not in _ConfusionManager.__false_negatives:
					_ConfusionManager.__false_negatives[labelManager.label()] = 0
				_ConfusionManager.__false_negatives[labelManager.label()] += 1

	@staticmethod
	def increment_outlier_cnt(outlier_type):
		if outlier_type not in _ConfusionManager.__outlier_cnts:
			_ConfusionManager.__outlier_cnts[outlier_type] = 0
		_ConfusionManager.__outlier_cnts[outlier_type] += 1
		if labelManager.has_label():
			if labelManager.is_benign():
				if labelManager.label() not in _ConfusionManager.__false_positives:
					_ConfusionManager.__false_positives[labelManager.label()] = 0
				_ConfusionManager.__false_positives[labelManager.label()] += 1
			else:
				if labelManager.label() not in _ConfusionManager.__true_positives:
					_ConfusionManager.__true_positives[labelManager.label()] = 0
				_ConfusionManager.__true_positives[labelManager.label()] += 1


def normal_cnt():
	return _ConfusionManager.get_normal_cnt()


def outlier_types():
	return _ConfusionManager.get_outlier_types()


def outliers(outlier_type):
	return _ConfusionManager.get_outliers(outlier_type)


def accumulated_outliers():
	return _ConfusionManager.get_accumulated_outliers()


def increment_normal_cnt():
	_ConfusionManager.increment_normal_cnt()


def increment_outlier_cnt(outlier_type):
	_ConfusionManager.increment_outlier_cnt(outlier_type)


def confusion_matrix_string():
	confusion_matrix_string = ""
	confusion_matrix_string += "### Confusion Matrix ###\n"
	confusion_matrix_string += f"{'Normal:' : <33}" + "{}\n".format(normal_cnt())
	confusion_matrix_string += f"{'Outliers:' : <33}" + "{}\n".format(accumulated_outliers())
	for outlier_type in outlier_types():
		confusion_matrix_string += "    " + f"{outlier_type + ':': <29}" + "{}\n".format(outliers(outlier_type))
	if labelManager.has_label():
		confusion_matrix_string += f"{'True Positives:' : <33}" + "{}\n".format(_ConfusionManager.get_accumulated_true_positives())
		for label in _ConfusionManager.get_true_positive_labels():
			confusion_matrix_string += "    " + f"{label + ':': <29}" + "{}\n".format(_ConfusionManager.get_true_positives(label))
		confusion_matrix_string += f"{'True Negatives:' : <33}" + "{}\n".format(_ConfusionManager.get_accumulated_true_negatives())
		for label in _ConfusionManager.get_true_negative_labels():
			confusion_matrix_string += "    " + f"{label + ':': <29}" + "{}\n".format(_ConfusionManager.get_true_negatives(label))
		confusion_matrix_string += f"{'False Positives:' : <33}" + "{}\n".format(_ConfusionManager.get_accumulated_false_positives())
		for label in _ConfusionManager.get_false_positive_labels():
			confusion_matrix_string += "    " + f"{label + ':': <29}" + "{}\n".format(_ConfusionManager.get_false_positives(label))
		confusion_matrix_string += f"{'False Negatives:' : <33}" + "{}\n".format(_ConfusionManager.get_accumulated_false_negatives())
		for label in _ConfusionManager.get_false_negative_labels():
			confusion_matrix_string += "    " + f"{label + ':': <29}" + "{}\n".format(_ConfusionManager.get_false_negatives(label))
		confusion_matrix_string += f"{'Precision:' : <33}" + "{}\n".format(_ConfusionManager.get_accumulated_precision())
		confusion_matrix_string += f"{'Recall:' : <33}" + "{}\n".format(_ConfusionManager.get_accumulated_recall())
		confusion_matrix_string += "####################"
	return confusion_matrix_string


# Dev Test:
if __name__ == "__main__":
	increment_outlier_cnt(OUTLIER_UNSPECIFIED)
	increment_outlier_cnt(OUTLIER_UNSPECIFIED)
	increment_outlier_cnt(OUTLIER_ZERO)
	increment_outlier_cnt(OUTLIER_ZERO)
	increment_outlier_cnt(OUTLIER_ZERO)
	increment_outlier_cnt("TEST")
	print("Outlier Counts: {}".format(_ConfusionManager.__outlier_cnts))
