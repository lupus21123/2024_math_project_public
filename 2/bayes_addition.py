import os
import sys
import argparse
import logging

import math
from collections import defaultdict

def training(instances, labels):
    separated = defaultdict(list)
    for instance, label in zip(instances, labels):
        separated[label].append(instance)
    
    summaries = {}
    for class_value, rows in separated.items():
        summaries[class_value] = [
            (calculate_mean_std([row[i] for row in rows]) + (len(rows),))
            for i in range(len(rows[0]))
        ]
    return summaries

def calculate_mean_std(data):
    mean = sum(data) / len(data)
    variance = sum((x - mean) ** 2 for x in data) / len(data)
    std_dev = math.sqrt(variance)
    return mean, std_dev

# Gaussian
def gaussian_probability(x, mean, std_dev):
    if std_dev == 0:
        return 1 if x == mean else 0
    exponent = math.exp(-((x - mean) ** 2 / (2 * std_dev ** 2)))
    return (1 / (math.sqrt(2 * math.pi) * std_dev)) * exponent

def calculate_class_probabilities(summaries, instance):
    total_rows = sum(summaries[label][0][2] for label in summaries)
    probabilities = {}
    for class_value, class_summaries in summaries.items():
        probabilities[class_value] = (
            class_summaries[0][2] / total_rows  # P(Class )
        )
        for i, (mean, std_dev, _) in enumerate(class_summaries):
            probabilities[class_value] *= gaussian_probability(instance[i], mean, std_dev)
    return probabilities

# predict 함수 구현
def predict(instance, parameters):
    probabilities = calculate_class_probabilities(parameters, instance)
    return max(probabilities, key=probabilities.get)


def report(predictions, answers):
    if len(predictions) != len(answers):
        logging.error("The lengths of two arguments should be same")
        sys.exit(1)

    # accuracy
    correct = 0
    for idx in range(len(predictions)):
        if predictions[idx] == answers[idx]:
            correct += 1
    accuracy = round(correct / len(answers), 2) * 100

    # precision
    tp = 0
    fp = 0
    for idx in range(len(predictions)):
        if predictions[idx] == 1:
            if answers[idx] == 1:
                tp += 1
            else:
                fp += 1
    precision = round(tp / (tp + fp), 2) * 100

    # recall
    tp = 0
    fn = 0
    for idx in range(len(answers)):
        if answers[idx] == 1:
            if predictions[idx] == 1:
                tp += 1
            else:
                fn += 1
    recall = round(tp / (tp + fn), 2) * 100

    logging.info("accuracy: {}%".format(accuracy))
    logging.info("precision: {}%".format(precision))
    logging.info("recall: {}%".format(recall))

def load_raw_data(fname):
    instances = []
    labels = []
    with open(fname, "r") as f:
        f.readline() 
        for line in f:
            try:
                tmp = line.strip().split(",")
                avg_temperature = float(tmp[1].strip())
                max_temperature = float(tmp[2].strip())
                min_temperature = float(tmp[3].strip())
                power = float(tmp[7].strip())
                label = int(tmp[8].strip())
                instances.append([avg_temperature, max_temperature, min_temperature, power])
                labels.append(label)
            except ValueError as e:
                logging.error(f"Error parsing line: {line.strip()} ({e})")
                continue
    return instances, labels



def run(train_file, test_file):
    # training phase
    instances, labels = load_raw_data(train_file)
    logging.debug("instances: {}".format(instances))
    logging.debug("labels: {}".format(labels))
    parameters = training(instances, labels)

    # testing phase
    instances, labels = load_raw_data(test_file)
    predictions = []
    for instance in instances:
        result = predict(instance, parameters)

        if result not in [0, 1]:
            logging.error("The result must be either 0 or 1")
            sys.exit(1)

        predictions.append(result)
    
    # report
    report(predictions, labels)

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--training", required=True, metavar="<file path to the training dataset>", help="File path of the training dataset", default="training.csv")
    parser.add_argument("-u", "--testing", required=True, metavar="<file path to the testing dataset>", help="File path of the testing dataset", default="testing.csv")
    parser.add_argument("-l", "--log", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")

    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    logging.basicConfig(level=args.log)

    if not os.path.exists(args.training):
        logging.error("The training dataset does not exist: {}".format(args.training))
        sys.exit(1)

    if not os.path.exists(args.testing):
        logging.error("The testing dataset does not exist: {}".format(args.testing))
        sys.exit(1)

    run(args.training, args.testing)

if __name__ == "__main__":
    main()
