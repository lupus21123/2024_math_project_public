import os
import sys
import argparse
import logging
import math

def bivariate_normal_pdf(x1, x2, x1_mean, x1_stdev, x2_mean, x2_stdev, cor):
    coeff = 1 / (2 * math.pi * x1_stdev * x2_stdev * math.sqrt(1 - cor**2))
    z1 = (x1 - x1_mean) / x1_stdev
    z2 = (x2 - x2_mean) / x2_stdev
    exponent = -1 / (2 * (1 - cor**2)) * (z1**2 + z2**2 - 2 * cor * z1 * z2)
    return coeff * math.exp(exponent)

def training(instances, labels):
    cases = []
    ret_list = []
    parameter_list = []
    for i in range(1, 7):
        for j in range(i+1, 8):
            cases.append((i, j))
    for case in cases:
        m = case[0]
        n = case[1]
        x1_label0 = []
        x1_label1 = []
        x2_label0 = []
        x2_label1 = []
        for i in range(len(instances)):
            if labels[i] == 0:
                x1_label0.append(instances[i][m])
                x2_label0.append(instances[i][n])
            else:
                x1_label1.append(instances[i][m])
                x2_label1.append(instances[i][n])

        probability_label0 = len(x1_label0) / (len(x1_label0) + len(x1_label1))
        probability_label1 = len(x1_label1) / (len(x1_label0) + len(x1_label1))

        x1_label0_mean = sum(x1_label0) / len(x1_label0)
        x1_label0_stdev = ((sum([i ** 2 for i in x1_label0]) / len(x1_label0)) - x1_label0_mean ** 2) ** 0.5
        x2_label0_mean = sum(x2_label0) / len(x2_label0)
        x2_label0_stdev = ((sum([i ** 2 for i in x2_label0]) / len(x2_label0)) - x2_label0_mean ** 2) ** 0.5
        x1x2_label0 = []
        for i in range(len(x1_label0)):
            x1x2_label0.append(x1_label0[i]*x2_label0[i])
        x1x2_label0_mean = sum(x1x2_label0) / len(x1x2_label0)
        x1x2_label0_cov = x1x2_label0_mean -  x1_label0_mean * x2_label0_mean
        x1x2_label0_cor = x1x2_label0_cov / (x1_label0_stdev * x2_label0_stdev)

        x1_label1_mean = sum(x1_label1) / len(x1_label1)
        x1_label1_stdev = ((sum([i ** 2 for i in x1_label1]) / len(x1_label1)) - x1_label1_mean ** 2) ** 0.5
        x2_label1_mean = sum(x2_label1) / len(x2_label1)
        x2_label1_stdev = ((sum([i ** 2 for i in x2_label1]) / len(x2_label1)) - x2_label1_mean ** 2) ** 0.5
        x1x2_label1 = []
        for i in range(len(x1_label1)):
            x1x2_label1.append(x1_label1[i]*x2_label1[i])
        x1x2_label1_mean = sum(x1x2_label1) / len(x1x2_label1)
        x1x2_label1_cov = x1x2_label1_mean -  x1_label1_mean * x2_label1_mean
        x1x2_label1_cor = x1x2_label1_cov / (x1_label1_stdev * x2_label1_stdev)

        parameter = {"label0" : (x1_label0_mean, x1_label0_stdev, x2_label0_mean, x2_label0_stdev, x1x2_label0_cor, probability_label0), "label1" : (x1_label1_mean, x1_label1_stdev, x2_label1_mean, x2_label1_stdev, x1x2_label1_cor, probability_label1)}
        parameter_list.append(parameter)

        tp = 0 
        fp = 0
        fn = 0
        for i in range(len(instances)):
            x1 = instances[i][m]
            x2 = instances[i][n]
            probability_X_label0 = bivariate_normal_pdf(x1, x2, x1_label0_mean, x1_label0_stdev, x2_label0_mean, x2_label0_stdev, x1x2_label0_cor)
            probability_X_label1 = bivariate_normal_pdf(x1, x2, x1_label1_mean, x1_label1_stdev, x2_label1_mean, x2_label1_stdev, x1x2_label1_cor)
            probability_label0_X = (probability_X_label0 *  probability_label0) / (probability_X_label0 *  probability_label0 + probability_X_label1 *  probability_label1)
            probability_label1_X = (probability_X_label1 *  probability_label1) / (probability_X_label0 *  probability_label0 + probability_X_label1 *  probability_label1)
            delta_P = probability_label0_X - probability_label1_X
            if delta_P < 0 and labels[i] == 1:
                tp += 1
            elif delta_P < 0 and labels[i] == 0:
                fp += 1
            elif delta_P > 0 and labels[i] == 1:
                fn += 1
        try:
            precision = round(tp / (tp + fp), 2)
        except:
            precision = 0

        recall = round(tp / (tp + fn), 2)

        try:
            f1_score = (2 * recall * precision) / (recall + precision)
        except:
            f1_score - 0

        ret_list.append(f1_score)
    
    max_idx = 0
    max_idx_list = []
    for i in range(1, len(ret_list)):
        if ret_list[i] > ret_list[max_idx]:
            max_idx = i
    max_idx_list.append(max_idx)
    for i in range(1, len(ret_list)):
        if ret_list[i] == ret_list[max_idx] and i != max_idx:
            max_idx_list.append(i)
    case_final = [cases[i] for i in max_idx_list]
    parameter_final = [parameter_list[i] for i in max_idx_list]

    return case_final, parameter_final


def predict(instance, features, parameters):
    x1 = instance[features[0]]
    x2 = instance[features[1]]
    x1_label0_mean = parameters["label0"][0]
    x1_label0_stdev = parameters["label0"][1]
    x2_label0_mean = parameters["label0"][2]
    x2_label0_stdev = parameters["label0"][3]
    x1x2_label0_cor = parameters["label0"][4]
    probability_label0 = parameters["label0"][5]
    x1_label1_mean = parameters["label1"][0]
    x1_label1_stdev = parameters["label1"][1]
    x2_label1_mean = parameters["label1"][2]
    x2_label1_stdev = parameters["label1"][3]
    x1x2_label1_cor = parameters["label1"][4]
    probability_label1 = parameters["label1"][5]
    probability_X_label0 = bivariate_normal_pdf(x1, x2, x1_label0_mean, x1_label0_stdev, x2_label0_mean, x2_label0_stdev, x1x2_label0_cor)
    probability_X_label1 = bivariate_normal_pdf(x1, x2, x1_label1_mean, x1_label1_stdev, x2_label1_mean, x2_label1_stdev, x1x2_label1_cor)
    probability_label0_X = (probability_X_label0 *  probability_label0) / (probability_X_label0 *  probability_label0 + probability_X_label1 *  probability_label1)
    probability_label1_X = (probability_X_label1 *  probability_label1) / (probability_X_label0 *  probability_label0 + probability_X_label1 *  probability_label1)
    if probability_label0_X > probability_label1_X:
        return 0
    else:
        return 1


def f1_score_calculator(predictions, answers):
    # precision
    tp = 0
    fp = 0
    for idx in range(len(predictions)):
        if predictions[idx] == 1:
            if answers[idx] == 1:
                tp += 1
            else:
                fp += 1
    try:
        precision = round(tp / (tp + fp), 2)
    except:
        precision = 0

    # recall
    tp = 0
    fn = 0
    for idx in range(len(answers)):
        if answers[idx] == 1:
            if predictions[idx] == 1:
                tp += 1
            else:
                fn += 1
    recall = round(tp / (tp + fn), 2)

    f1_score = (2 * recall * precision) / (recall + precision)

    return f1_score


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
    try:
        precision = round(tp / (tp + fp), 2)
    except:
        precision = 0

    # recall
    tp = 0
    fn = 0
    for idx in range(len(answers)):
        if answers[idx] == 1:
            if predictions[idx] == 1:
                tp += 1
            else:
                fn += 1
    recall = round(tp / (tp + fn), 2)

    f1_score = (2 * recall * precision) / (recall + precision)

    logging.info("accuracy: {}%".format(accuracy))
    logging.info("precision: {}%".format(precision * 100))
    logging.info("recall: {}%".format(recall * 100))
    logging.info("f1 score: {}".format(f1_score))

def load_raw_data(fname):
    instances = []
    labels = []
    with open(fname, "r") as f:
        f.readline()
        for line in f:
            tmp = line.strip().split(", ")
            tmp[1] = float(tmp[1])
            tmp[2] = float(tmp[2])
            tmp[3] = float(tmp[3])
            tmp[4] = float(tmp[4])
            tmp[5] = int(tmp[5])
            tmp[6] = int(tmp[6])
            tmp[7] = float(tmp[7])
            tmp[8] = int(tmp[8])
            instances.append(tmp[:-1])
            labels.append(tmp[-1])
    return instances, labels

def run(train_file, test_file):
    # training phase
    features_list = ["date","avg (temperature)", "max (temperature)", "min (temperature)", "avg (humidity)", "max (humidity)", "min (humidity)","power"]
    instances, labels = load_raw_data(train_file)
    logging.debug("instances: {}".format(instances))
    logging.debug("labels: {}".format(labels))
    features, parameters = training(instances, labels)

    # testing phase
    f1_score_list = []
    instances, labels = load_raw_data(test_file)

    for i in range(len(features)):
        predictions = []
        for instance in instances:
            result = predict(instance, features[i], parameters[i])

            if result not in [0, 1]:
                logging.error("The result must be either 0 or 1")
                sys.exit(1)

            predictions.append(result)
        f1_score_list.append(f1_score_calculator(predictions, labels))

    final_idx = 0
    for i in range(len(f1_score_list)):
        if f1_score_list[i] > f1_score_list[final_idx]:
            final_idx = i
    
    predictions = []
    for instance in instances:
        result = predict(instance, features[final_idx], parameters[final_idx])

        if result not in [0, 1]:
            logging.error("The result must be either 0 or 1")
            sys.exit(1)

        predictions.append(result)

    # report
    feature1 = features_list[features[final_idx][0]]
    feature2 = features_list[features[final_idx][1]]
    logging.debug(f"selected features: {feature1} and {feature2}")
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