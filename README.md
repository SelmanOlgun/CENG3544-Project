# Detecting Phishing Websites Using Machine Learning Techniques

## Overview
This project aims to detect phishing websites using various machine learning techniques. The study involves training different models on the "Phishing Websites" dataset from the UCI Machine Learning Repository and evaluating their performances. The models used include Logistic Regression, K-Nearest Neighbors (KNN), Random Forest, Naive Bayes, and Decision Tree. The top-performing models were then combined into an ensemble method using Stacking to improve prediction accuracy.

## Table of Contents
- [Overview](#overview)
- [Dataset](#dataset)
- [Features](#features)
- [Models](#models)
- [Results](#results)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Dataset
The dataset used in this project is the "Phishing Websites" dataset from the [UCI Machine Learning Repository](https://archive.ics.uci.edu/ml/datasets/Phishing+Websites). It contains features extracted from URLs to help identify whether a website is phishing or not.

## Features
Key features used in this project include:
- URL length
- Presence of IP address
- Use of '@' symbol
- SSL state
- Domain age
- And many more...

## Models
The following machine learning models were trained and evaluated:
- Logistic Regression
- K-Nearest Neighbors (KNN)
- Random Forest
- Naive Bayes
- Decision Tree

The Stacking model was created using the top-performing models: Random Forest, Logistic Regression, and Decision Tree.

## Results
The performance of the models was evaluated using F1 score and accuracy metrics. The Stacking model outperformed the individual models, achieving the highest accuracy and F1 score.

| Model               | F1 Score | Accuracy |
|---------------------|----------|----------|
| Stacking            | 0.964    | 0.959    |
| Random Forest       | 0.962    | 0.956    |
| Decision Tree       | 0.957    | 0.951    |
| Logistic Regression | 0.939    | 0.930    |
| KNN                 | 0.938    | 0.929    |
| Naive Bayes         | 0.399    | 0.573    |

## Installation
To run this project, you need to have Python and the following libraries installed:
- pandas
- numpy
- scikit-learn
- matplotlib
- jupyter

You can install these libraries using pip:
```bash
pip install pandas numpy scikit-learn matplotlib jupyter
