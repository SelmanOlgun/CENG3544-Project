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
- **having_ip_address**: Whether the URL contains an IP address
- **url_length**: Length of the URL
- **shortining_service**: Use of shortening services
- **having_at_symbol**: Presence of '@' symbol in the URL
- **double_slash_redirecting**: Double slash redirecting
- **prefix_suffix**: Use of prefix and suffix in the URL
- **having_sub_domain**: Presence of subdomains
- **sslfinal_state**: State of SSL
- **domain_registration_length**: Length of domain registration
- **favicon**: Use of favicon
- **port**: Port numbers
- **https_token**: Use of HTTPS token in the URL
- **request_url**: Request URL
- **url_of_anchor**: URL of anchor
- **links_in_tags**: Links in tags
- **sfh**: Server Form Handler
- **submitting_to_email**: Submitting to email
- **abnormal_url**: Abnormal URL
- **redirect**: Redirect
- **on_mouseover**: On mouse over
- **rightclick**: Right click
- **popupwindow**: Popup window
- **iframe**: IFrame
- **age_of_domain**: Age of domain
- **dnsrecord**: DNS record
- **google_index**: Google index
- **links_pointing_to_page**: Links pointing to page
- **statistical_report**: Statistical report

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
- re
- urllib
- ssl
- socket
- whois
- BeautifulSoup
- requests
- datetime
- dns.resolver
- joblib

You can install these libraries using pip:
```bash
pip install pandas numpy scikit-learn matplotlib jupyter re urllib3 ssl socket whois beautifulsoup4 requests python-dateutil dnspython joblib
