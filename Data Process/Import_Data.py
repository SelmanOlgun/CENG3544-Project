from ucimlrepo import fetch_ucirepo
import pandas as pd

phishing_websites = fetch_ucirepo(id=327)
X = phishing_websites.data.features
y = phishing_websites.data.targets
phishing_data = pd.concat([X, y], axis=1)

csv_path = "Raw_data.csv"
phishing_data.to_csv(csv_path, index=False)

