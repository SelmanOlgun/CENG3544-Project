import pandas as pd

phishing_data = pd.read_csv('Raw_data.csv')
phishing_data.drop(['web_traffic', 'page_rank'], axis=1, inplace=True)

csv_path = "Final_data.csv"
phishing_data.to_csv(csv_path, index=False)
