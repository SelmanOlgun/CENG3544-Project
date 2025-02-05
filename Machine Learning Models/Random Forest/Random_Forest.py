import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, accuracy_score
import joblib

file_path = 'C:/Users/Selito/Desktop/Project/Data Process/Final_data.csv'
data = pd.read_csv(file_path)

X = data.drop('result', axis=1)
y = data['result']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

random_forest_model = RandomForestClassifier()

random_forest_model.fit(X_train_scaled, y_train)

y_pred = random_forest_model.predict(X_test_scaled)

f1 = f1_score(y_test, y_pred)
accuracy = accuracy_score(y_test, y_pred)

print(f"F1 Score: {f1}")
print(f"Accuracy: {accuracy}")

joblib.dump(random_forest_model, "Random_Forest_Model.joblib")
