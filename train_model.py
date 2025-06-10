import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

# Load preprocessed data
data = pd.read_csv("preprocessed_cyber_data.csv")

# Split into features and target
X = data.drop("Attack_Label", axis=1)
y = data["Attack_Label"]

# Split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train the model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate accuracy
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"✅ Model Accuracy: {accuracy * 100:.2f}%")

# Save the trained model
joblib.dump(model, "cybersecurity_model.pkl")
print("✅ Model saved as cybersecurity_model.pkl")
