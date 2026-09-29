import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report

# Load dataset
df = pd.read_csv("Dataset/synthetic_dataset.csv")

print("Columns in dataset:", df.columns)

# Clean dataset
df = df.dropna(subset=["url", "label"])
df = df[df["url"].str.strip() != ""]
df = df[df["label"].astype(str).str.strip() != ""]

# Your dataset already contains 'good' and 'bad' labels
X = df["url"]
y = df["label"]

# Create ML pipeline
pipeline = Pipeline([
    ("vectorizer", TfidfVectorizer(
        token_pattern=r"[A-Za-z0-9.]+",
        lowercase=True,
        ngram_range=(1, 2),
        max_features=70000
    )),
    ("model", LogisticRegression(max_iter=1200))
])

# Split data
x_train, x_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42)

# Train model
pipeline.fit(x_train, y_train)

# Print training and testing accuracy
print("Training accuracy:", pipeline.score(x_train, y_train))
print("Testing accuracy:", pipeline.score(x_test, y_test))

# Predictions for evaluation metrics
y_pred = pipeline.predict(x_test)

# Calculate metrics
acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, pos_label="bad")
rec = recall_score(y_test, y_pred, pos_label="bad")
f1 = f1_score(y_test, y_pred, pos_label="bad")

print("Accuracy:", acc)
print("Precision:", prec)
print("Recall:", rec)
print("F1 Score:", f1)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Save the trained model
joblib.dump(pipeline, "model/model.joblib")
print("Model saved to model folder")
