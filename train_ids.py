import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib

def main():
    print("=" * 60)
    print("Machine Learning Intrusion Detection System (IDS) - Training")
    print("Dataset: Official UNSW-NB15 Benchmark Dataset")
    print("=" * 60)

    train_path = "UNSW_NB15_training-set.csv"
    test_path = "UNSW_NB15_testing-set.csv"

    if not os.path.exists(train_path) or not os.path.exists(test_path):
        print(f"\n[!] Dataset files not found in the current folder.")
        print(f"Please ensure '{train_path}' and '{test_path}' are placed in your 'intrusion_detector' folder.")
        return

    print(f"[+] Loading training set from {train_path}...")
    train_df = pd.read_csv(train_path)
    print(f"[+] Loading testing set from {test_path}...")
    test_df = pd.read_csv(test_path)

    print(f"[+] Training set shape: {train_df.shape}")
    print(f"[+] Testing set shape: {test_df.shape}")

    # Combine for consistent one-hot encoding of categorical features (proto, service, state)
    train_df['is_train'] = 1
    test_df['is_train'] = 0
    combined = pd.concat([train_df, test_df], ignore_index=True)

    drop_cols = ['id', 'attack_cat', 'is_train', 'label']
    feature_cols = [c for c in combined.columns if c not in drop_cols]

    print("[+] Preprocessing and encoding categorical features...")
    combined_encoded = pd.get_dummies(combined[feature_cols], drop_first=True)
    combined_encoded['label'] = combined['label']
    combined_encoded['is_train'] = combined['is_train']

    train_processed = combined_encoded[combined_encoded['is_train'] == 1].drop(columns=['is_train'])
    test_processed = combined_encoded[combined_encoded['is_train'] == 0].drop(columns=['is_train'])

    X_train = train_processed.drop(columns=['label'])
    y_train = train_processed['label']
    X_test = test_processed.drop(columns=['label'])
    y_test = test_processed['label']

    print(f"[+] Processed training features: {X_train.shape[1]}")
    print(f"[+] Training samples: {X_train.shape[0]}, Testing samples: {X_test.shape[0]}")

    print("\n[+] Training Random Forest Classifier on UNSW-NB15 benchmark...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    print("[+] Model training completed successfully!")

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[+] Official Test Set Accuracy: {acc * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    model_filename = "ids_random_forest.pkl"
    joblib.dump((model, list(X_train.columns)), model_filename)
    print(f"\n[+] Trained model and feature metadata saved successfully to '{model_filename}'")
    print("=" * 60)

if __name__ == "__main__":
    main()
