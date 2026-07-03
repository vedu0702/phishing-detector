import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import pickle

def train_and_save_model():
    # 100% Valid Dataset Matrix (Har row me exactly 6 integers hain)
    # Features: [length, has_at, subdomains, has_dash, has_keyword, result]
    raw_data = [,  # Google (Safe),  # Wikipedia (Safe),  # Apple (Safe),  # Microsoft (Safe),  # Long Phishing Link (Unsafe),  # Fake Banking Portal (Unsafe),  # shekarius.xyz style short phishing (Unsafe),  # marketplace-124 style hosting phishing (Unsafe),  # Short xyz fraud string (Unsafe)
        [90, 1, 4, 1, 1, 0]   # Random script attack (Unsafe)
    ]
    
    columns = ['length', 'has_at', 'subdomains', 'has_dash', 'has_keyword', 'result']
    data = pd.DataFrame(raw_data, columns=columns)
    
    X = data.drop(columns=['result'])
    y = data['result']
    
    # Train model using standard machine learning pipeline
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X, y)
    
    # Save model weights securely
    with open("phishing_model.pkl", "wb") as f:
        pickle.dump(model, f)

if __name__ == "__main__":
    train_and_save_model()
