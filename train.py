import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import pickle

def train_and_save_model():
    # Real Balanced Training Dataset (Isme chote patterns ko bhi phishing sikhaya hai)
    # columns: [length, has_at, subdomains, has_dash, has_keyword, result]
    raw_data = [, # Safe Google, # Safe Wiki, # Safe Apple, # Phishing long, # Phishing long, # Phishing short like shekarius.xyz, # Phishing marketplace-124, # Phishing xyz, # Phishing long
        [32, 0, 0, 0, 0, 1]  # Safe long path
    ]
    
    columns = ['length', 'has_at', 'subdomains', 'has_dash', 'has_keyword', 'result']
    data = pd.DataFrame(raw_data, columns=columns)
    
    X = data.drop(columns=['result'])
    y = data['result']
    
    # Train Random Forest Classifier
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X, y)
    
    # Save model
    with open("phishing_model.pkl", "wb") as f:
        pickle.dump(model, f)

if __name__ == "__main__":
    train_and_save_model()
