import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import pickle

def train_and_save_model():
    # Load dataset
    data = pd.read_csv("phishing_dataset.csv")
    
    # Split features and labels
    X = data.drop(columns=['result'])
    y = data['result']
    
    # Train Real Machine Learning Model
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X, y)
    
    # Save the trained model to a file
    with open("phishing_model.pkl", "wb") as f:
        pickle.dump(model, f)

if __name__ == "__main__":
    train_and_save_model()
