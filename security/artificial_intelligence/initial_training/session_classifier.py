"""
file contains all the classifier classes
"""
from pathlib import Path

import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib
import numpy as np
from sympy.codegen.cnodes import static

# loading pseudo session data
DATA_PATH = Path(__file__).parent / "training_data.csv"
session_df = pd.read_csv(DATA_PATH)

# Feature and Label selection
X = session_df[["bytes_sent", "bytes_received", "replay_violations", "throttle_violations", "syn_flood_violations", "icmp_flood_violations",
                "duration"]].values
y = session_df['was_flagged'].values

# normalization features
session_scaler = StandardScaler()
session_scaled = session_scaler.fit_transform(X)

# split
X_train, X_test, y_train, y_test = train_test_split(session_scaled, y, test_size=0.20, random_state=42, shuffle=True)

# conversion of tensors

X_train_tensor = torch.tensor(X_train, dtype=torch.float32)
y_train_tensor = torch.tensor(y_train, dtype=torch.float32).unsqueeze(1)
X_test_tensor = torch.tensor(X_test, dtype=torch.float32)
y_test_tensor = torch.tensor(y_test, dtype=torch.float32).unsqueeze(1)

train_session_dataset = torch.utils.data.TensorDataset(X_train_tensor, y_train_tensor)
train_session_loader = torch.utils.data.DataLoader(train_session_dataset, batch_size=16, shuffle=True)

# Define the model
class SessionClassifier(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = nn.Sequential(
            nn.Linear(7, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.fc(x)

class SessionAutoEncoder(nn.Module):
    def __init__(self):
        super().__init__()
        self.session_encoder = nn.Sequential(
            nn.Linear(7, 16),
            nn.ReLU(),
            nn.Linear(16, 4)
        )

        self.session_decoder = nn.Sequential(
            nn.Linear(4, 16),
            nn.ReLU(),
            nn.Linear(16, 7)
        )
    def forward(self, x):
        encoded = self.session_encoder(x)
        decoder = self.session_decoder(encoded)
        return decoder

    def encode(self, x):
        return self.forward_session_encoders(x)

"""setup and beginning of logic for supervised session classifier"""
session_classifier_model = SessionClassifier()
criterion = nn.BCELoss()
optimizer = torch.optim.Adam(session_classifier_model.parameters(), lr=0.001)

# Train
for epoch in range(200):
    session_classifier_model.train()
    for X_batch, y_batch in train_session_loader:
        optimizer.zero_grad()
        output = session_classifier_model(X_batch)
        loss = criterion(output, y_batch)
        loss.backward()
        optimizer.step()
    #print(f"Epoch {epoch+1}, Loss: {loss.item():.4f}")


# Save model and scaler
torch.save(session_classifier_model.state_dict(), 'classifier.pt')

joblib.dump(session_scaler, 'scaler.pkl')

"""Ending of logic for supervised session classifier"""
"""Beginning of logic for unsupervised autoencoder for deep packet inspection"""
auto_encoder_model = SessionAutoEncoder()
auto_criterion = nn.MSELoss()
auto_optimizer = torch.optim.Adam(auto_encoder_model.parameters(), lr=0.001)

# Train loop
for epoch in range(500):
    auto_encoder_model.train()
    epoch_loss = 0.0
    for X_batch, _ in train_session_loader:
        auto_optimizer.zero_grad()
        output = auto_encoder_model(X_batch)
        loss = auto_criterion(output, X_batch)
        loss.backward()
        auto_optimizer.step()
        epoch_loss += loss.item()

    #print(f"Epoch {epoch + 1}, Loss: {epoch_loss:.4f}")

# Save the trained autoencoder and scaler
torch.save(auto_encoder_model.state_dict(), 'autoencoder.pt')
joblib.dump(session_scaler, 'auto_scaler.pkl')

class LegionnaireMLDecisionEngine:
    # Engine that will be integrated into the IPS to integrate both supervised and unsupervised ML models
    def __init__(self):
        # Load models and scalers
        self.classifier = SessionClassifier()
        self.classifier.load_state_dict(torch.load('classifier.pt'))
        self.classifier.eval()

        self.autoencoder = SessionAutoEncoder()
        self.autoencoder.load_state_dict(torch.load('autoencoder.pt'))
        self.autoencoder.eval()

        self.scaler = joblib.load('scaler.pkl')  # same for both models

    def evaluate(self, session_obj):
        """
        Main method: evaluates a session using hybrid ML logic.
        Returns structured risk score and decision.
        """
        #print('hi')
        #print(session_obj)
        session_features = np.array([
            session_obj["bytes_sent"],
            session_obj["bytes_received"],
            session_obj["replay_violations"],
            session_obj["throttle_violations"],
            session_obj["syn_flood_violations"],
            session_obj["icmp_flood_violations"],
            session_obj["duration"]
        ])

        scaled = self.scaler.transform(session_features.reshape(1, -1))
        x = torch.tensor(scaled, dtype=torch.float32).squeeze(0)

        # Supervised confidence score
        with torch.no_grad():
            prob = self.classifier(x).item()

        # Autoencoder reconstruction MSE
        with torch.no_grad():
            reconstruction = self.autoencoder(x)
            mse = F.mse_loss(reconstruction, x).item()

        # Fusion: weighted score + flag
        score = (0.5 * prob) + (0.5 if mse > 0.01 else 0.0)
        final_flag = score > 0.75

        return \
            {
            "supervised_prob": prob,
            "unsupervised_mse": mse,
            "risk_score": score,
            "final_flag": final_flag,
            "explanation": {
                'supervised_model_triggered': prob > 0.5,
                'autoencoder_unsupervised_triggered': mse > 0.01
            }
        }
        # function returns reasons as to why the AI models flagged a session

    @staticmethod
    def load_iron_model():
        if SessionClassifier.model:
            if SessionClassifier.model_path.exists():
                SessionClassifier.model = joblib.load(SessionClassifier)

            else:
                raise FileNotFoundError("Model file not found.")

    @staticmethod
    def classify_session(session):
        SessionClassifier.load_iron_model()

        features = [
            session.bytes_sent,
            session.bytes_received,
            session.replay_violations,
            session.throttle_violations,
            session.syn_flood_violations,
            session.icmp_flood_violations
        ]

        prediction = SessionClassifier.model.predict([features])[0]
        return prediction == 1
