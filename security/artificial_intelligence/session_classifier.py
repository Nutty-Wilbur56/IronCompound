import pandas as pd
import torch
import torch.nn as nn
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib

# loading pseudo session data
session_df = pd.read_csv('session_train.csv')

# Feature and Label selection
X = session_df[["bytes_sent", "bytes_received", "replay_violations", "throttle_violations", "flooding_violations",
                "duration"]].values
y = session_df['was_flagged'].values

# normalization features
session_scaler = StandardScaler()
session_scaled = session_scaler.fit_transform(X)

# split
X_train, X_test, y_train, y_test = train_test_split(session_scaled, y, test_size=0.2, random_state=42)

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
            nn.Linear(6, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.fc(x)

model = SessionClassifier()
criterion = nn.BCELoss()
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

# Train
for epoch in range(20):
    model.train()
    for X_batch, y_batch in train_session_loader:
        optimizer.zero_grad()
        output = model(X_batch)
        loss = criterion(output, y_batch)
        loss.backward()
        optimizer.step()
    print(f"Epoch {epoch+1}, Loss: {loss.item():.4f}")

# Save model and scaler
torch.save(model.state_dict(), 'classifier.pt')

joblib.dump(session_scaler, 'scaler.pkl')
