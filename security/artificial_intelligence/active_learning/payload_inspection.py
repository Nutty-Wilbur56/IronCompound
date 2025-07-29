import torch
from torch.utils.data import Dataset, DataLoader
import numpy as np

MAX_PAYLOAD_LEN = 256  # fixed size for input sequences

class PayloadDataset(Dataset):
    def __init__(self, samples, labels):
        """
        samples: List of raw byte arrays (bytes or bytearray)
        labels: List of 0 or 1
        """
        self.samples = samples
        self.labels = labels

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        payload = self.samples[idx]
        label = self.labels[idx]

        # Convert to numpy array of ints
        payload_np = np.frombuffer(payload, dtype=np.uint8)

        # Pad or truncate
        if len(payload_np) < MAX_PAYLOAD_LEN:
            padded = np.pad(payload_np, (0, MAX_PAYLOAD_LEN - len(payload_np)), 'constant')
        else:
            padded = payload_np[:MAX_PAYLOAD_LEN]

        # Normalize to [0,1]
        padded = padded / 255.0

        # Convert to torch tensor
        payload_tensor = torch.tensor(padded, dtype=torch.float32)

        return payload_tensor, label

# Example usage:
# samples = [b'\x01\x02...', b'\x45\x56...']  # raw byte payloads
# labels = [0, 1]
# dataset = PayloadDataset(samples, labels)
# dataloader = DataLoader(dataset, batch_size=32, shuffle=True)
import torch.nn as nn
import torch.nn.functional as F

class PayloadCNN(nn.Module):
    def __init__(self):
        super(PayloadCNN, self).__init__()
        self.conv1 = nn.Conv1d(in_channels=1, out_channels=16, kernel_size=5, padding=2)
        self.pool = nn.MaxPool1d(2)
        self.conv2 = nn.Conv1d(16, 32, 5, padding=2)
        self.fc1 = nn.Linear(32 * (MAX_PAYLOAD_LEN // 2 // 2), 64)  # after two poolings of stride 2
        self.fc2 = nn.Linear(64, 1)  # binary output

    def forward(self, x):
        # x shape: (batch_size, seq_len)
        x = x.unsqueeze(1)  # Add channel dim: (batch_size, 1, seq_len)
        x = self.pool(F.relu(self.conv1(x)))  # (batch, 16, seq_len/2)
        x = self.pool(F.relu(self.conv2(x)))  # (batch, 32, seq_len/4)
        x = x.view(x.size(0), -1)  # flatten
        x = F.relu(self.fc1(x))
        x = torch.sigmoid(self.fc2(x))
        return x.squeeze(1)  # output shape (batch_size,)


import torch.optim as optim

def train(model, dataloader, criterion, optimizer, device):
    model.train()
    running_loss = 0.0
    correct = 0
    total = 0
    for inputs, labels in dataloader:
        inputs, labels = inputs.to(device), labels.float().to(device)

        optimizer.zero_grad()
        outputs = model(inputs)
        loss = criterion(outputs, labels)
        loss.backward()
        optimizer.step()

        running_loss += loss.item() * inputs.size(0)
        preds = (outputs > 0.5).float()
        correct += (preds == labels).sum().item()
        total += labels.size(0)

    epoch_loss = running_loss / total
    epoch_acc = correct / total
    return epoch_loss, epoch_acc

def validate(model, dataloader, criterion, device):
    model.eval()
    running_loss = 0.0
    correct = 0
    total = 0
    with torch.no_grad():
        for inputs, labels in dataloader:
            inputs, labels = inputs.to(device), labels.float().to(device)
            outputs = model(inputs)
            loss = criterion(outputs, labels)
            running_loss += loss.item() * inputs.size(0)
            preds = (outputs > 0.5).float()
            correct += (preds == labels).sum().item()
            total += labels.size(0)

    epoch_loss = running_loss / total
    epoch_acc = correct / total
    return epoch_loss, epoch_acc

# Example main training loop
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model = PayloadCNN().to(device)
criterion = nn.BCELoss()
optimizer = optim.Adam(model.parameters(), lr=0.001)

num_epochs = 10
for epoch in range(num_epochs):
    train_loss, train_acc = train(model, train_loader, criterion, optimizer, device)
    val_loss, val_acc = validate(model, val_loader, criterion, device)
    print(f"Epoch {epoch+1}/{num_epochs}: "
          f"Train Loss={train_loss:.4f}, Train Acc={train_acc:.4f} | "
          f"Val Loss={val_loss:.4f}, Val Acc={val_acc:.4f}")
