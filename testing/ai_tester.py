# pseudo_playback.py
import csv
from security.artificial_intelligence.deep_packet_inspection.payload_inspection import PayloadCNN

with open("tests/data/test_traffic.csv") as f:
    reader = csv.DictReader(f)
    for row in reader:
        result = PayloadCNN.predict(row)
        print(row["client_id"], result)