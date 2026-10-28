"""
Script to generate the synthetic network flow dataset of exactly 5,000 records
and save it as both JSON and CSV files in backend/models/
"""
import os
import csv
import json
import random
from ml_engine import generate_synthetic_dataset, FEATURE_NAMES

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(MODEL_DIR, exist_ok=True)

JSON_PATH = os.path.join(MODEL_DIR, "synthetic_flow_dataset_5000.json")
CSV_PATH = os.path.join(MODEL_DIR, "synthetic_flow_dataset_5000.csv")

def main():
    print("Generating exactly 5,000 synthetic network flow records...")
    dataset = generate_synthetic_dataset(5000)
    assert len(dataset) == 5000, f"Expected 5,000 records, got {len(dataset)}"
    
    # Save as JSON
    with open(JSON_PATH, "w") as f:
        json.dump(dataset, f, indent=2)
    print(f"Saved JSON dataset to {JSON_PATH} ({os.path.getsize(JSON_PATH)} bytes)")

    # Save as CSV
    fieldnames = list(dataset[0].keys())
    with open(CSV_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(dataset)
    print(f"Saved CSV dataset to {CSV_PATH} ({os.path.getsize(CSV_PATH)} bytes)")

    # Print summary statistics
    dist = {}
    for r in dataset:
        dist[r["label"]] = dist.get(r["label"], 0) + 1
    print("Class Distribution:", dist)

if __name__ == "__main__":
    main()
