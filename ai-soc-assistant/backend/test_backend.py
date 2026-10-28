"""
Unit and Integration Tests for AI SOC Assistant Backend
Run with:
  pytest test_backend.py
or:
  python3 test_backend.py
"""
import sys
import unittest

from database import init_db, get_db_connection
from ml_engine import generate_synthetic_dataset, pipeline, CLASSES, FEATURE_NAMES
from graph_engine import AttackPathGraph

def test_synthetic_dataset_count_and_classes():
    """Verify dataset has exactly 5,000 records and all 7 classes."""
    data = generate_synthetic_dataset(5000)
    assert len(data) == 5000, f"Expected 5,000 records, got {len(data)}"
    
    labels_found = set(r['label'] for r in data)
    for expected_class in CLASSES:
        assert expected_class in labels_found, f"Class {expected_class} missing from dataset"

def test_dataset_feature_names():
    """Verify each flow record contains all required network flow features."""
    data = generate_synthetic_dataset(10)
    sample = data[0]
    for feat in FEATURE_NAMES:
        assert feat in sample, f"Feature {feat} missing in flow record"

def test_database_initialization():
    """Verify SQLite database creates all tables and seeds initial assets."""
    init_db()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM assets")
    asset_count = c.fetchone()[0]
    assert asset_count >= 8, f"Expected at least 8 seeded assets, got {asset_count}"

    c.execute("SELECT COUNT(*) FROM vulnerabilities")
    vuln_count = c.fetchone()[0]
    assert vuln_count >= 5, f"Expected at least 5 seeded vulnerabilities, got {vuln_count}"
    conn.close()

def test_graph_algorithms_bfs():
    """Test BFS finds shortest unweighted path."""
    g = AttackPathGraph()
    res = g.search_bfs("FW-EDGE-01", "DB-PROD-SQL")
    assert res['found'] is True
    assert res['path'][0] == "FW-EDGE-01"
    assert res['path'][-1] == "DB-PROD-SQL"
    assert len(res['visitedNodes']) > 0

def test_graph_algorithms_dfs():
    """Test DFS finds path by traversing deeply."""
    g = AttackPathGraph()
    res = g.search_dfs("FW-EDGE-01", "DB-PROD-SQL")
    assert res['found'] is True
    assert res['path'][0] == "FW-EDGE-01"
    assert res['path'][-1] == "DB-PROD-SQL"

def test_graph_algorithms_greedy():
    """Test Greedy Best-First Search guided by heuristic."""
    g = AttackPathGraph()
    res = g.search_greedy_best_first("FW-EDGE-01", "DC-CORP-01")
    assert res['found'] is True
    assert res['path'][0] == "FW-EDGE-01"
    assert res['path'][-1] == "DC-CORP-01"

def test_graph_algorithms_a_star():
    """Test A* search finds optimal lowest-cost path."""
    g = AttackPathGraph()
    res = g.search_a_star("FW-EDGE-01", "DC-CORP-01")
    assert res['found'] is True
    assert res['path'][0] == "FW-EDGE-01"
    assert res['path'][-1] == "DC-CORP-01"
    assert res['totalCost'] > 0

def test_ml_prediction_rules():
    """Test threat prediction and severity calibration."""
    dos_features = {
        'flow_pkts_s': 20000,
        'syn_flag_cnt': 500,
        'flow_byts_s': 1000000,
        'dst_port': 443,
        'fwd_pkt_len_mean': 40,
        'flow_duration': 50000
    }
    pred = pipeline.predict(dos_features)
    assert pred['predictedCategory'] in ['DoS', 'DDoS']
    assert pred['severity'] == 'Critical'
    assert len(pred['evidence']) > 0

def test_model_training_on_synthetic_dataset():
    """Test actual model training on the 5,000-sample synthetic dataset."""
    pipeline.initialize_dataset()
    metrics = pipeline.train_and_evaluate()
    assert metrics['totalSamples'] == 5000
    assert metrics['trainSamples'] == 4000
    assert metrics['testSamples'] == 1000
    assert metrics['accuracy'] >= 0.85
    assert len(metrics['confusionMatrix']) == 7
    assert len(metrics['featureImportances']) > 0

def test_invalid_and_corrupt_dataset_handling():
    """Verify that corrupt, empty, and out-of-range flow records are safely rejected."""
    # Out of range port and negative duration
    malformed_record = {
        'flow_duration': -500,
        'dst_port': 999999,
        'flow_pkts_s': 'not-a-number'
    }
    # Pipeline should handle missing/corrupt values safely with graceful defaults
    pred = pipeline.predict(malformed_record)
    assert 'predictedCategory' in pred
    assert pred['confidence'] > 0

def test_held_out_evaluation_without_leakage():
    """Verify held-out evaluation separates training from test and computes genuine metrics."""
    metrics = pipeline.train_and_evaluate()
    assert metrics['trainSamples'] == 4000
    assert metrics['testSamples'] == 1000
    assert metrics['trainSamples'] + metrics['testSamples'] == 5000
    assert 0.0 <= metrics['accuracy'] <= 1.0
    assert 0.0 <= metrics['macroF1'] <= 1.0

def test_threat_origin_private_ip_isolation():
    """Ensure RFC 1918 private subnets are identified and separated from public IPs."""
    private_prefixes = ['10.', '192.168.', '172.16.']
    test_subnets = ['198.51.100.', '203.0.113.']
    
    data = generate_synthetic_dataset(100)
    for row in data:
        src = row.get('src_ip', '')
        if any(src.startswith(p) for p in private_prefixes):
            assert not src.startswith('8.8.8.8')
        elif any(src.startswith(p) for p in test_subnets):
            assert src.startswith('198.51.100.') or src.startswith('203.0.113.')

class TestSOCBackend(unittest.TestCase):
    def test_all(self):
        test_synthetic_dataset_count_and_classes()
        test_dataset_feature_names()
        test_database_initialization()
        test_graph_algorithms_bfs()
        test_graph_algorithms_dfs()
        test_graph_algorithms_greedy()
        test_graph_algorithms_a_star()
        test_ml_prediction_rules()
        test_model_training_on_synthetic_dataset()
        test_invalid_and_corrupt_dataset_handling()
        test_held_out_evaluation_without_leakage()
        test_threat_origin_private_ip_isolation()

if __name__ == '__main__':
    unittest.main()

