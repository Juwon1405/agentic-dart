import pytest
import json
import re
from unittest.mock import patch, MagicMock
from dart_mcp.sift_adapters.mftecmd import sift_mftecmd_timestomp
from dart_mcp import analyze_kerberos_events, detect_ransomware_behavior

def test_active_timestomp():
    mock_data = [{
        "FileName": "evil.exe",
        "ParentPath": "C:\\Windows",
        "Created0x10": "2023-01-01 00:00:00",
        "LastModified0x10": "2023-01-01 00:00:00",
        "Created0x30": "2023-01-01 00:00:00",
        "LastModified0x30": "2023-01-02 00:00:00",
    }]
    with patch("dart_mcp.sift_adapters.mftecmd._read_csv", return_value=mock_data, create=True):
        with patch("dart_mcp.sift_adapters.mftecmd.safe_evidence_input", return_value=MagicMock()):
            with patch("dart_mcp.sift_adapters.mftecmd._sha256", return_value="fake_hash"):
                findings = sift_mftecmd_timestomp("dummy_path")
                assert any(f["pattern"] == "SI_MODIFIED_PREDATES_FN_MODIFIED" for f in findings)

def test_active_tgt_anomaly():
    mock_events = [
        {"EventID": 4768, "TargetUserName": "admin", "IpAddress": "1.1.1.1"},
        {"EventID": 4768, "TargetUserName": "admin", "IpAddress": "2.2.2.2"},
    ]
    mock_path = MagicMock()
    mock_path.read_text.return_value = json.dumps(mock_events)
    mock_path.exists.return_value = True
    
    with patch("dart_mcp._safe_resolve", return_value=mock_path):
        with patch("dart_mcp._sha256", return_value="fake_hash"):
            res = analyze_kerberos_events("dummy.json")
            assert "unusual_tgt_source" in res["findings"]
            assert any(f["user"] == "admin" and f["count"] == 2 for f in res["findings"]["unusual_tgt_source"])

def test_active_ransomware_image():
    # We must preserve other keys to avoid KeyError in the loop
    from dart_mcp import RANSOMWARE_INDICATORS
    mock_indicators = RANSOMWARE_INDICATORS.copy()
    mock_indicators["image"] = [re.compile(r"wanadecryptor", re.I)]
    
    with patch("dart_mcp.RANSOMWARE_INDICATORS", mock_indicators):
        processes = [{
            "image": "C:\\Users\\Public\\wanadecryptor.exe",
            "CommandLine": "safe.exe",
            "start_ts": "2023-01-01 00:00:00"
        }]
        res = detect_ransomware_behavior(processes=processes)
        assert any("IMAGE_MATCH" in str(f) for f in res.get("findings", []))
