from datetime import datetime, timezone
from ipaddress import ip_address
from uuid import uuid4

import pytest
from pydantic import ValidationError

from alerting.schema import Alert, Incident, Severity, ThreatClass


def make_alert(**overrides):
    data = {
        "alert_id": uuid4(),
        "timestamp": datetime.now(timezone.utc),
        "flow_id": "test-flow",
        "threat_class": ThreatClass.DDOS,
        "confidence": 0.95,
        "risk_score": 85,
        "severity": Severity.HIGH,
        "evidence": ["high SYN rate"],
    }

    data.update(overrides)
    return Alert(**data)


def test_valid_alert():
    alert = make_alert()

    assert alert.confidence == 0.95
    assert alert.risk_score == 85
    assert alert.threat_class == ThreatClass.DDOS
    assert alert.severity == Severity.HIGH


def test_invalid_confidence():
    with pytest.raises(ValidationError):
        make_alert(confidence=1.5)


def test_invalid_risk_score():
    with pytest.raises(ValidationError):
        make_alert(risk_score=150)


def test_invalid_threat_class():
    with pytest.raises(ValidationError):
        make_alert(threat_class="random_attack")


def test_invalid_severity():
    with pytest.raises(ValidationError):
        make_alert(severity="SUPER_HIGH")


def test_extra_fields_rejected():
    with pytest.raises(ValidationError):
        make_alert(unexpected_field="not allowed")


def test_valid_incident():
    now = datetime.now(timezone.utc)

    incident = Incident(
        incident_id=uuid4(),
        source_ip=ip_address("10.0.0.50"),
        first_seen=now,
        last_seen=now,
        alert_count=4,
        combined_risk=94,
        risk_level=Severity.CRITICAL,
        threat_classes=[
            ThreatClass.PORTSCAN,
            ThreatClass.DNS_TUNNEL,
        ],
    )

    assert incident.alert_count == 4
    assert incident.combined_risk == 94


def test_writer_accepts_models_and_dicts():
    from unittest.mock import MagicMock, patch
    from alerting import writer

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

    with patch.object(writer, "_get_connection", return_value=mock_conn):
        # 1. Pydantic Alert
        alert_model = make_alert()
        writer.write_alert(alert_model)
        assert mock_cursor.execute.called

        # 2. Pipeline Dict Alert
        alert_dict = {
            "alert_id": str(uuid4()),
            "timestamp": "2026-09-21T10:00:00Z",
            "flow_id": "test-flow-dict",
            "threat_class": "ddos",
            "confidence": 0.9,
            "risk_score": 80,
            "severity": "HIGH",
            "evidence": ["evidence 1"],
            "incident_id": "INC-000001",
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
        }
        writer.write_alert(alert_dict)
        assert mock_cursor.execute.call_count >= 2

        # 3. Incident dict upsert
        incident_dict = {
            "incident_id": "INC-000001",
            "src_ip": "192.168.1.100",
            "first_seen": "2026-09-21T10:00:00Z",
            "last_seen": "2026-09-21T10:05:00Z",
            "alert_count": 2,
            "risk_score": 85,
            "severity": "HIGH",
            "threat_classes": ["ddos"],
        }
        writer.upsert_incident(incident_dict)
        assert mock_cursor.execute.call_count >= 3