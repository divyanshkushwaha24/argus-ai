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