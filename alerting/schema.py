"""
Argus AI — Canonical alert schema.

This file defines the single validated schema that all detectors
must conform to before an alert can be written to PostgreSQL.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from ipaddress import IPv4Address, IPv6Address

class ThreatClass(str, Enum):
    """The six threat categories defined by the project."""

    DDOS = "ddos"
    BEACON = "beacon"
    DNS_TUNNEL = "dns_tunnel"
    JA3_MALWARE = "ja3_malware"
    PORTSCAN = "portscan"
    EXFIL = "exfil"


class Severity(str, Enum):
    """Allowed alert severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Alert(BaseModel):
    """
    Canonical alert passed from the detection/fusion layer
    to the database writer.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
    )

    alert_id: UUID
    timestamp: datetime
    flow_id: str = Field(min_length=1)
    threat_class: ThreatClass
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: int = Field(ge=0, le=100)
    severity: Severity
    evidence: list[str] = Field(min_length=1)
    incident_id: Optional[UUID] = None
    
class Incident(BaseModel):
    """Canonical incident stored in PostgreSQL."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
    )

    incident_id: UUID
    source_ip: IPv4Address | IPv6Address
    first_seen: datetime
    last_seen: datetime
    alert_count: int = Field(ge=0)
    combined_risk: int = Field(ge=0, le=100)
    risk_level: Severity
    threat_classes: list[ThreatClass] = Field(min_length=1)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None