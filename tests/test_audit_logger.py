import sqlite3

from guardrails.audit_logger import log_event, read_events, verify_chain


def test_audit_events_are_hash_chained_and_verifiable(tmp_path):
    db = tmp_path / "audit.db"
    log_event("Input Scan", "REDACT", ["PII-REDACT-001"], db_path=db)
    log_event("Output Validation", "ALLOW", ["OUTPUT-ALLOW-001"], db_path=db)

    assert verify_chain(db_path=db)["valid"] is True
    events = read_events(db_path=db)
    assert len(events) == 2
    assert events[0]["event_type"] == "Output Validation"


def test_audit_chain_detects_tampering(tmp_path):
    db = tmp_path / "audit.db"
    log_event("Input Scan", "BLOCK", ["INJ-001"], db_path=db)

    conn = sqlite3.connect(db)
    conn.execute("UPDATE audit_events SET verdict='ALLOW' WHERE sequence=1")
    conn.commit()
    conn.close()

    assert verify_chain(db_path=db)["valid"] is False
