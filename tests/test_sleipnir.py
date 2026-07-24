import pytest
import os
import tempfile
import yaml
from unittest.mock import patch, MagicMock
from core.bus import EventBus, IncidentState
from core.engine import SOAREngine


def test_incident_state_constants():
    assert IncidentState.NEW == "NEW"
    assert IncidentState.RUNNING == "RUNNING"
    assert IncidentState.CONTAINED == "CONTAINED"
    assert IncidentState.RESOLVED == "RESOLVED"
    assert IncidentState.FAILED == "FAILED"


def test_event_bus_init():
    event = {"rule_title": "Test", "severity": "HIGH"}
    bus = EventBus("INC-001", event)
    assert bus.incident_id == "INC-001"
    assert bus.state == IncidentState.NEW
    assert len(bus.audit_log) == 0
    assert bus.context["event"] == event


def test_event_bus_transition():
    bus = EventBus("INC-002", {"rule_title": "Test"})
    bus.transition(IncidentState.RUNNING, "Starting playbook")
    assert bus.state == IncidentState.RUNNING
    assert len(bus.audit_log) == 1
    assert bus.audit_log[0]["state"] == "RUNNING"
    assert bus.audit_log[0]["message"] == "Starting playbook"


def test_event_bus_log_action():
    bus = EventBus("INC-003", {"rule_title": "Test"})
    bus.log_action("fenrir_update", "SUCCESS", "Updated IOCs")
    assert len(bus.audit_log) == 1
    assert bus.audit_log[0]["action"] == "fenrir_update"
    assert bus.audit_log[0]["status"] == "SUCCESS"


def test_event_bus_get_summary():
    bus = EventBus("INC-004", {"rule_title": "Test"})
    bus.transition(IncidentState.RUNNING, "Start")
    bus.transition(IncidentState.CONTAINED, "Done")
    summary = bus.get_summary()
    assert summary["incident_id"] == "INC-004"
    assert summary["final_state"] == IncidentState.CONTAINED
    assert len(summary["audit_trail"]) == 2


def test_engine_load_playbook():
    playbook_data = {"name": "Test Playbook", "steps": [{"name": "Step 1", "action": "wait", "params": {"seconds": 0}}]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.dump(playbook_data, f)
        tmp_path = f.name
    try:
        engine = SOAREngine(tmp_path, asgard_root="C:\\fake")
        assert engine.playbook["name"] == "Test Playbook"
        assert len(engine.playbook["steps"]) == 1
    finally:
        os.remove(tmp_path)


def test_engine_unknown_action():
    playbook_data = {"name": "Test", "steps": [{"name": "Bad Step", "action": "nonexistent_action", "params": {}}]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.dump(playbook_data, f)
        tmp_path = f.name
    try:
        engine = SOAREngine(tmp_path, asgard_root="C:\\fake")
        summary = engine.execute({"rule_title": "Test"})
        assert summary["final_state"] == IncidentState.FAILED
    finally:
        os.remove(tmp_path)


def test_engine_wait_action():
    playbook_data = {"name": "Wait Test", "steps": [{"name": "Wait", "action": "wait", "params": {"seconds": 0}}]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.dump(playbook_data, f)
        tmp_path = f.name
    try:
        engine = SOAREngine(tmp_path, asgard_root="C:\\fake")
        summary = engine.execute({"rule_title": "Test"})
        assert summary["final_state"] == IncidentState.CONTAINED
    finally:
        os.remove(tmp_path)


@patch("core.engine.subprocess.run")
def test_engine_dispatch_mock(mock_run):
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "Mocked output"
    mock_run.return_value = mock_result

    playbook_data = {"name": "Mock Test", "steps": [{"name": "Fenrir", "action": "fenrir_update", "params": {}}]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.dump(playbook_data, f)
        tmp_path = f.name
    try:
        engine = SOAREngine(tmp_path, asgard_root="C:\\Progetti\\Asgard")
        summary = engine.execute({"rule_title": "Test"})
        assert summary["final_state"] == IncidentState.CONTAINED
        mock_run.assert_called_once()
    finally:
        os.remove(tmp_path)
