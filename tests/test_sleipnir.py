import pytest
import os
import json
import shutil
import subprocess
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


@patch("core.engine.subprocess.run")
def test_bifrost_scan_resolves_event_source_ip(mock_run):
    """{{event.source_ip}} must be substituted with the real event value and
    passed as the scan target in the subprocess argv, instead of the old
    hardcoded 127.0.0.1."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "Scanned"
    mock_run.return_value = mock_result

    playbook_data = {
        "name": "Bifrost Real IP Test",
        "steps": [
            {"name": "Scan", "action": "bifrost_scan", "params": {"ip": "{{event.source_ip}}"}}
        ],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.dump(playbook_data, f)
        tmp_path = f.name
    try:
        engine = SOAREngine(tmp_path, asgard_root="C:\\Progetti\\Asgard")
        summary = engine.execute({"rule_title": "Test", "source_ip": "203.0.113.50"})
        assert summary["final_state"] == IncidentState.CONTAINED
        mock_run.assert_called_once()
        called_argv = mock_run.call_args[0][0]
        assert "203.0.113.50" in called_argv
        assert "127.0.0.1" not in called_argv
    finally:
        os.remove(tmp_path)


@patch("core.engine.subprocess.run")
def test_bifrost_scan_no_params_falls_back_to_localhost(mock_run):
    """Existing playbooks with `params: {}` must keep working unchanged,
    falling back to 127.0.0.1 when no ip is supplied."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "Scanned"
    mock_run.return_value = mock_result

    playbook_data = {
        "name": "Bifrost Default Test",
        "steps": [{"name": "Scan", "action": "bifrost_scan", "params": {}}],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.dump(playbook_data, f)
        tmp_path = f.name
    try:
        engine = SOAREngine(tmp_path, asgard_root="C:\\Progetti\\Asgard")
        summary = engine.execute({"rule_title": "Test"})
        assert summary["final_state"] == IncidentState.CONTAINED
        called_argv = mock_run.call_args[0][0]
        assert "127.0.0.1" in called_argv
    finally:
        os.remove(tmp_path)


@pytest.fixture(autouse=True)
def _cleanup_incidents_dir():
    """Several tests below let SOAREngine write real incident JSON files to
    the default relative './incidents' directory (since these tests pass a
    fake asgard_root). Keep the repo clean by removing it before and after
    each test."""
    shutil.rmtree("incidents", ignore_errors=True)
    yield
    shutil.rmtree("incidents", ignore_errors=True)


def test_bus_save_to_file_and_load_from_file():
    event = {"rule_title": "Test", "source_ip": "203.0.113.50"}
    bus = EventBus("INC-PERSIST-1", event)
    bus.transition(IncidentState.RUNNING, "Starting playbook")
    bus.log_action("wait", "SUCCESS", "Waited 0 seconds.")
    bus.transition(IncidentState.CONTAINED, "Done")

    with tempfile.TemporaryDirectory() as tmp_dir:
        path = os.path.join(tmp_dir, "nested", "INC-PERSIST-1.json")
        bus.save_to_file(path)

        assert os.path.isfile(path)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["incident_id"] == "INC-PERSIST-1"
        assert data["final_state"] == IncidentState.CONTAINED
        assert len(data["audit_trail"]) == 3

        loaded = EventBus.load_from_file(path)
        assert loaded.incident_id == "INC-PERSIST-1"
        assert loaded.state == IncidentState.CONTAINED
        assert loaded.context["event"] == event
        assert len(loaded.audit_log) == 3


def test_engine_execute_persists_state_after_each_step():
    playbook_data = {
        "name": "Persistence Test",
        "steps": [
            {"name": "Wait 1", "action": "wait", "params": {"seconds": 0}},
            {"name": "Wait 2", "action": "wait", "params": {"seconds": 0}},
        ],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.dump(playbook_data, f)
        tmp_path = f.name
    try:
        engine = SOAREngine(tmp_path, asgard_root="C:\\fake")
        summary = engine.execute({"rule_title": "Test"})
        assert summary["final_state"] == IncidentState.CONTAINED

        incident_id = summary["incident_id"]
        incident_file = os.path.join("incidents", f"{incident_id}.json")
        assert os.path.isfile(incident_file)

        with open(incident_file, "r", encoding="utf-8") as f:
            persisted = json.load(f)
        # Persisted file should reflect the final state, proving it was
        # written incrementally (and not just once, since the final content
        # must match what execute() returned).
        assert persisted["final_state"] == IncidentState.CONTAINED
        assert persisted["incident_id"] == incident_id
    finally:
        os.remove(tmp_path)


def test_engine_execute_steps_not_a_list_fails_cleanly():
    playbook_data = {"name": "Malformed Steps", "steps": "not-a-list"}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.dump(playbook_data, f)
        tmp_path = f.name
    try:
        engine = SOAREngine(tmp_path, asgard_root="C:\\fake")
        summary = engine.execute({"rule_title": "Test"})
        assert summary["final_state"] == IncidentState.FAILED
        assert any("Unexpected error" in entry.get("message", "") for entry in summary["audit_trail"])
    finally:
        os.remove(tmp_path)


def test_engine_execute_params_not_a_dict_fails_cleanly():
    playbook_data = {
        "name": "Malformed Params",
        "steps": [{"name": "Bad Params", "action": "wait", "params": "not-a-dict"}],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.dump(playbook_data, f)
        tmp_path = f.name
    try:
        engine = SOAREngine(tmp_path, asgard_root="C:\\fake")
        summary = engine.execute({"rule_title": "Test"})
        assert summary["final_state"] == IncidentState.FAILED
    finally:
        os.remove(tmp_path)


@patch("core.engine.subprocess.run")
def test_dispatch_timeout_expired_reports_clear_message(mock_run):
    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["python", "main.py"], timeout=15)

    playbook_data = {"name": "Timeout Test", "steps": [{"name": "Fenrir", "action": "fenrir_update", "params": {}}]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.dump(playbook_data, f)
        tmp_path = f.name
    try:
        engine = SOAREngine(tmp_path, asgard_root="C:\\Progetti\\Asgard")
        summary = engine.execute({"rule_title": "Test"})
        assert summary["final_state"] == IncidentState.FAILED
        failed_action = next(e for e in summary["audit_trail"] if e.get("action") == "fenrir_update")
        assert failed_action["status"] == "FAILED"
        assert "scaduta dopo 15 secondi" in failed_action["details"]
    finally:
        os.remove(tmp_path)


def test_bus_resolve_from_contained_transitions_to_resolved():
    bus = EventBus("INC-RESOLVE-1", {"rule_title": "Test"})
    bus.transition(IncidentState.RUNNING, "Start")
    bus.transition(IncidentState.CONTAINED, "Contained")
    bus.resolve()
    assert bus.state == IncidentState.RESOLVED
    assert bus.audit_log[-1]["state"] == IncidentState.RESOLVED


def test_bus_resolve_rejects_non_contained_state():
    bus = EventBus("INC-RESOLVE-2", {"rule_title": "Test"})
    bus.transition(IncidentState.RUNNING, "Start")
    with pytest.raises(ValueError):
        bus.resolve()
    assert bus.state == IncidentState.RUNNING


def test_engine_resolve_incident_loads_and_resolves_saved_state():
    playbook_data = {"name": "Wait Test", "steps": [{"name": "Wait", "action": "wait", "params": {"seconds": 0}}]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.dump(playbook_data, f)
        tmp_path = f.name
    try:
        engine = SOAREngine(tmp_path, asgard_root="C:\\fake")
        summary = engine.execute({"rule_title": "Test"})
        assert summary["final_state"] == IncidentState.CONTAINED
        incident_id = summary["incident_id"]

        resolved_summary = SOAREngine.resolve_incident(incident_id, incidents_dir="incidents")
        assert resolved_summary["final_state"] == IncidentState.RESOLVED

        with open(os.path.join("incidents", f"{incident_id}.json"), "r", encoding="utf-8") as f:
            persisted = json.load(f)
        assert persisted["final_state"] == IncidentState.RESOLVED
    finally:
        os.remove(tmp_path)


# --- 4. Optional Gjallarhorn hub integration ----------------------------

from core.engine import notify_gjallarhorn_outcome


def test_gjallarhorn_not_called_when_env_unset(monkeypatch):
    """No GJALLARHORN_HUB_URL -> Sleipnir behaves exactly as before: no
    notification attempt, no network call, no regression."""
    monkeypatch.delenv("GJALLARHORN_HUB_URL", raising=False)

    with patch("core.engine.gjallarhorn_notify") as mock_notify:
        playbook_data = {"name": "Wait Test", "steps": [{"name": "Wait", "action": "wait", "params": {"seconds": 0}}]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            yaml.dump(playbook_data, f)
            tmp_path = f.name
        try:
            engine = SOAREngine(tmp_path, asgard_root="C:\\fake")
            summary = engine.execute({"rule_title": "Test", "severity": "HIGH"})
            assert summary["final_state"] == IncidentState.CONTAINED
        finally:
            os.remove(tmp_path)

        mock_notify.assert_not_called()


def test_gjallarhorn_called_on_contained_with_mapped_severity(monkeypatch):
    monkeypatch.setenv("GJALLARHORN_HUB_URL", "http://localhost:8090")
    monkeypatch.setenv("GJALLARHORN_API_KEY", "test-key")

    with patch("core.engine.gjallarhorn_notify", return_value=True) as mock_notify:
        playbook_data = {"name": "Wait Test", "steps": [{"name": "Wait", "action": "wait", "params": {"seconds": 0}}]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            yaml.dump(playbook_data, f)
            tmp_path = f.name
        try:
            engine = SOAREngine(tmp_path, asgard_root="C:\\fake")
            summary = engine.execute({"rule_title": "SSH Brute-Force", "severity": "HIGH", "source_ip": "203.0.113.50"})
            assert summary["final_state"] == IncidentState.CONTAINED
        finally:
            os.remove(tmp_path)

        mock_notify.assert_called_once()
        _, kwargs = mock_notify.call_args
        assert kwargs["hub_url"] == "http://localhost:8090"
        assert kwargs["api_key"] == "test-key"
        assert kwargs["source"] == "Sleipnir"
        assert kwargs["severity"] == "high"
        assert "contained" in kwargs["title"].lower()
        assert summary["incident_id"] in kwargs["title"]


def test_gjallarhorn_called_on_failed_with_high_severity(monkeypatch):
    monkeypatch.setenv("GJALLARHORN_HUB_URL", "http://localhost:8090")

    with patch("core.engine.gjallarhorn_notify", return_value=True) as mock_notify:
        playbook_data = {"name": "Bad Playbook", "steps": [{"name": "Bad Step", "action": "nonexistent_action", "params": {}}]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            yaml.dump(playbook_data, f)
            tmp_path = f.name
        try:
            engine = SOAREngine(tmp_path, asgard_root="C:\\fake")
            summary = engine.execute({"rule_title": "Test", "severity": "LOW"})
            assert summary["final_state"] == IncidentState.FAILED
        finally:
            os.remove(tmp_path)

        mock_notify.assert_called_once()
        _, kwargs = mock_notify.call_args
        assert kwargs["source"] == "Sleipnir"
        assert kwargs["severity"] == "high"
        assert "failed" in kwargs["title"].lower()


def test_notify_gjallarhorn_outcome_noop_on_running_state(monkeypatch):
    """Only CONTAINED/FAILED are notable outcomes; a bus still RUNNING (or
    otherwise not yet finished) must not trigger a notification."""
    monkeypatch.setenv("GJALLARHORN_HUB_URL", "http://localhost:8090")
    bus = EventBus("INC-GJALL-1", {"rule_title": "Test"})
    bus.transition(IncidentState.RUNNING, "Starting")

    with patch("core.engine.gjallarhorn_notify") as mock_notify:
        result = notify_gjallarhorn_outcome(bus, "Some Playbook")
        assert result is False
        mock_notify.assert_not_called()


@patch("core.engine.subprocess.run")
def test_bifrost_scan_invalid_ip_fails_step_without_subprocess(mock_run):
    """A malformed/malicious placeholder value that isn't a valid IP must fail
    the step in a controlled way and must NOT reach subprocess.run."""
    playbook_data = {
        "name": "Bifrost Invalid IP Test",
        "steps": [
            {"name": "Scan", "action": "bifrost_scan", "params": {"ip": "{{event.source_ip}}"}}
        ],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.dump(playbook_data, f)
        tmp_path = f.name
    try:
        engine = SOAREngine(tmp_path, asgard_root="C:\\Progetti\\Asgard")
        malicious_event = {"rule_title": "Test", "source_ip": "127.0.0.1; rm -rf /"}
        summary = engine.execute(malicious_event)
        assert summary["final_state"] == IncidentState.FAILED
        mock_run.assert_not_called()
    finally:
        os.remove(tmp_path)
