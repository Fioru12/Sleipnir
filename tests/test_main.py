"""Tests for main.py's CLI wiring - previously 0% covered by any test."""
import os
import pytest
import main
from core.engine import SOAREngine


def test_run_playbook_invokes_engine_execute_with_mock_event(monkeypatch, capsys):
    calls = {}

    class FakeEngine:
        def __init__(self, playbook_path):
            calls["playbook_path"] = playbook_path

        def execute(self, trigger_event):
            calls["trigger_event"] = trigger_event
            return {"audit_trail": [{"timestamp": "t", "state": "CONTAINED", "message": "ok"}]}

    monkeypatch.setattr(main, "SOAREngine", FakeEngine)
    main.run_playbook("playbooks/brute_force_playbook.yaml")

    assert calls["playbook_path"] == "playbooks/brute_force_playbook.yaml"
    assert calls["trigger_event"]["severity"] == "HIGH"
    out = capsys.readouterr().out
    assert "INCIDENT AUDIT TRAIL" in out


def test_resolve_incident_cli_success(monkeypatch, capsys):
    monkeypatch.setattr(
        SOAREngine, "resolve_incident",
        staticmethod(lambda incident_id, incidents_dir: {"final_state": "RESOLVED"}),
    )
    main.resolve_incident_cli("INC-999", "incidents")
    out = capsys.readouterr().out
    assert "RESOLVED" in out


def test_resolve_incident_cli_missing_file_exits_cleanly(monkeypatch, capsys):
    def _raise(incident_id, incidents_dir):
        raise FileNotFoundError()

    monkeypatch.setattr(SOAREngine, "resolve_incident", staticmethod(_raise))
    with pytest.raises(SystemExit) as exc:
        main.resolve_incident_cli("INC-missing", "incidents")
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "No saved state found" in out


def test_main_dispatches_run_subcommand(monkeypatch):
    called = {}
    monkeypatch.setattr(main, "run_playbook", lambda path: called.setdefault("path", path))
    monkeypatch.setattr("sys.argv", ["main.py", "run", "--playbook", "custom.yaml"])
    main.main()
    assert called["path"] == "custom.yaml"


def test_main_dispatches_resolve_subcommand(monkeypatch):
    called = {}
    monkeypatch.setattr(
        main, "resolve_incident_cli",
        lambda incident_id, incidents_dir: called.setdefault("args", (incident_id, incidents_dir)),
    )
    monkeypatch.setattr("sys.argv", ["main.py", "resolve", "--incident-id", "INC-1", "--incidents-dir", "custom_dir"])
    main.main()
    assert called["args"] == ("INC-1", "custom_dir")


def test_main_defaults_to_run_playbook_when_no_subcommand(monkeypatch):
    called = {}
    monkeypatch.setattr(main, "run_playbook", lambda path: called.setdefault("path", path))
    monkeypatch.setattr("sys.argv", ["main.py"])
    main.main()
    assert called["path"] == "playbooks/brute_force_playbook.yaml"
