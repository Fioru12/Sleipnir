import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import yaml
from core.engine import SOAREngine
from core.bus import EventBus


def _engine_with_playbook(playbook: dict, tmp_path):
    pb = tmp_path / "pb.yaml"
    pb.write_text(yaml.safe_dump(playbook), encoding="utf-8")
    eng = SOAREngine(str(pb), asgard_root=str(tmp_path))
    return eng


def test_retry_eventually_succeeds(tmp_path, monkeypatch):
    eng = _engine_with_playbook({"name": "t", "steps": [
        {"name": "flaky", "action": "wait", "params": {"seconds": 0}, "retries": 2},
    ]}, tmp_path)
    calls = {"n": 0}

    def flaky(action, params, bus, timeout=15):
        calls["n"] += 1
        if calls["n"] < 3:
            return False, "boom transitorio"
        return True, "ok"

    monkeypatch.setattr(eng, "_dispatch_real_action", flaky)
    monkeypatch.setattr("core.engine.time.sleep", lambda s: None)
    bus = EventBus("INC-t", {})
    ok, details = eng._run_step_with_retry({"action": "wait", "retries": 2, "retry_delay": 0}, {}, bus)
    assert ok is True
    assert calls["n"] == 3
    assert "tentativo 3/3" in details


def test_retry_exhausted_reports_attempts(tmp_path, monkeypatch):
    eng = _engine_with_playbook({"name": "t", "steps": []}, tmp_path)
    monkeypatch.setattr(eng, "_dispatch_real_action", lambda a, p, b, timeout=15: (False, "sempre giu"))
    monkeypatch.setattr("core.engine.time.sleep", lambda s: None)
    ok, details = eng._run_step_with_retry({"action": "wait", "retries": 1, "retry_delay": 0}, {}, EventBus("x", {}))
    assert ok is False
    assert "2 tentativi" in details


def test_invalid_ip_never_retried(tmp_path, monkeypatch):
    eng = _engine_with_playbook({"name": "t", "steps": []}, tmp_path)
    calls = {"n": 0}

    def counting(action, params, bus, timeout=15):
        calls["n"] += 1
        return eng.__class__._dispatch_real_action(eng, action, params, bus, timeout=timeout)

    monkeypatch.setattr(eng, "_dispatch_real_action", counting)
    ok, details = eng._run_step_with_retry(
        {"action": "bifrost_scan", "retries": 3, "retry_delay": 0},
        {"ip": "not-an-ip; rm -rf /"}, EventBus("x", {}),
    )
    assert ok is False
    assert "Invalid IP" in details
    assert calls["n"] == 1


def test_parallel_group_runs_all(tmp_path):
    eng = _engine_with_playbook({"name": "t", "steps": [
        {"name": "grp", "parallel": [
            {"name": "a", "action": "wait", "params": {"seconds": 0}},
            {"name": "b", "action": "wait", "params": {"seconds": 0}},
        ]},
        {"name": "tail", "action": "wait", "params": {"seconds": 0}},
    ]}, tmp_path)
    summary = eng.execute({"rule_title": "test"})
    assert summary["final_state"] == "CONTAINED"
    actions = [e.get("action") for e in summary["audit_trail"] if "action" in e]
    assert "grp" in actions


def test_parallel_group_failure_fails_playbook(tmp_path):
    eng = _engine_with_playbook({"name": "t", "steps": [
        {"name": "grp", "parallel": [
            {"name": "ok", "action": "wait", "params": {"seconds": 0}},
            {"name": "ko", "action": "does_not_exist", "params": {}},
        ]},
    ]}, tmp_path)
    summary = eng.execute({"rule_title": "test"})
    assert summary["final_state"] == "FAILED"


def test_continue_on_failure_skips_ahead(tmp_path):
    eng = _engine_with_playbook({"name": "t", "steps": [
        {"name": "ko", "action": "does_not_exist", "params": {}, "continue_on_failure": True},
        {"name": "ok", "action": "wait", "params": {"seconds": 0}},
    ]}, tmp_path)
    summary = eng.execute({"rule_title": "test"})
    assert summary["final_state"] == "CONTAINED"
