import yaml
import time
import os
import re
import sys
import subprocess
import ipaddress
from typing import Dict, Any, List
from core.bus import EventBus, IncidentState
from core.colors import Colors
from core.gjallarhorn_client import notify as gjallarhorn_notify

_PLACEHOLDER_RE = re.compile(r"^\{\{\s*event\.([A-Za-z0-9_]+)\s*\}\}$")

# Sleipnir incidents don't carry a Heimdall-style severity field on the bus
# itself, but the trigger event they were fired from often does (LOW/MEDIUM/
# HIGH/CRITICAL). Gjallarhorn's hub expects lowercase values.
_GJALLARHORN_SEVERITY_MAP = {
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}


def _map_severity_for_gjallarhorn(severity: Any, default: str = "medium") -> str:
    return _GJALLARHORN_SEVERITY_MAP.get(str(severity).upper(), default)


def notify_gjallarhorn_outcome(bus: "EventBus", playbook_name: str) -> bool:
    """Notifies the centralized Gjallarhorn hub when a playbook reaches one
    of the two outcomes worth surfacing: CONTAINED (success) or FAILED.

    No-op (returns False) unless GJALLARHORN_HUB_URL is set in the
    environment - Sleipnir keeps working exactly as before when Gjallarhorn
    isn't configured. Never raises: gjallarhorn_client.notify() already
    swallows network errors.
    """
    hub_url = os.environ.get("GJALLARHORN_HUB_URL")
    if not hub_url:
        return False

    if bus.state not in (IncidentState.CONTAINED, IncidentState.FAILED):
        return False

    api_key = os.environ.get("GJALLARHORN_API_KEY", "")
    trigger_event = bus.trigger_event or {}
    last_entry = bus.audit_log[-1] if bus.audit_log else {}

    if bus.state == IncidentState.CONTAINED:
        severity = _map_severity_for_gjallarhorn(trigger_event.get("severity"), default="medium")
        title = f"Playbook '{playbook_name}' contained incident {bus.incident_id}"
    else:
        severity = "high"
        title = f"Playbook '{playbook_name}' FAILED for incident {bus.incident_id}"

    message = (
        f"Incident: {bus.incident_id}\n"
        f"Trigger: {trigger_event.get('rule_title', 'Manual Trigger')}\n"
        f"Final state: {bus.state}\n"
        f"{last_entry.get('message', '')}"
    )

    return gjallarhorn_notify(
        hub_url=hub_url,
        api_key=api_key,
        source="Sleipnir",
        severity=severity,
        title=title,
        message=message,
    )


def _resolve_params(params: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Resolve `{{event.<field>}}` placeholders found in string param values against
    the trigger event dict. Non-string values and strings without a recognized
    placeholder are returned unchanged, so playbooks with `params: {}` (or with
    plain literal values) keep working exactly as before.
    """
    resolved: Dict[str, Any] = {}
    for key, value in params.items():
        if isinstance(value, str):
            match = _PLACEHOLDER_RE.match(value.strip())
            if match:
                field = match.group(1)
                if field in event:
                    resolved[key] = event[field]
                else:
                    # Placeholder references a field the event doesn't have;
                    # leave the raw value untouched rather than guessing.
                    resolved[key] = value
            else:
                resolved[key] = value
        else:
            resolved[key] = value
    return resolved


def _validate_ip(value: Any) -> str:
    """
    Validate that `value` is a syntactically valid IPv4/IPv6 address before it is
    ever placed into a subprocess argv. Raises ValueError with a clear message
    if not, so the caller can fail the step instead of shelling out with
    attacker-controlled/malformed data.
    """
    try:
        ipaddress.ip_address(str(value))
    except ValueError:
        raise ValueError(f"Invalid IP address for action parameter: {value!r}")
    return str(value)

class SOAREngine:
    """
    Real-world SOAR engine that parses YAML playbooks and executes
    actual Asgard suite modules via subprocess orchestration.
    """

    def __init__(self, playbook_path: str, asgard_root: str = None):
        self.playbook_path = playbook_path
        if asgard_root is None:
            self.asgard_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        else:
            self.asgard_root = asgard_root
        self.playbook = self._load_playbook()

    def _load_playbook(self) -> Dict[str, Any]:
        with open(self.playbook_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def _incident_file_path(self, incident_id: str) -> str:
        return os.path.join(self.asgard_root, "Sleipnir", "incidents", f"{incident_id}.json") \
            if os.path.isdir(os.path.join(self.asgard_root, "Sleipnir")) \
            else os.path.join("incidents", f"{incident_id}.json")

    def execute(self, trigger_event: Dict[str, Any]) -> Dict[str, Any]:
        name = self.playbook.get("name", "Unnamed Playbook")
        incident_id = f"INC-{int(time.time())}"

        bus = EventBus(incident_id, trigger_event)
        bus.transition(IncidentState.RUNNING, f"Executing playbook: {name}")

        incident_path = self._incident_file_path(incident_id)
        bus.save_to_file(incident_path)

        print(f"{Colors.MAGENTA}[SOAR ENGINE]{Colors.ENDC} Starting Playbook: {Colors.BOLD}{name}{Colors.ENDC}")
        print(f"Incident ID: {incident_id} | Trigger: {trigger_event.get('rule_title', 'Manual Trigger')}\n")

        try:
            steps = self.playbook.get("steps", [])
            if not isinstance(steps, list):
                raise TypeError(f"Playbook 'steps' must be a list, got {type(steps).__name__}")

            for i, step in enumerate(steps, 1):
                if not isinstance(step, dict):
                    raise TypeError(f"Step {i} must be a mapping, got {type(step).__name__}")

                step_name = step.get("name", f"Step {i}")
                action = step.get("action")
                raw_params = step.get("params", {}) or {}
                if not isinstance(raw_params, dict):
                    raise TypeError(
                        f"Step '{step_name}' params must be a mapping, got {type(raw_params).__name__}"
                    )
                params = _resolve_params(raw_params, trigger_event)

                print(f"  {Colors.CYAN}[Step {i}]{Colors.ENDC} {step_name} ({action})...")

                success, details = self._dispatch_real_action(action, params, bus)

                if success:
                    print(f"    {Colors.GREEN}[SUCCESS]{Colors.ENDC} Action executed successfully.")
                    bus.log_action(action, "SUCCESS", details)
                else:
                    print(f"    {Colors.RED}[FAILED]{Colors.ENDC} Action failed: {details}")
                    bus.log_action(action, "FAILED", details)
                    bus.transition(IncidentState.FAILED, f"Playbook failed at step: {step_name}")
                    bus.save_to_file(incident_path)
                    notify_gjallarhorn_outcome(bus, name)
                    return bus.get_summary()

                bus.save_to_file(incident_path)

            bus.transition(IncidentState.CONTAINED, "All playbook steps executed successfully. Threat contained.")
            bus.save_to_file(incident_path)
            notify_gjallarhorn_outcome(bus, name)
            print(f"\n{Colors.GREEN}[SOAR COMPLETE]{Colors.ENDC} Incident {incident_id} successfully contained.")
            return bus.get_summary()

        except Exception as e:
            print(f"\n{Colors.RED}[SOAR ERROR]{Colors.ENDC} Unexpected failure during execution: {e}")
            bus.transition(IncidentState.FAILED, f"Unexpected error during playbook execution: {e}")
            bus.save_to_file(incident_path)
            notify_gjallarhorn_outcome(bus, name)
            return bus.get_summary()

    @staticmethod
    def resolve_incident(incident_id: str, incidents_dir: str = "incidents") -> Dict[str, Any]:
        """
        Load a previously persisted incident (see EventBus.save_to_file /
        execute()) and explicitly transition it from CONTAINED to RESOLVED.
        This is a manual step, invoked e.g. via `python main.py resolve
        --incident-id INC-XXX`; it does not resume automatic execution.
        """
        path = os.path.join(incidents_dir, f"{incident_id}.json")
        bus = EventBus.load_from_file(path)
        bus.resolve()
        bus.save_to_file(path)
        return bus.get_summary()

    def _dispatch_real_action(self, action: str, params: Dict[str, Any], bus: EventBus) -> tuple:
        try:
            if action == "heimdall_simulate":
                path = os.path.join(self.asgard_root, "Heimdall")
                res = subprocess.run([sys.executable, "run_local_demo.py"], cwd=path, capture_output=True, text=True, encoding="utf-8", timeout=15)
                return res.returncode == 0, res.stdout or res.stderr

            elif action == "mjolnir_run_triage":
                path = os.path.join(self.asgard_root, "Mjolnir")
                res = subprocess.run([sys.executable, "main.py", "triage", "--simulate"], cwd=path, capture_output=True, text=True, encoding="utf-8", timeout=15)
                return res.returncode == 0, res.stdout or res.stderr

            elif action == "bifrost_scan":
                path = os.path.join(self.asgard_root, "Bifrost")
                target_ip = params.get("ip") or params.get("source_ip") or "127.0.0.1"
                try:
                    target_ip = _validate_ip(target_ip)
                except ValueError as e:
                    return False, str(e)
                res = subprocess.run([sys.executable, "main.py", "scan", target_ip, "--enrich"], cwd=path, capture_output=True, text=True, encoding="utf-8", timeout=15)
                return res.returncode == 0, res.stdout or res.stderr

            elif action == "yggdrasil_audit":
                path = os.path.join(self.asgard_root, "Yggdrasil")
                res = subprocess.run([sys.executable, "main.py", "audit"], cwd=path, capture_output=True, text=True, encoding="utf-8", timeout=15)
                return res.returncode == 0, res.stdout or res.stderr

            elif action == "fenrir_update":
                path = os.path.join(self.asgard_root, "Fenrir")
                res = subprocess.run([sys.executable, "main.py", "update"], cwd=path, capture_output=True, text=True, encoding="utf-8", timeout=15)
                return res.returncode == 0, res.stdout or res.stderr

            elif action == "wait":
                seconds = params.get("seconds", 1)
                time.sleep(seconds)
                return True, f"Waited {seconds} seconds."

            else:
                return False, f"Unknown action: {action}"
        except subprocess.TimeoutExpired as e:
            timeout = e.timeout
            return False, f"Action '{action}' scaduta dopo {timeout} secondi (timeout)."
        except Exception as e:
            return False, str(e)
