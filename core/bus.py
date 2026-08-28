import datetime
import json
import os
from typing import Dict, Any, List

class IncidentState:
    NEW = "NEW"
    RUNNING = "RUNNING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FAILED = "FAILED"

class EventBus:
    """
    Tracks incident state transitions and execution audit logs
    during SOAR playbook execution.
    """

    def __init__(self, incident_id: str, trigger_event: Dict[str, Any]):
        self.incident_id = incident_id
        self.trigger_event = trigger_event
        self.state = IncidentState.NEW
        self.audit_log: List[Dict[str, Any]] = []
        self.context: Dict[str, Any] = {"event": trigger_event}

    def transition(self, new_state: str, message: str):
        self.state = new_state
        entry = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "state": new_state,
            "message": message
        }
        self.audit_log.append(entry)

    def log_action(self, action_name: str, status: str, details: Any):
        entry = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": action_name,
            "status": status,
            "details": details
        }
        self.audit_log.append(entry)

    def get_summary(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "final_state": self.state,
            "audit_trail": self.audit_log,
            "context": self.context
        }

    def resolve(self):
        """
        Explicitly transition a contained incident to RESOLVED. This is a
        manual, human-triggered step (e.g. via `python main.py resolve`) and
        is only valid once the automated playbook has already reached
        CONTAINED; it will not fire automatically at the end of execute().
        """
        if self.state != IncidentState.CONTAINED:
            raise ValueError(
                f"Cannot resolve incident '{self.incident_id}' from state "
                f"'{self.state}'; only a CONTAINED incident can be resolved."
            )
        self.transition(IncidentState.RESOLVED, "Incident manually marked as resolved.")

    def save_to_file(self, path: str):
        """
        Persist the current incident state (summary: incident_id, final_state,
        full audit_trail, context) as JSON to `path`, creating the parent
        directory if it doesn't exist yet. Intended to be called after every
        step so a mid-playbook crash doesn't lose the audit trail.
        """
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.get_summary(), f, indent=2, default=str)

    @classmethod
    def load_from_file(cls, path: str) -> "EventBus":
        """
        Reconstruct an EventBus from a JSON file previously written by
        save_to_file(). Useful for post-mortem inspection or for manually
        resolving an incident; does not resume automatic execution.
        """
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        context = data.get("context", {}) or {}
        trigger_event = context.get("event", {})

        bus = cls(data["incident_id"], trigger_event)
        bus.state = data.get("final_state", IncidentState.NEW)
        bus.audit_log = data.get("audit_trail", [])
        bus.context = context
        return bus
