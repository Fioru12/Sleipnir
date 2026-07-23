import datetime
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
