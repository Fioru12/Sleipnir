import yaml
import time
from typing import Dict, Any, List
from core.bus import EventBus, IncidentState
from core.colors import Colors

class SOAREngine:
    """
    Parses and executes YAML SOAR playbooks, orchestrating
    security tools and automated responses.
    """

    def __init__(self, playbook_path: str):
        self.playbook_path = playbook_path
        self.playbook = self._load_playbook()

    def _load_playbook(self) -> Dict[str, Any]:
        with open(self.playbook_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def execute(self, trigger_event: Dict[str, Any]) -> Dict[str, Any]:
        name = self.playbook.get("name", "Unnamed Playbook")
        incident_id = f"INC-{int(time.time())}"
        
        bus = EventBus(incident_id, trigger_event)
        bus.transition(IncidentState.RUNNING, f"Executing playbook: {name}")

        print(f"{Colors.MAGENTA}[SOAR ENGINE]{Colors.ENDC} Starting Playbook: {Colors.BOLD}{name}{Colors.ENDC}")
        print(f"Incident ID: {incident_id} | Trigger: {trigger_event.get('rule_title', 'Manual Trigger')}\n")

        steps = self.playbook.get("steps", [])
        for i, step in enumerate(steps, 1):
            step_name = step.get("name", f"Step {i}")
            action = step.get("action")
            params = step.get("params", {})

            print(f"  {Colors.CYAN}[Step {i}]{Colors.ENDC} {step_name}...")
            time.sleep(0.5) # Simulated execution delay for realism

            success, details = self._dispatch_action(action, params, bus)

            if success:
                print(f"    {Colors.GREEN}[SUCCESS]{Colors.ENDC} {action} completed.")
                bus.log_action(action, "SUCCESS", details)
            else:
                print(f"    {Colors.RED}[FAILED]{Colors.ENDC} {action} failed: {details}")
                bus.log_action(action, "FAILED", details)
                bus.transition(IncidentState.FAILED, f"Playbook failed at step: {step_name}")
                return bus.get_summary()

        bus.transition(IncidentState.CONTAINED, "All playbook steps executed successfully. Threat contained.")
        print(f"\n{Colors.GREEN}[SOAR COMPLETE]{Colors.ENDC} Incident {incident_id} successfully contained.")
        return bus.get_summary()

    def _dispatch_action(self, action: str, params: Dict[str, Any], bus: EventBus) -> tuple:
        # Simulated connector actions for Asgard integration
        if action == "heimdall_block_ip":
            ip = params.get("ip", "127.0.0.1")
            return True, f"Firewall rule applied. Blocked IP {ip} via UFW/Netsh."

        elif action == "mjolnir_run_triage":
            return True, "Host triage executed. Captured 142 processes and 23 network sockets."

        elif action == "fenrir_check_ioc":
            indicator = params.get("indicator", "unknown")
            return True, f"IOC {indicator} checked against CTI database. Match found: High Risk."

        elif action == "telegram_notify":
            msg = params.get("message", "Security Alert")
            return True, f"Notification dispatched to Telegram channel: '{msg}'"

        elif action == "wait":
            seconds = params.get("seconds", 1)
            time.sleep(seconds)
            return True, f"Waited {seconds} seconds."

        else:
            return False, f"Unknown action: {action}"
