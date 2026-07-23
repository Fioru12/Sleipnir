import yaml
import time
import os
import sys
import subprocess
from typing import Dict, Any, List
from core.bus import EventBus, IncidentState
from core.colors import Colors

class SOAREngine:
    """
    Real-world SOAR engine that parses YAML playbooks and executes
    actual Asgard suite modules via subprocess orchestration.
    """

    def __init__(self, playbook_path: str, asgard_root: str = "C:\\Progetti\\Asgard"):
        self.playbook_path = playbook_path
        self.asgard_root = asgard_root
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

            print(f"  {Colors.CYAN}[Step {i}]{Colors.ENDC} {step_name} ({action})...")

            success, details = self._dispatch_real_action(action, params, bus)

            if success:
                print(f"    {Colors.GREEN}[SUCCESS]{Colors.ENDC} Action executed successfully.")
                bus.log_action(action, "SUCCESS", details)
            else:
                print(f"    {Colors.RED}[FAILED]{Colors.ENDC} Action failed: {details}")
                bus.log_action(action, "FAILED", details)
                bus.transition(IncidentState.FAILED, f"Playbook failed at step: {step_name}")
                return bus.get_summary()

        bus.transition(IncidentState.CONTAINED, "All playbook steps executed successfully. Threat contained.")
        print(f"\n{Colors.GREEN}[SOAR COMPLETE]{Colors.ENDC} Incident {incident_id} successfully contained.")
        return bus.get_summary()

    def _dispatch_real_action(self, action: str, params: Dict[str, Any], bus: EventBus) -> tuple:
        try:
            if action == "heimdall_simulate":
                path = os.path.join(self.asgard_root, "Heimdall")
                res = subprocess.run([sys.executable, "run_local_demo.py"], cwd=path, capture_output=True, text=True, timeout=15)
                return res.returncode == 0, res.stdout or res.stderr

            elif action == "mjolnir_run_triage":
                path = os.path.join(self.asgard_root, "Mjolnir")
                res = subprocess.run([sys.executable, "main.py", "triage", "--simulate"], cwd=path, capture_output=True, text=True, timeout=15)
                return res.returncode == 0, res.stdout or res.stderr

            elif action == "bifrost_scan":
                path = os.path.join(self.asgard_root, "Bifrost")
                res = subprocess.run([sys.executable, "main.py", "scan", "127.0.0.1", "--enrich"], cwd=path, capture_output=True, text=True, timeout=15)
                return res.returncode == 0, res.stdout or res.stderr

            elif action == "yggdrasil_audit":
                path = os.path.join(self.asgard_root, "Yggdrasil")
                res = subprocess.run([sys.executable, "main.py", "audit"], cwd=path, capture_output=True, text=True, timeout=15)
                return res.returncode == 0, res.stdout or res.stderr

            elif action == "fenrir_update":
                path = os.path.join(self.asgard_root, "Fenrir")
                res = subprocess.run([sys.executable, "main.py", "update"], cwd=path, capture_output=True, text=True, timeout=15)
                return res.returncode == 0, res.stdout or res.stderr

            elif action == "wait":
                seconds = params.get("seconds", 1)
                time.sleep(seconds)
                return True, f"Waited {seconds} seconds."

            else:
                return False, f"Unknown action: {action}"
        except Exception as e:
            return False, str(e)
