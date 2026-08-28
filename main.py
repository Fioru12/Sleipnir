import sys
import argparse
from core.engine import SOAREngine
from core.colors import Colors

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def run_playbook(playbook_path: str):
    print(Colors.MAGENTA + "=" * 65 + Colors.ENDC)
    print(f"{Colors.BOLD} Sleipnir - Asgard SOAR Automation Engine{Colors.ENDC}")
    print(Colors.MAGENTA + "=" * 65 + Colors.ENDC)

    mock_event = {
        "rule_title": "SSH Brute-Force Attack Detected",
        "severity": "HIGH",
        "source_ip": "203.0.113.50",
        "hostname": "server01-production"
    }

    engine = SOAREngine(playbook_path)
    summary = engine.execute(mock_event)

    print("\n" + Colors.MAGENTA + "=" * 65 + Colors.ENDC)
    print(f"{Colors.BOLD} INCIDENT AUDIT TRAIL:{Colors.ENDC}")
    for log in summary["audit_trail"]:
        print(f" [{log['timestamp']}] {log.get('state', log.get('action'))}: {log.get('message', log.get('details'))}")
    print(Colors.MAGENTA + "=" * 65 + Colors.ENDC)

def resolve_incident_cli(incident_id: str, incidents_dir: str):
    print(Colors.MAGENTA + "=" * 65 + Colors.ENDC)
    print(f"{Colors.BOLD} Sleipnir - Incident Resolution{Colors.ENDC}")
    print(Colors.MAGENTA + "=" * 65 + Colors.ENDC)
    try:
        summary = SOAREngine.resolve_incident(incident_id, incidents_dir=incidents_dir)
    except FileNotFoundError:
        print(f"{Colors.RED}[ERROR]{Colors.ENDC} No saved state found for incident '{incident_id}' in '{incidents_dir}'.")
        sys.exit(1)
    except ValueError as e:
        print(f"{Colors.RED}[ERROR]{Colors.ENDC} {e}")
        sys.exit(1)

    print(f"Incident {incident_id} is now: {Colors.GREEN}{summary['final_state']}{Colors.ENDC}")
    print(Colors.MAGENTA + "=" * 65 + Colors.ENDC)


def main():
    parser = argparse.ArgumentParser(description="Sleipnir: Asgard SOAR Automation Engine")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    run_p = subparsers.add_parser("run", help="Run a SOAR playbook")
    run_p.add_argument("--playbook", default="playbooks/brute_force_playbook.yaml", help="Path to YAML playbook")

    resolve_p = subparsers.add_parser("resolve", help="Manually resolve a CONTAINED incident")
    resolve_p.add_argument("--incident-id", required=True, help="Incident ID to resolve (e.g. INC-12345)")
    resolve_p.add_argument("--incidents-dir", default="incidents", help="Directory where incident state files are stored")

    args = parser.parse_args()

    if args.command == "run":
        run_playbook(args.playbook)
    elif args.command == "resolve":
        resolve_incident_cli(args.incident_id, args.incidents_dir)
    else:
        run_playbook("playbooks/brute_force_playbook.yaml")

if __name__ == "__main__":
    main()
