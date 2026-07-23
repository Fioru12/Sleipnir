<div align="center">

# SLEIPNIR

### **Asgard Cybersecurity Suite — Module VI (SOAR Automation Engine)**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![YAML Playbooks](https://img.shields.io/badge/Playbooks-YAML-orange?style=for-the-badge)
![SOAR](https://img.shields.io/badge/Security-SOAR-purple?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)

</div>

> **Perché ho costruito Sleipnir?**  
> Nei SOC moderni il vero collo di bottiglia non è la mancanza di alert, ma la fatica degli analisti nel dover eseguire sempre le stesse azioni ripetitive a ogni incidente: bloccare l'IP, raccogliere lo snapshot della macchina, interrogare il feed CTI e avvisare il team su Telegram. Sleipnir è il motore **SOAR (Security Orchestration, Automation and Response)** leggero in Python che automatizza questi flussi tramite **Playbook YAML**, collegando tra loro tutti i moduli della suite Asgard.

---

## Come Funziona (Playbook-Driven Automation)

1. **Trigger**: Riceve un evento di sicurezza (es. alert da Heimdall).
2. **State Machine & Event Bus**: Traccia lo stato dell'incidente (`NEW -> RUNNING -> CONTAINED`) registrando un audit trail immutabile.
3. **Action Dispatcher**: Esegue i passaggi del playbook in modo sequenziale o condizionale (es. isolamento firewall, triage forense, verifica CTI, notifica Telegram).

---

## Esempio di Playbook YAML (`brute_force_playbook.yaml`)

```yaml
name: "Automated Brute-Force Incident Response Playbook"
trigger: "SSH_BRUTE_FORCE"

steps:
  - name: "Isolate Attacker IP on Firewall"
    action: "heimdall_block_ip"
    params:
      ip: "{{event.source_ip}}"

  - name: "Run Host Forensic Triage"
    action: "mjolnir_run_triage"
    params:
      host: "{{event.hostname}}"

  - name: "Verify Threat Intel on Attacker IP"
    action: "fenrir_check_ioc"
    params:
      indicator: "{{event.source_ip}}"

  - name: "Notify SOC via Telegram"
    action: "telegram_notify"
    params:
      message: "SOAR Automated Response: Brute-force neutralized."
```

---

## Quick Start

```bash
# Clona e installa
cd Sleipnir
pip install -r requirements.txt

# Esegui il playbook di automazione
python main.py run --playbook playbooks/brute_force_playbook.yaml
```

---

<div align="center">

**Sviluppato da [Fioru12](https://github.com/Fioru12)** — Parte della Suite Asgard.

</div>
