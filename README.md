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
  - name: "Update Threat Intel (Fenrir)"
    action: "fenrir_update"
    params: {}

  - name: "Run HIDS Simulation (Heimdall)"
    action: "heimdall_simulate"
    params: {}

  - name: "Run Host Forensic Triage (Mjolnir)"
    action: "mjolnir_run_triage"
    params: {}

  - name: "Scan Attacker IP on the Network (Bifrost)"
    action: "bifrost_scan"
    params:
      ip: "{{event.source_ip}}"

  - name: "Audit Active Directory (Yggdrasil)"
    action: "yggdrasil_audit"
    params: {}

  - name: "Wait for Analysis"
    action: "wait"
    params:
      seconds: 2
```

Il placeholder `{{event.source_ip}}` viene risolto dal motore contro l'evento di trigger reale (quello passato a `SOAREngine.execute()`) prima di essere inoltrato al subprocess. Il valore risolto viene validato come indirizzo IP (modulo `ipaddress`) prima di essere usato negli argomenti di `bifrost_scan`: se il valore non è un IP valido, lo step fallisce con un errore invece di eseguire comunque il subprocess.

---

## Integrazione Opzionale con Gjallarhorn

Quando un incidente raggiunge uno dei due esiti "degni di nota" — `CONTAINED` (playbook completato con successo) o `FAILED` (uno step è fallito, o è stata sollevata un'eccezione) — Sleipnir può notificare l'hub centralizzato **Gjallarhorn** invece di (o oltre a) limitarsi a scrivere l'audit trail locale:

- Imposta `GJALLARHORN_HUB_URL` (es. `http://localhost:8090`) e opzionalmente `GJALLARHORN_API_KEY` nell'ambiente.
- Se impostata, `core/engine.py` invia una notifica (`source="Sleipnir"`) tramite `core/gjallarhorn_client.py` ad ogni transizione a `CONTAINED` (severità ricavata, se presente, dal campo `severity` dell'evento di trigger) o `FAILED` (severità `high`).
- Se `GJALLARHORN_HUB_URL` non è impostata, non viene fatto alcun tentativo di rete: il comportamento di Sleipnir resta identico a prima di questa integrazione.

`gjallarhorn_client.py` è copiato in `core/gjallarhorn_client.py` (nessuna dipendenza dal resto del progetto Gjallarhorn) ed espone `notify()`, che non solleva mai eccezioni.

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
