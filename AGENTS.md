# Codex Agent Guidance for Purview SIT Analyzer

This repository contains a collection of scripts and notebooks used by security
engineers to extract and analyse **Sensitive Information Types (SITs)** from
Microsoft Purview exports and other artefacts.  The code is still in active
development; please follow these instructions when using Codex to interact
with this project.

## Environment setup

* Use **Python 3.10 or newer** on a Linux or macOS environment.
* Create and activate a virtual environment before running any scripts.  For
  example:

  ```bash
  python3 -m venv .venv
  source .venv/bin/activate