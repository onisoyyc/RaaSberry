# RaaSBerry 🍓

## Overview
RaaSBerry is a research-focused project aimed at understanding the core components of ransomware. This tool simulates ransomware behavior in a safe, controlled environment for educational purposes. The objective is to develop a “troll” ransomware that temporarily restricts access to files but releases them after a set time, allowing users to explore evasion, obfuscation, and detection avoidance techniques. **Note**: This project is intended strictly for educational and research purposes.

## Features (Planned)
- **Time-Limited File Encryption**: Encrypts user-selected files temporarily and decrypts them automatically after a defined period.
- **Evasion Tactics**: Implements methods to avoid detection by antivirus and security solutions.
- **Obfuscation**: Applies advanced obfuscation techniques to disguise key functionality.
- **Anti-Analysis Techniques**: Detects if it’s running in an analysis environment or sandbox and hides critical functions accordingly.

## Getting Started

> **⚠ Important:** This project is in the early stages and is intended for research use only. Ensure you have permission to run this code in your environment and are in a controlled, isolated setup.

### Installation (Placeholder)
Instructions for setting up RaaSBerry will be added once the project reaches a usable state.

### Prerequisites
- Python 3.x or higher
- Virtual environment (recommended for isolation)

## Roadmap

### Phase 1: Project Initialization
- [ ] Define project structure and core requirements
- [ ] Set up repository with essential files:
  - `.gitignore`
  - `CODEOWNERS`
  - `LICENSE` (TBD)

### Phase 2: Basic Encryption & Decryption Mechanism
- [ ] Implement temporary file encryption and automatic decryption after a set period
- [ ] Develop encryption key generation and secure key storage (while files are locked)
- [ ] Ensure minimal impact to file integrity during encryption/decryption

### Phase 3: Evasion Techniques
- [ ] Research common antivirus detection methods and build evasion mechanisms
- [ ] Implement basic detection evasion techniques to minimize initial flagging

### Phase 4: Obfuscation
- [ ] Apply code obfuscation to core functions
- [ ] Test different obfuscation techniques and evaluate effectiveness against static analysis

### Phase 5: Anti-Analysis Techniques
- [ ] Implement sandbox and analysis detection methods
- [ ] Pack critical functions and enable runtime unpacking to evade dynamic analysis

### Phase 6: Testing & Refinement
- [ ] Test the malware in isolated environments
- [ ] Refine based on test results to improve evasion and obfuscation
- [ ] Add user warnings and ensure proper documentation

### Phase 7: Documentation & Release
- [ ] Write detailed documentation for installation and usage (research-focused)
- [ ] Publish results, findings, and lessons learned from the project

## Contributing
This project is open to contributions for research and development purposes only. Please follow the contribution guidelines and ensure all code aligns with the project’s ethical guidelines.