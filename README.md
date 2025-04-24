# CTFtunnel

A robust OpenVPN management tool designed for Capture The Flag competitions and cybersecurity training environments.

## Overview

CTFtunnel streamlines the process of setting up, configuring, and managing OpenVPN connections for CTF competitions. It creates separate subnets for players and challenge machines, ensuring proper network isolation while maintaining secure accessibility.

## Features

- **Easy Setup and Configuration**: Deploy OpenVPN server optimized for CTF environments with minimal effort
- **Dual Subnet Architecture**: Automatically configure separate networks for players (10.0.0.0/24) and challenge machines (10.0.1.0/24)
- **Player Management**: Generate, distribute, and revoke player certificates and configurations
- **Machine Integration**: Assign static IPs to CTF challenge machines with proper routing
- **Certificate Management**: Automated handling of PKI and certificate revocation lists (CRL)
- **Configuration Persistence**: Save user configurations for consistent deployment
- **Export/Import**: Backup and restore client configurations
- **Error Recovery**: Robust error handling with automatic troubleshooting
- **Interactive CLI**: User-friendly color-coded interface

## Requirements

- Ubuntu/Debian-based Linux system
- Root privileges
- Python 3.6+
- Required packages: `openvpn`, `easy-rsa`, `termcolor`

## Quick Start

1. Clone the repository
   ```bash
   git clone https://github.com/yourusername/CTFtunnel.git
   cd CTFtunnel
    ```
2. Run the tool (requires root)
    ```bash
    sudo python3 ctftunnel.py
    ```
3. Follow the interactive prompts to:
   - Install and configure OpenVPN
   - Add players
   - Add CTF machines with static IPs
   - Export configurations
   
# Use Cases

- CTF Competitions: Create isolated networks for cybersecurity competitions
- Training Environments: Set up practice labs for penetration testing
- Remote Teams: Establish secure connections for distributed CTF teams
- Education: Build controlled network environments for cybersecurity courses

# Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

# License
This project is licensed under the GNU GPL v3 License - see the LICENSE file for details.

# Acknowledgments
- OpenVPN community
- EasyRSA project
