# eha-PrivilegeScaler
A utility that automatically adjusts user privileges on a system to the least privilege necessary based on application usage patterns (determined via process monitoring). - Focused on Automates common endpoint hardening tasks. Examples include configuring firewall rules, disabling unnecessary services, and checking system configurations against security benchmarks (e.g., CIS benchmarks). Reports on compliance and provides remediation suggestions.

## Install
`git clone https://github.com/ShadowStrikeHQ/eha-privilegescaler`

## Usage
`./eha-privilegescaler [params]`

## Parameters
- `-h`: Show help message and exit
- `-u`: The username to analyze.  If not provided, analyzes all users.
- `-p`: The process name to monitor. If not provided, monitors all processes.
- `-b`: No description provided
- `-c`: No description provided
- `-d`: Perform a dry run; do not actually change any privileges or settings.
- `-v`: Enable verbose output to the console.

## License
Copyright (c) ShadowStrikeHQ
