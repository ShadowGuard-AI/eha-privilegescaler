![Banner](banner.png)

# eha-PrivilegeScaler
A utility that lists processes and reports what would be checked for privilege review. It changes nothing on the system: it does not adjust privileges, apply a benchmark, disable services, or configure a firewall. Each report line states what would be checked and that no action was performed. - Focused on listing processes with optional user and process filters, and reporting the checks that a hardening review would cover, including benchmark, service, and firewall checks, without performing them.

## Install
`git clone https://github.com/ShadowStrikeHQ/eha-privilegescaler`

## Usage
`python3 main.py [-u user] [-p process] [-b benchmark] [-c config]`

Notes on behaviour:
- This tool lists processes and reports what would be checked. It changes nothing on the system, in any mode.
- A configuration file is optional. A run with no config file at all works, and an empty valid YAML file is accepted as an empty configuration.
- If a user or process filter matches zero processes, the run prints a plain nothing matched line and exits non-zero, with no action or completion lines.

## Parameters
- `-h`: Show help message and exit
- `-u`: The username to analyze.  If not provided, analyzes all users.
- `-p`: The process name to monitor. If not provided, monitors all processes.
- `-b`: No description provided
- `-c`: No description provided
- `-d`: Report only. This tool changes nothing on the system in any mode.
- `-v`: Enable verbose output to the console.

## License
Copyright (c) ShadowStrikeHQ
