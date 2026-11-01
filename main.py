#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import time
import psutil
import yaml

# Constants
LOG_FILE = "eha-PrivilegeScaler.log"
CONFIG_FILE = "config.yaml"  # Added for future configurations
DEFAULT_BENCHMARK = "cis"

# Configure logging
# Logging goes to a file in the starting folder, configured at import.
# That means even a --help run creates eha-PrivilegeScaler.log, and the
# console stays quiet unless --verbose adds a stream handler in main.
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def setup_argparse():
    """
    Sets up the argument parser for the CLI.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(
        description="A utility that lists processes and reports what would be checked for privilege review. It changes nothing on the system."
    )
    parser.add_argument(
        "-u",
        "--user",
        type=str,
        help="The username to analyze.  If not provided, analyzes all users.",
    )
    parser.add_argument(
        "-p",
        "--process",
        type=str,
        help="The process name to monitor. If not provided, monitors all processes.",
    )
    parser.add_argument(
        "-b",
        "--benchmark",
        type=str,
        default=DEFAULT_BENCHMARK,
        help=f"Security benchmark to use (e.g., cis). Defaults to {DEFAULT_BENCHMARK}.",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        default=CONFIG_FILE,
        help=f"Configuration file path. Defaults to {CONFIG_FILE}.",
    )
    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        help="Report only. This tool changes nothing on the system in any mode.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output to the console.",
    )

    return parser


def load_configuration(config_file):
    """
    Loads configuration from a YAML file.

    Args:
        config_file (str): Path to the configuration file.

    Returns:
        dict: Configuration dictionary, or None if loading fails.
    """
    # The config is optional: no setting currently needs it.
    # The return contract matters more than the contents: a missing file and
    # an empty file both give {} and the run continues, while malformed YAML
    # gives None and main exits. Nothing downstream reads any key yet.
    if not os.path.exists(config_file):
        logging.info(f"No configuration file at {config_file}; continuing with no configuration.")
        print(f"No configuration file found at {config_file}; continuing with no configuration.")
        return {}
    try:
        with open(config_file, "r") as f:
            config = yaml.safe_load(f)
        if config is None:
            config = {}
        logging.info(f"Configuration loaded from {config_file}")
        return config
    except FileNotFoundError:
        return {}
    except yaml.YAMLError as e:
        logging.error(f"Error loading YAML configuration: {e}")
        print(f"Error loading YAML configuration: {e}")
        return None


def get_user_processes(username=None):
    """
    Gets a list of processes associated with a given username.

    Args:
        username (str, optional): The username to filter by. Defaults to None (all users).

    Returns:
        list: A list of psutil.Process objects.
    """
    processes = []
    # process_iter with a fixed attribute list takes one snapshot per
    # process. A process can still exit between the snapshot and the checks
    # below, which is why NoSuchProcess is handled per process instead of
    # failing the whole listing.
    for proc in psutil.process_iter(["pid", "name", "username"]):
        try:
            if username is None or proc.info["username"] == username:
                processes.append(proc)
        except psutil.NoSuchProcess:
            logging.warning(f"Process with PID {proc.info['pid']} no longer exists.")
        except Exception as e:
            logging.error(f"Error getting process info: {e}")
    return processes


def analyze_process_privileges(process, dry_run=False):
    """
    Analyzes the privileges of a given process.  This is a placeholder; actual privilege
    analysis would require OS-specific code.

    Args:
        process (psutil.Process): The process to analyze.
        dry_run (bool, optional): Whether to perform a dry run. Defaults to False.

    Returns:
        None
    """
    try:
        process_name = process.info["name"]
        pid = process.info["pid"]
        logging.info(f"Analyzing process: {process_name} (PID: {pid})")

        print(f"Checking process {process_name} (PID: {pid})...")
        print("Check report: this process would be checked for privilege review. No action was performed.")

    except psutil.NoSuchProcess:
    # A hazard in these handlers: if reading process.info itself is what
    # raised, pid and process_name may not be bound yet, and the handler can
    # raise NameError while trying to report the first error.
        logging.warning(f"Process with PID {pid} no longer exists.")
        print(f"Warning: Process with PID {pid} no longer exists.")
    except Exception as e:
        logging.error(f"Error analyzing process {process.info['name']}: {e}")
        print(f"Error analyzing process {process_name}: {e}")


def apply_security_benchmark(benchmark_name, dry_run=False):
    """
    Applies a security benchmark to the system.  This is a placeholder.

    Args:
        benchmark_name (str): The name of the benchmark to apply.
        dry_run (bool, optional): Whether to perform a dry run. Defaults to False.

    Returns:
        None
    """
    logging.info(f"Check report for benchmark: {benchmark_name}")
    print(f"Checking security benchmark: {benchmark_name}...")
    print(f"Check report: the {benchmark_name} benchmark would be checked. No action was performed.")


def disable_unnecessary_services(dry_run=False):
    """
    Disables unnecessary services on the system. This is a placeholder.

    Args:
        dry_run (bool, optional): Whether to perform a dry run. Defaults to False.

    Returns:
        None
    """
    logging.info("Check report for services.")
    print("Checking unnecessary services...")
    print("Check report: unnecessary services would be checked. No action was performed.")


def configure_firewall(dry_run=False):
    """
    Configures firewall rules.  This is a placeholder.

    Args:
        dry_run (bool, optional): Whether to perform a dry run. Defaults to False.

    Returns:
        None
    """
    logging.info("Check report for firewall rules.")
    print("Checking firewall rules...")
    print("Check report: firewall rules would be checked. No action was performed.")


def main():
    """
    Main function to execute the privilege scaler.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))
        logging.getLogger().setLevel(logging.DEBUG)
        print("Verbose mode enabled.")

    logging.info("Starting eha-PrivilegeScaler...")

    config = load_configuration(args.config)
    if config is None:
        logging.error("Failed to load configuration. Exiting.")
        print("Failed to load configuration. Exiting.")
        sys.exit(1)

    try:
        processes = get_user_processes(args.user)
        matched = []
        for process in processes:
            # The name filter is a case-insensitive substring match, not an exact
            # name. Asking for python also matches python3 and anything containing
            # the word, which is the behaviour I wanted for a review listing.
            if args.process is None or args.process.lower() in process.info["name"].lower():
                matched.append(process)
        if args.user is not None:
            # get_user_processes already filtered by user; keep matched as is
            pass
        # The user filter in get_user_processes and the process filter above both apply.
        count = len(matched)
        print(f"Processes matched: {count}")
        if count == 0:
            print("No processes matched. Nothing was checked.")
            logging.info("No processes matched. Nothing was checked.")
            sys.exit(1)
        # These three calls and the per-process check are report only. The
        # dry_run flag is threaded through every one of them, but there is no
        # applying mode behind it: this tool changes nothing in any mode, and
        # the printed lines say exactly that.
        apply_security_benchmark(args.benchmark, args.dry_run)
        disable_unnecessary_services(args.dry_run)
        configure_firewall(args.dry_run)
        for process in matched:
            analyze_process_privileges(process, args.dry_run)
    except SystemExit:
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

    logging.info("Check report finished. No action was performed.")
    print("Check report finished. No action was performed.")


if __name__ == "__main__":
    main()