#!/usr/bin/env bash
#
# server_health_check.sh
#
# A script to check the health
# of multiple remote servers via SSH.
#
# Usage: ./server_health_check.sh -f <server_list_file> -u <remote_user>
#
# --- Part 1: "Strict Mode" ---
# set -e: exit immediately if any command fails
# set -u: exit if an undefined variable is used
# set -o pipefail: if any command in a pipeline fails, treat the whole pipeline as failed
set -euo pipefail
# --- Global Constants ---
# We use uppercase names by convention for constants
LOG_FILE=$(mktemp /tmp/server_health.XXXXXX)
readonly LOG_FILE
# 'readonly' means this value cannot be changed
# --- Function Definitions ---
# Log an informational message to both screen and log file
log_info() {
  echo "[INFO] $1" | tee -a "$LOG_FILE"
}

# Log an error message to stderr and to the log file
log_error() {
  # >&2 sends the output to stderr
  echo "[ERROR] $1" | tee -a "$LOG_FILE" >&2
}

# Print script usage
print_usage() {
  echo "Usage: $0 -f <server_list_file> -u <remote_user>"
  echo " -f: Path to a file containing a list of servers (one per line)."
  echo " -u: The remote SSH user to connect as."
  echo " -h: Display this help message."
}

# This function will clean up after the script
cleanup() {
  echo "Cleaning up temporary log file: $LOG_FILE"
  rm -f "$LOG_FILE"
}

# Set up trap early to ensure cleanup happens on exit
# trap is the "hook". We tell it:
# "Whenever this script exits for any reason (EXIT),
# or receives INT/TERM signals, call the cleanup function."
trap cleanup EXIT INT TERM

check_server() {
  local server="$1"
  local user="$2"

  log_info "--- Checking Server: $server ---"

  # Use SSH here-command to send a batch of commands
  ssh -n -o ConnectTimeout=5 "${user}@${server}" << 'EOF'
  # 1. Uptime check
  echo "--- System Uptime ---"
  uptime
  # 2. Disk Check (Root partition)
  echo "--- Disk Usage (Root /) ---"
  # NR==2 means print only the second line of df output
  df -h / | awk 'NR==2 {print "Used: " $5 " (" $3 "/" $2 ")"}'
  # 3. Memory Check
  echo "--- Memory Usage ---"
  free -m | awk 'NR==2 {
  printf "Used: %sMB / Total: %sMB (%.2f%%)\n", $3, $2, ($3/$2)*100
  }'
  # 4. Security Check (SSH brute-force failures)
  echo "--- Security (SSH) ---"
  AUTH_LOG="/var/log/auth.log"
  if [[ -f "$AUTH_LOG" ]]; then
   count=$(grep -c "Failed password" "$AUTH_LOG")
   echo "Failed SSH Attempts: $count"
  else
   echo "Failed SSH Attempts: auth log not found."
  fi
EOF
  log_info "--- Finished Check: $server ---"
}
# Main function: core logic of the script
main() {
  local server_file=""
  local remote_user=""
  # --- Argument Parsing (using getopts) ---
  while getopts ":f:u:h" opt; do
    case "$opt" in
      f)
        server_file="$OPTARG"
        ;;
      u)
        remote_user="$OPTARG"
        ;;
      h)
        print_usage
        exit 0
        ;;
      \?) # Invalid flag
        log_error "Invalid option: -$OPTARG"
        print_usage
        exit 1
        ;;
      :) # Missing value for a flag
        log_error "Option -$OPTARG requires an argument."
        print_usage
        exit 1
        ;;
    esac
  done
  # --- Input Validation ---
  if [[ -z "$server_file" || -z "$remote_user" ]]; then
    log_error "Missing required arguments."
    print_usage
    exit 1
  fi
  # Define an empty array to hold the servers
  declare -a servers=()
  # Read the server file line by line
  while IFS= read -r line; do
    # Skip empty lines and comments
    if [[ -z "$line" || "$line" == \#* ]]; then
      continue
    fi
    # Add the server to the array
    servers+=("$line")
  done < "$server_file"
  if [[ ${#servers[@]} -eq 0 ]]; then
    log_error "No servers found in $server_file. Exiting."
    exit 1
  fi

  log_info "Found ${#servers[@]} servers to check. Starting..."
  log_info "Configuration valid. Starting health checks..."

  # Perform health checks on all servers
  for server_host in "${servers[@]}"; do
    check_server "$server_host" "$remote_user"
  done
  log_info "All checks completed."
}

# --- Script Entry Point ---
echo "Script started. Log file created at: $LOG_FILE"

# Call main with all script arguments
main "$@"