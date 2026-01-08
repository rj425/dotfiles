## Customisations

# disable brew analytics
export HOMEBREW_NO_ANALYTICS=1

# Enable dark background
# alias mc='mc -b'

# Hide env variable input
# Example:
# ask_input SECRET_PASS
ask_input() {
  local v_name=$1
  if [ -z "${v_name}" ]; then
    echo "$v_name is empty"
    return
  fi
  if [ ${#v_name} -lt 3 ];then
    echo "Less than 3 chars"
    return 1
  fi
  stty -echo
  if [ -n "$ZSH_VERSION" ]; then
    read -r "$v_name?$v_name: " </dev/tty
    stty echo
  elif [ -n "$BASH_VERSION" ]; then
    read -s -p "$v_name: " $v_name
    echo
    stty echo
  else
    echo "Neither bash or zsh. Can't proceed"
    stty echo
    return 1
  fi
}

# Hide unnecessary DNS information
alias dig='dig +short'

#-------- AWS CLI related -------

# Check AWS profile credential expiration
# Usage: aws-check-expiry [profile-name]
# If no profile specified, uses $AWS_PROFILE or 'default'
aws-check-expiry() {
  local profile="${1:-${AWS_PROFILE:-default}}"
  local creds_file="${AWS_SHARED_CREDENTIALS_FILE:-$HOME/.aws/credentials}"
  
  if [ ! -f "$creds_file" ]; then
    printf "❌ Credentials file not found: %s\n" "$creds_file"
    return 1
  fi
  
  # Extract expiration from credentials file
  local expiration=$(awk -v profile="$profile" '
    BEGIN { in_section=0 }
    /^\[/ { in_section=0 }
    $0 ~ "^\\[" profile "\\]$" { in_section=1; next }
    in_section && /^expiration[[:space:]]*=/ { 
      sub(/^expiration[[:space:]]*=[[:space:]]*/, "")
      print
      exit
    }
  ' "$creds_file")
  
  if [ -z "$expiration" ]; then
    printf "ℹ️  No expiration found for profile '%s'\n" "$profile"
    printf "   (Permanent credentials or profile doesn't exist)\n"
    return 2
  fi
  
  # Parse expiration timestamp
  local exp_timestamp=$(date -j -f "%Y-%m-%dT%H:%M:%S" "$(echo $expiration | sed 's/\.[0-9]*//;s/[+-][0-9][0-9]:[0-9][0-9]$//' | sed 's/Z$//')" "+%s" 2>/dev/null)
  
  if [ -z "$exp_timestamp" ]; then
    printf "⚠️  Could not parse expiration: %s\n" "$expiration"
    return 1
  fi
  
  local current_timestamp=$(date +%s)
  local seconds_left=$((exp_timestamp - current_timestamp))
  
  printf "Profile: %s\n" "$profile"
  
  if [ $seconds_left -gt 0 ]; then
    local hours=$((seconds_left / 3600))
    local minutes=$(((seconds_left % 3600) / 60))
    local seconds=$((seconds_left % 60))
    
    # Choose emoji based on time remaining
    local time_emoji="⏱️"
    if [ $seconds_left -lt 300 ]; then
      time_emoji="🔴"
    elif [ $seconds_left -lt 1800 ]; then
      time_emoji="⚠️"
    elif [ $seconds_left -lt 3600 ]; then
      time_emoji="⏰"
    else
      time_emoji="✅"
    fi
    
    printf "%s Expires in: %dh %dm %ds\n" "$time_emoji" "$hours" "$minutes" "$seconds"
    printf "   Expiration: %s\n" "$expiration"
  else
    printf "🔴 EXPIRED\n"
    printf "   Expired: %s\n" "$expiration"
    return 1
  fi
}

# Show current AWS Region and change to required if required to do so:
aws-switch-region() {
  echo "Current AWS Region: ${AWS_REGION:-not set} (environment vars)"
  echo ""
  
  # Hardcoded list of commonly used AWS regions with descriptions
  # Format: region_code|flag|description
  local all_regions=(
    "us-east-1|🇺🇸|US East (N. Virginia)"
    "us-west-2|🇺🇸|US West (Oregon)"
    "eu-west-1|🇮🇪|Europe (Ireland)"
  )
  
  echo "Select AWS Region:"
  echo ""
  
  # Display menu with proper UTF-8 handling
  local i=1
  local region_codes=()
  for region_line in "${all_regions[@]}"; do
    region_code="${region_line%%|*}"
    region_rest="${region_line#*|}"
    region_flag="${region_rest%%|*}"
    region_desc="${region_rest#*|}"
    printf "  %d) %s  %-15s - %s\n" "$i" "$region_flag" "$region_code" "$region_desc"
    region_codes+=("$region_code")
    ((i++))
  done
  printf "  %d) quit\n" "$i"
  echo ""
  
  # Read user input
  local choice
  printf "Choice: "
  read choice
  
  if [[ "$choice" =~ ^[0-9]+$ ]]; then
    if [ "$choice" -eq "$i" ]; then
      echo "No changes made"
    elif [ "$choice" -ge 1 ] && [ "$choice" -lt "$i" ]; then
      local selected_region="${region_codes[$choice]}"
      export AWS_REGION="$selected_region"
      export AWS_DEFAULT_REGION="$selected_region"
      echo ""
      echo "✓ AWS Region set to: $selected_region"
    else
      echo "Invalid option"
    fi
  else
    echo "Invalid input"
  fi
}

#-------- Kubernetes related functions and aliases -------

# Kubernetes cli shortcut
alias k='kubectl'
alias kd='kubectl describe'
alias kg='kubectl get'

# Switch Kubernetes namespace
kx() {
  local context=$1
  kubectl config set-context --current --namespace "${context:-default}"
}

# Kubernetes completion
[[ /usr/local/bin/kubectl ]] && source <(kubectl completion zsh)

## Kubernetes
# https://github.com/kubernetes/kubernetes/issues/17512
# EKS cluster resource usage
alias util='kubectl get nodes --no-headers | awk '\''{print $1}'\'' | xargs -I {} sh -c '\''echo {} ; kubectl describe node {} | grep Allocated -A 5 | grep -ve Event -ve Allocated -ve percent -ve -- ; echo '\'''
alias cpualloc='util | grep % | awk '\''{print $1}'\'' | awk '\''{ sum += $1 } END { if (NR > 0) { print sum/(NR*20), "%\n" } }'\'''
alias memalloc='util | grep % | awk '\''{print $5}'\'' | awk '\''{ sum += $1 } END { if (NR > 0) { print sum/(NR*75), "%\n" } }'\'''

# List all kubernetes CPU allocations
kube-alloc() {
  kubectl get po --all-namespaces -o=jsonpath="{range .items[*]}{.metadata.namespace}:{.metadata.name}{'\n'}{range .spec.containers[*]}  {.name}:{.resources.requests.cpu}{'\n'}{end}{'\n'}{end}"
}

# kubectl top wrapper
# Requires: Kubernetes Metrics Server
# https://docs.aws.amazon.com/eks/latest/userguide/metrics-server.html
kube-top() {
  join -1 2 -2 2 -a 1 -a 2 -o "2.1 0 1.3 2.3 2.5 1.4 2.4 2.6" -e '<wait>' \
  <( kubectl top pods --all-namespaces | sort --key 2 -b ) \
  <( kubectl get pods --all-namespaces -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,"CPU_REQ(cores)":".spec.containers[*].resources.requests.cpu","MEMORY_REQ(bytes)":".spec.containers[*].resources.requests.memory","CPU_LIM(cores)":".spec.containers[*].resources.limits.cpu","MEMORY_LIM(bytes)":".spec.containers[*].resources.limits.memory" | sort --key 2 -b ) \
  | column -t -s' '
}

# List ALL pods in all namespaces and nodes where they are running
kube-status() {
  kubectl get pod -o=custom-columns=NAME:.metadata.name,STATUS:.status.phase,NODE:.spec.nodeName --all-namespaces
}

#-------- Kubernetes related functions and aliases (END) -------

#-------- VICE Command Line Tools Wrappers -------
#--------   https://vice-tools.viasat.io/  -------
#-------------------------------------------------

# Vice CLI defaults: use a string from vicecli_user, otherwise - $USER variable
if [ -f "${HOME}/.vicecli_user" ]; then
  export VICECLI_DEFAULT_USER=$(cat "${HOME}/.vicecli_user")
else
  export VICECLI_DEFAULT_USER=$USER
fi

# Refresh Vice CLI token and login
vcli() {
  local token_file="$HOME/.vice/jwt-io-prod-$USER"
  
  # Check for extra JWT files and offer to clean them up
  if [ -d "$HOME/.vice" ]; then
    local extra_tokens=($(find "$HOME/.vice" -name "jwt-io-prod-*" -type f ! -name "jwt-io-prod-$USER"))
    if [ ${#extra_tokens[@]} -gt 0 ]; then
      printf "⚠️  Found extra JWT token files:\n"
      for token in "${extra_tokens[@]}"; do
        printf "   - %s\n" "$(basename "$token")"
      done
      printf "\n"
      local cleanup_choice
      read "cleanup_choice?Do you want to remove these files? (y/N): "
      if [[ "$cleanup_choice" =~ ^[Yy]$ ]]; then
        for token in "${extra_tokens[@]}"; do
          rm -f "$token"
          printf "   ✓ Removed: %s\n" "$(basename "$token")"
        done
        printf "\n"
      fi
    fi
  fi
  
  # Check if token file exists and validate current session
  if [ -f "$token_file" ]; then
    printf "🔍 Checking current Vice CLI session...\n"
    local response=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer $(cat $token_file)" https://api.global.viasat.io/api/v1/users/whoami)
    local http_code=$(echo "$response" | tail -1)
    local body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "200" ]; then
      # Extract username from response (format: "uid=username,ou=people,dc=viasat,dc=io")
      local username=$(echo "$body" | jq -r '.' | grep -oE 'uid=[^,]+' | cut -d'=' -f2)
      
      # Extract expiration time from JWT token
      local jwt_payload=$(cat "$token_file" | cut -d'.' -f2)
      # Add padding if needed for base64 decoding
      local padding=$((4 - ${#jwt_payload} % 4))
      if [ $padding -ne 4 ]; then
        jwt_payload="${jwt_payload}$(printf '=%.0s' $(seq 1 $padding))"
      fi
      local exp_timestamp=$(echo "$jwt_payload" | base64 -d 2>/dev/null | jq -r '.exp // empty')
      
      if [ -n "$exp_timestamp" ]; then
        local current_timestamp=$(date +%s)
        local seconds_left=$((exp_timestamp - current_timestamp))
        
        if [ $seconds_left -gt 0 ]; then
          local hours=$((seconds_left / 3600))
          local minutes=$(((seconds_left % 3600) / 60))
          local seconds=$((seconds_left % 60))
          
          printf "✅ Session is still active\n"
          printf "⏱️  Time until expiry: %d hours %d minutes %d seconds\n" "$hours" "$minutes" "$seconds"
          if [ -n "$username" ]; then
            printf "👤 User: %s\n" "$username"
          fi
          printf "\n"
          printf "💡 Usage examples:\n"
          printf "  # List all groups in the VICE Stripe\n"
          printf "  vice -s runners groups list\n"
          printf "\n"
          printf "  # curl example with bearer token\n"
          printf "  curl -H \"Authorization: Bearer \$(cat %s)\" https://api.global.viasat.io/api/v1/environments/runners/dns/internal\n" "$token_file"
          return 0
        else
          printf "⚠️  Token has expired\n"
        fi
      else
        printf "⚠️  Could not parse token expiration\n"
      fi
    else
      printf "⚠️  Session is not active (HTTP %s)\n" "$http_code"
    fi
    printf "\n"
  fi
  
  # Refresh the token
  printf "⚙️  Refreshing Vice CLI token for user: %s\n" "$VICECLI_DEFAULT_USER"
  if vice --username $USER --refresh --token push; then
    printf "✅ Vice CLI token refreshed successfully and saved to %s\n" "$token_file"
    printf "\n"
    printf "Usage examples:\n"
    printf "  # List all groups in the VICE Stripe\n"
    printf "  vice -s runners groups list\n"
    printf "\n"
    printf "  # curl example with bearer token\n"
    printf "  curl -H \"Authorization: Bearer \$(cat %s)\" https://api.global.viasat.io/api/v1/environments/runners/dns/internal\n" "$token_file"
  else
    printf "❌ Failed to refresh Vice CLI token\n"
    return 1
  fi
}

# Wrapper for Alohomora (Vice tool)
# Authenticates to AWS using temporary credentials via Alohomora
# Usage: use <profile-name> [-force] [-timing]
# Example: use my-aws-profile
# Force refresh: use my-aws-profile -force
# Show timing: use my-aws-profile -timing
use() {
  if [ $# -eq 0 ]; then
    printf "Error: AWS profile name is required\n"
    printf "Usage: use <profile-name> [-force] [-timing]\n"
    printf "\nAvailable profiles:\n"
    aws configure list-profiles | sed 's/^/  /'
    return 1
  fi
  
  local POSITIONAL=()
  local FORCE="no"
  local TIMING="no"
  local start_time_ms=$(python3 -c 'import time; print(int(time.time() * 1000))')
  local last_time_ms=$start_time_ms
  
  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -force|--force)
        FORCE="yes"
        shift
        ;;
      -timing|--timing)
        TIMING="yes"
        shift
        ;;
      -*)
        printf "Unknown option: %s\n" "$1"
        printf "Usage: use <profile-name> [-force] [-timing]\n"
        return 1
        ;;
      *)
        POSITIONAL+=("$1")
        shift
        ;;
    esac
  done
  
  set -- "${POSITIONAL[@]}"
  
  # Helper function to print timing with millisecond precision
  _print_timing() {
    if [ "$TIMING" = "yes" ]; then
      local current_time_ms=$(python3 -c 'import time; print(int(time.time() * 1000))')
      local elapsed_ms=$((current_time_ms - last_time_ms))
      local total_ms=$((current_time_ms - start_time_ms))
      
      # Format elapsed time
      local elapsed_str
      if [ $elapsed_ms -ge 1000 ]; then
        local elapsed_s=$((elapsed_ms / 1000))
        local elapsed_ms_remainder=$((elapsed_ms % 1000))
        elapsed_str=$(printf "%d.%03ds" "$elapsed_s" "$elapsed_ms_remainder")
      else
        elapsed_str=$(printf "%dms" "$elapsed_ms")
      fi
      
      # Format total time
      local total_str
      if [ $total_ms -ge 1000 ]; then
        local total_s=$((total_ms / 1000))
        local total_ms_remainder=$((total_ms % 1000))
        total_str=$(printf "%d.%03ds" "$total_s" "$total_ms_remainder")
      else
        total_str=$(printf "%dms" "$total_ms")
      fi
      
      printf "⏱️  [+%s | total: %s] %s\n" "$elapsed_str" "$total_str" "$1"
      last_time_ms=$current_time_ms
    fi
  }
  
  # Validate profile name provided
  if [ -z "$1" ]; then
    printf "Error: AWS profile name is required\n"
    printf "Usage: use <profile-name> [-force] [-timing]\n"
    return 1
  fi
  
  local profile="$1"
  _print_timing "Starting use() for profile: $profile"
  
  # Check if profile exists, offer to create if it doesn't
  _print_timing "Checking if profile exists"
  local config_file="${AWS_CONFIG_FILE:-$HOME/.aws/config}"
  local credentials_file="${AWS_SHARED_CREDENTIALS_FILE:-$HOME/.aws/credentials}"
  local profile_exists=0
  
  # Fast check: look for profile in config or credentials file
  if [ -f "$config_file" ] && grep -q "^\[profile ${profile}\]" "$config_file" 2>/dev/null; then
    profile_exists=1
  elif [ -f "$credentials_file" ] && grep -q "^\[${profile}\]" "$credentials_file" 2>/dev/null; then
    profile_exists=1
  fi
  
  if [ $profile_exists -eq 0 ]; then
    printf "⚠️  Profile '%s' does not exist\n" "$profile"
    printf "\nAvailable profiles:\n"
    aws configure list-profiles | sed 's/^/  /'
    printf "\n"
    local create_choice
    read "create_choice?Do you want to create this profile? (y/N): "
    if [[ "$create_choice" =~ ^[Yy]$ ]]; then
      aws configure --profile "$profile"
      return $?
    else
      printf "Cancelled\n"
      return 1
    fi
  fi
  _print_timing "Profile exists"
  
  # Clear any existing AWS credentials from environment
  unset AWS_ACCESS_KEY_ID
  unset AWS_SECRET_ACCESS_KEY
  unset AWS_SESSION_TOKEN
  
  # Set the profile
  export AWS_PROFILE="$profile"
  _print_timing "Environment variables cleared and profile set"
  
  # Check if authentication is needed using credential expiration
  local needs_auth="no"
  local needs_alohomora_auth="no"
  
  if [ "$FORCE" = "yes" ]; then
    needs_auth="yes"
    needs_alohomora_auth="yes"
    printf "🔄 Forcing credential refresh for profile: %s\n" "$profile"
    _print_timing "Force flag detected"
  else
    # Check alohomora session validity first
    _print_timing "Checking alohomora session"
    local cookiejar_file="$HOME/.alohomora.cookiejar"
    
    if [ -f "$cookiejar_file" ]; then
      # Get file modification time (last session refresh)
      local mod_time=$(stat -f "%m" "$cookiejar_file" 2>/dev/null)
      local current_time=$(date +%s)
      local session_age=$((current_time - mod_time))
      
      # Assume SSO session is valid for 8 hours (28800 seconds)
      local session_timeout=28800
      
      if [ $session_age -gt $session_timeout ]; then
        needs_alohomora_auth="yes"
        local hours=$((session_age / 3600))
        printf "⚠️  Alohomora SSO session expired (%dh ago)\n" "$hours"
        _print_timing "Alohomora session expired"
      else
        local remaining=$((session_timeout - session_age))
        local hours=$((remaining / 3600))
        local minutes=$(((remaining % 3600) / 60))
        printf "✅ Alohomora SSO session valid (expires in %dh %dm)\n" "$hours" "$minutes"
        _print_timing "Alohomora session valid"
      fi
    else
      needs_alohomora_auth="yes"
      printf "⚠️  No alohomora session found (~/.alohomora.cookiejar)\n"
      _print_timing "No alohomora cookiejar found"
    fi
    
    # Check expiration from credentials file
    _print_timing "Checking credential expiration"
    
    # Run aws-check-expiry silently to check status
    aws-check-expiry "$profile" >/dev/null 2>&1
    local expiry_result=$?
    
    if [ $expiry_result -eq 0 ]; then
      # Credentials are valid with expiration
      needs_auth="no"
      printf "✅ AWS credentials valid for profile: %s" "$profile"
      aws-check-expiry "$profile"
      _print_timing "Credentials are valid"
    else
      # Either no expiration field or expired - need to authenticate
      needs_auth="yes"
      printf "🔐 Authentication needed for profile: %s" "$profile"
      _print_timing "Need authentication"
    fi
    
    # Determine if we need to authenticate
    if [ "$needs_auth" = "yes" ]; then
      # Always authenticate if AWS creds are missing/expired
      needs_auth="yes"
    elif [ "$needs_alohomora_auth" = "yes" ]; then
      # If only alohomora session expired but AWS creds valid, warn but don't force auth
      printf "\n⚠️  Note: AWS credentials are valid, but alohomora session needs refresh\n"
      printf "    Next credential refresh will require re-authentication\n"
      printf "    Use 'use %s -force' to refresh alohomora session now\n" "$profile"
      needs_auth="no"
    fi
  fi
  
  # Authenticate if needed
  if [ "$needs_auth" = "yes" ]; then
    # Use installed binary in ~/.bin, fallback to git repo, then PATH
    local alohomora_bin
    if [ -x "$HOME/.bin/alohomora" ]; then
      alohomora_bin="$HOME/.bin/alohomora"
    elif [ -x "/Users/vturbinskii/git/Extras/alohomora/go-alohomora" ]; then
      alohomora_bin="/Users/vturbinskii/git/Extras/alohomora/go-alohomora"
    elif command -v alohomora >/dev/null 2>&1; then
      alohomora_bin="alohomora"
    else
      printf "❌ Alohomora binary not found. Please install it to ~/.bin/alohomora\n"
      return 1
    fi
    
    _print_timing "Checking alohomora binary: $alohomora_bin"
    if [ ! -x "$alohomora_bin" ] && [ "$alohomora_bin" != "alohomora" ]; then
      printf "❌ Alohomora binary not found or not executable: %s\n" "$alohomora_bin"
      return 1
    fi
    
    printf "\n"
    _print_timing "Starting alohomora authentication"
    "$alohomora_bin" --duration 14400 --alohomora-profile "$profile"
    local auth_result=$?
    _print_timing "Alohomora authentication completed"
    
    if [ $auth_result -ne 0 ]; then
      printf "\n"
      printf "❌ Authentication failed\n"
      return 1
    fi
    
    printf "✅ Authentication successful\n"
    # Show new expiration
    _print_timing "Checking new expiration"
    aws-check-expiry "$profile"
    
    printf "\n"
    # Verify login and display connection info after authentication
    _print_timing "Verifying AWS login"
    check_aws_login
    _print_timing "AWS login verification completed"
  else
    # Check if we should verify the connection
    # Only call check_aws_login if credentials expire in less than 30 minutes
    _print_timing "Checking if connection verification needed"
    local creds_file="${AWS_SHARED_CREDENTIALS_FILE:-$HOME/.aws/credentials}"
    local expiration=$(awk -v profile="$profile" '
      BEGIN { in_section=0 }
      /^\[/ { in_section=0 }
      $0 ~ "^\\[" profile "\\]$" { in_section=1; next }
      in_section && /^expiration[[:space:]]*=/ { 
        sub(/^expiration[[:space:]]*=[[:space:]]*/, "")
        print
        exit
      }
    ' "$creds_file")
    
    if [ -n "$expiration" ]; then
      local exp_timestamp=$(date -j -f "%Y-%m-%dT%H:%M:%S" "$(echo $expiration | sed 's/\.[0-9]*//;s/[+-][0-9][0-9]:[0-9][0-9]$//' | sed 's/Z$//')" "+%s" 2>/dev/null)
      if [ -n "$exp_timestamp" ]; then
        local current_timestamp=$(date +%s)
        local seconds_left=$((exp_timestamp - current_timestamp))
        
        # Only call check_aws_login if less than 30 minutes (1800 seconds) remaining
        if [ $seconds_left -lt 1800 ]; then
          _print_timing "Credentials expiring soon, verifying connection"
          printf "\n"
          check_aws_login
          _print_timing "Connection verification completed"
        else
          _print_timing "Credentials valid for >30min, skipping verification"
        fi
      fi
    fi
  fi
  
  _print_timing "use() completed successfully"
}

# Check AWS authentication status and display connection details
# Usage: check_aws_login [-v|--verbose]
# Returns: 0 if authenticated, 1 if not
check_aws_login() {
  local verbose="no"
  
  # Parse arguments
  if [ "$1" = "-v" ] || [ "$1" = "--verbose" ]; then
    verbose="yes"
  fi
  
  # Try to get caller identity
  local identity_json=$(aws sts get-caller-identity 2>/dev/null)
  
  if [ $? -ne 0 ]; then
    printf "❌ AWS authentication failed - credentials are expired or invalid\n"
    if [ -n "$AWS_PROFILE" ]; then
      printf "   Profile: %s\n" "$AWS_PROFILE"
    fi
    return 1
  fi
  
  # Extract identity information
  local account_id=$(echo "$identity_json" | jq -r '.Account // "N/A"')
  local user_id=$(echo "$identity_json" | jq -r '.UserId // "N/A"')
  local arn=$(echo "$identity_json" | jq -r '.Arn // "N/A"')
  
  # Determine if this is a user or assumed role
  local identity_type="User"
  local identity_name=""
  if [[ "$arn" == *":assumed-role/"* ]]; then
    identity_type="Role"
    identity_name=$(echo "$arn" | sed 's/.*:assumed-role\/\([^/]*\).*/\1/')
  elif [[ "$arn" == *":user/"* ]]; then
    identity_name=$(echo "$arn" | sed 's/.*:user\/\(.*\)/\1/')
  fi
  
  # Get account alias
  local account_alias=$(aws iam list-account-aliases 2>/dev/null | jq -r '.AccountAliases[0] // empty')
  local account_display="${account_alias:-$account_id}"
  
  # Display basic information
  printf "✅ Connected to AWS\n"
  printf "   Account: %s" "$account_display"
  if [ -n "$account_alias" ] && [ "$account_alias" != "$account_id" ]; then
    printf " (%s)" "$account_id"
  fi
  printf "\n"
  
  if [ -n "$identity_name" ]; then
    printf "   %s: %s\n" "$identity_type" "$identity_name"
  fi
  
  if [ -n "$AWS_PROFILE" ]; then
    printf "   Profile: %s\n" "$AWS_PROFILE"
  fi
  
  if [ -n "$AWS_REGION" ]; then
    printf "   Region: %s\n" "$AWS_REGION"
  fi
  
  # Check for session expiration (for temporary credentials)
  if [[ "$arn" == *":assumed-role/"* ]] || [[ "$arn" == *":sts:"* ]]; then
    # Try to get session token expiration from credentials
    local credentials_json=$(aws configure export-credentials 2>/dev/null)
    if [ $? -eq 0 ]; then
      local expiration=$(echo "$credentials_json" | jq -r '.Expiration // empty')
      if [ -n "$expiration" ]; then
        # Parse ISO 8601 timestamp - handle both with and without timezone
        local exp_timestamp=$(date -j -f "%Y-%m-%dT%H:%M:%S" "$(echo $expiration | sed 's/\.[0-9]*//;s/[+-][0-9][0-9]:[0-9][0-9]$//' | sed 's/Z$//')" "+%s" 2>/dev/null)
        
        if [ -n "$exp_timestamp" ]; then
          local current_timestamp=$(date +%s)
          local seconds_left=$((exp_timestamp - current_timestamp))
          
          if [ $seconds_left -gt 0 ]; then
            local hours=$((seconds_left / 3600))
            local minutes=$(((seconds_left % 3600) / 60))
            local seconds=$((seconds_left % 60))
            
            # Choose emoji based on time remaining
            local time_emoji="⏱️"
            if [ $seconds_left -lt 300 ]; then
              # Less than 5 minutes - urgent
              time_emoji="🔴"
            elif [ $seconds_left -lt 1800 ]; then
              # Less than 30 minutes - warning
              time_emoji="⚠️"
            elif [ $seconds_left -lt 3600 ]; then
              # Less than 1 hour
              time_emoji="⏰"
            else
              # Plenty of time
              time_emoji="✅"
            fi
            
            printf "   %s Session expires in: %dh %dm %ds\n" "$time_emoji" "$hours" "$minutes" "$seconds"
          else
            printf "   🔴 Session has EXPIRED\n"
          fi
        fi
      fi
    fi
  fi
  
  # Verbose mode - show full ARN
  if [ "$verbose" = "yes" ]; then
    printf "\n"
    printf "Detailed information:\n"
    printf "   ARN: %s\n" "$arn"
    printf "   User ID: %s\n" "$user_id"
  fi
  
  return 0
}

#-------- VICE Command Line Tools Wrappers (END) -------

#-------- Terraform and Terragrunt aliases, variables, wrappers -------

# Enable caching for Terraform plugins
export TF_PLUGIN_CACHE_DIR="$HOME/.terraform.d/plugin-cache"

# Common terragrunt shortcut
alias tg=terragrunt

# Common terraform alias
alias tf="terraform"
unalias tga 2>/dev/null || true
unalias tgp 2>/dev/null || true
unalias tgo 2>/dev/null || true

# Check Terragrunt version and determine which flag to use
# Returns: "legacy" for --terragrunt-source-update (< 0.59.10)
#          "new" for --source-update (>= 0.59.10)
#          "error" if version cannot be determined
_terragrunt_version_check() {
  # Capture the output of the terragrunt version command
  local version_info
  version_info=$(terragrunt -version 2>&1)
  
  # Extract the version number - handle various formats
  local terragrunt_version
  terragrunt_version=$(echo "$version_info" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)

  if [ -z "$terragrunt_version" ]; then
    echo "error"
    return 1
  fi

  # Compare version with 0.59.10 using awk
  # Returns "lt" if less than, "ge" if greater than or equal
  local version_check
  version_check=$(awk -v ver="$terragrunt_version" 'BEGIN {
    split(ver, v, ".")
    major = v[1] + 0
    minor = v[2] + 0
    patch = v[3] + 0
    
    if (major < 0) { print "lt"; exit }
    if (major > 0) { print "ge"; exit }
    if (minor < 59) { print "lt"; exit }
    if (minor > 59) { print "ge"; exit }
    if (patch < 10) { print "lt"; exit }
    print "ge"
  }')

  if [ "$version_check" = "lt" ]; then
    echo "legacy"
  else
    echo "new"
  fi
}

# Most useful terragrunt alias
tga() {
  local flag_type=$(_terragrunt_version_check)
  
  if [ "$flag_type" = "error" ]; then
    echo "Warning: Could not detect Terragrunt version, using legacy flag"
    terragrunt apply --terragrunt-source-update "$@"
    return $?
  fi

  if [ "$flag_type" = "legacy" ]; then
    terragrunt apply --terragrunt-source-update "$@"
  else
    terragrunt apply --source-update "$@"
  fi
}

tgp() {
  local flag_type=$(_terragrunt_version_check)
  
  if [ "$flag_type" = "error" ]; then
    echo "Warning: Could not detect Terragrunt version, using legacy flag"
    terragrunt plan --terragrunt-source-update "$@"
    return $?
  fi

  if [ "$flag_type" = "legacy" ]; then
    terragrunt plan --terragrunt-source-update "$@"
  else
    terragrunt plan --source-update "$@"
  fi
}

alias tgaa="terragrunt apply"
alias tgpp="terragrunt plan"

tgo() {
  local flag_type=$(_terragrunt_version_check)
  
  if [ "$flag_type" = "error" ]; then
    echo "Warning: Could not detect Terragrunt version, using legacy flag"
    terragrunt output --terragrunt-source-update "$@"
    return $?
  fi

  if [ "$flag_type" = "legacy" ]; then
    terragrunt output --terragrunt-source-update "$@"
  else
    terragrunt output --source-update "$@"
  fi
}

alias tgr="terragrunt refresh"

# Enable Terraform debug
# Useful for debugging API calls and internals
# Output is written to $HOME/.terraform-debug
# Security: Remove log file when not used (might contain sensitive info)
tf_debug() {
   if [ -z "${TF_LOG+x}" ] || [ -z "${TF_LOG_PATH+x}" ]; then
      export TF_LOG=TRACE
      export TF_LOG_PATH=$HOME/.terraform-debug
      echo "Terraform debugging is enabled"
      echo "Writing debug info to $HOME/.terraform-debug"
      echo
      return 0
   else
      unset TF_LOG
      unset TF_LOG_PATH
      echo "Terraform debugging is disabled"
      echo
      return 0
   fi
}

# The path where to download Terraform code when using remote Terraform configurations.
# Default is .terragrunt-cache in the working directory
export TERRAGRUNT_DOWNLOAD=$HOME/.terragrunt.cache

# Terragrunt will try to use this version first (w/o tfenv)
# export TERRAGRUNT_TFPATH=/usr/local/bin/terraform

#-------- Terraform and Terragrunt aliases, variables, wrappers (END) -------

# List all available custom functions and aliases from .zshrc
list-zsh-functions() {
  echo "════════════════════════════════════════════════════════════════"
  echo "              CUSTOM FUNCTIONS FROM .zshrc"
  echo "════════════════════════════════════════════════════════════════"
  echo ""
  
  # Extract all function definitions from .zshrc
  grep -E '^[a-zA-Z0-9_-]+\(\)' ~/.zshrc | sed 's/().*//' | sort | while IFS= read -r func; do
    # Get the first comment line above the function if it exists
    local line_num=$(grep -n "^${func}()" ~/.zshrc | cut -d: -f1 | head -1)
    if [ -n "$line_num" ]; then
      local prev_line=$((line_num - 1))
      local comment=$(sed -n "${prev_line}p" ~/.zshrc | grep -E '^[[:space:]]*#' | sed 's/^[[:space:]]*#[[:space:]]*//')
      if [ -n "$comment" ]; then
        printf "  %-30s - %s\n" "$func" "$comment"
      else
        printf "  %-30s\n" "$func"
      fi
    fi
  done
  
  echo ""
  echo "════════════════════════════════════════════════════════════════"
  echo "              CUSTOM ALIASES FROM .zshrc"
  echo "════════════════════════════════════════════════════════════════"
  echo ""
  
  # Extract all aliases from .zshrc (excluding commented ones)
  grep -E "^alias " ~/.zshrc | sed "s/^alias /  /" | sort
  
  echo ""
  
  # Check if personal aliases file exists and show them too
  if [ -f "${HOME}/.zshrc_personal_aliases.zsh" ]; then
    echo "════════════════════════════════════════════════════════════════"
    echo "        PERSONAL ALIASES FROM .zshrc_personal_aliases.zsh"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    
    # Extract functions from personal aliases file
    if grep -qE '^[a-zA-Z0-9_-]+\(\)' "${HOME}/.zshrc_personal_aliases.zsh" 2>/dev/null; then
      echo "Functions:"
      grep -E '^[a-zA-Z0-9_-]+\(\)' "${HOME}/.zshrc_personal_aliases.zsh" | sed 's/().*//' | sort | while IFS= read -r func; do
        printf "  %-30s\n" "$func"
      done
      echo ""
    fi
    
    # Extract aliases from personal aliases file
    if grep -qE "^alias " "${HOME}/.zshrc_personal_aliases.zsh" 2>/dev/null; then
      echo "Aliases:"
      grep -E "^alias " "${HOME}/.zshrc_personal_aliases.zsh" | sed "s/^alias /  /" | sort
      echo ""
    fi
  fi
  
  echo "════════════════════════════════════════════════════════════════"
  echo ""
  echo "Total custom functions: $(grep -cE '^[a-zA-Z0-9_-]+\(\)' ~/.zshrc)"
  echo "Total custom aliases: $(grep -cE '^alias ' ~/.zshrc)"
  if [ -f "${HOME}/.zshrc_personal_aliases.zsh" ]; then
    echo "Total personal functions: $(grep -cE '^[a-zA-Z0-9_-]+\(\)' "${HOME}/.zshrc_personal_aliases.zsh" 2>/dev/null || echo 0)"
    echo "Total personal aliases: $(grep -cE '^alias ' "${HOME}/.zshrc_personal_aliases.zsh" 2>/dev/null || echo 0)"
  fi
  echo ""
}

# Load personal functions and aliases
test -e "${HOME}/.zshrc_personal_aliases.zsh" && source "${HOME}/.zshrc_personal_aliases.zsh"

# Create temporary Kubernetes pod for debugging
# Usage: kube-helper [host]
# 
# Arguments:
#   host - Run in privileged mode with host filesystem mounted at /host
#
# Examples:
#   kube-helper       - Standard container
#   kube-helper host  - Privileged container with host access
#
# The pod will handle SIGTERM properly and exit gracefully
kube-helper() {
  local mode="${1:-standard}"
  local privileged_mode=false
  local extra_args=""
  
  if [ "$mode" = "host" ]; then
    privileged_mode=true
    echo "🚀 Starting k-helper container in PRIVILEGED mode..."
    echo "   Image: gi-docker.docker.artifactory.viasat.com/viasat-ubuntu22"
    echo "   Mode: Privileged with host PID namespace and filesystem"
    echo ""
    echo "⚠️  WARNING: This container has full access to the host system!"
    echo ""
  elif [ "$mode" = "standard" ]; then
    echo "🚀 Starting k-helper container..."
    echo "   Image: gi-docker.docker.artifactory.viasat.com/viasat-ubuntu22"
    echo "   Mode: Standard (non-privileged)"
    echo ""
  else
    echo "❌ Invalid argument: $mode"
    echo ""
    echo "Usage: kube-helper [host]"
    echo ""
    echo "Arguments:"
    echo "  (none)  - Standard container"
    echo "  host    - Privileged container with host filesystem at /host"
    echo ""
    echo "Examples:"
    echo "  kube-helper       - Standard container"
    echo "  kube-helper host  - Privileged container with host access"
    return 1
  fi

  # Start the container with proper signal handling
  if [ "$privileged_mode" = true ]; then
    # Use a temporary file for the overrides JSON
    local overrides_file=$(mktemp)
    cat > "$overrides_file" <<'EOF'
{
  "spec": {
    "hostPID": true,
    "hostNetwork": true,
    "hostIPC": true,
    "containers": [{
      "name": "k-helper",
      "image": "gi-docker.docker.artifactory.viasat.com/viasat-ubuntu22",
      "command": ["/bin/bash", "-c", "trap \"exit 0\" SIGTERM SIGINT; sleep infinity & wait $!"],
      "stdin": true,
      "tty": true,
      "securityContext": {
        "privileged": true
      },
      "volumeMounts": [{
        "name": "host",
        "mountPath": "/host"
      }]
    }],
    "volumes": [{
      "name": "host",
      "hostPath": {
        "path": "/",
        "type": "Directory"
      }
    }]
  }
}
EOF
    
    kubectl run k-helper \
      --image=gi-docker.docker.artifactory.viasat.com/viasat-ubuntu22 \
      --restart=Never \
      --overrides="$(cat $overrides_file)"
    
    # Cleanup temp file
    rm -f "$overrides_file"
  else
    kubectl run k-helper \
      --image=gi-docker.docker.artifactory.viasat.com/viasat-ubuntu22 \
      --restart=Never \
      --command -- /bin/bash -c 'trap "exit 0" SIGTERM SIGINT; sleep infinity & wait $!'
  fi

  # Check if the container started successfully
  if [ $? -ne 0 ]; then
    echo "❌ Failed to start the k-helper container."
    return 1
  fi

  echo "⏳ Waiting for pod to be ready..."
  # Wait until the pod is in 'Running' state
  if ! kubectl wait --for=condition=ready pod/k-helper --timeout=60s 2>/dev/null; then
    echo "❌ k-helper container did not reach the 'Running' state in time."
    echo "   Check status: kubectl describe pod k-helper"
    return 1
  fi

  echo "✅ Pod is ready!"
  echo ""
  
  if [ "$privileged_mode" = true ]; then
    echo "💡 Host filesystem is mounted at: /host"
    echo ""
    echo "🔧 Setting up host access..."
    
    # Create helper script to enter host
    kubectl exec k-helper -- /bin/bash -c '
      cat > /usr/local/bin/enter-host <<'\''SCRIPT'\''
#!/bin/bash
# Enter host root filesystem
# Since we share hostPID, hostNetwork, and hostIPC, we just need to chroot
exec chroot /host /bin/bash -c "cd /root; export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec /bin/bash"
SCRIPT
      chmod +x /usr/local/bin/enter-host
    ' 2>/dev/null
    
    echo "✅ Host access ready"
    echo ""
    echo "💡 Usage:"
    echo "   enter-host    - Enter host namespace (systemctl works)"
    echo ""
    echo "💡 Examples:"
    echo "   # Enter host environment"
    echo "   enter-host"
    echo "   systemctl status"
    echo "   ps aux"
    echo "   journalctl -xe"
    echo ""
    echo "   # Access container filesystem from host"
    echo "   ls /host/etc"
    echo ""
    echo "   # Run single command on host"
    echo "   nsenter -t 1 -m -u -n -i -p systemctl status"
    echo ""
  fi

  # Open an interactive shell inside the container
  echo "🔗 Opening interactive shell..."
  echo "   (type 'exit' or press Ctrl+D to exit)"
  echo ""
  kubectl exec -ti k-helper -- /bin/bash

  # After exiting the shell, offer to delete the pod
  echo ""
  echo "📝 k-helper session ended."
  echo ""
  read "cleanup?Delete the k-helper pod? (Y/n): "
  
  if [[ ! "$cleanup" =~ ^[Nn]$ ]]; then
    echo "🗑️  Deleting pod..."
    kubectl delete pod k-helper --wait=false
    echo "✅ Pod deletion initiated"
  else
    echo "💡 To delete later, run: kubectl delete pod k-helper"
  fi
}

export AWS_EC2_METADATA_DISABLED=true

# Read about terragrunt performance
# https://terragrunt.gruntwork.io/docs/troubleshooting/performance/
export TG_TF_FORWARD_STDOUT=true
export TERRAGRUNT_FORWARD_TF_STDOUT=true
export TERRAGRUNT_STRICT_CONTROL=skip-dependencies-inputs
export TG_DEPENDENCY_FETCH_OUTPUT_FROM_STATE=true
export TERRAGRUNT_FETCH_DEPENDENCY_OUTPUT_FROM_STATE=true

# Create External Secret Operator test secret
# Usage: test-eso <environment>
# Example: test-eso dubsre-prod
# Cleanup: test-eso dubsre-prod -cleanup
test-eso() {
  local env_name=$1
  local cleanup_flag=$2
  
  if [ -z "${env_name}" ]; then
    echo "Error: Environment name is required"
    echo "Usage: test-eso <environment> [-cleanup]"
    echo "Example: test-eso dubsre-prod"
    echo "Cleanup: test-eso dubsre-prod -cleanup"
    return 1
  fi
  
  # Set Vault address
  export VAULT_ADDR='https://vault.seceng-iam.viasat.io'
  
  # Check if logged into Vault
  if ! vault token lookup &>/dev/null; then
    echo "Not logged into Vault. Attempting login..."
    vault login -method=oidc
    if [ $? -ne 0 ]; then
      echo "Error: Vault login failed"
      return 1
    fi
  fi
  
  # Handle cleanup flag
  if [ "$cleanup_flag" = "-cleanup" ]; then
    echo "🧹 Cleaning up test secrets..."
    local vault_path="${env_name}/services/test"
    
    # Delete ExternalSecret
    if kubectl get externalsecret test-eso -n default &>/dev/null; then
      echo "Deleting ExternalSecret 'test-eso'..."
      kubectl delete externalsecret test-eso -n default
      if [ $? -eq 0 ]; then
        echo "✓ ExternalSecret deleted"
      else
        echo "✗ Failed to delete ExternalSecret"
      fi
    else
      echo "⚠ ExternalSecret 'test-eso' not found"
    fi
    
    # Delete Secret
    if kubectl get secret test-eso -n default &>/dev/null; then
      echo "Deleting Secret 'test-eso'..."
      kubectl delete secret test-eso -n default
      if [ $? -eq 0 ]; then
        echo "✓ Secret deleted"
      else
        echo "✗ Failed to delete Secret"
      fi
    else
      echo "⚠ Secret 'test-eso' not found"
    fi
    
    # Delete from Vault
    if vault kv get -mount viasat "${vault_path}" &>/dev/null; then
      echo "Deleting secret from Vault at: viasat/${vault_path}..."
      vault kv metadata delete -mount viasat "${vault_path}"
      if [ $? -eq 0 ]; then
        echo "✓ Vault secret deleted"
      else
        echo "✗ Failed to delete Vault secret"
      fi
    else
      echo "⚠ Vault secret not found at: viasat/${vault_path}"
    fi
    
    echo ""
    echo "✓ Cleanup complete!"
    return 0
  fi
  
  # Check if secret exists in Vault
  # Note: vault cluster requires -mount flag with "viasat" mount point
  local vault_path="${env_name}/services/test"
  echo "Checking if secret exists in Vault at: viasat/${vault_path}"
  
  if ! vault kv get -mount viasat "${vault_path}" &>/dev/null; then
    echo "⚠ Secret does not exist in Vault at path: viasat/${vault_path}"
    echo "Creating dummy test secret with username and password..."
    
    # Create the secret with dummy test values
    vault kv put -mount viasat "${vault_path}" username="test-user" password="test-password-12345"
    
    if [ $? -eq 0 ]; then
      echo "✓ Dummy secret created successfully in Vault"
    else
      echo "✗ Failed to create secret in Vault"
      return 1
    fi
  else
    echo "✓ Secret exists in Vault"
  fi
  
  # Check if ExternalSecret already exists
  if kubectl get externalsecret test-eso -n default &>/dev/null; then
    echo "⚠ ExternalSecret 'test-eso' already exists in namespace 'default'"
    
    # Check if the associated Secret exists
    if kubectl get secret test-eso -n default &>/dev/null; then
      echo "✓ Associated Secret 'test-eso' exists"
      
      # Validate the secret has the expected keys
      if kubectl get secret test-eso -n default -o jsonpath='{.data.password}' &>/dev/null; then
        echo "✓ Secret has 'password' field"
        local password_value=$(kubectl get secret test-eso -n default -o jsonpath='{.data.password}' | base64 -d)
        echo "  Password content: ${password_value}"
      else
        echo "✗ Secret is missing 'password' field"
      fi
      
      echo ""
      echo "SUCCESS: ExternalSecret and Secret are properly configured"
      echo "To remove, run:"
      echo "  kubectl delete externalsecret test-eso -n default"
      echo "  kubectl delete secret test-eso -n default"
      echo ""
      echo "To also delete the secret from Vault, run:"
      echo "  vault kv metadata delete -mount viasat ${env_name}/services/test"
      return 0
    else
      echo "✗ Associated Secret 'test-eso' does NOT exist"
      echo "The ExternalSecret exists but hasn't synced yet, or there's an issue"
      echo "Check the ExternalSecret status:"
      echo "  kubectl describe externalsecret test-eso -n default"
      return 1
    fi
  fi
  
  # Create the ExternalSecret
  echo "Creating ExternalSecret 'test-eso'..."
  
  cat <<EOF | kubectl apply -f -
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: test-eso
  namespace: default
  annotations:
    argocd.argoproj.io/sync-wave: "-1"
spec:
  refreshInterval: 1h0m0s
  secretStoreRef:
    kind: ClusterSecretStore
    name: vault-kube-auth
  data:
  - remoteRef:
      key: ${env_name}/services/test
      property: password
    secretKey: password
  - remoteRef:
      key: ${env_name}/services/test
      property: username
    secretKey: username
  target:
    creationPolicy: Orphan
    name: test-eso
    template:
      type: Opaque
      data:
        password: "{{ .password }} and {{ .username }}"
EOF
  
  if [ $? -eq 0 ]; then
    echo "✓ ExternalSecret created successfully"
    echo ""
    echo "Waiting for Secret to be created..."
    sleep 3
    
    # Check if the Secret was created
    if kubectl get secret test-eso -n default &>/dev/null; then
      echo "✓ Secret 'test-eso' has been created"
      echo ""
      echo "To view the secret:"
      echo "  kubectl get secret test-eso -n default -o yaml"
      echo ""
      echo "To decode the password:"
      echo "  kubectl get secret test-eso -n default -o jsonpath='{.data.password}' | base64 -d"
      local password_value=$(kubectl get secret test-eso -n default -o jsonpath='{.data.password}' | base64 -d)
      echo "  Password content: ${password_value}"
      echo ""
      echo "To clean up completely, run:"
      echo "  kubectl delete externalsecret test-eso -n default"
      echo "  kubectl delete secret test-eso -n default"
      echo "  vault kv metadata delete -mount viasat ${env_name}/services/test"
    else
      echo "⚠ Secret not yet created. Check ExternalSecret status:"
      echo "  kubectl describe externalsecret test-eso -n default"
    fi
  else
    echo "✗ Failed to create ExternalSecret"
    return 1
  fi
}

# Continuously ping URL and collect statistics
# Monitors HTTP endpoint availability and response times
# Press Ctrl+C to stop and view detailed statistics
#
# Usage: ping-url <url> [timeout_seconds]
#
# Examples:
#   ping-url https://api.github.com/status
#   ping-url https://apt.git.viasat.com/status
#   ping-url https://checkip.amazonaws.com
#   ping-url https://api.example.com/health 10
#
# Statistics shown on exit:
#   - Total/successful/failed requests
#   - Packet loss percentage
#   - Response times: min, avg, max, P75, P95, P99
ping-url() {
  local PINGURL="$1"
  local TIMEOUT="${2:-5}"
  
  if [ -z "$PINGURL" ]; then
    echo "❌ Error: No URL provided"
    echo ""
    echo "Usage: ping-url <url> [timeout_seconds]"
    echo ""
    echo "Examples:"
    echo "  ping-url https://api.github.com/status"
    echo "  ping-url https://apt.git.viasat.com/status"
    echo "  ping-url https://checkip.amazonaws.com"
    echo "  ping-url https://api.example.com/health 10"
    return 1
  fi
  
  echo "🌐 Pinging: $PINGURL"
  echo "⏱️  Timeout: ${TIMEOUT}s"
  echo "Press Ctrl+C to stop and see statistics"
  echo ""
  
  # Arrays to store metrics
  local response_times=()
  local status_codes=()
  local total_requests=0
  local failed_requests=0
  local success_requests=0
  
  # Trap Ctrl+C to show statistics before exit
  trap 'show_stats' INT
  
  show_stats() {
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "📊 Statistics"
    echo "═══════════════════════════════════════════════════════════"
    echo "Total requests:    $total_requests"
    echo "Successful (200):  $success_requests"
    echo "Failed:            $failed_requests"
    
    if [ $total_requests -gt 0 ]; then
      local loss_percent=$(awk "BEGIN {printf \"%.2f\", ($failed_requests / $total_requests) * 100}")
      echo "Loss:              ${loss_percent}%"
    fi
    
    if [ ${#response_times[@]} -gt 0 ]; then
      echo ""
      echo "Response Times (ms):"
      
      # Sort response times
      local sorted_times=($(printf '%s\n' "${response_times[@]}" | sort -n))
      
      # Calculate min, max, avg
      local min=${sorted_times[1]}
      local max=${sorted_times[-1]}
      local sum=0
      for time in "${response_times[@]}"; do
        sum=$((sum + time))
      done
      local avg=$((sum / ${#response_times[@]}))
      
      # Calculate percentiles
      local count=${#sorted_times[@]}
      local p75_idx=$(( (count * 75) / 100 ))
      local p95_idx=$(( (count * 95) / 100 ))
      local p99_idx=$(( (count * 99) / 100 ))
      
      # Ensure indices are at least 1
      [ $p75_idx -lt 1 ] && p75_idx=1
      [ $p95_idx -lt 1 ] && p95_idx=1
      [ $p99_idx -lt 1 ] && p99_idx=1
      
      local p75=${sorted_times[$p75_idx]}
      local p95=${sorted_times[$p95_idx]}
      local p99=${sorted_times[$p99_idx]}
      
      echo "  Min:     ${min}ms"
      echo "  Avg:     ${avg}ms"
      echo "  Max:     ${max}ms"
      echo "  P75:     ${p75}ms"
      echo "  P95:     ${p95}ms"
      echo "  P99:     ${p99}ms"
    fi
    
    echo "═══════════════════════════════════════════════════════════"
    
    # Reset trap and kill the loop
    trap - INT
    kill -INT $$
  }
  
  # Main loop
  while true; do
    ((total_requests++))
    
    # Measure response time and status code
    local start_time=$(python3 -c 'import time; print(int(time.time() * 1000))')
    local http_status=$(curl --max-time ${TIMEOUT} -s -o /dev/null -w "%{http_code}" "${PINGURL}" 2>/dev/null)
    local end_time=$(python3 -c 'import time; print(int(time.time() * 1000))')
    local response_time=$((end_time - start_time))
    
    status_codes+=("$http_status")
    
    if [ "$http_status" = "200" ]; then
      ((success_requests++))
      response_times+=("$response_time")
      echo "✓ [$(date '+%H:%M:%S')] ${response_time}ms - HTTP 200"
    else
      ((failed_requests++))
      if [ "$http_status" = "000" ]; then
        echo "✗ [$(date '+%H:%M:%S')] TIMEOUT (>${TIMEOUT}s)"
      else
        echo "✗ [$(date '+%H:%M:%S')] ${response_time}ms - HTTP ${http_status}"
      fi
    fi
    
    sleep 1
  done
}

eks-list-update-kubeconfigs() {
  local kubeconfig_dir="$HOME/.kube/aws-configs"
  
  # Create directory if it doesn't exist
  mkdir -p "$kubeconfig_dir"
  
  # Array to collect all kubeconfig paths from ALL existing files
  local kubeconfig_files=()
  
  # First, collect all existing kubeconfig files in the directory
  # Use nullglob to avoid glob expansion errors when directory is empty
  if [ -d "$kubeconfig_dir" ] && [ -n "$(ls -A "$kubeconfig_dir" 2>/dev/null)" ]; then
    for existing_config in "$kubeconfig_dir"/*; do
      if [ -f "$existing_config" ]; then
        kubeconfig_files+=("$existing_config")
      fi
    done
  fi
  
  echo "Found ${#kubeconfig_files[@]} existing kubeconfig(s) in $kubeconfig_dir"
  echo ""
  
  # Get account alias for current profile
  local ACCOUNT_ALIAS=$(aws iam list-account-aliases | jq -r '.AccountAliases[0]')
  
  if [ -z "$ACCOUNT_ALIAS" ] || [ "$ACCOUNT_ALIAS" = "null" ]; then
    echo "❌ Could not retrieve AWS account alias for current profile"
    
    # If we have existing configs, still set KUBECONFIG
    if [ ${#kubeconfig_files[@]} -gt 0 ]; then
      echo "⚠️  Using existing kubeconfig files only"
      # Jump to the export section
    else
      return 1
    fi
  else
    echo "Current Account: $ACCOUNT_ALIAS"
    echo "Updating clusters for this account..."
    echo ""
    
    # Track new configs added for current account
    local new_configs_count=0
  
  for aws_region in us-east-1 us-west-2 eu-west-1 ap-southeast-1; do
    echo "Processing region: $aws_region"
    
    local LIST_CLUSTERS=$(aws eks list-clusters --region ${aws_region} --output json 2>/dev/null)
    local aws_result=$?
    
    if [ $aws_result -ne 0 ]; then
      echo "  ⚠️  Failed to list clusters in $aws_region"
      continue
    fi
    
    # Parse clusters into array without subshell
    local clusters=()
    while IFS= read -r cluster_name; do
      if [ -n "$cluster_name" ]; then
        clusters+=("$cluster_name")
      fi
    done < <(echo ${LIST_CLUSTERS} | jq -r '.clusters[]')
    
    if [ ${#clusters[@]} -eq 0 ]; then
      echo "  No clusters found"
      continue
    fi
    
    for cluster_name in "${clusters[@]}"; do
      local config_name="${ACCOUNT_ALIAS}_${cluster_name}"
      local config_path="${kubeconfig_dir}/${config_name}"
      
      echo "  - Updating kubeconfig for: $cluster_name"
      
      # Update kubeconfig to specific file
      if aws eks update-kubeconfig \
        --name ${cluster_name} \
        --region ${aws_region} \
        --alias "${config_name}" \
        --kubeconfig "${config_path}" >/dev/null 2>&1; then
        echo "    ✓ Saved to: ${config_path}"
        
        # Add to array if not already there
        local already_exists=0
        for existing in "${kubeconfig_files[@]}"; do
          if [ "$existing" = "$config_path" ]; then
            already_exists=1
            break
          fi
        done
        
        if [ $already_exists -eq 0 ]; then
          kubeconfig_files+=("${config_path}")
          ((new_configs_count++))
        fi
        
        echo "    DEBUG: Array now has ${#kubeconfig_files[@]} items"
      else
        echo "    ✗ Failed to update kubeconfig"
      fi
    done
    echo ""
  done
  
  fi
  
  # Set KUBECONFIG environment variable with all configs
  if [ ${#kubeconfig_files[@]} -gt 0 ]; then
    # Join array elements with : separator using printf
    local kubeconfig_value=$(printf "%s:" "${kubeconfig_files[@]}")
    # Remove trailing colon
    kubeconfig_value="${kubeconfig_value%:}"
    
    unset KUBECONFIG
    export KUBECONFIG="$kubeconfig_value"
    
    echo "════════════════════════════════════════════════════════════"
    if [ -n "$ACCOUNT_ALIAS" ]; then
      echo "✅ Updated ${new_configs_count} cluster(s) for account: $ACCOUNT_ALIAS"
    fi
    echo "✅ KUBECONFIG set with ${#kubeconfig_files[@]} total file(s)"
    echo ""
    echo "All kubeconfig files:"
    for config in "${kubeconfig_files[@]}"; do
      echo "  - $(basename $config)"
    done
    echo ""
    echo "Available contexts:"
    kubectl config get-contexts --output=name | sort
  else
    echo "❌ No kubeconfig files found"
    return 1
  fi
}
