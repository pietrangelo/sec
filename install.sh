#!/usr/bin/env bash
#
# A script to install the latest release of sec from Forgejo.
#
# Usage:
#   curl -skSL https://git.pietrangelo.org/pj/sec/raw/branch/main/install.sh | bash
#
# This script will:
# 1. Detect the user's OS and architecture.
# 2. Fetch the latest release from GitHub.
# 3. Download the correct release asset.
# 4. Unpack the binary and move it to /usr/local/bin.
# 5. Make the binary executable.

set -xeo pipefail

# --- Configuration ---
FORGEJO_REPO="pj/sec"
BINARY_NAME="sec"
INSTALL_DIR="/usr/local/bin"

# --- Helper Functions ---

# Function to print informational messages.
msg() {
  echo -e "\033[32mINFO:\033[0m $1"
}

# Function to print error messages and exit.
err() {
  echo -e "\033[31mERROR:\033[0m $1" >&2
  exit 1
}

# Check for required tools before starting.
check_dependencies() {
  for cmd in curl tar gzip; do
    if ! command -v "$cmd" &>/dev/null; then
      err "'$cmd' is not installed, but is required. Please install it and try again."
    fi
  done
}

# Detect the operating system and architecture.
detect_os_and_arch() {
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  ARCH="$(uname -m)"

  case "$OS" in
  linux) OS="linux" ;;
  darwin) OS="mac" ;;
  *) err "Unsupported operating system: $OS" ;;
  esac

  case "$ARCH" in
  x86_64 | amd64) ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *) err "Unsupported architecture: $ARCH" ;;
  esac
}

# Fetch the latest release version from the GitHub API.
get_latest_release_version() {
  msg "Fetching the latest release version..."
  local api_url="https://git.pietrangelo.org/api/v1/repos/${FORGEJO_REPO}/releases/latest"

  # Use curl with grep and sed to extract the tag name, avoiding a dependency on jq.
  VERSION=$(curl -sk "$api_url" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

  if [ -z "$VERSION" ]; then
    err "Could not fetch the latest release version. Please check that the FORGEJO_REPO variable is set correctly."
  fi
  msg "The latest version is $VERSION"
}

# Download and install the binary.
download_and_install() {
  local asset_filename="${BINARY_NAME}-${OS}-${ARCH}"
  local download_url="https://git.pietrangelo.org/${FORGEJO_REPO}/releases/download/${VERSION}/${asset_filename}"
  local tmp_dir=$(mktemp -d)

  # Ensure the temporary directory is cleaned up on exit.
  trap 'rm -rf "$tmp_dir"' EXIT

  msg "Downloading from $download_url"
  if ! curl -kL "$download_url" -o "${tmp_dir}/${asset_filename}"; then
    err "Failed to download the release asset. Please check the URL and your network connection."
  fi

  # msg "Extracting the binary..."
  # tar -xzf "${tmp_dir}/${asset_filename}" -C "$tmp_dir"

  msg "Installing '${BINARY_NAME}' to '${INSTALL_DIR}'..."
  if [ -w "$INSTALL_DIR" ]; then
    mv "${tmp_dir}/${asset_filename}" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
  else
    msg "Write permissions are required for ${INSTALL_DIR}. Using sudo..."
    sudo mv "${tmp_dir}/${asset_filename}" "${INSTALL_DIR}/${BINARY_NAME}"
    sudo chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
  fi

  msg "'${BINARY_NAME}' has been installed successfully!"
  msg "You can now run '${BINARY_NAME}' from your terminal."
}

# --- Main Logic ---

main() {
  if [ "$FORGEJO_REPO" == "YOUR_USER/YOUR_REPO" ]; then
    err "Please edit the script and set the FORGEJO_REPO variable to your repository."
  fi

  check_dependencies
  detect_os_and_arch
  get_latest_release_version
  download_and_install
}

# --- Run the Script ---
main
