#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_REPO_ROOT="${MODULE_REPO_ROOT:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
FHEM_TOOLKIT_ROOT="${FHEM_TOOLKIT_ROOT:-$(cd "${MODULE_REPO_ROOT}/.." && pwd)/fhem-devcontainer-toolkit}"
export MODULE_REPO_ROOT

exec "${FHEM_TOOLKIT_ROOT}/addons/svn/scripts/sync-module-to-svn.sh"
