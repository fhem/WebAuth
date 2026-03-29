#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_REPO_ROOT="${MODULE_REPO_ROOT:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
FHEM_TOOLKIT_ROOT="${FHEM_TOOLKIT_ROOT:-$(cd "${MODULE_REPO_ROOT}/.." && pwd)/fhem-devcontainer-toolkit}"

if [[ -d "${MODULE_REPO_ROOT}/t" ]]; then
  : "${FHEM_TEST_ROOT:=${MODULE_REPO_ROOT}/t}"
else
  : "${FHEM_TEST_ROOT:=${MODULE_REPO_ROOT}/fhem/t}"
fi
export FHEM_TEST_ROOT

if [[ -f "${FHEM_RUNTIME_ROOT:-/opt/fhem}/fhem.pl" ]]; then
  RUN_ROOT="${FHEM_RUNTIME_ROOT:-/opt/fhem}"
elif [[ -f "${MODULE_REPO_ROOT}/fhem/fhem.pl" ]]; then
  RUN_ROOT="${FHEM_SOURCE_ROOT:-${MODULE_REPO_ROOT}/fhem}"
else
  RUN_ROOT="${FHEM_SOURCE_ROOT:?FHEM_SOURCE_ROOT must point to a full FHEM source tree or a bootstrapped runtime}"
fi

export FHEM_RUN_ROOT="${RUN_ROOT}"

exec "${FHEM_TOOLKIT_ROOT}/base/scripts/pick-fhem-test.sh"
