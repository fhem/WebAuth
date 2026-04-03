#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <test-file>" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_REPO_ROOT="${MODULE_REPO_ROOT:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
TEST_ARG="$1"

if [[ -d "${MODULE_REPO_ROOT}/t" ]]; then
  TEST_ROOT="${FHEM_TEST_ROOT:-${MODULE_REPO_ROOT}/t}"
else
  TEST_ROOT="${FHEM_TEST_ROOT:-${MODULE_REPO_ROOT}/fhem/t}"
fi

if [[ "${TEST_ARG}" = /* ]]; then
  TEST_FILE="${TEST_ARG}"
else
  TEST_FILE="${TEST_ROOT}/${TEST_ARG}"
fi

if [[ ! -f "${TEST_FILE}" ]]; then
  echo "Missing test file: ${TEST_FILE}" >&2
  exit 1
fi

if [[ -f "${FHEM_RUNTIME_ROOT:-/opt/fhem}/fhem.pl" ]]; then
  RUN_ROOT="${FHEM_RUNTIME_ROOT:-/opt/fhem}"
elif [[ -f "${MODULE_REPO_ROOT}/fhem/fhem.pl" ]]; then
  RUN_ROOT="${FHEM_SOURCE_ROOT:-${MODULE_REPO_ROOT}/fhem}"
else
  RUN_ROOT="${FHEM_SOURCE_ROOT:?FHEM_SOURCE_ROOT must point to a full FHEM source tree or a bootstrapped runtime}"
fi


cd "${RUN_ROOT}"
PERL5LIB="${RUN_ROOT}/lib:${FHEM_PERL5LIB:-/usr/src/app/core/lib/perl5}${PERL5LIB:+:$PERL5LIB}"
export PERL5LIB

prove_cmd=(prove)

if [[ -n "${FHEM_PROVE_ARGS:-}" ]]; then
  read -r -a prove_args <<<"${FHEM_PROVE_ARGS}"
  prove_cmd+=("${prove_args[@]}")
fi

if [[ -n "${FHEM_PROVE_EXEC:-}" ]]; then
  prove_cmd+=(--exec "${FHEM_PROVE_EXEC}")
fi

"${prove_cmd[@]}" "${TEST_FILE}"
