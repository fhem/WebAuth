#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_REPO_ROOT="${MODULE_REPO_ROOT:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"

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

cd "${FHEM_TEST_ROOT}"
PERL5LIB="${FHEM_RUN_ROOT}/lib:${FHEM_PERL5LIB:-/usr/src/app/core/lib/perl5}${PERL5LIB:+:$PERL5LIB}"
export PERL5LIB

mapfile -t tests < <(find . -name '*.t' | sort)
if [[ ${#tests[@]} -eq 0 ]]; then
  echo "No .t tests found under $(pwd)" >&2
  exit 1
fi

PS3="Select a test to run: "
select test in "${tests[@]}"; do
  if [[ -z "${test:-}" ]]; then
    echo "Invalid selection" >&2
    continue
  fi

  test_path="${FHEM_TEST_ROOT}/${test#./}"
  prove_cmd=(prove)

  case "${test}" in
    ./FHEM/Core/Authentication/*)
      prove_cmd+=(-I lib -r -vv)
      ;;
    *)
      prove_cmd+=(-I FHEM -r -vv --exec "perl fhem.pl -t")
      ;;
  esac

  cd "${FHEM_RUN_ROOT}"
  exec "${prove_cmd[@]}" "${test_path}"
done
