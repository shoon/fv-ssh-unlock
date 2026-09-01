#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd -- "${script_dir}/.." && pwd)"
main_floor="${MAIN_COVERAGE_FLOOR:-70}"
mock_floor="${MOCK_COVERAGE_FLOOR:-70}"

temporary_root="${RUNNER_TEMP:-}"
remove_temporary_root=0
if [[ -z "${temporary_root}" ]]; then
  temporary_root="$(mktemp -d)"
  remove_temporary_root=1
fi
if [[ "${remove_temporary_root}" -eq 1 ]]; then
  trap 'rm -rf -- "${temporary_root}"' EXIT
fi

main_profile="${temporary_root}/fv-ssh-unlock-main.cover"
mock_profile="${temporary_root}/fv-ssh-unlock-mock.cover"

cd -- "${repository_root}"
go test -count=1 -covermode=atomic -coverprofile="${main_profile}" ./...
(
  cd tools/mock-fv-ssh-server
  go test -count=1 -covermode=atomic -coverprofile="${mock_profile}" ./...
)

main_report="$(go tool cover -func="${main_profile}")"
mock_report="$(cd tools/mock-fv-ssh-server && go tool cover -func="${mock_profile}")"
printf '%s\n' "${main_report}"
printf '%s\n' "${mock_report}"

main_total="$(printf '%s\n' "${main_report}" | awk '$1 == "total:" { value=$3; sub(/%$/, "", value); print value }')"
mock_total="$(printf '%s\n' "${mock_report}" | awk '$1 == "total:" { value=$3; sub(/%$/, "", value); print value }')"
if [[ ! "${main_total}" =~ ^[0-9]+([.][0-9]+)?$ || ! "${mock_total}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "could not parse aggregate coverage totals" >&2
  exit 1
fi

summary="$(printf '### Go statement coverage\n\n| Module | Actual | Required |\n| --- | ---: | ---: |\n| Main | %s%% | %s%% |\n| Mock SSH server | %s%% | %s%% |\n' \
  "${main_total}" "${main_floor}" "${mock_total}" "${mock_floor}")"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  printf '%s\n' "${summary}" >> "${GITHUB_STEP_SUMMARY}"
else
  printf '%s\n' "${summary}"
fi

failed=0
if ! awk -v actual="${main_total}" -v floor="${main_floor}" \
  'BEGIN { exit !(actual + 0 >= floor + 0) }'; then
  echo "main module coverage ${main_total}% is below ${main_floor}%" >&2
  failed=1
fi
if ! awk -v actual="${mock_total}" -v floor="${mock_floor}" \
  'BEGIN { exit !(actual + 0 >= floor + 0) }'; then
  echo "mock module coverage ${mock_total}% is below ${mock_floor}%" >&2
  failed=1
fi
exit "${failed}"
