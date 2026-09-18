#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2020-2021 CERN.
# SPDX-FileCopyrightText: 2020 Northwestern University.
# SPDX-FileCopyrightText: 2021 TU Wien.
# SPDX-FileCopyrightText: 2022 Graz University of Technology.
# SPDX-License-Identifier: MIT

# Usage:
#   ./run-tests.sh [pytest options and args...]
#
# Note: the DB and CACHE services to use are determined by corresponding environment
#       variables if they are set -- otherwise, the following defaults are used:
#       DB=postgresql and CACHE=redis
#
# Example for using mysql instead of postgresql:
#    DB=mysql ./run-tests.sh

set -o errexit
set -o nounset

function cleanup {
  eval "$(docker-services-cli down --env)"
}

keep_services=0
pytest_args=()
for arg in "$@"; do
    case ${arg} in
        -K|--keep-services)
            keep_services=1
            ;;
        *)
            pytest_args+=( "${arg}" )
            ;;
    esac
done

if [[ ${keep_services} -eq 0 ]]; then
    trap cleanup EXIT
fi

eval "$(docker-services-cli up --db ${DB:-postgresql} --cache ${CACHE:-redis} --env)"
python -m pytest ${pytest_args[@]+"${pytest_args[@]}"}
tests_exit_code=$?
exit "$tests_exit_code"
