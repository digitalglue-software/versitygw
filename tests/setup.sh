#!/usr/bin/env bats

# Copyright 2024 Versity Software
# This file is licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

source ./tests/env.sh
source ./tests/report.sh
source ./tests/setup_mc.sh
source ./tests/versity.sh

# bats setup function
setup() {
  check_env_vars
  if [ "$RUN_VERSITYGW" == "true" ]; then
    if ! run_versity_app; then
      log 2 "error starting versity apps"
      return 1
    fi
  fi

  log 4 "Running test $BATS_TEST_NAME"
  if [[ $LOG_LEVEL -ge 5 ]]; then
    start_time=$(date +%s)
    export start_time
  fi

  if [[ $RUN_S3CMD == true ]]; then
    S3CMD_OPTS=()
    S3CMD_OPTS+=(-c "$S3CMD_CONFIG")
    S3CMD_OPTS+=(--access_key="$AWS_ACCESS_KEY_ID")
    S3CMD_OPTS+=(--secret_key="$AWS_SECRET_ACCESS_KEY")
    export S3CMD_CONFIG S3CMD_OPTS
  fi

  if [[ $RUN_MC == true ]]; then
    if ! check_add_mc_alias; then
      log 2 "mc alias check/add failed"
      return 1
    fi
  fi

  export AWS_PROFILE
}

# fail a test
# param:  error message
#fail() {
#  log 1 "$1"
#  exit 1
#}

# bats teardown function
teardown() {
  # shellcheck disable=SC2154
  if [ "$REMOVE_TEST_FILE_FOLDER" == "true" ]; then
    log 6 "removing test file folder"
    if ! error=$(rm -rf "${TEST_FILE_FOLDER:?}" 2>&1); then
      log 3 "unable to remove test file folder: $error"
    fi
  fi
  stop_versity
  if [[ $LOG_LEVEL -ge 5 ]]; then
    end_time=$(date +%s)
    log 4 "Total test time: $((end_time - start_time))"
  fi
  if [[ -n "$COVERAGE_DB" ]]; then
    record_result
  fi
}
