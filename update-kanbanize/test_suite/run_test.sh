#!/bin/bash
set -ueo pipefail

DEBUG=$1

while IFS=$'\t' read -ra line; do 
  STATE_TEST="${line[0]}"
  TEST_TYPE="${line[1]}"
  TEST_DTA="${line[2]}"

  echo "Testing ${TEST_TYPE}... ${TEST_DTA} which should ${STATE_TEST}"
  pushd .. >/dev/null 2>&1

  case "${TEST_TYPE}" in
    pull_request)
      sed -e "s|PR_TITLE|${TEST_DTA}|g" test_suite/pull_request_template.json > test_suite/event.json
      ;;
    create)
      sed -e "s|BRANCH_NAME|${TEST_DTA}|g" test_suite/create_branch_template.json > test_suite/event.json
      ;;
    *)
      echo "Malformed test data"
      exit 2
  esac

  set +e
  if $DEBUG; then
    act "${TEST_TYPE}" --secret-file "${HOME}/.secrets" -W test_suite -e test_suite/event.json 
  else
    act "${TEST_TYPE}" --secret-file "${HOME}/.secrets" -W test_suite -e test_suite/event.json --quiet > /dev/null 2>&1
  fi
  ACT_RUN_EXIT_CODE=$?
  set -e
  case "${STATE_TEST}" in
    SUCCEED)
      if [[ $ACT_RUN_EXIT_CODE -eq 0 ]]; then
        echo "SUCCESS: ${TEST_TYPE} Test '${TEST_DTA}' expected 0, got ${ACT_RUN_EXIT_CODE}"
      else
        echo "FAIL: ${TEST_TYPE} Test '${TEST_DTA}' expected 0, got ${ACT_RUN_EXIT_CODE}"
      fi
      ;;
    FAIL)
      if [[ $ACT_RUN_EXIT_CODE -gt 0 ]]; then
        echo "SUCCESS: ${TEST_TYPE} Test '${TEST_DTA}' expected non-zero, got ${ACT_RUN_EXIT_CODE}"
      else
        echo "FAIL: ${TEST_TYPE} Test '${TEST_DTA}' expected non-zero, got ${ACT_RUN_EXIT_CODE}"
      fi
      ;;
    *)
      echo "Received malformed test data, bailing"
      exit 2
      ;;
  esac
  popd >/dev/null 2>&1
  echo
  break
done < test_data.tsv

rm event.json
