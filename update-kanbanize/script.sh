#!/bin/bash
set -ueo pipefail

REGEX='[0-9]{3,}'
TEST_STRING="${BRANCH_REF}${PR_TITLE}"

echo "### Update Kanbanize Summary" >> "${GITHUB_STEP_SUMMARY}"

echo "Attempted to extract the *first matched* Kanbanize Card ID from '${TEST_STRING}' with the Regular Expression '${REGEX}'" >> "${GITHUB_STEP_SUMMARY}"

update_custom_field() {
  local _CARD_ID="${1}"
  local _FIELD_ID="${2}"
  local _VALUE="${3}"
  RESPONSE=$(curl --silent -XPATCH \
    --write-out "%{json}" \
    -H "apikey: ${KANBANIZE_API_KEY}" \
    -H "Content-Type: application/json" \
    "${KANBANIZE_BASE_URI}/cards/${_CARD_ID}" \
    --data '{"custom_fields_to_add_or_update":[{"field_id": '"${_FIELD_ID}"', "value": "'"${_VALUE}"'"}]}') 
  case $(jq -sr .[1].http_code <<< "${RESPONSE}") in
    20*)
      echo "Updated Custom Field #${_FIELD_ID} on Card ${_CARD_ID} with ${_VALUE}" >> "${GITHUB_STEP_SUMMARY}"
      ;;
    404)
      echo "ERROR: Failed to update Custom Field #${_FIELD_ID} on Card ${_CARD_ID} with '${_VALUE}', due to '$(jq -sr '.[0].error.message' <<<"${RESPONSE}")'" >> "${GITHUB_STEP_SUMMARY}"
      exit 2
      ;;
    401)
      echo "ERROR: Failed to update Custom Field #${_FIELD_ID} on Card ${_CARD_ID} with '${_VALUE}', due to a missing or expired API KEY" >> "${GITHUB_STEP_SUMMARY}"
      exit 2
      ;;
     *)
      echo "ERROR: Failed to update Custom Field #${_FIELD_ID} on Card ${_CARD_ID} with '${_VALUE}', due to an unknown error:" >> "${GITHUB_STEP_SUMMARY}"
      echo '```json' >> "${GITHUB_STEP_SUMMARY}"
      jq -sr . <<< "${RESPONSE}" >> "${GITHUB_STEP_SUMMARY}"
      echo '```' >> "${GITHUB_STEP_SUMMARY}"
      exit 2
      ;;
  esac
  cat "${GITHUB_STEP_SUMMARY}"
}

if [[ "${TEST_STRING}" =~ $REGEX ]]; then
  KANBANIZE_CARD_ID="${BASH_REMATCH[0]}"

  echo "Detected Kanbanize Card ID: ${KANBANIZE_CARD_ID}" >> "${GITHUB_STEP_SUMMARY}"
  
  # This sets the github actions output
  echo "kanbanize-card-id=${KANBANIZE_CARD_ID}" >> "${GITHUB_OUTPUT}"

  case "${EVENT_NAME}" in
    pull_request)
      PR_URL="https://github.com/${REPOSITORY}/pull/${PR_ID}"
      update_custom_field "${KANBANIZE_CARD_ID}" "${KANBANIZE_PR_ID}" "${PR_URL}"
      ;;
    create)
      SHORT_BRANCH_REF="${TEST_STRING/refs\/heads\//}"
      BRANCH_URL="https://github.com/${REPOSITORY}/tree/${SHORT_BRANCH_REF}"
      update_custom_field "${KANBANIZE_CARD_ID}" "${KANBANIZE_BRANCH_ID}" "${BRANCH_URL}"
      ;;
    *)
      echo "ERROR: Event Type ${EVENT_NAME} is not supported by this Action!" >> "${GITHUB_STEP_SUMMARY}"
      exit 2
      ;;
  esac

else
  echo "ERROR: No Kanbanize Card ID Detected in '${TEST_STRING}'" >> "${GITHUB_STEP_SUMMARY}"
  exit 2
fi
