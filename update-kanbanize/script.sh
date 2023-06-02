#!/bin/bash
set -ueo pipefail

echo "Original PR Title: ${PR_TITLE}"
echo "Original Ref Name: ${BRANCH_REF}"
echo "API_KEY: ${KANBANIZE_API_KEY}"

REGEX='[0-9]{3,}'

TEST_STRING="${BRANCH_REF}${PR_TITLE}"

# Create a Regular Expression Match on a set of 3 or more numbers
# only the first match is used.
if [[ "${TEST_STRING}" =~ $REGEX ]]; then
  KANBANIZE_CARD_ID="${BASH_REMATCH[0]}"

  echo "Detected Kanbanize Card ID: ${KANBANIZE_CARD_ID}"
  
  # This sets the github actions output
  echo "kanbanize-card-id=${KANBANIZE_CARD_ID}" >> "$GITHUB_OUTPUT"

  case "${EVENT_NAME}" in
    pull_request)
      PR_URL="https://github.com/${REPOSITORY}/pull/${PR_ID}"

      curl -v -XPATCH \
        -H "apikey: ${KANBANIZE_API_KEY}" \
        -H "Content-Type: application/json" \
        "${KANBANIZE_BASE_URI}/cards/212" \
        --data '{"custom_fields_to_add_or_update":[{"field_id": '"${KANBANIZE_PR_ID}"', "value": "'"${PR_URL}"'"}]}' |\
        jq -r .
      ;;
    create)
      SHORT_BRANCH_REF="${BRANCH_REF/refs\/heads\//}"
      BRANCH_URL="https://github.com/${REPOSITORY}/tree/${SHORT_BRANCH_REF}"
      echo "Branch URL: ${BRANCH_URL}" 1>&2
      ;;
    *)
      echo "I have no idea what this is"
      exit 2
      ;;
  esac

else

  echo "No Kanbanize Card ID Detected in '${PR_TITLE}'"

  # This will cause the action step to fail
  exit 2
fi
