#!/bin/bash

#set -euxo pipefail
set -eo pipefail

check_endpoint_exists_and_disabled () {
  local endpoint_to_enable=$1
  shift
  local endpoints=("$@")
  local endpoint_passed=false
  local endpoint_disabled=false

  for endpoint in "${endpoints[@]}"
  do
    endpoint_name="$(jq -r '.name' <<<"$endpoint")"
    endpoint_status="$(jq -r '.status' <<<"$endpoint")"
    if [ "${endpoint_name}" == "${endpoint_to_enable}" ]
    then
      endpoint_passed=true
      if [ "${endpoint_status}" == "Disabled" ]
      then
        endpoint_disabled=true
      fi
    fi
  done

  if $endpoint_passed
  then
    if $endpoint_disabled
    then
      echo "endpoint exists and is disabled"
      return 0
    else
      echo "endpoint exists but is enabled"
      return 1
    fi
  else
    echo "endpoint not in profile"
    return 1
  fi
}

set_enabled_endpoints () {
  local endpoints=("$@")

  for endpoint in "${endpoints[@]}"
  do
    endpoint_status="$(jq -r '.status' <<<"$endpoint")"
    if [ "${endpoint_status}" == "Enabled" ]
    then
      endpoint_id="$(jq -r '.id' <<<"$endpoint")"
      ENABLED_ENDPOINTS+=("$endpoint")
    fi
  done
}
  
set_endpoint_to_enable () {
  local endpoint_to_enable_name="$1"
  shift
  local endpoints=("$@")

  for endpoint in "${endpoints[@]}"
  do
    endpoint_name="$(jq -r '.name' <<<"$endpoint")"
    if [ "${endpoint_name}" == "${endpoint_to_enable_name}" ]
    then
      ENABLE_ENDPOINT=${endpoint}
    fi
  done
}
 
enable_endpoint () {
  local endpoint=$1
  local endpoint_id="$(jq -r '.id' <<<"$endpoint")"
  local endpoint_name="$(jq -r '.name' <<<"$endpoint")"
  local request_url="https://management.azure.com$endpoint_id?api-version=2018-04-01"
  local request_body="{\"id\": \"${endpoint_id}\", \"name\": \"${endpoint_name}\", \"type\": \"Microsoft.Network/trafficManagerProfiles/azureEndpoints\", \"properties\": { \"endpointStatus\": \"Enabled\"}}"

  local request_response=$(curl -X PATCH "${request_url}" -H "Authorization: Bearer ${ACCESS_TOKEN}" -H "Content-Type: application/json" --data "${request_body}")
  echo "${request_response}"

}

disable_endpoint () {
  local endpoint=$1
  local endpoint_id="$(jq -r '.id' <<<"$endpoint")"
  local endpoint_name="$(jq -r '.name' <<<"$endpoint")"
  local request_url="https://management.azure.com$endpoint_id?api-version=2018-04-01"
  local request_body="{\"id\": \"${endpoint_id}\", \"name\": \"${endpoint_name}\", \"type\": \"Microsoft.Network/trafficManagerProfiles/azureEndpoints\", \"properties\": { \"endpointStatus\": \"Disabled\"}}"

  local request_response=$(curl -X PATCH "${request_url}" -H "Authorization: Bearer ${ACCESS_TOKEN}" -H "Content-Type: application/json" --data "${request_body}")
  echo "${request_response}"

}

disable_endpoints () {
  local endpoints=("$@")

  for endpoint in "${endpoints[@]}"
  do
    disable_endpoint "${endpoint}"
  done
}

PROFILE_ID=$1
ENDPOINT_NAME=$2

if [ -z "$3" ]
then
  echo "Generating token for GitHub Runner"
  ACCESS_TOKEN=$(curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com' -H Metadata:true -s | jq -r .access_token)
else
  echo "Generating token for Local Machine"
  ACCESS_TOKEN=$(az account get-access-token --resource "https://management.azure.com" | jq -r '.accessToken')
fi

PROFILE_ATTRIBUTES=$(curl -X GET "https://management.azure.com$PROFILE_ID?api-version=2018-04-01" -H "Authorization: Bearer ${ACCESS_TOKEN}" -H "Content-Type: application/json")

declare -a ARRAY
declare -a ENABLED_ENDPOINTS
ENABLE_ENDPOINT=""

for endpoint in $(jq -c -r '.properties.endpoints[] | {name: .name, id: .id, status: .properties.endpointStatus}' <<<"$PROFILE_ATTRIBUTES")
do 
  ARRAY+=($endpoint)
done

check_endpoint_exists_and_disabled "$ENDPOINT_NAME" "${ARRAY[@]}"
set_enabled_endpoints "${ARRAY[@]}"
set_endpoint_to_enable "$ENDPOINT_NAME" "${ARRAY[@]}"
enable_endpoint "$ENABLE_ENDPOINT"
disable_endpoints "${ENABLED_ENDPOINTS[@]}"

