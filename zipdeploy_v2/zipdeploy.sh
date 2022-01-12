#!/bin/bash
if [[ -z $1 ]] || [[ -z $2 ]]; then echo "error: target Traffic Manager Profile OR package path/name not set"; exit 1; fi
TM_ID=$1
PACKAGE_LOCATION=$2
echo "Pulling token"
if [ -z "$3" ]
then
  echo "Pulling token for GitHub Runner"
  token=$(curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com' -H Metadata:true -s | jq -r .access_token)
else
  echo "Pulling token for Local Machine"
  token=$(az account get-access-token --resource "https://management.azure.com" | jq -r '.accessToken')
fi
ENDPOINT_INFO=$(curl -H "Authorization: Bearer $token" -H "Content-Type: application/json" -X GET https://management.azure.com${TM_ID}?api-version=2018-04-01 | jq -r '{ host:  .properties.monitorConfig.customHeaders[] | select(.name=="host").value, endpoints: [ .properties.endpoints[].properties | select(.endpointStatus=="Enabled") ] }')
SUBSCRIPTION_ID=$(echo $ENDPOINT_INFO | jq -r '.endpoints[0].targetResourceId ' | cut -d '/' -f3)
HOST=$(jq -r .host <<<$ENDPOINT_INFO)
IP_ID=$(jq -r '.endpoints[0].targetResourceId' <<<$ENDPOINT_INFO)
# IP_IDS is not yet implemented, will be used when deploying to multiple targets
#IP_IDS=$(jq -r '.endpoints[].targetResourceId' <<<$ENDPOINT_INFO)
ALL_GATEWAYS=$(curl -X GET -H "Authorization: Bearer $token" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/providers/Microsoft.Network/applicationGateways?api-version=2021-03-01 )
TARGET_ENDPOINTS=$(jq -r ".value[] | select(.properties.frontendIPConfigurations[].properties.publicIPAddress.id==\"$IP_ID\") | (.properties.httpListeners[] | if (.properties.hostNames | index(\"$HOST\") != null) and .properties.protocol == \"Https\" then .id else empty end) as \$listener_id | ( .properties.requestRoutingRules[].properties | select(.httpListener.id==\$listener_id).backendAddressPool.id ) as \$backend_id | .properties.backendAddressPools[] | select(.id==\$backend_id) | .properties.backendAddresses[].fqdn " <<<$ALL_GATEWAYS)
APP_HOSTNAMES=()
for app in ${TARGET_ENDPOINTS}; do
  APPS+=($app)
done
APP_IDS=()
for app in ${APPS[*]}; do 
  id=$(curl -H "Authorization: Bearer $token" -H "Content-Type: application/json" -X GET "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/providers/Microsoft.Web/sites?api-version=2021-02-01" | jq -r  ".value[] | if (.properties.enabledHostNames | index(\"$app\") != null ) then .id else empty end") 
  APP_IDS+=($id)
done
CREDENTIALS=()
for app_id in ${APP_IDS[*]}; do  app_creds=$(curl -H "Authorization: Bearer $token" -H "Content-Type: application/json" -X POST https://management.azure.com$app_id/config/publishingcredentials/list?api-version=2021-02-01 -d '' | jq -r .properties.scmUri); CREDENTIALS+=($app_creds); done
for cred in ${CREDENTIALS[*]}; do
  curl -X POST --fail --data-binary @"${PACKAGE_LOCATION}" "$cred"/api/zipdeploy
done

  

