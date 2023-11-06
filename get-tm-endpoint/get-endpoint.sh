#!/bin/bash
if [[ -z $1 ]]; then echo "error: traffic manager name not set"; exit 1; fi
TM_NAME=$1
# There are difference in the json returned from az cli from local dev, and curl when running on an instance with MI using the token endpoint
token=$(curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com' -H Metadata:true -s | jq -r .access_token)
# if curl fails, $token will be ""
set -eo pipefail
if [[ -z $token ]]; 
    then
        TM_PROFILE_FILTER=" .[] | select(.name==\"$TM_NAME\") | { deploymentTargets : [ .endpoints[] | select(.endpointStatus==\"Enabled\") ] }"
        subscriptions=$(az account list | jq -r '.[].id')
        for sub in $subscriptions; do
          TM_ALL_PROFILES=$(az network traffic-manager profile list --subscription=$sub | jq -r )
          TM_PROFILE=$(jq -r "$TM_PROFILE_FILTER" <<<$TM_ALL_PROFILES)
          if [[ "$TM_PROFILE" != "" ]]; then break; fi
        done
        if [[ -z $TM_PROFILE ]]; then echo "error: traffic manager profile not found."; exit 1; fi
        TM_DEPLOYMENT_TARGET_APP_NAME=$(jq -r -c ".deploymentTargets[] | .target"  <<<$TM_PROFILE | cut -d . -f1 )
    else
        TM_PROFILE_FILTER=".value[] | select(.name==\"$TM_NAME\") | { deploymentTargets : [ .properties.endpoints[] | select(.properties.endpointStatus==\"Enabled\") ] }"
        subscriptions=$(curl -X GET https://management.azure.com/subscriptions?api-version=2020-01-01 -H "Authorization: Bearer $token" | jq  -r '.value[].subscriptionId')
        for sub in $subscriptions; do
            TM_ALL_PROFILES=$(curl -X GET "https://management.azure.com/subscriptions/$sub/providers/Microsoft.Network/trafficmanagerprofiles?api-version=2018-08-01" -H "Authorization: Bearer $token" -H "Content-Type: application/json")
            if [[ $(jq 'has("error")' <<<$TM_ALL_PROFILES) == "true" ]]; then echo $(jq .error.message <<<$TM_ALL_PROFILES); fi
            TM_PROFILE=$(jq -r "$TM_PROFILE_FILTER" <<<$TM_ALL_PROFILES)
            if [[ $TM_PROFILE != "" ]]; then TM_SUB=$sub; break; fi
        done
        if [[ -z $TM_PROFILE ]]; then echo "error: traffic manager profile not found."; exit 1; fi
        TM_DEPLOYMENT_TARGET_APP_NAME=$(jq -r -c ".deploymentTargets[].properties | .target"  <<<$TM_PROFILE | cut -d . -f1 )
fi
TM_DEPLOYMENT_TARGET_COUNT=$(jq -r ".deploymentTargets | length"  <<<$TM_PROFILE)
TM_DEPLOYMENT_TARGET_COLOR=$(jq -r -c "[ .deploymentTargets[].name ]"  <<<$TM_PROFILE)
if [[ $TM_DEPLOYMENT_TARGET_COUNT -eq 1 ]];
    then 
        echo $TM_DEPLOYMENT_TARGET_APP_NAME
    elif [[ $TM_DEPLOYMENT_TARGET_COUNT -gt 1 ]]; 
        then 
        echo "error: expected 1 deployment target, got ${TM_DEPLOYMENT_TARGET_COUNT}: $TM_DEPLOYMENT_TARGET_COLOR"
        exit 1
    elif [[ $TM_DEPLOYMENT_TARGET_COUNT -lt 1 ]]; 
        then 
        echo "error: expected 1 deployment target, got ${TM_DEPLOYMENT_TARGET_COUNT}: $TM_DEPLOYMENT_TARGET_COLOR"
        exit 1
    else 
        echo "error: you may not be logged in to the azure cli. expected a number, got: $TM_DEPLOYMENT_TARGET_COUNT"
        exit 1
fi
