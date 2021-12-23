#!/bin/bash
if [[ -z $1 ]] || [[ -z $2 ]]; then echo "error: target app service / function app / logic app name OR package path/name not set"; exit 1; fi
APP_NAME=$1
PACKAGE_LOCATION=$2
token=$(curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com' -H Metadata:true -s | jq -r .access_token)
set -eo pipefail
if [[ -z $token ]];
    then
        subscriptions=$(az account list | jq -r '.[].id')
        for sub in $subscriptions; do
          app_info=$(az resource list --subscription=sfs-sub-dev | jq -r ".[] | select(.type==\"Microsoft.Web/sites\" and .name==\"${APP_NAME}\") | { name: .name, id: .id, resourceGroup: .resourceGroup }")
          if [[ $app_info != "" ]]; then break; fi
        done
        if [[ $app_info == "" ]]; then echo "error: target app not found"; exit 1; fi
        APP_ID=$(jq -r '.id' <<<$app_info)
        publishInfo=$(az rest --method POST --url https://management.azure.com${APP_ID}/config/publishingcredentials/list?api-version=2019-08-01)
    else
        subscriptions=$(curl -X GET https://management.azure.com/subscriptions?api-version=2020-01-01 -H "Authorization: Bearer $token" | jq  -r '.value[].subscriptionId')
        for sub in $subscriptions; do
            app_id=$(curl -X GET "https://management.azure.com/subscriptions/$sub/resources?api-version=2021-04-01" -H "Authorization: Bearer $token" -H "Content-Type: application/json" | jq -r ".value[] | select(.name==\"${APP_NAME}\" and .type==\"Microsoft.Web/sites\") | .id")
        if [[ $app_id != "" ]]; then break; fi
        done
        publishInfo=$(curl -X POST https://management.azure.com${app_id}/config/publishingcredentials/list?api-version=2019-08-01 -H "Authorization: Bearer $token" -H "Content-Type: application/json" -H "Content-Length: 0")
fi
publishName=$(jq -r '.properties.publishingUserName' <<<$publishInfo)
publishPass=$(jq -r '.properties.publishingPassword' <<<$publishInfo)
curl -XPOST --fail -u "$publishName:$publishPass" --data-binary @"${PACKAGE_LOCATION}" "https://${APP_NAME}.scm.azurewebsites.net/api/zipdeploy"
