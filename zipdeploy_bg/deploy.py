from pyexpat.errors import messages
import sys
import logging
import xmltodict
import requests
from azure.identity import DefaultAzureCredential
from azure.mgmt.trafficmanager import TrafficManagerManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.apimanagement import ApiManagementClient

WEBAPP_CLIENT_API_VERSION = '2021-01-15'
TM_CLIENT_API_VERSION = '2022-01-29'
NETWORK_CLIENT_API_VERSION = '2021-02-01'
RG_CLIENT_API_VERSION = '2021-04-01'
APIM_CLIENT_API_VERSION = '2021-08-01'

logging.basicConfig(level=logging.INFO)


def parse_script_args(args):
    try:
        tm_id = args[1]
        path_to_package = args[2]
    except IndexError:
        message = f'Expected arguments are, in order: <traffic manager profile resource id>, <deployment package path/location>'
        logging.error(message)
        raise RuntimeError(message)
    message = 'parsed script arguments'
    logging.info(message)
    return tm_id, path_to_package


def parse_tm_id(tm_id):
    try:
        tm_id_split = tm_id.split('/')
        sub_id = tm_id_split[2]
        tm_rg_name = tm_id_split[4]
        tm_name = tm_id_split[8]
    except IndexError:
        message = f'Expected resource ID was not in the right format. Expected:  "/subscriptions/<sub id>/resourceGroups/<rg name>/providers/Microsoft.Network/trafficManagerProfiles/<tm profile name>"'
        logging.error(message)
        raise RuntimeError(message)
    message = 'parsed Traffic Manager profile ID'
    logging.info(message)
    return sub_id, tm_rg_name, tm_name


def get_azure_credential():
    message = 'DefaultAzureCredential'
    logging.debug(message)
    return DefaultAzureCredential()


def get_traffic_manager_client(creds: DefaultAzureCredential, sub_id: str):
    message = f'returning traffic manager client on API version {TM_CLIENT_API_VERSION}'
    logging.debug(message)
    return TrafficManagerManagementClient(creds, sub_id, api_version=TM_CLIENT_API_VERSION)


def get_network_management_client(creds: DefaultAzureCredential, sub_id: str):
    message = f'returning network management client on API version {NETWORK_CLIENT_API_VERSION}'
    logging.debug(message)
    return NetworkManagementClient(creds, sub_id, api_version=NETWORK_CLIENT_API_VERSION)


def get_web_app_client(creds: DefaultAzureCredential, sub_id: str):
    message = f'returning web app client on API version {WEBAPP_CLIENT_API_VERSION}'
    logging.debug(message)
    return WebSiteManagementClient(creds, sub_id, api_version=WEBAPP_CLIENT_API_VERSION)


def get_apim_client(creds: DefaultAzureCredential, sub_id: str):
    message = f'returning APIM client on API version {APIM_CLIENT_API_VERSION}'
    logging.debug(message)
    return ApiManagementClient(creds, sub_id, api_version=APIM_CLIENT_API_VERSION)


def get_traffic_manager_profile(client: TrafficManagerManagementClient, rg_name: str, name:str):
    message = f'attempting to retrieve TM Profile {name} in {rg_name}'
    logging.debug(message)
    profile = client.profiles.get(rg_name, name).as_dict()
    try:
        hostname = [header['value'] for header in profile['monitor_config'] ['custom_headers'] if header['name'] == 'host'][0]
    except:
        message = f'Failed to derive hostname from traffic manager profile'
        logging.error(message)
        raise(RuntimeError)
    message = f'Will deploy to application serving {hostname}'
    logging.info(message)
    return profile, hostname


def get_traffic_manager_target_endpoints(profile: dict):
    message = f'building map of enabled traffic manager endpoints'
    logging.debug(message)
    endpoints = {}
    for endpoint in profile['endpoints']:
        if endpoint['endpoint_status'] == 'Enabled':
            endpoints[endpoint['name']] = {
                'ip_id': endpoint['target_resource_id'],
                'headers': {item['name']: item['value'] for item in endpoint['custom_headers']},
            }
    message = f'Retrieved enabled Traffic Manager Endpoints'
    logging.info(message)
    return endpoints


def get_application_gateways(client: NetworkManagementClient):
    message = f'building map of all application gateways in subscription'
    logging.debug(message)
    all_gateways = client.application_gateways.list_all()
    gateways = {}
    for gateway in all_gateways:
        gateways[gateway.as_dict()['name']] = gateway.as_dict()
    message = f'Retrieved all Application Gateways from subscription'
    logging.info(message)
    return gateways


def get_gateways_with_public_ip(gateways: dict, ip_ids: list):
    message = f'Will parse gateway map to return all gateways using provided public ip list'
    logging.debug(message)
    matching_gateways = {}
    for gateway_name, gateway_info in gateways.items():
        for config in gateway_info['frontend_ip_configurations']:
            if config.get('public_ip_address', {}).get('id') in ip_ids:
                #frontend_ips.append(config['id'])
                matching_gateways[gateway_name] = gateway_info
    message = f'Parsed App Gateways used by enabled endpoints'
    logging.info(message)
    return matching_gateways


def get_matching_gateway_listener(gateway, app_fqdn):
    matching_listeners = []
    for listener in gateway['http_listeners']:
        if listener['protocol'].lower() == "https" and app_fqdn in listener.get('host_name', []):
            matching_listeners.append(listener['id'])
    if len(matching_listeners) > 1:
        message = f'Found more than one matching listener. This is not expected behavior'
        logging.error(message)
        raise(RuntimeError)
    elif matching_listeners == []:
        return None
    else:
        return matching_listeners[0]


def get_matching_request_routing_rule(gateway, listener_id):
    if listener_id is None:
        return None
    matching_request_routing_rules = []
    for rule in gateway['request_routing_rules']:
        if rule['http_listener']['id'] == listener_id:
            matching_request_routing_rules.append(rule)
    if len(matching_request_routing_rules) > 1:
        message = f'Found more than one matching routing rule. This is not expected behavior'
        logging.error(message)
        raise(RuntimeError)
    elif matching_request_routing_rules == []:
        return None
    else:
        return matching_request_routing_rules[0]


def get_matching_backend_address_pool(gateway, routing_rule):
    if routing_rule is None:
        return []
    target_fqdns = []
    for pool in gateway['backend_address_pools']:
        if routing_rule['backend_address_pool']['id'] == pool['id']:
            for address in pool['backend_addresses']:
                target_fqdns.append(address['fqdn'])
    return target_fqdns


def get_matching_rewrite_rule_set(gateway, routing_rule):
    if routing_rule is None:
        return None
    rw_rule_set_id = routing_rule.get('rewrite_rule_set', {}).get('id', None)
    if rw_rule_set_id is None:
        return None
    for rewrite_rule_set in gateway['rewrite_rule_sets']:
        if rewrite_rule_set['id'] == rw_rule_set_id:
            return rewrite_rule_set


def get_rewrite_rule_path(ruleset):
    rewrite_paths = []
    for rule in ruleset['rewrite_rules']:
        rewrite_paths.append(rule['action_set']['url_configuration']['modified_path'])
    if len(rewrite_paths) > 1:
        message = f'more than one rewrite rule affects the path.'
        logging.error(message)
        raise(RuntimeError)
    elif rewrite_paths == []:
        message = f'rewrite rules do not contain an action set which modifies the url path'
        logging.error(message)
        raise(RuntimeError)
    else:
        return rewrite_paths[0]
    

def get_gateway_backends(gateways: dict, endpoints:dict, app_fqdn: str):
    # Grab All App Gateways that are using the references Public IPs from the target TM Endpoints
    message = f'Will pull Public IP Address Azure resource IDs from all enabled Traffic Manager Endpoints'
    logging.debug(message)
    ip_ids = [v['ip_id'] for k, v in endpoints.items()]
    gateways_using_ips = get_gateways_with_public_ip(gateways, ip_ids)
    deployment_targets = []
    for gateway in gateways_using_ips.values():
        listener_id = get_matching_gateway_listener(gateway, app_fqdn)
        request_routing_rule = get_matching_request_routing_rule(gateway, listener_id)
        backend_fqdns = get_matching_backend_address_pool(gateway, request_routing_rule)
        rewrite_rule_set = get_matching_rewrite_rule_set(gateway, request_routing_rule)
        if rewrite_rule_set is None:
            rewrite_path = None
        else:
            rewrite_path = get_rewrite_rule_path(rewrite_rule_set)
        for fqdn in backend_fqdns:
            deployment_targets.append(
                {
                    'fqdn': fqdn,
                    'rewrite_path': rewrite_path,
                    'tm-color': gateway['tags']['Scope'],
                }
            )
    return deployment_targets


def get_all_apims(client: ApiManagementClient):
    message = f'will retrieve all api management services within subscription'
    logging.debug(message)
    all_apims = [item.as_dict()
                 for item in client.api_management_service.list()]
    apim_by_hostname_map = {}
    for apim in all_apims:
        for configuration in apim['hostname_configurations']:
            apim_by_hostname_map[configuration['host_name']] = {
                'name': apim['name'],
                'resource_group': apim['id'].split("/")[4],
                'id': apim['id'],
            }
    message = f'built map of apim instances by hostname'
    logging.info(message)
    return apim_by_hostname_map


def filter_webapps(apim_by_hostname_map, targets):
    message = f'will split out gateway backends into webapps and apim backends'
    logging.debug(message)
    webapp_targets = [
        target for target in targets if target['fqdn'] not in apim_by_hostname_map.keys()]
    apim_targets = [
        target for target in targets if target['fqdn'] in apim_by_hostname_map.keys()]
    num_webapps = len(webapp_targets)
    num_apims = len(apim_targets)
    message = f'split out {num_webapps} web apps and {num_apims} apim backends'
    logging.info(message)
    return webapp_targets, apim_targets


def get_apis(client: ApiManagementClient, apim_by_hostname_map):
    message = f'will retrieve all APIs hosted by the APIM instances'
    logging.debug(message)
    all_apis = {}
    for apim_fqdn, apim_info in apim_by_hostname_map.items():
        all_apis[apim_fqdn] = [ item.as_dict() for item in client.api.list_by_service(
            apim_info['resource_group'], apim_info['name'] )]
    apis = []
    for k, v in all_apis.items():
        for l in v:
            apis.append(l['id'])
    num_apis = len(set(apis))
    message = f'retrieved {num_apis} APIs from {", ".join(all_apis.keys())}'
    logging.info(message)
    return all_apis


def filter_target_apis(apim_targets, all_apis):
    message = f'will filter out APIM APIs'
    logging.debug(message)
    target_apis = []
    for target in apim_targets:
        try:
            message = f'will attempt to pull API version from rewrite path'
            logging.debug(message)
            api_version = target['rewrite_path'].split("/")[2]
        except IndexError:
            message = f'API version not specified in path, will set to "None"'
            logging.debug(message)
            api_version = None
        except AttributeError:
            message = f'If api_verson is already a None type, it can mean the there is no rewrite rule associated with the listener in the app gateway'
            logging.error(message)
            raise(RuntimeError)
        except:
            bad_target_fqdn = target['fqdn']
            message = f'Parsing the "rewrite_path" attribute for {bad_target_fqdn} failed'
            logging.error(message)
            raise(RuntimeError)
        api_path = target['rewrite_path'].split("/")[1]
        api_names = [api['name'] for api in all_apis[target['fqdn']] if api['path'] ==
                   api_path and api['api_version'] == api_version or api['path'] == api_path and api_version == None]
        for api_name in api_names:
            message = f'found api {api_name} on path {api_path}, version {api_version}'
            logging.debug('message')
            target_apis.append({
                'fqdn': target['fqdn'],
                'api_path': api_path,
                'api_name': api_name,
                'api_version': api_version,
                'tm-color': target['tm-color'],
            })
    message = f'got {len(target_apis)} APIM APIs from APIM targets'
    logging.info(message)
    return target_apis


def get_apim_policies(client: ApiManagementClient, apis, webapp_targets, apim_by_hostname_map):
    message = f'will parse through policies to get API backends'
    logging.debug(message)
    matching_api_policies = []
    for api in apis:
        target_api_policies = client.api_policy.list_by_api(
            apim_by_hostname_map[api['fqdn']]['resource_group'],
            apim_by_hostname_map[api['fqdn']]['name'],
            api['api_name']
        )
        api['policy'] = [pol['value'] for pol in [item for item in target_api_policies.as_dict()['value']]][0].replace('\r\n', '')
        matching_api_policies.append(api)
    backends_list = []
    for api in matching_api_policies:
        pol = api['policy']
        backends_policy = xmltodict.parse(pol)
        backends = [
            {
                'fqdn': item['set-backend-service']['@base-url'],
                'tm-color': item['@condition'].split('==')[1],
            } for item in backends_policy['policies']['inbound']['choose']['when']]
        filtered_backends = [
            item for item in backends if api['tm-color'] in item['tm-color']
        ]
        backends_list = backends_list + filtered_backends
    message = f'found apim target backends within api policies, combined with webapp targets'
    logging.info(message)
    return webapp_targets + backends_list


def get_target_webapps(webapps: dict, target_hostnames: list):
    message = f'Will get all webapps with hostnames in target list'
    logging.debug(message)
    filtered_webapps = []
    for webapp in webapps:
        for hostname in webapp['enabled_host_names']:
            if hostname in target_hostnames:
                target = {
                    'name': webapp['name'],
                    'resource_group': webapp['resource_group'],
                    'id': webapp['id'],
                }
                filtered_webapps.append(target)
    message = f'Got all webapps in target hostname list'
    logging.info(message)
    return filtered_webapps


def summarize_deploy_results(results: list):
    message = f'Will generate list of deployment successes for failures'
    logging.debug(message)
    success_list = []
    for item in results:
        if item['response_code'] == 200:
            success_list.append(True)
        else:
            success_list.append(False)
    message = f'Generated a list of deployment successes or failures'
    logging.info(message)
    return all(success_list)


def deploy_to_webapps(client: WebSiteManagementClient, target_webapps, deployment_package_path):
    message = f'Will attempt to deploy to target backends'
    logging.debug(message)
    target_hostnames = [target['fqdn'].replace('https://', '') for target in target_webapps]
    all_webapps = [webapp.as_dict() for webapp in client.web_apps.list()]
    filtered_webapps = get_target_webapps(all_webapps, target_hostnames)
    for webapp in filtered_webapps:
        results = []
        creds = client.web_apps.begin_list_publishing_credentials(
            webapp['resource_group'],
            webapp['name'],
        )
        deploy_uri = "/".join([creds.result().as_dict()['scm_uri'], 'api/zipdeploy'])
        with open(deployment_package_path, 'rb') as f:
            package = f.read()
            files = {'file': package}
            deploy_response = requests.post(deploy_uri, files=files)
            result = {
                'name' : webapp['name'],
                'response_code' : deploy_response.status_code,
                'reason' : deploy_response.reason,
            }
            results.append(result)
    successful_deployment = summarize_deploy_results(results)
    if successful_deployment:
        message = f'Successfully deployed to: {[ item["name"] for item in results]}'
        logging.info(message)
    else:
        message = f'Failed to deploy to target(s): {results}'
        logging.error(message)
        raise(RuntimeError)
    message = f'Deployment actions complete'
    logging.info(message)
    return results


def main():

    tm_id, package_location = parse_script_args(sys.argv)
    sub_id, tm_rg_name, tm_name = parse_tm_id(tm_id)
    az_creds = get_azure_credential()

    # Traffic Manager
    tm_client = get_traffic_manager_client(az_creds, sub_id)
    tm_profile, target_fqdn = get_traffic_manager_profile(tm_client, tm_rg_name, tm_name)
    enabled_endpoints = get_traffic_manager_target_endpoints(tm_profile)

    # Some validation stuff to do when not so lazy
    if len(enabled_endpoints.keys()) < 1:
        message = f'Traffic Manager Profile has no enabled endpoints'
        logging.error(message)
        raise RuntimeError(message)

    # App Gateway Stuff
    net_client = get_network_management_client(az_creds, sub_id)
    all_app_gateways = get_application_gateways(net_client)
    gateway_backends = get_gateway_backends(all_app_gateways, enabled_endpoints, target_fqdn)

    # APIM Stuff
    apim_client = ApiManagementClient(az_creds, sub_id)
    apim_by_hostname_map = get_all_apims(apim_client)
    all_apis = get_apis(apim_client, apim_by_hostname_map)
    webapp_targets, apim_targets = filter_webapps(apim_by_hostname_map, gateway_backends)
    target_apis = filter_target_apis(apim_targets, all_apis)
    all_targets = get_apim_policies(apim_client, target_apis, webapp_targets, apim_by_hostname_map)

    # Web App Stuff
    webapp_client = get_web_app_client(az_creds, sub_id)
    deployment_results = deploy_to_webapps(webapp_client, all_targets, package_location)
    logging.info(deployment_results)


if __name__ == "__main__":
    main()


# Make a set out of deployment targets in case a multiple show up somewhere
