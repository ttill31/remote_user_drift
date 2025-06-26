from os import getenv
from os.path import exists
from time import sleep
from typing import Any
from argparse import ArgumentParser, ArgumentError, Namespace
from requests import get, post, Response
from msal import ConfidentialClientApplication
from dotenv import load_dotenv

from entra_user import EntraUser
from sql_wrapper import SQLWrapper

MS_GRAPH_URL_LOGIN: str = r'https://login.microsoftonline.com/{{tenant-id}}'
MS_GRAPH_URL_GET_GROUP_MEMBERS: str = r'https://graph.microsoft.com/v1.0/groups/{{group-id}}/members?$select=id,displayName'
MS_GRAPH_URL_GET_AUDIT_LOGS: str = r"https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=(userId eq '{{user-id}}')&$select=ipAddress,location,createdDateTime&$top=50&$orderby=createdDateTime desc"
MS_GRAPH_DEFAULT_SCOPES: str = r'https://graph.microsoft.com/.default'

def main() -> None:
    args: dict[str, str] | None = get_args()
    
    if args:
        env_info: tuple[str, str, str, str] | None = get_env_configuration(args['file'])
        if env_info:
            azure_token: str = get_access_token(env_info[0], env_info[1], env_info[2])
            target_groups: list[str] = get_target_groups(env_info[3])
            users: set[EntraUser] = get_members_from_groups(azure_token, target_groups)

            get_user_audit_log_information(azure_token, users)



def get_target_groups(groups: str) -> list[str]:
    return groups.split('|')

def get_access_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    return_value: str = ''

    app: ConfidentialClientApplication = ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=MS_GRAPH_URL_LOGIN.replace(r'{{tenant-id}}', tenant_id)
    )

    result: dict[str | Any, Any | Any | str] | None = app.acquire_token_for_client(scopes=[MS_GRAPH_DEFAULT_SCOPES])

    if result:
        return_value = result.get('access_token', '')
    
    return return_value

def create_headers(token: str, include_app_type: bool = False) -> dict[str, str]:
    return {
        'Authorization': f'Bearer {token}'
    } if not include_app_type else {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

def soft_graph_call(url: str, headers: dict[str, str], max_tries: int = 15, json_payload: dict[str, Any] | None = None) -> Response:
    try_count: int = 0

    while try_count < max_tries:
        response: Response = get(url=url, headers=headers,timeout=(10,60)) if json_payload is None else post(
            url=url, headers=headers, timeout=(10, 60), json=json_payload)

        match(response.status_code):
            case 200: # Everything is okay
                return response
            
            case 429: # We're getting throttled
                wait_for: int = int(response.headers.get('Retry-After', '5'))
                sleep(wait_for)

            case 502 | 503 | 504: # Transient error
                wait_for: int = (2 ** try_count)
                sleep(wait_for)

            case _:
                print(f'Unhandled error {response.status_code} during graph call to {url}')

        try_count += 1

    raise Exception(f'Microsoft graph call failed after {max_tries} tries.')

def get_members_from_groups(token: str, target_groups: list[str]) -> set[EntraUser]:
    employees: list[EntraUser] = list()

    for group in target_groups:
        employees.extend(query_ms_graph_for_members(token, group))

    return set(employees)

def query_ms_graph_for_members(token: str, group_id: str) -> list[EntraUser]:
    headers: dict[str, str] = create_headers(token)
    url: str | None = MS_GRAPH_URL_GET_GROUP_MEMBERS.replace(r'{{group-id}}', group_id)
    emp_data: list[EntraUser] = list()

    while url:
        response: Response = soft_graph_call(url, headers)
        data: Any = response.json()
        url = data.get('@odata.nextLink', None)
        emp_data.extend(
            [
                EntraUser(
                    value['id'],
                    value['displayName'],
                    set(),
                    set()
                )
                for value in data.get('value', {})
            ]
        )

    return emp_data

def get_user_audit_log_information(token: str, users: set[EntraUser]) -> None:
    headers: dict[str, str] = create_headers(token=token)

    for user in users:
        print(f'Scanning audit logs for {user.display_name}')
        url: str = MS_GRAPH_URL_GET_AUDIT_LOGS.replace(r'{{user-id}}', user.id)

        response: Response = soft_graph_call(url, headers)
        data: Any = response.json()
        url = data.get('@odata.nextLink', None)

        for entry in data.get('value', {}):
            user.ip_addresses.add(entry['ipAddress'])
            user.states.add(entry['location']['state'])


def get_args() -> dict[str, str] | None:
    parser: ArgumentParser = ArgumentParser()

    parser.add_argument('-f', '--file', help="""The env file that contains the tenant ID and client ID. Should contain the following entries:\n
                        CLIENT_ID=\"<CLIENT ID>\"\n
                        CLIENT_SECRET=\"<CLIENT SECRET>\"\n
                        TENANT_ID=\"<TENANT ID>\"\n
                        TARGET_GROUPS=\"<TARGET_ONE>|<TARGET_TWO>...\"""", 
                        required=True)
    
    return _validate_args(parser)

def _validate_args(parser: ArgumentParser) -> dict[str, str] | None:
    parsed_args: dict[str, str] | None = None

    try:
        args: Namespace = parser.parse_args()

        # Were both arguments provided and does the file exist?
        if args.file and exists(args.file):
            parsed_args = {
                'file': args.file,
            }
        else:
            parser.error('Valid arguments not specified.')
    except ArgumentError as err:
        print(f'{err.argument_name}: {err.message}')
        print('\nPlease specify -h flag for help for more information.')
    except Exception as err:
        print(f'Generic error?! {err}')
    finally:
        return parsed_args

def get_env_configuration(env_file: str) -> tuple[str, str, str, str] | None:
    if load_dotenv(env_file):
        tenant_id: str | None = getenv('TENANT_ID')
        client_id: str | None = getenv('CLIENT_ID')
        client_secret: str | None = getenv('CLIENT_SECRET')
        target_groups: str | None = getenv('TARGET_GROUPS')

        return_tuple: tuple[str | None, str | None, str | None, str | None] = (
            tenant_id,
            client_id,
            client_secret,
            target_groups
        )

        return return_tuple if all(return_tuple) else None

    return None

if __name__ == '__main__':
    main()