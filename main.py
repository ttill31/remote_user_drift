from os import getenv
from os.path import exists
from time import sleep
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from typing import Any
from argparse import ArgumentParser, ArgumentError, Namespace
from requests import get, post, Response
from msal import ConfidentialClientApplication
from rich.progress import track
from dotenv import load_dotenv

from entra_user import EntraUser
from sql_wrapper import SQLWrapper

# MS Graph URLs
MS_GRAPH_URL_LOGIN: str = r'https://login.microsoftonline.com/{{tenant-id}}'
MS_GRAPH_URL_GET_GROUP_MEMBERS: str = r'https://graph.microsoft.com/v1.0/groups/{{group-id}}/members?$select=id,displayName'
MS_GRAPH_URL_GET_AUDIT_LOGS: str = r"https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=(userId eq '{{user-id}}' and createdDateTime gt {{date-time}})&$select=ipAddress,location,createdDateTime&$top=50&$orderby=createdDateTime desc"
MS_GRAPH_URL_SEND_MAIL: str = r'https://graph.microsoft.com/v1.0/users/{{upn}}/sendMail'
MS_GRAPH_DEFAULT_SCOPES: str = r'https://graph.microsoft.com/.default'

# IP Quality Score URL
IPQS_PROXY_API: str = r'https://ipqualityscore.com/api/json/ip/{{api-token}}/{{target-ip}}?strictness=0&allow_public_access_points=false'

# IP Quality Score Concern Threshold
IPQS_THRESHOLD: int = 75

# Our HTML template file
HTML_TEMPLATE: str = 'template.html'

def main() -> None:
    args: dict[str, str] | None = get_args()
    
    if args:
        env_info: tuple[str, str, str, str, str, str, str] | None = get_env_configuration(args['env'])
        if env_info:
            # Token acquisition
            azure_token: str = get_access_token(env_info[0], env_info[1], env_info[2])

            ipqs_token: str = env_info[4]
            from_email: str = env_info[5]
            to_emails: str = env_info[6]

            # Perform Azure related actions
            target_groups: list[str] = get_target_groups(env_info[3])
            users: set[EntraUser] = get_members_from_groups(azure_token, target_groups)

            # Adjust our MS Graph URL to include today's date as a filter
            add_date_filter()
            get_user_audit_log_information(azure_token, users)

            # Create our database object and pull all employee information out
            sql_object: SQLWrapper = create_sql_object(args['database'])
            db_users: dict[str, str] = sql_object.get_all_employee_entries()

            # Create initial entries if one didn't exist
            if not create_new_entries(sql_object, users, db_users):
                print('Issues creating database entries for missing users. Aborting program.')
                return
            
            detect_concerns(ipqs_token, users, db_users)

            if not notify_of_alerts(azure_token, from_email, to_emails, users):
                print('Sending emails didn\'t go as planned.')

            # Let's save our results to the database
            if not update_employee_entries(sql_object, users):
                print('Issues updating database entries for users.')

def notify_of_alerts(token: str, from_email: str, to_emails: str, users: set[EntraUser]) -> bool:
    total_success: bool = True

    to_addresses: list[str] = to_emails.split('|')
    html_template: str = read_in_html_template(HTML_TEMPLATE).replace(r'{{CURRENT_YEAR}}', get_current_year(), 1)

    for user in users:
        if len(user.alerts) > 0:
            formatted_msg: str = ''

            for alert in user.alerts:
                formatted_msg = f'{formatted_msg}<p>{alert}</p>'

            html_msg: str = html_template.replace(r'{{ALERTS_HTML}}', formatted_msg, 1)

            email_message: dict[str, Any] = build_message(
                to_addresses,
                'Potential Remote Employee Security Concern',
                html_msg,
                [from_email]
            )

            if not send_email(token, from_email, email_message) and total_success:
                total_success = False

    return total_success

def read_in_html_template(html_file_path: str) -> str:
    if not exists(html_file_path): return ''
    with open(html_file_path, 'r', encoding='utf8') as file_stream:
        return file_stream.read()

def create_new_entries(sql_obj: SQLWrapper, entra_user_info: set[EntraUser], db_users: dict[str, str]) -> bool:
    success: bool = True

    for user in entra_user_info:
        if user.id not in db_users:
            state_copy: set[str] = user.states.copy()
            if not sql_obj.create_employee_entry(user.id, state_copy.pop()): # User might have more than one state, so just pop a random one off the stack
                success = False

    return success

def update_employee_entries(sql_obj: SQLWrapper, entra_user_info: set[EntraUser]) -> bool:
    success: bool = True

    for user in entra_user_info:
        if not sql_obj.update_employee_entry(user):
            success = False

    return success

def detect_concerns(ipqs_token: str, entra_user_info: set[EntraUser], db_user_info: dict[str, str]) -> None:
    for user in track(entra_user_info, description='Detecting security concerns...'):
        name: str = user.display_name
        previous_state: str = db_user_info.get(user.display_name, '')
        diff_state_detected: bool = False
        multiple_states_detected: bool = len(user.states) > 1

        if previous_state:
            for state in user.states:
                if previous_state != state:
                    diff_state_detected = True

        if multiple_states_detected:
            user.alerts.append(f'{name} has had a location reported across these states: {" ".join(user.states)}.')

        if diff_state_detected:
            user.alerts.append(f'{name} has been detected as working in a different state than usual.')

        for ip in user.ip_addresses:
            ip_results: dict[str, int | bool] = query_ipqs_for_ip_reputation(ipqs_token, ip)

            if ip_results['score'] >= IPQS_THRESHOLD or ip_results['mobile'] or ip_results['proxy'] or ip_results['tor']:
                user.alerts.append(f"""
                                        {name}\'s internet connection for IP {ip} is exhibiting risky behavior</br>
                                        Fraud Score: {ip_results['score']}</br>
                                        Mobile Detected: {ip_results['mobile']}</br>
                                        Proxy Detected: {ip_results['proxy']}</br>
                                        VPN Detected: {ip_results['vpn']}</br>
                                        TOR Detected: {ip_results['tor']}
                                        """)

def create_sql_object(database_file: str) -> SQLWrapper:
    if not exists(database_file):
        print(f'{database_file} does not exist, creating...')

    return SQLWrapper(database_file)

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

def soft_api_call(url: str, headers: dict[str, str], max_tries: int = 15, json_payload: dict[str, Any] | None = None) -> Response:
    try_count: int = 0

    while try_count < max_tries:
        response: Response = get(url=url, headers=headers,timeout=(10,180)) if json_payload is None else post(
            url=url, headers=headers, timeout=(10, 180), json=json_payload)

        match(response.status_code):
            case 200 |202: # Everything is okay
                return response
            
            case 401: # Not authorized, immediately jump our retries
                try_count = (max_tries + 1)

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
        response: Response = soft_api_call(url, headers)
        data: Any = response.json()
        url = data.get('@odata.nextLink', None)
        emp_data.extend(
            [
                EntraUser(
                    value['id'],
                    value['displayName'],
                    set(),
                    set(),
                    list()
                )
                for value in data.get('value', {})
            ]
        )

    return emp_data

def get_user_audit_log_information(token: str, users: set[EntraUser]) -> None:
    headers: dict[str, str] = create_headers(token=token)

    for user in track(users, description='Scanning user audit logs...'):
        url: str = MS_GRAPH_URL_GET_AUDIT_LOGS.replace(r'{{user-id}}', user.id)

        response: Response = soft_api_call(url, headers)
        data: Any = response.json()

        for entry in data.get('value', {}):
            user.ip_addresses.add(entry['ipAddress'])
            user.states.add(entry['location']['state'])

def send_email(token: str, from_addr: str, message: dict[str, Any]) -> bool:
    headers: dict[str, str] = create_headers(token=token, include_app_type=True)
    url: str = MS_GRAPH_URL_SEND_MAIL.replace(r'{{upn}}', from_addr.strip().lower())
    success: bool = True

    try:
        response: Response = soft_api_call(url=url, headers=headers, json_payload=message)
        success = response.ok
    except Exception as err:
        print(f'Error: {err}')
        return False
    finally:
        return success
    
def build_message(recipients: list[str], subject: str, message: str, reply_to: list[str] = [], content_type: str = 'html') -> dict[str, Any]:
    return {
        'message': {
            'subject': subject,
            'body': {
                'contentType': content_type,
                'content': message
            },
            'toRecipients': _format_email_list(recipients),
            'replyTo': _format_email_list(reply_to)
        },
        'saveToSentItems': str(True)
    }

def _format_email_list(email_list: list[str]) -> list[dict[str, dict[str, str]]]:
    return [
        {
            'emailAddress': {
                'address': email
            }
        }
        for email in email_list
    ]

def query_ipqs_for_ip_reputation(token: str, target_ip: str) -> dict[str, int | bool]:
    url: str = IPQS_PROXY_API.replace(r'{{api-token}}', token).replace(r'{{target-ip}}', target_ip)

    # Weirdly IP Quality Score doesn't seem to support modern auth or headers, so just specify the url
    response: Response = soft_api_call(url=url, headers={})

    data: Any = response.json()

    return {
        'score': int(data.get('fraud_score', 0)),
        'mobile': bool(data.get('mobile', False)),
        'proxy': bool(data.get('proxy', False)),
        'vpn': bool(data.get('vpn', False)),
        'tor': bool(data.get('tor', False))
    }

def get_args() -> dict[str, str] | None:
    parser: ArgumentParser = ArgumentParser()

    parser.add_argument('-e', '--env', help="""The env file that contains the tenant ID and client ID. Should contain the following entries:\n
                        CLIENT_ID=\"<CLIENT ID>\"\n
                        CLIENT_SECRET=\"<CLIENT SECRET>\"\n
                        TENANT_ID=\"<TENANT ID>\"\n
                        TARGET_GROUPS=\"<TARGET_ONE>|<TARGET_TWO>...\"""", 
                        required=True)
    parser.add_argument('-d', '--database', help='The SQL Lite DB file we should use or create.', required=True)
    
    return _validate_args(parser)

def _validate_args(parser: ArgumentParser) -> dict[str, str] | None:
    parsed_args: dict[str, str] | None = None

    try:
        args: Namespace = parser.parse_args()

        # Were both arguments provided and does the file exist?
        if args.env and exists(args.env):
            parsed_args = {
                'env': args.env,
                'database': args.database
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

def get_env_configuration(env_file: str) -> tuple[str, str, str, str, str, str, str] | None:
    if load_dotenv(env_file):
        tenant_id: str | None = getenv('TENANT_ID')
        client_id: str | None = getenv('CLIENT_ID')
        client_secret: str | None = getenv('CLIENT_SECRET')
        target_groups: str | None = getenv('TARGET_GROUPS')
        ipqs_key: str | None = getenv('IPQS_API')
        from_email: str | None = getenv('FROM_EMAIL')
        to_email: str | None = getenv('TO_EMAIL')

        return_tuple: tuple[str | None, str | None, str | None, str | None, str | None, str | None, str | None] = (
            tenant_id,
            client_id,
            client_secret,
            target_groups,
            ipqs_key,
            from_email,
            to_email
        )

        return return_tuple if all(return_tuple) else None

    return None

def add_date_filter() -> None:
    now: datetime = datetime.now(tz=ZoneInfo('America/Denver'))
    yesterday: datetime = (now - timedelta(days=1))
    formatted_yesterday: str = yesterday.strftime('%Y-%m-%dT00:00:00Z')
    
    # Access the global variable for editing
    global MS_GRAPH_URL_GET_AUDIT_LOGS
    MS_GRAPH_URL_GET_AUDIT_LOGS = MS_GRAPH_URL_GET_AUDIT_LOGS.replace(r'{{date-time}}', formatted_yesterday)

def get_current_year() -> str:
    return datetime.now().strftime('%Y')

if __name__ == '__main__':
    main()