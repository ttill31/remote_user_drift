from typing import Any
from argparse import ArgumentParser, ArgumentError, Namespace
from requests import get, post, Response
from msal import PublicClientApplication

from entra_user import EntraUser

MS_GRAPH_URL_GET_GROUP_MEMBERS: str = r'https://graph.microsoft.com/v1.0/groups/{{group-id}}/members?$select=id,displayName'
MS_GRAPH_URL_GET_AUDIT_LOGS: str = r"https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=(userId eq '{{user-id}}')&$select=ipAddress,location,createdDateTime&$top=10&$orderby=createdDateTime desc"

def main() -> None:
    pass

def get_delegated_token(tenant_id: str, client_id: str) -> str:
    """Retrieves an access token that allows a user to perform actions on mail boxes in a M365 tenant.

    Args:
        tenant_id (str): The ID of the M365 tenant we're trying to access.
        client_id (str): The client ID of the application that will grant us permissions to access mail boxes.

    Raises:
        Exception: Generic error if an access token was unable to be acquired.

    Returns:
        str: The access token that grants permission for all mailbox related actions.
    """
    print(r'Acquiring authorization to perform mailbox actions. You should see a browser window open and ask you to login.')

    scopes: list[str] = ['Mail.ReadWrite', 'Mail.ReadWrite.Shared']
    authority_url: str = f'https://login.microsoftonline.com/{tenant_id}'
    app: PublicClientApplication = PublicClientApplication(client_id, authority=authority_url)
    result: (dict[str, Any] | dict[str, str] | Any) = app.acquire_token_interactive(scopes=scopes)

    if 'access_token' in result:
        print('Token successfully acquired!\n')
        return result['access_token']
    else:
        raise Exception('Authentication failed.')
    

if __name__ == '__main__':
    main()