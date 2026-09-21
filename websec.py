import argparse
import sys
import requests

BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/153.0.0.0 Safari/537.36"
)

def parse_arguments():
    parser = argparse.ArgumentParser(description='Assess the security configuration of a web application.')

    parser.add_argument('url',help='The target URL, e.g. https://example.com')
    parser.add_argument('-A','--user-agent',type=str, help=(
            'Set a custom User-Agent. Use "default" for a browser-like '
            'User-Agent. If omitted, Requests uses its own User-Agent.'
        ),)

    return parser.parse_args()

def build_request_headers(user_agent):
    if user_agent is None:
        return None
    if user_agent.lower() == "default":
        user_agent = BROWSER_USER_AGENT

    return {
        "User-Agent": user_agent
    }


def fetch_response(url, headers=None):
        
    try:
        return requests.get(url, headers=headers, timeout=10, allow_redirects=True)
    except requests.exceptions.InvalidURL:
        print(f'Invalid URL: {url}')    
    except requests.exceptions.Timeout:
        print('Request timed out')
    except requests.exceptions.ConnectionError:
        print(f'Could not connect to {url}')
    except requests.exceptions.RequestException as error:
        print('Request failed', error)
    return None    


def print_response_info(response):
    print(f'Requested URL: {response.request.url}')
    print(f'Final URL {response.url}')
    print(f'Status code: {response.status_code}')

    print("\nResponse headers:")

    for name,value in response.headers.items():
        print(f'- {name}: {value}')


def main():
    args = parse_arguments()
    headers = build_request_headers(args.user_agent)
    response = fetch_response(args.url, headers)

    if response is None:
        sys.exit(1)

    print_response_info(response)


if __name__ == "__main__":
    main()