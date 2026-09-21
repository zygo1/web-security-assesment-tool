import argparse
import sys
import requests

BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/153.0.0.0 Safari/537.36"
)

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

# checking and gathering the missing headers
def check_missing_security_headers(response):
    missing_headers = []

    for header_name in SECURITY_HEADERS:
        header_value = response.headers.get(header_name)

        if header_value is None:
            missing_headers.append(header_name)

    return missing_headers

def validate_security_headers(response):
    misconfigured_headers = []


    return misconfigured_headers

# printing the results of check_security_headers
def print_security_headers_results(missing_headers):
    print(f'Security headers check:')
    
    if missing_headers:
        print("Missing Headers:")

        for header_name in missing_headers:
            print(f' - {header_name}')
    else:
        print('No security headers are missing')


def parse_arguments():
    parser = argparse.ArgumentParser(description='Assess the security configuration of a web application.')

    parser.add_argument('url',help='The target URL, e.g. https://example.com')
    parser.add_argument('-A','--user-agent',type=str, help=(
            'Set a custom User-Agent. Use "default" for a browser-like '
            'User-Agent. If omitted, Requests uses its own User-Agent.'
        ),)
    parser.add_argument('-v','--verbose', action="count", default=0)

    return parser.parse_args()

# for now i just add the user-agent in the request headers
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


#print the results from fetch_response
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

    
    if (args.verbose >= 1):
        print_response_info(response)


    missing_headers = check_missing_security_headers(response)
    misconfigured_headers = validate_security_headers(response)
    # prepei na omadopoihsw ta print kai na ta valw se 1 function, kapws etsi dld:
    # print_security_headers_results(missing_headers, misconfigured_headers)
    print('\n')
    print_security_headers_results(missing_headers)

if __name__ == "__main__":
    main()