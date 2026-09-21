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

