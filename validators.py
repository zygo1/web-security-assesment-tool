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

def validate_csp(value):
    pass

def validate_x_frame_options(value):
    pass

def validate_x_content_type_options(value):
    if value.strip().lower() != "nosniff":
        return 'Expected value: "nosniff"'
    return None

def validate_hsts(value):
    pass


HEADER_VALIDATORS = {
    "Content-Security-Policy": validate_csp,
    "Strict-Transport-Security": None,
    "X-Frame-Options": validate_x_frame_options,
    "X-Content-Type-Options": validate_x_content_type_options,
    "Referrer-Policy": None,
    "Permissions-Policy": None
}

def validate_security_headers(response):
    misconfigured_headers = []

    for header_name, validator in HEADER_VALIDATORS.items():
        header_value = response.headers.get(header_name)

        if header_name is None:
            continue

        # h ypoloipi logikh edw


    return misconfigured_headers

