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
    pass

def validate_hsts(value):
    pass



def validate_security_headers(response):
    misconfigured_headers = []


    return misconfigured_headers

