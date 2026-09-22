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

#Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; frame-ancestors 'self'

def validate_csp(value):
    findings = []

    directives = {}

    for directive in value.split(';'):
        parts = directive.strip().split()

        if not parts:
            continue

        directive_name = parts[0].lower()
        directive_values= parts[1:]

        directives[directive_name] = directive_values

        script_sources = directives.get('script-src', directives.get('default-src'))

        if script_sources is None:
            findings.append('The policy does not define "script-src" or "default-src", '
            "so script sources are not restricted by these directives.")
        else:
            normalized_sources = set()

            for source in script_sources:
                lowercase_source = source.lower()
                normalized_sources.add(lowercase_source)
            #script sources dld: 'self','unsafe-inline' 'https...' ktlp

            if "'unsafe-inline'" in normalized_sources:
                findings.append('The script policy contains "\'unsafe-inline\'", which may '
                "allow inline JavaScript. Consider using nonces or hashes.")

            if "'unsafe-eval'" in normalized_sources:
                findings.append('The script policy contains "\'unsafe-eval\'", which permits '
                "string-to-code evaluation and weakens protection against XSS.")

            if "*" in normalized_sources:
                findings.append('The script policy contains the wildcard source "*", '
                "which may allow scripts from untrusted origins.")

        # ta directives einai key value pairs dld:
#           directives = {
#               "default-src": ["'self'"],
#               "script-src": ["'self'", "'unsafe-inline'"],
#               "base-uri": ["'none'"],
#           }

        if "base-uri" not in directives:
            findings.append('The policy does not define "base-uri". Consider using '
            '"base-uri \'self\'" or "base-uri \'none\'".')            

        if "frame-ancestors" not in directives:
            findings.append('The policy does not define "frame-ancestors". Framing may still '
            "be restricted by X-Frame-Options, so manual validation is needed.")

        return findings

def validate_x_frame_options(value):
    normalized_value = value.strip().upper()

    if normalized_value.startswith('ALLOW-FROM'):
        return (
            'The "ALLOW-FROM" directive is obsolete and is not supported '
            'by modern browsers. Use "DENY" or "SAMEORIGIN", or configure '
            'the CSP frame-ancestors directive.'
        )
    
    if normalized_value not in {'DENY', 'SAMEORIGIN'}:
        return (
            f'Invalid X-Frame-Options value: "{value}". '
            'Expected "DENY" or "SAMEORIGIN".'
        )
    
    return None
 
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

