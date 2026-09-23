import re

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

def get_sources(directives, directive_name):
    if directive_name in directives:
        return directives[directive_name]

    if "default-src" in directives:
        return directives['default-src']
    
    return None

def validate_hsts(value):
    findings = []

    directives = {}

    for directive in value.split(';'):
        part = directive.strip().lower()

        if not part:
            continue

        if "=" in part:
            parts = part.split('=')
            directive_name = parts[0]
            directive_value = parts[1]
            directives[directive_name] = directive_value
        else:
            directives[part] = None

    if 'max-age' not in directives:
        findings.append( 'The HSTS policy does not define the required "max-age" directive.')
        return findings

    max_age_value = directives['max-age']


    #max-age must contain only digits
    if not re.fullmatch(r"[0-9]+", max_age_value):
        findings.append( f'Invalid HSTS max-age value: "{max_age_value}". '
            "Expected a non-negative integer representing seconds.")
        return findings

    max_age = int(max_age_value)

    if max_age == 0:
        findings.append('The HSTS max-age is set to 0, which disables the HSTS policy.')

    if 'includesubdomains' not in directives:
        findings.append('The HSTS policy does not include "includeSubDomains". '
              'Note, that this is optional if not "preload is present. "'
                "Subdomains are not covered by this policy.")

    #extra requirements when preload is requested.
    if 'preload' in directives:
        if (max_age < 31536000):
            findings.append("The HSTS policy requests preloading, but max-age is less "
                "than 31536000 seconds (one year).")

        if "includesubdomains" not in directives:
            findings.append(
                'The HSTS policy requests preloading but does not include '
                'the required "includeSubDomains" directive.'
            )
    return findings

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

    script_sources = get_sources(directives, 'script-src')
    object_sources = get_sources(directives, 'object-src')

    if script_sources is None:
        findings.append('The policy does not define "script-src" or "default-src", '
        "so script sources are not restricted by these directives.")
    else:
        normalized_sources = set()

        for source in script_sources:
            lowercase_source = source.lower()
            normalized_sources.add(lowercase_source)
        #script sources: 'self','unsafe-inline' 'https...' ktlp

        if "'unsafe-inline'" in normalized_sources:
            findings.append('The script policy contains "\'unsafe-inline\'", which may '
            "allow inline JavaScript. Consider using nonces or hashes.")

        if "'unsafe-eval'" in normalized_sources:
            findings.append('The script policy contains "\'unsafe-eval\'", which permits '
            "string-to-code evaluation and weakens protection against XSS.")

        if "*" in normalized_sources:
            findings.append('The script policy contains the wildcard source "*", '
            "which may allow scripts from untrusted origins.")

    if object_sources is None:
        findings.append('The policy does not define "object-src" or "default-src", '
                        "so object sources are not restricted by these directives") 
    else:
        normalized_objects = set()

        for _object in object_sources:
            lowercase_object = _object.lower()
            normalized_objects.add(lowercase_object)

        if "data:" in normalized_objects or "blob:" in normalized_objects:
            findings.append('The object policy allows "data:"/"blob:" sources, '
                            "which can bypass origin restrictions.")

        if "*" in normalized_objects or "https:" in normalized_objects or "http:" in normalized_objects or "filesystem:" in normalized_objects:
            findings.append('The object policy allows sources from any origin '
            '("*" or scheme-only "https:"), which may permit objects from '
            "untrusted domains.")

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
        return [
            'The "ALLOW-FROM" directive is obsolete and is not supported '
            'by modern browsers. Use "DENY" or "SAMEORIGIN", or configure '
            'the CSP frame-ancestors directive.'
        ]
    
    if normalized_value not in {'DENY', 'SAMEORIGIN'}:
        return [
            f'Invalid X-Frame-Options value: "{value}". '
            'Expected "DENY" or "SAMEORIGIN".'
        ]
    
    return []
 
def validate_x_content_type_options(value):
    if value.strip().lower() != "nosniff":
         return [
            f'Invalid X-Content-Type-Options value: "{value}". '
            'Expected "nosniff".'
        ]
    return []

VALID_REFERRER_HEADERS = [
    'no-referrer',
    'no-referrer-when-downgrade',
    'origin',
    'origin-when-cross-origin',
    'same-origin',
    'strict-origin',
    'strict-origin-when-cross-origin',
    'unsafe-url'
]

PERMISSIVE_REFERRER_POLICIES = {
    "unsafe-url",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
}

def validate_referrer_policy(value):
    findings = []
    policies = []

    for policy in value.split(','):
        normalized_value = policy.strip().lower()

        if normalized_value:
            policies.append(normalized_value)

    recognized_polices = []

    for policy in policies:
        if policy in VALID_REFERRER_HEADERS:
            recognized_polices.append(policy)

    if not recognized_polices:
        findings.append(f'Invalid Referrer-Policy value: "{value}". '
            "No recognized policy was found.")

        return findings

    effective_policy = recognized_polices[-1]
    print('effective: ', effective_policy)

    if effective_policy in PERMISSIVE_REFERRER_POLICIES:
        findings.append(f'The effective Referrer-Policy "{effective_policy}" may '
                        'disclose more referrer information that necessary. Consider '
                        '"strict-origin-when-cross-origin", "strict-origin", '
                        '"same-origin", or "no-referrer".')

    return findings


HEADER_VALIDATORS = {
    "Content-Security-Policy": validate_csp,
    "Strict-Transport-Security": validate_hsts,
    "X-Frame-Options": validate_x_frame_options,
    "X-Content-Type-Options": validate_x_content_type_options,
    "Referrer-Policy": validate_referrer_policy,
}

def validate_security_headers(response):
    misconfigured_headers = {}

    for header_name, validator in HEADER_VALIDATORS.items():
        header_value = response.headers.get(header_name)

        if header_value is None:
            continue

        findings = validator(header_value)

        if findings:
            if header_name not in misconfigured_headers:
                misconfigured_headers[header_name]= {
                    "value": header_value,
                    "findings": []
                }

            for finding in findings:
                misconfigured_headers[header_name]['findings'].append(finding)

    return misconfigured_headers
