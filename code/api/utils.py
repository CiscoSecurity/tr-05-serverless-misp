from urllib.error import URLError, HTTPError
from uuid import uuid4

import jwt
from api.errors import (
    AuthorizationError, InvalidArgumentError,
    CriticalMISPResponseError
)
from flask import request, jsonify, current_app, g
from jwt import (
    PyJWKClient, InvalidSignatureError, InvalidAudienceError,
    DecodeError, PyJWKClientError, MissingRequiredClaimError
)
from pymisp import PyMISP, exceptions

NO_AUTH_HEADER = 'Authorization header is missing'
WRONG_AUTH_TYPE = 'Wrong authorization type'
WRONG_PAYLOAD_STRUCTURE = 'Wrong JWT payload structure'
WRONG_JWT_STRUCTURE = 'Wrong JWT structure'
WRONG_AUDIENCE = 'Wrong configuration-token-audience'
KID_NOT_FOUND = 'kid from JWT header not found in API response'
WRONG_KEY = ('Failed to decode JWT with provided key. '
             'Make sure domain in custom_jwks_host '
             'corresponds to your SecureX instance region.')
JWKS_HOST_MISSING = ('jwks_host is missing in JWT payload. Make sure '
                     'custom_jwks_host field is present in module_type')
WRONG_JWKS_HOST = ('Wrong jwks_host in JWT payload. Make sure domain follows '
                   'the visibility.<region>.cisco.com structure')


def set_ctr_entities_limit(payload):
    try:
        ctr_entities_limit = int(payload['CTR_ENTITIES_LIMIT'])
        assert ctr_entities_limit > 0
    except (KeyError, ValueError, AssertionError):
        ctr_entities_limit = current_app.config['CTR_DEFAULT_ENTITIES_LIMIT']
    current_app.config['CTR_ENTITIES_LIMIT'] = ctr_entities_limit


def get_auth_token():
    """
    Parse and validate incoming request Authorization header.
    """
    expected_errors = {
        KeyError: NO_AUTH_HEADER,
        AssertionError: WRONG_AUTH_TYPE
    }
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_key():
    """
    Get Authorization token and validate its signature
    against the public key from /.well-known/jwks endpoint.
    """
    expected_errors = {
        KeyError: WRONG_PAYLOAD_STRUCTURE,
        AssertionError: JWKS_HOST_MISSING,
        InvalidSignatureError: WRONG_KEY,
        DecodeError: WRONG_JWT_STRUCTURE,
        InvalidAudienceError: WRONG_AUDIENCE,
        MissingRequiredClaimError: WRONG_PAYLOAD_STRUCTURE,
        PyJWKClientError: KID_NOT_FOUND,
        URLError: WRONG_JWKS_HOST,
        HTTPError: WRONG_JWKS_HOST,
        ConnectionError: WRONG_JWKS_HOST
    }

    try:
        token = get_auth_token()
        jwks_host = jwt.decode(
            token, options={'verify_signature': False}
        ).get('jwks_host')
        assert jwks_host

        jwks_client = PyJWKClient(f'https://{jwks_host}/.well-known/jwks')
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        aud = request.url_root
        payload = jwt.decode(
            token, signing_key.key,
            algorithms=['RS256'], audience=[aud.rstrip('/')]
        )
        current_app.config['HOST'] = payload['HOST']
        set_ctr_entities_limit(payload)

        return payload['AuthKey']
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_json(schema):
    """
    Parse the incoming request's data as JSON.
    Validate it against the specified schema.
    """

    data = request.get_json(force=True, silent=True, cache=False)

    message = schema.validate(data)

    if message:
        raise InvalidArgumentError(message)

    return data


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(data):
    return jsonify({'errors': [data]})


def format_docs(docs):
    return {'count': len(docs), 'docs': docs}


def jsonify_result():
    result = {'data': {}}

    if g.get('verdicts'):
        result['data']['verdicts'] = format_docs(g.verdicts)
    if g.get('judgements'):
        result['data']['judgements'] = format_docs(g.judgements)
    if g.get('sightings'):
        result['data']['sightings'] = format_docs(g.sightings)
    if g.get('indicators'):
        result['data']['indicators'] = format_docs(g.indicators)
    if g.get('relationships'):
        result['data']['relationships'] = format_docs(g.relationships)

    if g.get('errors'):
        result['errors'] = g.errors
        if not result['data']:
            del result['data']

    return jsonify(result)


def transient_id(entity_type, uuid=None):
    if uuid:
        return f'transient:{entity_type}-{uuid}'
    return f'transient:{entity_type}-{uuid4()}'


def remove_duplicates(observables):
    return [dict(t) for t in {tuple(d.items()) for d in observables}]


def filter_observables(observables):
    supported_types = current_app.config['SUPPORTED_TYPES']
    observables = remove_duplicates(observables)
    return list(
        filter(lambda obs: (
                obs['type'] in supported_types and obs["value"] != "0"
        ), observables)
    )


def create_misp_instance():
    try:
        return PyMISP(
            key=get_key(),
            url=current_app.config['HOST'],
            ssl=current_app.config['MISP_VERIFYCERT'],
            tool=current_app.config['USER_AGENT'],
            timeout=current_app.config['MISP_TIMEOUT_SEC']
        )
    except exceptions.PyMISPError as error:
        raise CriticalMISPResponseError(error.message) from error
