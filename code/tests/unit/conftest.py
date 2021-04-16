import jwt

from app import app
from pytest import fixture
from http import HTTPStatus
from unittest.mock import MagicMock, patch
from api.errors import INVALID_ARGUMENT
from tests.unit.payloads_for_tests import PRIVATE_KEY


@fixture(scope='session')
def client():
    app.rsa_private_key = PRIVATE_KEY

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    def _make_jwt(
            jwks_host='visibility.amp.cisco.com',
            aud='http://localhost',
            kid='02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            wrong_structure=False
    ):
        payload = {
            'AuthKey': 'test',
            'HOST': 'https://1.2.3.4',
            'jwks_host': jwks_host,
            'aud': aud,
        }

        if wrong_structure:
            payload.pop('AuthKey')

        return jwt.encode(
            payload, client.application.rsa_private_key, algorithm='RS256',
            headers={
                'kid': kid
            }
        )

    return _make_jwt


@fixture(scope='module')
def invalid_json_expected_payload():
    def _make_message(message):
        return {
            'errors': [{
                'code': INVALID_ARGUMENT,
                'message': message,
                'type': 'fatal'
            }]
        }

    return _make_message


def mock_api_response(text='', status_code=HTTPStatus.OK, payload=None):
    mock_response = MagicMock()

    mock_response.text = text
    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.json = lambda: payload

    return mock_response


@fixture(scope='function')
def misp_client():
    with patch.multiple(
            'pymisp.PyMISP',
            recommended_pymisp_version=MagicMock(
                return_value={'version': '2.4.125'}
            ),
            misp_instance_version=MagicMock(
                return_value={
                    'version': '2.4.125',
                    'perm_sync': True,
                    'perm_sighting': True}
            ),
            get_user=MagicMock(return_value=['test_user'] * 3),
            describe_types_remote=MagicMock(
                return_value={
                    'sane_defaults':
                        {
                            'md5': {
                                'default_category': 'Payload delivery',
                                'to_ids': 1
                            },
                            'sha1': {
                                'default_category': 'Payload delivery',
                                'to_ids': 1
                            },
                            'sha256': {
                                'default_category': 'Payload delivery',
                                'to_ids': 1
                            },
                            'filename': {
                                'default_category': 'Payload delivery',
                                'to_ids': 1
                            },
                            'domain': {
                                'default_category': 'Network activity',
                                'to_ids': 1
                            }
                        },
                    'types': ['md5', 'sha1', 'sha256', 'filename', 'domain'],
                    'categories':
                        [
                            'Internal reference',
                            'Targeting data',
                            'Antivirus detection'
                        ],
                    'category_type_mappings': {
                        'Internal reference': ['text'],
                        'Targeting data': ['target-user'],
                        'Antivirus detection': ['link'],
                        'Other': ['comment', 'text']}
                }),
            search=MagicMock(
                return_value=[
                    {"Event": {
                        "id": "1",
                        "date": "2014-10-02",
                        "threat_level_id": "1",
                        "info": "Test Event With High Threat Level",
                        "uuid": "542e4c9c-cadc-4f8f-bb11-6d13950d210b"
                    }}
                ]
            )
    ) as patch_misp:
        yield patch_misp


@fixture(scope='function')
def misp_client_error():
    with patch('requests.Session.send') as patch_request:
        patch_request.return_value = mock_api_response(
            status_code=500, text='internal_error'
        )
        yield patch_request


@fixture(scope='module')
def misp_internal_expected_payload(route):
    payload = {
        'errors': [
            {'code': 'unknown',
             'message': 'Unexpected response from MISP: Unable to connect to '
                        'MISP (https://1.2.3.4). Please make sure the API key '
                        'and the URL are correct (http/https is required): '
                        'Error code 500:\ninternal_error',
             'type': 'fatal'
             }
        ]
    }
    return payload


@fixture(scope='module')
def success_observe_body():
    return {
        'data': {
            'verdicts': {
                'count': 1,
                'docs': [
                    {'disposition': 2,
                     'disposition_name': 'Malicious',
                     'observable': {
                         'type': 'ip',
                         'value': '1.1.1.1'
                     },
                     'type': 'verdict'
                     }
                ]
            },
            'judgements': {
                'count': 1,
                'docs': [
                    {'confidence': 'Medium',
                     'severity': 'Medium',
                     'disposition': 2,
                     'disposition_name': 'Malicious',
                     'observable': {
                         'type': 'ip',
                         'value': '1.1.1.1'
                     },
                     'priority': 85,
                     'schema_version': '1.1.5',
                     'source': 'MISP',
                     'type': 'judgement',
                     "source_uri": (
                         "https://1.2.3.4/events/view/"
                         "542e4c9c-cadc-4f8f-bb11-6d13950d210b"
                     ),
                     }
                ]
            }
        }
    }


@fixture(scope='module')
def success_deliberate_body():
    return {
        'data': {
            'verdicts': {
                'count': 1,
                'docs': [
                    {'disposition': 2,
                     'disposition_name': 'Malicious',
                     'observable': {
                         'type': 'ip',
                         'value': '1.1.1.1'
                     },
                     'type': 'verdict'
                     }
                ]
            }
        }
    }


@fixture(scope='module')
def success_enrich_expected_payload(
        route, success_deliberate_body,
        success_observe_body
):
    payload_to_route_match = {
        '/deliberate/observables': success_deliberate_body,
        '/refer/observables': {'data': []},
        '/observe/observables': success_observe_body
    }
    return payload_to_route_match[route]
