from pytest import fixture
from http import HTTPStatus
from tests.unit.api.utils import get_headers
from unittest.mock import patch
from tests.unit.payloads_for_tests import EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
from tests.unit.conftest import mock_events


def routes():
    yield '/deliberate/observables'
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def invalid_json_value():
    return [{'type': 'ip', 'value': ''}]


@patch('api.enrich.create_misp_instance')
@patch('jwt.PyJWKClient.fetch_data')
def test_enrich_call_with_valid_jwt_but_invalid_json_value(
        mock_request, mock_instance, misp_client,
        route, client, valid_jwt, invalid_json_value,
        invalid_json_expected_payload
):
    mock_request.return_value = EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    response = client.post(route,
                           headers=get_headers(valid_jwt()),
                           json=invalid_json_value)
    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload(
        "{0: {'value': ['Field may not be blank.']}}"
    )


@patch('api.enrich.create_misp_instance')
@patch('jwt.PyJWKClient.fetch_data')
def test_enrich_call_success(mock_request, mock_instance, misp_client,
                             success_enrich_expected_payload,
                             route, client, valid_jwt, valid_json):
    mock_request.return_value = EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    mock_instance.return_value = mock_events()
    response = client.post(route, headers=get_headers(valid_jwt()),
                           json=valid_json)
    assert response.status_code == HTTPStatus.OK
    response = response.get_json()

    if route != '/refer/observables':
        if route == '/observe/observables':
            for doc in response['data']['verdicts']['docs']:
                assert doc.pop('judgement_id')
            for doc in response['data']['judgements']['docs']:
                assert doc.pop('valid_time')
                assert doc.pop('id')
            for doc in response['data']['sightings']['docs']:
                assert doc.pop('id')
            for doc in response['data']['relationships']['docs']:
                assert doc.pop('id')
                assert doc.pop('source_ref')

        for doc in response['data']['verdicts']['docs']:
            assert doc.pop('valid_time')
    assert response == success_enrich_expected_payload


@fixture(scope='module')
def valid_json():
    return [{'type': 'ip', 'value': '1.1.1.1'}]


@fixture(scope='module')
def unsupported_type_json():
    return [{'type': 'unsupported_type', 'value': '1.1.1.1'}]


@patch('api.enrich.create_misp_instance')
@patch('jwt.PyJWKClient.fetch_data')
def test_enrich_call_with_unsupported_type_json(
        mock_request, mock_instance,
        misp_client, unsupported_type_expected_body,
        route, client, valid_jwt, unsupported_type_json
):
    mock_request.return_value = EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    response = client.post(route, headers=get_headers(valid_jwt()),
                           json=unsupported_type_json)
    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == unsupported_type_expected_body
