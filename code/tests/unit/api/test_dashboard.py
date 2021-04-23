from collections import namedtuple
from http import HTTPStatus
from unittest.mock import patch

from pytest import fixture
from tests.unit.api.utils import get_headers
from tests.unit.payloads_for_tests import EXPECTED_RESPONSE_OF_JWKS_ENDPOINT

WrongCall = namedtuple('WrongCall', ('endpoint', 'payload', 'message'))


def wrong_calls():
    yield WrongCall(
        '/tiles/tile',
        {'tile-id': 'some_value'},
        "{'tile_id': ['Missing data for required field.'], "
        "'tile-id': ['Unknown field.']}"
    )
    yield WrongCall(
        '/tiles/tile',
        {'tile_id': ''},
        "{'tile_id': ['Field may not be blank.']}"
    )
    yield WrongCall(
        '/tiles/tile-data',
        {'tile-id': 'some_value', 'period': 'some_period'},
        "{'tile_id': ['Missing data for required field.'], "
        "'tile-id': ['Unknown field.']}"
    )
    yield WrongCall(
        '/tiles/tile-data',
        {'tile_id': '', 'period': 'some_period'},
        "{'tile_id': ['Field may not be blank.']}"
    )
    yield WrongCall(
        '/tiles/tile-data',
        {'tile_id': 'some_value', 'not_period': 'some_period'},
        "{'period': ['Missing data for required field.'], "
        "'not_period': ['Unknown field.']}"
    )
    yield WrongCall(
        '/tiles/tile-data',
        {'tile_id': 'some_value', 'period': ''},
        "{'period': ['Field may not be blank.']}"
    )


@fixture(
    scope='module',
    params=wrong_calls(),
    ids=lambda wrong_payload: f'{wrong_payload.endpoint}, '
                              f'{wrong_payload.payload}'
)
def wrong_call(request):
    return request.param


@patch('jwt.PyJWKClient.fetch_data')
def test_dashboard_call_with_wrong_payload(mock_request,
                                           wrong_call, client, valid_jwt,
                                           invalid_json_expected_payload):

    mock_request.return_value = EXPECTED_RESPONSE_OF_JWKS_ENDPOINT

    response = client.post(
        path=wrong_call.endpoint,
        headers=get_headers(valid_jwt()),
        json=wrong_call.payload
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload(
        wrong_call.message
    )


def routes():
    yield '/tiles'
    yield '/tiles/tile'
    yield '/tiles/tile-data'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@patch('jwt.PyJWKClient.fetch_data')
def test_dashboard_call_success(mock_request, route, client, valid_jwt):
    mock_request.return_value = EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    response = client.post(route, headers=get_headers(valid_jwt()))
    assert response.status_code == HTTPStatus.OK
