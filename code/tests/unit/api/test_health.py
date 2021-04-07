from http import HTTPStatus
from unittest.mock import patch

from pytest import fixture

from .utils import get_headers
from ..payloads_for_tests import EXPECTED_RESPONSE_OF_JWKS_ENDPOINT


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@patch('jwt.PyJWKClient.fetch_data')
def test_health_call_success(mock_request, route, client, valid_jwt):
    mock_request.return_value = EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    response = client.post(route, headers=get_headers(valid_jwt()))
    assert response.status_code == HTTPStatus.OK
