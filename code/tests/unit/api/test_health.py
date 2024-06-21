from http import HTTPStatus
from unittest.mock import patch, MagicMock

from pytest import fixture

from tests.unit.api.utils import get_headers
from tests.unit.payloads_for_tests import EXPECTED_RESPONSE_OF_JWKS_ENDPOINT


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@patch('api.health.create_misp_instance')
@patch('jwt.PyJWKClient.fetch_data')
def test_health_call_success(mock_request, mock_instance,
                             route, client, valid_jwt, misp_client):
    mock_request.return_value = EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    mock_instance.return_value = MagicMock()
    response = client.post(route, headers=get_headers(valid_jwt()))
    assert response.status_code == HTTPStatus.OK
    assert response.json == {'data': {'status': 'ok'}}
