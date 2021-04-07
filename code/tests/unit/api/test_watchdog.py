from http import HTTPStatus
from pytest import fixture


def routes():
    yield '/watchdog'


@fixture(scope='module', params=routes(), ids=lambda route: f'GET {route}')
def route(request):
    return request.param


def test_watchdog_call_success(route, client):
    response = client.get(route, headers={'Health-Check': 'test'})

    expected_payload = {'data': 'test'}

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload
