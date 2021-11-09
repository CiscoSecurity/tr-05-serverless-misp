from collections import namedtuple
from http import HTTPStatus

from pytest import fixture


Call = namedtuple('Call', ('method', 'route', 'expected_status_code'))


def calls():
    yield Call('POST', '/post', HTTPStatus.NOT_FOUND)
    yield Call('GET', '/get', HTTPStatus.NOT_FOUND)
    yield Call('PUT', '/put', HTTPStatus.NOT_FOUND)
    yield Call('DELETE', '/delete', HTTPStatus.NOT_FOUND)

    yield Call('GET', '/version', HTTPStatus.METHOD_NOT_ALLOWED)
    yield Call('GET', '/health', HTTPStatus.METHOD_NOT_ALLOWED)
    yield Call('GET', '/deliberate/observables', HTTPStatus.METHOD_NOT_ALLOWED)
    yield Call('GET', '/observe/observables', HTTPStatus.METHOD_NOT_ALLOWED)
    yield Call('GET', '/refer/observables', HTTPStatus.METHOD_NOT_ALLOWED)
    yield Call('POST', '/watchdog', HTTPStatus.METHOD_NOT_ALLOWED)


@fixture(scope='module',
         params=calls(),
         ids=lambda call: f'{call.method} {call.route}')
def call(request):
    return request.param


def test_non_relay_call_failure(call, client):
    response = client.open(call.route, method=call.method)
    assert response.status_code == call.expected_status_code
