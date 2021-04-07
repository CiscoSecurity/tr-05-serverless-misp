def get_headers(jwt, auth_type='Bearer'):
    return {'Authorization': f'{auth_type} {jwt}'}
