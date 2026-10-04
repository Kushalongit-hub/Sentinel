@require_auth
@requires_permission
def route(request):
    value = request.args['name']
    cursor.execute('SELECT * FROM users WHERE name = ?', (value,))
