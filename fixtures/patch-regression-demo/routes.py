def route(request):
    value = request.args['q']
    cursor.execute('SELECT ' + value)
