def download(request):
    return open(request.args['path'])
