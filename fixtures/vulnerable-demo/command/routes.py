from command.runner import shell
def route(request):
    shell(request.args['command'])

