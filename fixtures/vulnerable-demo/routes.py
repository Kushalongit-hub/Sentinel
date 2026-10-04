from service import create_user

def handler(request):
    name = request.args["name"]
    return create_user(name)
