def handler(request):
    name = request.args["name"]
    cursor.execute("SELECT * FROM users WHERE name = ?", [name])
