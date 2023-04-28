import init
from src.routes.scan_routes import scan_blueprint

# initalize the server
app = init.init_server()

# register the scanning route, meaning the server will now listen to requests to this route
app.register_blueprint(scan_blueprint)

# start the server
app.run()
