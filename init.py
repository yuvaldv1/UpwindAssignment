from flask import Flask
from config import Config


def init_server():
    """
    a function that initializes the server, returns an error if no access token was provided
    :return: the app (server)
    """
    app = Flask(__name__)

    if Config.ACCESS_TOKEN is None:
        print("Environment variable 'GITHUB_ACCESS_TOKEN' is not provided. Shutting down server...")
        exit(1)

    return app
