from flask import Blueprint, request
from src.handlers.scan_handler import scan_handler

# create a new route blueprint
scan_blueprint = Blueprint('scanning_route_BP', __name__)


@scan_blueprint.route('/api/v1/vulnerabilities/scan', methods=['POST'])
def scan():
    """
    a function that calls the handler of the route
    :return: the result of the handler I.E the vulnerabilities
    """
    return scan_handler(request)
