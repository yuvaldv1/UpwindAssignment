from src.vulnerability_object.vulnerability_obj import Vulnerability
from config import Config
import requests
import json
from src.constants import GITHUB_QUERY

PROVIDER_PATH = "https://api.github.com/graphql"


def check_vulnerability(ecosystem: str, library_name: str, library_version):
    """
    :param ecosystem: the ecosystem of the JSON file
    :param library_name: the name of the library we want to check
    :param library_name: the version of the library we want to check
    :return: a Vulnerability object
    """
    data = None
    # the header for our request. we insert the authorization token
    github_token = Config.ACCESS_TOKEN

    headers = {
        'Authorization': 'Bearer ' + github_token
    }

    # the query`s body, we replace the ecosystem name and the package with the given package name and ecosystem
    query = get_query(ecosystem, library_name)

    # we send the POST request to the provider and save the response
    response = requests.post(url=PROVIDER_PATH, json={'query': query}, headers=headers)
    if response.status_code == 200:
        print("Successfuly received scan result from provider")
        data = json.loads(response.text)
        if ('errors' in data):
            data = None

    else:
        # The request was not successful
        print("Request failed with status code:", response.status_code)

    vulnerability_obj = None
    if data is not None:
        vulnerability_obj = Vulnerability(library_name, library_version, data['data']['securityVulnerabilities']['nodes'])

    return vulnerability_obj

def get_query(ecosystem, library_name):
    """
    a function that returns the query to the provider with the correct format and variables
    :param ecosystem: the ecosystem of the package
    :param library_name: the name of the package
    """
    query = GITHUB_QUERY % (ecosystem.upper(), library_name)
    return query

