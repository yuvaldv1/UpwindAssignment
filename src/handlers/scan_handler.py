from config import Config
from src.providers import github_scanner
import base64
import json
from src.helpers.scan_helper import process_analysis_result


def scan_handler(request):
    """
    :return: returns a list of the vulnerable packages in the required form
    """
    vulnerable_packages = list()

    body = request.get_json()

    ecosystem = body.get('ecosystem')

    file_content = body.get('fileContent')

    if ecosystem is None or file_content is None:
        return 'Missing Parameter, Make sure to send ecosystem and fileContent', 401

    decoded_file_content = base64.b64decode(file_content).decode('utf-8')

    jsonified_file_content = json.loads(decoded_file_content)

    libraries = jsonified_file_content['dependencies']


    # for each library, check if its vulnerable and analyze the result
    for library_name in libraries:
        scan_result = None
        if Config.PROVIDER == 'GITHUB':
            scan_result = github_scanner.check_vulnerability(ecosystem, library_name, libraries[library_name])
        #elif: another provider, call it`s check_vulnerability function instead

        if scan_result is not None:
            process_analysis_result(scan_result, vulnerable_packages)
        else:
            error = "Error while scanning vulnerabilities of %s" % library_name
            return error, 500


    return {"vulnerablePackages": vulnerable_packages}, 200


