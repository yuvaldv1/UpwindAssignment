import json
import requests
from config import Config
from packaging import version
import operator


def process_analysis_result(vul_obj, result_list: list):
    """A function that receives a vulnerability object and checks for a relevant
       vulnerability for the package while also appending it to the final list in the 
       correct form.

    Args:
        vul_obj (Vulnerability):
        result_list (list): the final list of vulnerabilities
    """
    # check if the package has any vulnerabilities
    vulnerabilities_list = vul_obj.get_vulnerabilities()
    if len(vulnerabilities_list) is not None:
        for vulnerability in vulnerabilities_list:

            # check if the vulnerability is relevant in regard to version ranges
            is_relevant_vuln = check_library_version_vulnerability(vul_obj.get_lib_ver(),
                                                                   vulnerability['vulnerableVersionRange'])

            # if it is, insert it into the result list
            if is_relevant_vuln:
                node = build_node(vulnerability, vul_obj.get_lib_name(), vul_obj.get_lib_ver())
                result_list.append(node)



def check_library_version_vulnerability(curr_version: str, vulnerability_range: str) -> bool:
    """
    This function checks that curr_version is withing the range of the vulnerability
    :param curr_version: the current version of the library
    :param vulnerability_range: the range of the impacted versions (bottom or top range)
    :return: return True if the library version is impacted, False otherwise
    """

    # a python dictionary used to convert string based boolen operators to their corresponding python functions
    python_operators = {"<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge, "==": operator.eq,
                        "!=": operator.ne}

    # split the range conditions and parse the current version
    conditions = vulnerability_range.split(',')
    curr_version = version.parse(curr_version)

    # for each condition, put together an "if" statement and evaluate it
    for condition in conditions:
        op, version_range = condition.split()

        version_range = version.parse(version_range)

        op_func = python_operators[op]

        # if one of the 'if' statements doesn`t hold, we return False
        if not op_func(curr_version, version_range):
            return False

    # if everything is okay, we have found the relevant vulnerability
    return True


def build_node(vulnerability, library_name, library_version):
    """A function that builds a node for the final list.

    Args:
        vulnerability (dictionary): the relevant vulnerability
        library_name (string): 
        library_version (string): 

    Returns:
        the finished node
    """
    dictionary = {'name': library_name, 'version': library_version, 'severity': vulnerability['severity']}

    # if there is a fixed version, add it as well
    if vulnerability['firstPatchedVersion'] is not None:
        dictionary['firstPatchedVersion'] = vulnerability['firstPatchedVersion']['identifier']

    return dictionary
