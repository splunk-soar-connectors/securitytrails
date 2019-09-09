# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import requests
import json
from bs4 import BeautifulSoup

class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class SecuritytrailsConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(SecuritytrailsConnector, self).__init__()

        self._state = None
        self._base_url = None

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        try:
            url = self._base_url.encode('utf-8', 'ignore').decode('utf-8')
        except:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid base_url. Enter the Valid vaule.")

        url = self._base_url + endpoint

        api_key = config.get('api_key')

        if headers:
            headers = headers
        else:
            headers = {'APIKEY': api_key}

        try:
            r = request_func(
                            url,
                            data=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            params=params)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to SecurityTrails test endpoint")

        endpoint = '/ping/'

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            message = "Test Connectivity Failed for SecurityTrails. {}".format(str(response) if response else ''))
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_domain(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']
        endpoint = '/domain/{}'.format(domain)

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            message = "Failed Response to Lookup Domain."
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        data_output = {}
        ipv4_array = []

        for ip in response['current_dns']['a']['values']:
            ipv4_array.append({"type": "a", "ip": ip['ip']})

        data_output['a'] = ipv4_array
        ipv6_array = []

        for ip in response['current_dns']['aaaa']['values']:
            ipv6_array.append({"type": "aaaa", "ipv6": ip['ipv6']})

        data_output['aaaa'] = ipv6_array

        data_output['alexa_rank'] = response['alexa_rank']

        data_output['hostname'] = response['hostname']

        action_result.add_data(data_output)

        summary = action_result.update_summary({})
        summary['domain'] = domain

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_whois_domain(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']
        endpoint = '/domain/{}/whois'.format(domain)

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            message = "Failed Response to whois Domain."
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        data_output = response
        action_result.add_data(data_output)

        summary = action_result.update_summary({})
        summary['domain'] = domain

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_whois_history(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']
        endpoint = '/history/{}/whois?page=1'.format(domain)

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            message = "Failed Response to whois history."
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        data_output = response
        action_result.add_data(data_output)

        summary = action_result.update_summary({})
        summary['domain'] = domain

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_domain_searcher(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()
        api_key = config.get('api_key')
        endpoint = '/search/list'

        header_new = {'Content-Type': 'application/json', 'APIKEY': api_key}

        search_filter = param['filter']
        search_filter_string = param['filterstring']
        keyword = param['keyword']

        if keyword:
            output_params = {search_filter: search_filter_string, "keyword": keyword }
        else:
            output_params = {search_filter: search_filter_string}

        values = {}
        valid_filter = [
            "ipv4",
            "ipv6",
            "mx",
            "ns",
            "cname",
            "subdomain",
            "apex_domain",
            "soa_email",
            "tld",
            "whois_email",
            "whois_street1",
            "whois_street2",
            "whois_street3",
            "whois_street4",
            "whois_telephone",
            "whois_postalCode",
            "whois_organization",
            "whois_name",
            "whois_fax",
            "whois_city",
            "keyword"]

        for key, value in output_params.iteritems():
            if key not in valid_filter:
                message = ("{} is not a valid filter. Ignoring this key.Valid formats are: {}".format(str(key), str(", ".join(valid_filter))))
                return action_result.set_status(phantom.APP_ERROR, status_message=message)
            else:
                values['filter'] = output_params

        if values['filter']:
            json_dumps_values = json.dumps(values)
            ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=header_new, method="post", data=json_dumps_values)

        if (phantom.is_fail(ret_val)):
            message = ("Domain Searcher Failed: {} request received a non 200 response.".format(endpoint))
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        data_output = {}
        data_output = response
        action_result.add_data(data_output)

        summary = action_result.update_summary({})
        summary['filter'] = output_params

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_domain_category(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']
        endpoint = '/domain/{}/tags'.format(domain)

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            message = "Failed Response to domain category."
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        try:
            response['tags'][0]

        except:
            response['tags'] = "No Results"

        data_output = {}
        data_output = response
        action_result.add_data(data_output)

        summary = action_result.update_summary({})
        summary['domain'] = domain
        summary['tags'] = data_output['tags']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_domain_subdomain(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']
        endpoint = '/domain/{}/subdomains'.format(domain)

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            message = "Failed Response to domain subdomain."
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        outputArray = []

        for a in response['subdomains']:
            outputArray.append({"domain": a + "." + domain})

        data_output = outputArray
        action_result.add_data(data_output)

        summary = action_result.update_summary({})
        summary['domain'] = domain

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_domain_history(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']
        record_type = param['record_type']
        record_type = record_type.lower()
        type_check = ['a', 'aaaa', 'mx', 'ns', 'txt', 'soa']

        if record_type in type_check:
            endpoint = '/history/{}/dns/{}?page=1'.format(domain, record_type)
            ret_val, response = self._make_rest_call(endpoint, action_result)
        else:
            message = "Incorrect record_type {}. Allowed Records {}".format(record_type, ", ".join(type_check))
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            message = "Failed Response to domain history."
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        outputArray = []
        i = 1
        while i <= response['pages']:
            for a in response['records']:
                for value in a['values']:
                    option = {}
                    if len(a['organizations']) == 1:
                        option['organizations'] = a['organizations'][0]
                    else:
                        option['organizations'] = a['organizations']
                    option['first_seen'] = a['first_seen']
                    option['last_seen'] = a['last_seen']
                    option['ip'] = value['ip']
                    outputArray.append(option)
            i += 1
            endpoint = '/history/{}/dns/{}?page={}'.format(domain, record_type, i)

            self.save_progress("Downloading Page {} of output".format(i))

            ret_val, response = self._make_rest_call(endpoint, action_result)

            if (phantom.is_fail(ret_val)):
                message = "Failed Response to domain history for page {} of response.".format(i)
                return action_result.set_status(phantom.APP_ERROR, status_message=message)

        results = {"results": outputArray, "domain": domain}
        resultsJson = json.loads(json.dumps(results))
        data_output = resultsJson
        action_result.add_data(data_output)

        summary = action_result.update_summary({})
        summary['domain'] = data_output['domain']

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'lookup_domain':
            ret_val = self._handle_lookup_domain(param)

        elif action_id == 'whois_domain':
            ret_val = self._handle_whois_domain(param)

        elif action_id == 'whois_history':
            ret_val = self._handle_whois_history(param)

        elif action_id == 'domain_searcher':
            ret_val = self._handle_domain_searcher(param)

        elif action_id == 'domain_category':
            ret_val = self._handle_domain_category(param)

        elif action_id == 'domain_subdomain':
            ret_val = self._handle_domain_subdomain(param)

        elif action_id == 'domain_history':
            ret_val = self._handle_domain_history(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = config.get('base_url')

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            login_url = BaseConnector._get_phantom_base_url() + "login"
            print ("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print ("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SecuritytrailsConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
