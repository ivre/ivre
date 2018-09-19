import re
import os
import ivre.web.managementutils as mgmtutils
import ivre.web.commonutils as commonutils
from ivre import utils
from croniter import croniter
try:
    import ipaddress
except ImportError:
    # fallback to dict for Python 2.6
    from IPy import IP
from sys import modules as imported_modules


# TODO
# Deny access by default
class SecurityMiddleware(object):
    def __init__(self, body):
        self.message = body['message']
        self.agent_ip = body['agent_ip'] if 'agent_ip' in body and body['agent_ip'] else None
        self.type = body['type'] if 'type' in body else None
        self.is_from_agent = body['is_from_agent'] if 'is_from_agent' in body else None
        self.error = body['error'] if 'error' in body else None
        self.patterns = {
            'alphanumeric': re.compile('^([0-9]|[a-zA-Z]|_|-)+$'),
            'information': re.compile('^([-A-Za-z0-9+&@#/%?=~_|!:,.;\(\)])+$'),
            'ip_address': re.compile('^([A-F0-9a-f]|\.|:)+$'),
            'date': re.compile(
                '^((((19|[2-9]\d)\d{2})[/.-](0[13578]|1[02])[/.-](0[1-9]|[12]\d|3[01])\s(0[0-9]|1[0-9]|2[0-3]):([0-5][0-9]))|(((19|[2-9]\d)\d{2})[/.-](0[13456789]|1[012])[/.-](0[1-9]|[12]\d|30)\s(0[0-9]|1[0-9]|2[0-3]):([0-5][0-9]))|(((19|[2-9]\d)\d{2})[/.-](02)[/.-](0[1-9]|1\d|2[0-9])\s(0[0-9]|1[0-9]|2[0-3]):([0-5][0-9]))|(((1[6-9]|[2-9]\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00))[/.-](02)[/.-](29)\s(0[0-9]|1[0-9]|2[0-3]):([0-5][0-9])))$'),
            'cron': re.compile(
                '^(((\*|([0-9]|[1-5][0-9]?))|\*(/([0-9]|[1-5][0-9]))?)|(([0-9]|[1-5][0-8]?)-([0-5]|[1-5][0-9])))(,(((\*|([0-9]|[1-5][0-9]?))|\*(/([0-9]|[1-5][0-9]))?)|(([0-9]|[1-5][0-8]?)-([0-5]|[1-5][0-9]))))*\s(((\*|([0-1]?[0-9]|2[0-3]?))|\*(/([0-1]?[0-9]|2[0-3]))?)|(([0-1]?[0-9]|2[0-3]?)-([0-1]?[0-9]|2[0-3])))(,(((\*|([0-1]?[0-9]|2[0-3]?))|\*(/([0-1]?[0-9]|2[0-3]))?)|(([0-1]?[0-9]|2[0-3]?)\-([0-1]?[0-9]|2[0-3]))))*\s(\?|(((\*|([0-9]|[0-2][0-9]|3[0-1]?))|\*(/([0-9]|[0-2][0-9]|3[0-1]))?)|(([0-9]|[0-2][0-9]|3[0-1]?)\-([0-9]|[0-2][0-9]|3[0-1]))|([0-9]|[0-2][0-9]|3[0-1]?))(,(((\*|([0-9]|[0-2][0-9]|3[0-1]?))|\*(/([0-9]|[0-2][0-9]|3[0-1]))?)|(([0-9]|[0-2][0-9]|3[0-1]?)\-([0-9]|[0-2][0-9]|3[0-1]))|(\d\d?W)))*)\s(((\*|(\d|10|11|12|JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC))(/\d\d?)?)|((\d|10|11|12|JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)-(\d|10|11|12|JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)))(,(((\*|(\d|10|11|12|JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC))(/\d\d?)?)|((\d|10|11|12|JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)-(\d|10|11|12|JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC))))*\s(((\*|([0-7]|MON|TUE|WED|THU|FRI|SAT|SUN)L?)(/\d\d?)?)|(([0-7]|MON|TUE|WED|THU|FRI|SAT|SUN)L?-([0-7]|MON|TUE|WED|THU|FRI|SAT|SUN)L?)|([0-7]|MON|TUE|WED|THU|FRI|SAT|SUN)L?#([1-5]))(,(((\*|([0-7]|MON|TUE|WED|THU|FRI|SAT|SUN)L?)(/\d\d?)?)|(([0-7]|MON|TUE|WED|THU|FRI|SAT|SUN)L?-([0-7]|MON|TUE|WED|THU|FRI|SAT|SUN)L?)|([0-7]|MON|TUE|WED|THU|FRI|SAT|SUN)L?#([1-5])))*$'),
            'scan_id': re.compile('^([0-9]|[a-zA-Z]|_|-|\.|\[|\]|\s|/|:)+$'),
            'ip_exclude_list': re.compile('^([A-F0-9a-f]|\.|:|-|/|,)+$'),
            'prescan_opts': re.compile('^([0-9]|[a-zA-Z]|:|,|\s|-)+([0-9a-zA-Z]+|:|,|\s|-)$'),
            'prescan_zmap_port': re.compile(
                '^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9])$'),
            'prescan_nmap_ports': re.compile(
                '^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9])(?:\s(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9]))*$'),
            'mongo_allowed': re.compile(r'^[^$\'\"\\;{}]+$', re.M),
            'base64': re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
        }

    @staticmethod
    def __is_error(response):
        return response['error'] if isinstance(response, dict) and 'error' in response else response

    @staticmethod
    def validate_certificates(cert_path):
        cert_chain = {'key': None, 'crt': None, 'pem': None}

        if cert_path and not mgmtutils.is_valid_path(cert_path):
            return {
                "error": True,
                "message": 'Chosen certificates directory does not exists: {0}'.format(cert_path),
                "type": -1
            }
        else:

            certs_in_dir = os.listdir(cert_path)
            cert_extensions = ['.key', '.crt', '.pem']

            if len(certs_in_dir) != 3:
                return {
                    "error": True,
                    "message": 'Chosen certificates directory must contain a: .key, .crt and CA\'s .pem files only.',
                    "type": -1
                }

            for f in certs_in_dir:
                cert_file_path = os.path.join(cert_path, f)
                cert_ext = os.path.splitext(f)[1]
                if not mgmtutils.is_root(cert_file_path):
                    return {
                        "error": True,
                        "message": 'File with wrong permissions or owned not by root only: {0}'.format(cert_file_path),
                        "type": -1
                    }
                elif os.path.isfile(cert_file_path) and cert_ext in cert_extensions:
                    cert_extensions.remove(cert_ext)
                    cert_chain[cert_ext.replace('.', '')] = cert_file_path

            if cert_extensions:
                return {
                    "error": True,
                    "message": 'Chosen certificates directory does not contain these files: {0}'.format(
                        cert_extensions),
                    "type": -1
                }

            return {
                "error": False,
                "message": cert_chain,
                "type": -1
            }

    def validate_message(self):

        # basic tests
        if self.type is None and self.error:
            return {
                "error": False,
                "message": "Exception message!",
                "type": -1
            }
        elif isinstance(self.type, int) is False:
            return {
                "error": True,
                "message": "Invalid type <INT>: '{}'".format(
                    re.sub(r'[^0-9]', '*', str(self.type))),
                "type": -1
            }
        elif self.agent_ip is not None:
            agent_ip = self.__test_ip(self.agent_ip, 'agent_ip')
            if self.__is_error(agent_ip):
                return agent_ip
            else:
                self.agent_ip = agent_ip

        banned_root_keys = [p for p in self.message if '$' in p]
        if banned_root_keys:
            return self.__basic_error('"$" is not allowed in {}'.format(banned_root_keys))

        # Tests by message type

        if self.type in [commonutils.COMMON_MSG.RUN_NOW, commonutils.COMMON_MSG.RNT_JOB,
                         commonutils.COMMON_MSG.PRD_JOB]:
            return self.__test_ivre_task()

        elif self.type == commonutils.AGENT_MSG.TASK_RESULT:
            return self.__test_post_results()

        elif self.type == commonutils.AGENT_MSG.ACK:
            return self.__test_post_status()

        elif self.type == commonutils.AGENT_MSG.PASSIVE_RESULT:
            try:
                return self.__test_passive_detection()
            except Exception as e:
                utils.LOGGER.exception('[SecurityMiddleware - test_passive_detection] Exception: {}'.format(e))

        elif self.type == commonutils.COMMON_MSG.SAVE_IVRE_CONFIG:
            return self.__test_save_ivre_configs()

    def __test_ip(self, ip_address, comment):
        if self.patterns['ip_address'].match(ip_address) is None:
            return {
                "error": True,
                "message": "Supplied {} IP address is invalid.".format(comment),
                "type": -1
            }
        else:
            try:
                ip_address_valid = ip_address.decode("utf-8")
                if 'ipaddress' in imported_modules:
                    ip_address_valid = ipaddress.ip_address(ip_address_valid)
                elif 'IPy' in imported_modules:
                    ip_address_valid = IP(ip_address_valid)
            except ValueError:
                return {
                    "error": True,
                    "message": "Supplied {} IP address is invalid.".format(comment),
                    "type": -1
                }

            return {
                "error": False,
                "ip": str(ip_address_valid),
                "type": -1
            }

    def __test_text(self):
        if not self.message or self.patterns['information'].match(self.message) is None:
            return {
                "error": True,
                "message": "Supplied informative message is invalid",
                "type": -1
            }

        return {
            "error": False,
            "message": "Informative message is valid!",
            "type": -1
        }

    def __test_post_status(self):
        """
        {
            'message':{
                'task_id': <IGNORED>,
                'status': /commonutils.TASK_STS.*|commonutils.TMPLT_STS.*/
            },
            'type': commonutils.AGENT_MSG.ACK
        }
        """
        msg = self.message
        tasks_dict = commonutils.TASK_STS.__dict__
        templates_dict = commonutils.TMPLT_STS.__dict__
        allowed_tasks_sts = [tasks_dict[i] for i in tasks_dict.keys() if not i.startswith('__')]
        allowed_tmplt_sts = [templates_dict[i] for i in templates_dict.keys() if not i.startswith('__')]
        allowed_statuses = allowed_tasks_sts + allowed_tmplt_sts
        if 'status' not in msg:
            return self.__basic_error('status is missing!')
        elif not isinstance(msg['status'], int):
            return self.__basic_error('status must be an Integer.')
        elif not msg['status'] in allowed_statuses:
            return self.__basic_error('Status {} not allowed.'.format(msg['status']))

        return True

    def __test_ivre_task(self):
        msg = self.message

        if 'task' not in msg:
            return self.__basic_error('task is missing.')

        test_res = self.__test_scan_params(msg['task'])
        if self.__is_error(test_res):
            return test_res

        if self.type == commonutils.COMMON_MSG.RNT_JOB or ('run_at' in msg['task'] and msg['task']['run_at']):
            test_res = self.__test_run_at(msg['task'])
            if self.__is_error(test_res):
                return test_res

        if self.type == commonutils.COMMON_MSG.PRD_JOB or ('schedule' in msg['task'] and msg['task']['schedule']):
            test_res = self.__test_cron_job(msg['task'])
            if self.__is_error(test_res):
                return test_res

        return True

    def __test_post_results(self):
        """
        {
            "message": {
                "status": <INT>
                "scan_params": {
                    "nmap_template": <STRING>,
                    "name":"<STRING>",
                    "campaign":"<STRING>",
                    "schedule": <STRING>,
                    "ip":{
                    "start": <IP>,
                    "end": <IP>
                    },
                    "run_at":{
                        "hour": <INT>,
                        "month": <INT>,
                        "minute": <INT>,
                        "year": <INT>,
                        "day": <INT>,
                        "at_t": <DATETIME YYYY/MM/DD HH:mm>
                    },
                    "source":"source1",
                    "prescan":{
                        "notReally":"sure"
                    }
                "result": <BASE_64>
                }
            }
            "type": 105 / AGENT_MSG.TASK_RESULT
        }
        :return: dict
        """
        msg = self.message
        if self.type != commonutils.AGENT_MSG.TASK_RESULT:
            return self.__basic_error('Wrong message type: {}'.format(None))

        if 'status' not in msg:
            return self.__basic_error('Task\'s status is missing!')
        elif not isinstance(msg['status'], int):
            return self.__basic_error('Task\'s status must be an integer!')

        if 'scan_params' not in msg:
            return self.__basic_error('scan_params parameter is missing!')
        else:
            test_res = self.__test_scan_params(msg['scan_params'])
            if self.__is_error(test_res):
                return test_res

        if 'result' not in msg:
            return self.__basic_error('result parameter is missing!')
        elif self.patterns['base64'].match(msg['result']) is None:
            return self.__basic_error('result must be Base64 encoded.')

        if 'task_id' not in msg:
            return self.__basic_error('task_id parameter is missing!')
        elif self.patterns['alphanumeric'].match(msg['task_id']) is None:
            return self.__basic_error('Supplied parameter \'{0}\' contains invalid character/s: \'{1}\''.format(
                            re.sub(r'[^a-zA-Z0-9_-]', '*', msg['task_id']),
                            "".join(re.findall(r'[^a-zA-Z0-9_-]', msg['task_id']))
                        )
            )

        return True

    def __test_passive_detection(self):
        """
        {
            "uid" : "<STRING>",
            "recon_type" : "<STRING>",
            "ts" : <FLOAT/INT>,
            "value" : "<STRING>",
            "source" : "<STRING>",
            "host" : "<IP>",
            "srvport" : <INT>
        }
        :return: dict
        """
        msg = self.message

        for p in msg:
            if p in ['uid', 'recon_type', 'ts', 'value', 'source', 'host', 'srvport']:
                if p in ['uid', 'recon_type', 'value', 'source']:
                    res = self.__mongo_string(p, msg[p])
                    if self.__is_error(res):
                        return res
                elif p == 'host':
                    res = self.__test_ip(msg[p], '')
                    if self.__is_error(res):
                        return res
                elif p == 'srvport' and not isinstance(msg[p], int):
                    return self.__basic_error('"srvport" must be an Integer')
                elif p == 'ts' and not (isinstance(msg[p], float) or isinstance(msg[p], int)):
                    return self.__basic_error('"ts" must be a Number')
        return {
            "error": False,
            "message": "PASSIVE message is valid!",
            "type": -1
        }

    def __test_run_now(self):
        """
        {
        'body':{
            'message':{
                'nmap_template': STRING,
                'name': STRING,
                'campaign': STRING,
                'schedule': CRON_STRING,
                'ip':{
                    'start': IP,
                    'end': IP
                },
                'run_at':{
                    'hour': INT,
                    'month': INT,
                    'minute': INT,
                    'year': INT,
                    'day': INT,
                    'at_t': 'YYYY/MM/DD HH:mm'
                '},
                'source': STRING,
                'type':34
                },
                'type':34
            },
            'type':34
        }
        :return: boolean
        """
        msg = self.message

        # STRING test
        for param in ['nmap_template', 'name', 'campaign', 'source', 'ip']:

            if param not in msg or not msg[param]:
                return {
                    "error": True,
                    "message": "'{}' is missing".format(param),
                    "type": -1
                }
            if param is 'ip':
                for key in ['start', 'end']:
                    if key not in msg['ip'] or not msg['ip'][key]:
                        return {
                            "error": True,
                            "message": "'{}' is missing".format(param),
                            "type": -1
                        }
            else:
                if self.patterns['alphanumeric'].match(msg[param]) is None:
                    return {
                        "error": True,
                        "message": "Supplied parameter '{0}' contains invalid character/s: '{1}'".format(
                            re.sub(r'[^a-zA-Z0-9_-]', '&lt!&gt;', msg[param]),
                            "".join(re.findall(r'[^a-zA-Z0-9_-]', msg[param]))
                        ),
                        "type": -1
                    }

        # IP test
        ip_start, ip_end = self.__test_ip(msg['ip']['start'], 'start'), self.__test_ip(msg['ip']['end'], 'end')
        if self.__is_error(ip_start) is True:
            return ip_start
        elif self.__is_error(ip_end) is True:
            return ip_end
        elif ip_end['ip'] < ip_start['ip']:
            return {
                "error": True,
                "message": "Supplied IP address range is invalid.",
                "type": -1
            }

        msg['ip']['start'], msg['ip']['end'] = ip_start['ip'], ip_end['ip']

        return {
            "error": False,
            "message": "RUN_NOW message is valid!",
            "type": -1
        }

    def __test_run_at(self, task):
        if 'run_at' not in task or not task['run_at'] or 'at_t' not in task['run_at'] or not task['run_at']['at_t']:
            return {
                "error": True,
                "message": "Date parameter is missing",
                "type": -1
            }

        if not isinstance(task['run_at']['at_t'], str):
            return self.__basic_error('at_t parameter must be a string')

        if self.patterns['date'].match(task['run_at']['at_t']) is None:
            return {
                "error": True,
                "message": "Supplied date '{}' is invalid.".format(
                    re.sub(r'[^0-9/: ]', '*', task['run_at']['at_t'])),
                "type": -1
            }

        return {
            "error": False,
            "message": "OCCASIONAL params ares valid!",
            "type": -1
        }

    def __test_cron_job(self, task):
        if 'schedule' not in task or not task['schedule']:
            return {
                "error": True,
                "message": "Cron parameter is missing",
                "type": -1
            }

        if self.patterns['cron'].match(task['schedule']) is None:
            return {
                "error": True,
                "message": "Supplied Cron string '{}' is invalid.".format(
                    re.sub(r'[^0-9 *,-/]', '[*]', task['schedule'])),
                "type": -1
            }
        try:
            if not croniter.is_valid(task['schedule']):
                return self.__basic_error('Cron string is NOT valid')
        except Exception as e:
            return self.__basic_error('Cron string validation exception: {}'.format(e))

        return {
            "error": False,
            "message": "PERIODIC params are valid!",
            "type": -1
        }

    def __test_prescan(self, prescan_params):
        for p in ['zmap_opts', 'zmap_port', 'nmap_opts', 'nmap_ports']:
            param = prescan_params[p] if p in prescan_params else None
            if param is None:
                return {
                    "error": True,
                    "message": "Prescan parameter '{}' is missing".format(p),
                    "type": -1
                }
            elif p in ('zmap_opts', 'nmap_opts'):
                if param and self.patterns['prescan_opts'].match(param) is None:
                    return {
                        "error": True,
                        "message": "Prescan parameter '{}' is invalid".format(p),
                        "type": -1
                    }
            elif p is 'zmap_port':
                if param and self.patterns['prescan_zmap_port'].match(param) is None:
                    return {
                        "error": True,
                        "message": "Prescan parameter '{}' is invalid".format(p),
                        "type": -1
                    }
            elif p is 'nmap_ports':
                if param and self.patterns['prescan_nmap_ports'].match(param) is None:
                    return {
                        "error": True,
                        "message": "Prescan parameter '{}' is invalid".format(p),
                        "type": -1
                    }

        return {
            "error": False,
            "message": "PRESCAN params are valid!",
            "type": -1
        }

    def __test_save_ivre_configs(self):
        '''
        {
        'body': {
            u 'message': {
                u 'traceroute': BOOLEAN,
                u 'name': u STRING,
                u 'pings': u 'STRING',
                u 'osdetect': BOOLEAN,
                u 'exclude': IP_NMAP_SYNTAX,
                u 'categories': [STRING],
                u 'scans': u 'STRING'
            }, u 'type': 0
        },
        'type': 0
        }
        :return:
        '''
        msg = self.message
        # maybe it should be better to make this a constant in config.py
        default_conf = {
            'nmap': 'nmap',
            'pings': 'SE',
            'scans': 'SV',
            'osdetect': True,
            'traceroute': True,
            'resolve': 1,
            'verbosity': 2,
            'ports': None,
            'host_timeout': '15m',
            'script_timeout': '2m',
            'scripts_categories': ['default', 'discovery',
                                   'auth'],
            'scripts_exclude': ['broadcast', 'brute', 'dos',
                                'exploit', 'external', 'fuzzer',
                                'intrusive'],
            'scripts_force': None,
            'extra_options': None,
        }

        if 'template' not in msg:
            return {
                'error': True,
                'message': "'template' field is missing",
                'type': -1
            }
        elif 'templateName' not in msg:
            return {
                'error': True,
                'message': "'templateName' field is missing",
                'type': -1
            }

        template = msg['template']
        if not isinstance(template, dict):
            return {
                'error': True,
                'message': "Template is not valid",
                'type': -1
            }
        if self.patterns['alphanumeric'].match(msg['templateName']) is None:
            return {
                "error": True,
                "message": "Supplied parameter '{0}' contains invalid character/s: '{1}'".format(
                    re.sub(r'[^a-zA-Z0-9_-]', '*', msg['templateName']),
                    "".join(re.findall(r'[^a-zA-Z0-9_-]', msg['templateName']))
                ),
                "type": -1
            }

        for param in template.keys():

            if param not in default_conf:
                return {
                    'error': True,
                    'message': "Unknown template parameter '{}'".format(param),
                    'type': -1
                }

            if param in ['traceroute', 'osdetect']:
                if param in template and not isinstance(template[param], bool):
                    return {
                        'error': True,
                        'message': "Parameter template {} must be a boolean".format(param),
                        'type': -1
                    }

            elif param in template and param == 'name' and (
                    not template[param] or self.patterns['alphanumeric'].match(template[param]) is None):
                return {
                    'error': True,
                    'message': "Supplied template name is invalid.",
                    'type': -1
                }

            elif param in template and param == 'pings' and [p for p in template[param] if
                                                        p not in ['S', 'E', 'n', 'A', 'U', 'Y', 'P', 'M']]:
                utils.LOGGER.info(
                    "__test_save_ivre_configs: %s",
                    str(template[param]),
                )
                return {
                    'error': True,
                    'message': "Supplied host discovery option/s is/are invalid.",
                    'type': -1
                }

            elif param in template and param == 'scans' and [s for s in template[param] if
                                                        s not in ['S', 'V', 'T', 'A', 'W', 'M', 'N', 'F', 'X', 'Y',
                                                                  'Z']]:
                return {
                    'error': True,
                    'message': "Supplied scan techniques option/s is/are invalid.",
                    'type': -1
                }

            elif param in template and param == 'scripts_categories':
                all_categories = ['auth', 'broadcast', 'brute', 'default', 'discovery', 'dos', 'exploit', 'external',
                                  'fuzzer', 'intrusive', 'malware', 'safe', 'version', 'vuln']
                categories = [c for c in template['scripts_categories'] if c not in all_categories]
                if categories:
                    return {
                        'error': True,
                        'message': "Supplied categorie/s {0} is/are invalid".format(categories),
                        'type': -1
                    }

            elif param in template and param == 'exclude':
                if isinstance(template[param], list) and template[param]:
                    for ip in template[param]:
                        if ip and re.match(self.patterns['ip_exclude_list'], ip) is None:
                            return {
                                'error': True,
                                'message': "Supplied <b>exclude list</b> is invalid. Check this out: https://nmap.org/book/man-target-specification.html",
                                'type': -1
                            }
                else:
                    return {
                        'error': True,
                        'message': "Supplied exclude list format is invalid.",
                        'type': -1
                    }
            elif param in template and param == 'performance':
                pparams = mgmtutils.parse_performance_params(template[param])
                if isinstance(pparams, list) and template[param]:
                    for pparam in pparams:
                        if self.patterns['alphanumeric'].match(pparam) is None:
                            return {
                                'error': True,
                                'message': "Supplied <b>{}</b> is invalid.".format(pparam),
                                'type': -1
                            }
                else:
                    return {
                        'error': True,
                        'message': "Supplied performance params list format is invalid.",
                        'type': -1
                    }
        return {
            "error": False,
            "message": "SAVE_CONF message is valid!",
            "type": -1
        }

    def __test_scan_params(self, params):
        """
        :param params: {
                            "nmap_template": <STRING>,
                            "name":"<STRING>",
                            "campaign":"<STRING>",
                            "schedule": <CRON_STRING>,
                            "ip":{
                                "start": <IP>,
                                "end": <IP>
                            },
                            "run_at":{
                                "hour": <INT>,
                                "month": <INT>,
                                "minute": <INT>,
                                "year": <INT>,
                                "day": <INT>,
                                "at_t": <DATETIME YYYY/MM/DD HH:mm>
                            },
                            "source":"source1",
                            "prescan":{
                                "notReally":"sure"
                            }
                        }
        :return:
        """

        # STRING test
        for param in ['nmap_template', 'name', 'campaign', 'source', 'ip']:

            if param not in params or not params[param]:
                return {
                    "error": True,
                    "message": "'{}' is missing".format(param),
                    "type": -1
                }
            if param is 'ip':
                for key in ['start', 'end']:
                    if key not in params['ip'] or not params['ip'][key]:
                        return {
                            "error": True,
                            "message": "'{}' is missing".format(param),
                            "type": -1
                        }
            else:
                if self.patterns['alphanumeric'].match(params[param]) is None:
                    return {
                        "error": True,
                        "message": "Supplied parameter '{0}' contains invalid character/s: '{1}'".format(
                            re.sub(r'[^a-zA-Z0-9_-]', '*', params[param]),
                            "".join(re.findall(r'[^a-zA-Z0-9_-]', params[param]))
                        ),
                        "type": -1
                    }
        if 'prescan' in params and params['prescan']:
            test_res = self.__test_prescan(params['prescan'])
            if self.__is_error(test_res):
                return test_res

        # IP test
        ip_start, ip_end = self.__test_ip(params['ip']['start'], 'start'), self.__test_ip(params['ip']['end'], 'end')
        if self.__is_error(ip_start) is True:
            return ip_start
        elif self.__is_error(ip_end) is True:
            return ip_end
        elif ip_end['ip'] < ip_start['ip']:
            return {
                "error": True,
                "message": "Supplied IP address range is invalid.",
                "type": -1
            }

        params['ip']['start'], params['ip']['end'] = ip_start['ip'], ip_end['ip']

        return {
            "error": False,
            "message": "Scan params are valid!",
            "type": -1
        }

    @staticmethod
    def __basic_error(message):
        return {
            "error": True,
            "message": message,
            "type": -1
        }

    def __mongo_string(self, param_name, param):
        if type(param) is not str:
            return self.__basic_error('{} must be a String.'.format(param_name))
        elif self.patterns['mongo_allowed'].match(param) is None:
            return self.__basic_error("Supplied parameter '{0}' contains invalid character/s: '{1}'".format(
                re.sub(r'[$\'\"\\;{}]', '*', param),
                "".join(re.findall(r'[$\'\"\\;{}]', param))))
        return False
