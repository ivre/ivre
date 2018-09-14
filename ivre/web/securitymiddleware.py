import re
import os
import ipaddress
import ivre.web.managementutils as mgmtutils
import ivre.web.commonutils as commonutils
from ivre import utils


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
                '^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9])(?:\s(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9]))*$')
        }

    def __is_error(self, response):
        return response['error']

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
        if not self.message and isinstance(self.type, int) \
                and self.type in [commonutils.AGENT_MSG.GET_IPs, commonutils.BROWSER_MSG.GET_TEMPLATES,
                                  commonutils.COMMON_MSG.GET_SCHED_SCANS]:
            return {
                "error": False,
                "message": "Empty message with type: '{}'".format(self.type),
                "type": -1
            }
        elif self.type is None and self.error:
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

        # Tests by message type

        # From Agent
        if self.is_from_agent:

            if not self.message:
                return {
                    "error": False,
                    "message": "Empty message from agent with type: '{}'".format(self.type),
                    "type": -1
                }
            elif self.type == -1 and self.patterns['information'].match(self.message) is None:
                return {
                    "error": True,
                    "message": "Error message from agent with type: '{}'".format(self.type),
                    "type": -1
                }
            elif self.type == commonutils.COMMON_MSG.RUN_NOW:
                return self.__test_run_now_remote()
            elif 'info_type' in self.message and self.message['info_type'] == commonutils.COMMON_MSG.INFO:
                return self.__test_text()

            return {
                "error": False,
                "message": "Message from agent with type: '{}'".format(self.type),
                "type": -1
            }

        # From Browser
        if self.type in (commonutils.COMMON_MSG.RUN_NOW, commonutils.COMMON_MSG.RNT_JOB):
            run_now_resp, prescan_resp = self.__test_run_now(), self.__test_prescan()
            if self.__is_error(run_now_resp) is True:
                return run_now_resp
            elif self.__is_error(prescan_resp) is True or self.type == commonutils.COMMON_MSG.RUN_NOW:
                return prescan_resp
            elif self.type == commonutils.COMMON_MSG.RNT_JOB:
                return self.__test_run_at()
            # elif self.type == commonutils.COMMON_MSG.SCHEDULE_JOB:
            #     return self.__test_cron_job()

        elif self.type == commonutils.COMMON_MSG.SAVE_IVRE_CONFIG:
            return self.__test_save_ivre_configs()

        elif self.type in (commonutils.COMMON_MSG.GET_PERIODIC_SCAN_STS, commonutils.COMMON_MSG.RM_SCHED_SCAN):
            return self.__test_sched_scan_ops()

    def __test_ip(self, ip_address, comment):
        if self.patterns['ip_address'].match(ip_address) is None:
            return {
                "error": True,
                "message": "Supplied {} IP address is invalid.".format(comment),
                "type": -1
            }
        else:
            try:
                ip_address_valid = ipaddress.ip_address(ip_address.decode("utf-8"))
                ip_address_valid = str(ip_address_valid)
            except ValueError:
                return {
                    "error": True,
                    "message": "Supplied {} IP address is invalid.".format(comment),
                    "type": -1
                }

            return {
                "error": False,
                "ip": ip_address_valid,
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

    def __test_sched_scan_ops(self):
        msg = self.message
        for param in ['scan_id', 'scan_group']:

            if param not in msg or msg[param] is None or not msg[param]:
                return {
                    'error': True,
                    'message': "Parameter '{}' is missing".format(param),
                    "type": -1
                }
            elif param is 'scan_id':
                if self.patterns['scan_id'].match(msg[param]) is None:
                    return {
                        "error": True,
                        "message": "Supplied scan_id is invalid.",
                        "type": -1
                    }
            elif param is 'scan_group' and str(msg[param]) not in ('periodical', 'occasional'):
                return {
                    "error": True,
                    "message": "Supplied scan_group is invalid.",
                    "type": -1
                }

        return {
            "error": False,
            "message": "SCHED_OP remote message is valid!",
            "type": -1
        }

    def __test_run_now_remote(self):
        '''{
            "error": False,
            "message": {
                         "scan_params": params,
                         "name": zip_file_path,
                         "contents": data
             },
            "type": commonutils.COMMON_MSG.RUN_NOW
        }'''
        msg = self.message
        for param in ['scan_params', 'name', 'contents']:

            if param not in msg or not msg[param]:
                return {
                    "error": True,
                    "message": "'{}' is missing".format(param),
                    "type": -1
                }
            elif param is 'name':
                if self.patterns['alphanumeric'].match(msg[param]) is None:
                    return {
                        "error": True,
                        "message": "Ops! something is wrong with the file path",
                        "type": -1
                    }
        return {
            "error": False,
            "message": "RUN_NOW remote message is valid!",
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

    def __test_run_at(self):
        msg = self.message
        if 'run_at' not in msg or 'at_t' not in msg['run_at'] or not msg['run_at']['at_t']:
            return {
                "error": True,
                "message": "Date parameter is missing",
                "type": -1
            }

        if self.patterns['date'].match(msg['run_at']['at_t']) is None:
            return {
                "error": True,
                "message": "Supplied date '{}' is invalid.".format(
                    re.sub(r'[^0-9/: ]', '&lt!&gt;', msg['run_at']['at_t'])),
                "type": -1
            }

        return {
            "error": False,
            "message": "OCCASIONAL params ares valid!",
            "type": -1
        }

    def __test_cron_job(self):
        msg = self.message

        if 'schedule' not in msg or not msg['schedule']:
            return {
                "error": True,
                "message": "Cron parameter is missing",
                "type": -1
            }

        if self.patterns['cron'].match(msg['schedule']) is None:
            return {
                "error": True,
                "message": "Supplied Cron string '{}' is invalid.".format(
                    re.sub(r'[^0-9 *,-/]', '&lt!&gt;', msg['schedule'])),
                "type": -1
            }

        return {
            "error": False,
            "message": "PERIODIC params are valid!",
            "type": -1
        }

    def __test_prescan(self):
        msg = self.message
        if 'prescan' not in msg or not msg['prescan']:
            return {
                "error": True,
                "message": "Prescan parameters are missing",
                "type": -1
            }
        else:
            for p in ['zmap_opts', 'zmap_port', 'nmap_opts', 'nmap_ports']:
                if p not in msg['prescan'] or msg['prescan'][p] is None:
                    return {
                        "error": True,
                        "message": "Prescan parameter '{}' is missing".format(p),
                        "type": -1
                    }
                elif p in ('zmap_opts', 'nmap_opts'):
                    if msg['prescan'][p] and self.patterns['prescan_opts'].match(msg['prescan'][p]) is None:
                        return {
                            "error": True,
                            "message": "Prescan parameter '{}' is invalid".format(p),
                            "type": -1
                        }
                elif p is 'zmap_port':
                    if msg['prescan'][p] and self.patterns['prescan_zmap_port'].match(msg['prescan'][p]) is None:
                        return {
                            "error": True,
                            "message": "Prescan parameter '{}' is invalid".format(p),
                            "type": -1
                        }
                elif p is 'nmap_ports':
                    if msg['prescan'][p] and self.patterns['prescan_nmap_ports'].match(msg['prescan'][p]) is None:
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
        # mayabe it shuld be better to make this a constant in config.py
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
        if not isinstance(msg, dict):
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
