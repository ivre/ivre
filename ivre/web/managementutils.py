#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import os
import time
import json
import pprint
import base64
import shutil
import logging.config
import shlex
from string import Template
from subprocess import Popen, STDOUT, PIPE
from threading import Lock, Thread
from ivre.tools import runscans
import ivre.utils as utils
import ivre.web.commonutils as commonutils
lock = Lock()


SERVER_WORKING_DIR = "/tmp/ivre"
AGENT_WORKING_DIR = os.path.join(os.getcwd(), 'ivre_httpagent/')
CONFIG_FILE = '.ivre.conf'
CONFIG_DIR = os.path.join(os.path.expanduser('~'))
# NMAP_SCAN_TEMPLATES = config.NMAP_SCAN_TEMPLATES

# Logging configuration and setup.
AgentLoggingConfig = dict(
    version=1,
    formatters={
        'consoleFormat': {
            'format': '%(message)s'
        },
        'fileFormat': {
            'format': '%(asctime)s %(name)-12s %(levelname)-8s %(message)s'
        }
    },
    handlers={
        'consoleHandler': {
            'class': 'logging.StreamHandler',
            'formatter': 'consoleFormat',
            'level': logging.INFO
        },
        'rootHandler': {
            'class': 'logging.FileHandler',
            'formatter': 'fileFormat',
            'filename': '/var/log/dyne-general.log',
            'mode': 'a',
            'level': logging.DEBUG
        },
        'agentHandler': {
            'class': 'logging.FileHandler',
            'formatter': 'fileFormat',
            'filename': '/var/log/dyne-agent.log',
            'mode': 'a',
            'level': logging.DEBUG
        }
    },
    loggers={
        'dyne.wsagent': {
            'handlers': ['agentHandler'],
            'level': logging.DEBUG,
            'propagate': False
        }
    },
    root={
        'handlers': ['consoleHandler', 'rootHandler'],
        'level': logging.INFO
    }
)


# TODO solve log problem
# logging.config.dictConfig(loggingConfig)
# log = logging.getLogger("ivre")
def running_as_root():
    return os.getuid() == 0


if running_as_root():
    logging.config.dictConfig(AgentLoggingConfig)
    log = logging.getLogger("dyne.wsagent")
else:
    log = utils.LOGGER


def extract_occasional_scan_info(scan):
    at_t = scan["run_at"]["at_t"]
    try:
        future_event = time.mktime(time.strptime(at_t, '%Y/%m/%d %H:%M'))
        future_event = time.mktime(time.localtime(future_event))
    except Exception as e:
        return {
            "error": True,
            "message": str(e)
        }
    now = time.time()
    delay = int((future_event - now))

    return {"delay": delay, "error": False}


def parse_performance_params(raw_performance_params):
    performance_params = []
    pparams = raw_performance_params.split(' ')
    for pparam in pparams:
        param_istance = pparam.replace('_', '-')
        param_istance_list = param_istance.split('=')
        for p in param_istance_list:
            if p is not '' and p is not None:
                performance_params.append(p)
    return performance_params


def add_template(name, conf_json, exclude=None):
    from ivre import config
    try:
        pings = conf_json['pings'] if 'pings' in conf_json else None
        scans = conf_json['scans'] if 'scans' in conf_json else None
        osdetect = conf_json['osdetect'] if 'osdetect' in conf_json else None
        traceroute = conf_json['traceroute'] if 'traceroute' in conf_json else None
        scripts_categories = conf_json['scripts_categories'] if 'scripts_categories' in conf_json else None
        scripts_exclude = conf_json['scripts_exclude'] if 'scripts_exclude' in conf_json else None
        raw_performance = conf_json['performance'] if 'performance' in conf_json else None
        performance_params = parse_performance_params(raw_performance) if raw_performance is not None else None

        addr_exclude = [addr.strip() for addr in exclude] if exclude is not None else None
        # config_dir = str(working_dir).replace('ivrescans', '')
        # if working_dir == SERVER_WORKING_DIR:
        #     config_dir = "{0}{1}".format(config_dir, 'html/')

        config_template_file = os.path.join(CONFIG_DIR, '.ivre.conf.template')
        config_file = os.path.join(CONFIG_DIR, '.ivre.conf')
        # log.debug('config_template_file = ' + config_template_file)
        # log.debug('config_file = ' + config_file)
        if not os.path.exists(config_template_file):
            error = 'Error occurred while trying to save IVRE configs. {} do not exists.'.format(config_template_file)
            log.error(error)
            return {
                "error": True,
                "message": error
            }
        if not os.path.exists(config_file):
            error = 'Error occurred while trying to save IVRE configs. {} do not exists.'.format(config_file)
            log.error(error)
            return {
                "error": True,
                "message": error
            }

        # log.debug(performance_params)
        extra_options = performance_params

        d = {
            'host_timeout': '15m',  # default value: None
            'script_timeout': '2m',  # default value: None
            'pings': str(pings) if pings else None,
            'scans': str(scans) if scans else None,
            'osdetect': osdetect if osdetect else None,
            'traceroute': traceroute if traceroute else None,
            'scripts_categories': scripts_categories if scripts_categories else None,
            'scripts_exclude': scripts_exclude if scripts_exclude else None,
            'exclude': addr_exclude if addr_exclude else None,
            'extra_options': extra_options if extra_options else None
        }
        # log.debug('d = {}'.format(d))
        for k in d.keys():
            if d[k] is None:
                del d[k]
        # template = src.substitute(d)

        # log.debug('d = {}'.format(d))
        # print template

        # inserts template into Nmap templates
        current_templates = config.NMAP_SCAN_TEMPLATES
        current_templates[name] = d
        current_templates = pprint.pformat(current_templates, width=200)

        res = __write_templates_to_file(current_templates, name=name)
        return res

    except Exception as e:
        import sys
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        log.error('Something went wrong... stopping. Exception: {}'.format(e))

        return {
            "error": True,
            "message": "Error while saving configs: '{}'".format(e.args)
        }


def __write_templates_to_file(current_templates, name=None, ip=None):
    """
    :type name: basestring
    :type ip: list of str
    """
    # creates a new configuration file
    config_template_file = os.path.join(CONFIG_DIR, '.ivre.conf.template')
    config_file = os.path.join(CONFIG_DIR, '.ivre.conf')
    filein = open(config_template_file)
    src = Template(filein.read())
    filein.close()
    d = {
        'templates': current_templates
    }
    result = src.substitute(d)
    lock.acquire()
    try:
        fileout = open(config_file, 'w')
        try:
            fileout.write(result)
        finally:
            fileout.close()
    except IOError as e:
        return {
            "error": True,
            "message": "writing error : '{}'".format(e)
        }
    lock.release()
    # TODO front-end needs saved templates?
    # return create_template_response(commonutils.COMMON_MSG.SAVE_IVRE_CONFIG)
    if name:
        return {
            "error": False,
            "message": 'Template {} was correctly imported.'.format(name)
        }
    elif ip:
        return {
            "error": False,
            "message": 'IP {} was correctly excluded by all templates.'.format(', '.join(ip))
        }


def add_excluded_ip_to_template(detection, agent):
    """
    :param detection: dict
    :type agent: AgentClient
    """
    from ivre import config
    log.info('new detection: {}'.format(detection))
    if detection and 'source' in detection and detection['source'] == 'MODBUS_MASTER':
        agent.add_excluded_ip(detection['host'])

    for ip in agent.get_excluded_ip():
        for key in config.NMAP_SCAN_TEMPLATES:
            if "exclude" not in config.NMAP_SCAN_TEMPLATES[key]:
                config.NMAP_SCAN_TEMPLATES[key]["exclude"] = [ip]
            else:
                if ip not in config.NMAP_SCAN_TEMPLATES[key]["exclude"]:
                    config.NMAP_SCAN_TEMPLATES[key]["exclude"].append(ip)

    if agent.get_excluded_ip():
        current_templates = config.NMAP_SCAN_TEMPLATES
        current_templates = pprint.pformat(current_templates, width=200)
        res = __write_templates_to_file(current_templates, ip=agent.get_excluded_ip())
        log.info(res['message'] if 'message' in res else res)


def is_valid_path(path):
    if os.path.exists(path) and os.path.isdir(path):
        return True
    return False


def is_root(file_path):
    import stat
    file_stat = os.stat(file_path)
    bits = oct(stat.S_IMODE(file_stat[stat.ST_MODE]))
    return True if file_stat.st_uid == 0 and file_stat.st_gid == 0 and bits == '0600' else False


def create_dir(dir_path):
    if os.path.exists(dir_path):
        if not os.path.isdir(dir_path):
            log.error('%s already exists but isn\'t a directory', dir_path)
            exit(1)
        else:
            log.debug('No need to create %s as it already exists', dir_path)
    else:
        os.makedirs(dir_path)


def run_passive_scan(params, agent):
    """
    :param params: agent_conf
    :type agent: AgentClient ref
    """

    def handle_output(out):
        for stdout_line in iter(out.readline, ''):
            try:
                detection = json.loads(stdout_line)
                agent.post_passive_detection(detection)
                add_excluded_ip_to_template(detection, agent)
            except Exception as e:
                log.error('Exception while importing ip from passive detection: {}'.format(e))
                log.error('Exception caused by detection: {}'.format(stdout_line))
        out.close()

    cmd = "{} -b {} -i {} -e 'redef LogAscii::use_json=T;'".format(
        params['bro_path'],
        params['bro_script'],
        params['bro_interface'],
    )
    cmd = shlex.split(cmd)
    process = Popen(cmd, stdout=PIPE, stderr=STDOUT)
    t = Thread(target=handle_output, args=(process.stdout,))
    t.daemon = True  # thread dies with the program
    t.start()


def run_ivre_scan(params):
    """Executes a scan using IVRE runscans and automatically imports the results.

    if from_agent == True
        the scan is performed by a DyNE agent
    else
        is performed by the DyNe server


    :type params: dict
    :type from_agent: bool
    :rtype: dict
    """
    try:
        startAddress = params['ip']['start']
        endAddress = params['ip']['end']
        template = params['nmap_template']
        campaign = params['campaign']
        source = params['source']

        # This regular expression is just to ensure there isn't any
        # invalid characters for an IP address. Its purpose isn't to
        # properly validate IPv4/IPv6.
        patternIP = re.compile("[A-F0-9a-f\.:]+")

        if patternIP.match(startAddress) is None:
            return {
                "error": True,
                "message": "Supplied start IP address is invalid."
            }

        if patternIP.match(endAddress) is None:
            return {
                "error": True,
                "message": "Supplied end IP address is invalid."
            }

        patternTmpl = re.compile("[A-Za-z0-9\-\_]+")

        if patternTmpl.match(template) is None:
            return {
                "error": True,
                "message": "Supplied template name is invalid."
            }

        patternOther = re.compile("[A-Za-z0-9\-\_,]+")

        if patternOther.match(campaign) is None:
            return {
                "error": True,
                "message": "Supplied campaign name is invalid."
            }

        if patternOther.match(source) is None:
            return {
                "error": True,
                "message": "Supplied source name is invalid."
            }

        args = {'routable': True, 'range': [startAddress, endAddress], 'nmap-template': template,
                'output': 'XMLFork', 'again': ['all']}
        if 'prescan' in params and params['prescan'] is not None:
            if 'zmap_port' in params['prescan'] and params['prescan']['zmap_port']:
                args['zmap-prescan-port'] = params['prescan']['zmap_port']
            if 'zmap_opts' in params['prescan'] and params['prescan']['zmap_opts']:
                args['zmap-prescan-opts'] = params['prescan']['zmap_opts']
            if 'nmap_ports' in params['prescan'] and params['prescan']['nmap_ports']:
                args['nmap-prescan-ports'] = params['prescan']['nmap_ports']
            if 'nmap_opts' in params['prescan'] and params['prescan']['nmap_opts']:
                args['nmap-prescan-opts'] = params['prescan']['nmap_opts']

        log.debug('run_ivre_scan: About to execute the with following args %s', args)
        runscans.run(args)

        current_time = str(int(round(time.time() * 1000)))
        zip_file_path, destination_path = [p.format(startAddress, endAddress) for p in
                                           ['/scan_{0}-{1}__' + current_time,
                                            './scans/RANGE-{0}-{1}/up']]
        zip_file_path = zip_file_path.replace(".", "_")
        shutil.make_archive(AGENT_WORKING_DIR + zip_file_path, 'zip', destination_path)

        try:
            with open(AGENT_WORKING_DIR + zip_file_path + '.zip', 'rb') as f:
                data = base64.b64encode(f.read())

            f.close()
            scan_zip = {
                "scan_params": params,
                "name": zip_file_path.replace('/', ''),
                "contents": data
            }

            log.info(
                "run_ivre_scan: Scan %s has terminated with success: results has been packed and are ready to be sent",
                params['name'])

            return {
                "error": False,
                "message": scan_zip,
                "type": commonutils.COMMON_MSG.RUN_NOW
            }

        except Exception as e:
            log.exception("run_ivre_scan: Scan results packing failed with: {}".format(e))

            return {
                "error": True,
                "message": "Agent scan failed with: {0}".format(e)
            }

    except Exception as e:
        log.exception("run_ivre_scan: Scan execution failed with: {}".format(e))

        return {
            "error": True,
            "message": "Scan execution failed with: {0}".format(e)
        }


# TODO this functionality needs to be ported
def import_scada_devices():
    from ivre.utils import int2ip
    from ivre.db import db
    import glob
    database = db.nmap

    try:
        def gettoarchive(addr, source):
            return database.get(
                database.flt_and(database.searchhost(addr),
                                 database.searchsource(source))
            )

        tmp_dir = '/tmp/scada_devices'
        create_dir(tmp_dir)

        for i, p in enumerate(db.passive.get(db.passive.flt_empty)):
            if "MODBUS_SLAVE" in p["recontype"]:
                tmp_file_name = '{0}/tmp_{1}.xml'.format(tmp_dir, int2ip(p["addr"]))
                write_file_safely(tmp_file_name, fake_nmap_result(p["firstseen"], p["firstseen"], int2ip(p["addr"])))

        count = 0
        for filename in glob.glob(os.path.join(tmp_dir, '*.xml')):
            try:
                if database.store_scan(
                        filename,
                        categories=['SCADA_test'], source='SCADA_test',
                        needports=False, needopenports=False,
                        gettoarchive=gettoarchive, force_info=False,
                        merge=True, masscan_probes=None
                ):
                    count += 1
            except Exception as e:
                return {
                    'error': True,
                    'message': "Something went wrong while importing results from passive db: {}".format(e)
                }
        return {
            'error': False,
            'message': "{} <b>SCADA devices</b> imported.".format(count),
            "type": commonutils.BROWSER_MSG.SCAN_IMPORT
        }
    except Exception as e:
        return {
            'error': True,
            'message': "Something went wrong while importing scada devices: {}".format(e)
        }


def write_file_safely(fname, data):
    f = open(fname, 'w')
    f.write(data)
    f.flush()
    os.fsync(f.fileno())
    f.close()


def fake_nmap_result(firstseen, lastseen, addr):
    nmap_result = Template("""<nmaprun scanner="nmap">
                        <host starttime="$firstseen" endtime="$lastseen">
                            <status state="up" reason="syn-ack" reason_ttl="61"/>
                            <address addr="$addr" addrtype="ipv4"/>
                            <ports>
                                <port protocol="tcp" portid="502">
                                    <state state="open" reason="syn-ack" reason_ttl="61"/>
                                </port>
                            </ports>
                        </host>
                    </nmaprun>""")
    return nmap_result.substitute({
        'firstseen': int(time.mktime(time.localtime(firstseen))),
        'lastseen': int(time.mktime(time.localtime(lastseen))),
        'addr': str(addr)
    })
