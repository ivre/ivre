#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import os
import ast
import time
import json
import pprint
import base64
import pickle
import shutil
import zipfile
import datetime
import logging.config
import shlex
from random import randint
from string import Template
from subprocess import Popen, check_output, STDOUT, PIPE

from crontab import CronTab
from threading import Lock, Thread
lock = Lock()

# import ivre.config as config
from ivre import utils

# from concurrent.futures import ProcessPoolExecutor

SERVER_WORKING_DIR = "/tmp/ivre"
AGENT_WORKING_DIR = '/home/vm/to_delete/ivre'
CONFIG_FILE = '.ivre.conf'
CONFIG_DIR = os.path.join(os.path.expanduser('~'))
# NMAP_SCAN_TEMPLATES = config.NMAP_SCAN_TEMPLATES


class AGENT_MSG:
    GET_IPs = 100
    SET_TEMPLATES = 101
    # SCA only
    OVERWRITE_CONF = 102
    SET_RESULTS_PATH = 103
    TASK_RESULT = 105
    ACK = 200


class BROWSER_MSG:
    GET_TEMPLATES = 1
    SCAN_IMPORT = 2


# class TASK_STS:
#     RECEIVED = -1
#     PENDING = 0
#     COMPLETED = 1
#     PERIODIC = 10
#     PRD_PENDING_PAUSE = 11
#     PERIODIC_PAUSED = 12
#     PRD_PENDING_RESUME = 13
#     ERROR = 99
#     PENDING_CANC = 500
#     CANCELLED = 501


class COMMON_MSG:
    SAVE_IVRE_CONFIG = 0
    INFO = 29
    RM_SCHED_SCAN = 30
    GET_SCHED_SCANS = 31
    GET_PERIODIC_SCAN_STS = 32
    PRD_JOB = 33
    RNT_JOB = 34
    RUN_NOW = 35


class Timer(object):
    def __init__(self, timeout):
        self.timeout = timeout
        self.start = time.time()

    def has_expired(self):
        return True if int(time.time() - self.start) > self.timeout else False


# Logging configuration and setup.
loggingConfig = dict(
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

anti_brute = {
    'set_results_path': {},
    'MIN_WAIT': 2,
    'MAX_WAIT': 10
}

timeouts = []
# executor = ProcessPoolExecutor(max_workers=1)
# agent_executor = ProcessPoolExecutor(max_workers=1)

working_dir = None
results_path = None
wsBrowser = []
wsAgents = []

# used for async scans
ws_server = None

# logging.config.dictConfig(loggingConfig)
# TODO solve log problem
log = logging.getLogger("ivre")
# logging.config.dictConfig(loggingConfig)
# # log = logging.getLogger("dyne.wsagent")


def agent_handler(response):
    log.info("Agent %s", response.result())


# def start_agent_client(use_tls):
#     import wsagent
#     tornado.ioloop.IOLoop.instance().add_future(agent_executor.submit(wsagent.start_agent, use_tls), agent_handler)


def random_with_n_digits(n):
    range_start = 10 ** (n - 1)
    range_end = (10 ** n) - 1
    return randint(range_start, range_end)


def is_brute(func):
    if 'start' not in anti_brute[func] or anti_brute[func]['start'] is None:
        anti_brute[func]['start'] = time.time()
        return False
    else:
        elapsed = time.time() - anti_brute[func]['start']
        if elapsed < randint(anti_brute['MIN_WAIT'], anti_brute['MAX_WAIT']):
            return True
        else:
            anti_brute[func]['start'] = time.time()
            return False


def normalize_msg(message):
    return json.dumps(message) if isinstance(message, dict) else message


def getConnetedAgentIPs(web_response):
    IPs = []
    for ws in wsAgents:
        ip = ws.get_request_ip()
        if ip not in IPs:
            IPs.append(ip)

    if not web_response:
        return IPs

    return json.dumps({
        "error": False,
        "message": IPs,
        "type": AGENT_MSG.GET_IPs
    })


def schedule_periodical_scan(scan, scan_type):
    try:
        cron_string = scan['schedule']
        comment = scan_type + "[" + str(random_with_n_digits(3)) + "]-" + scan['ip']['start'] + "-" + scan['ip'][
            'end'] + "-" + scan['campaign'] + "-" + scan['nmap_template']
        ivre_runscans = "ivre runscans --routable --range {0} {1} --nmap-template {2} --output=XMLFork --again all".format(
            scan['ip']['start'],
            scan['ip']['end'],
            scan['nmap_template']
        )
        ivre_scan2db = "ivre scan2db -c {0} -s {1} --archive -r {2}".format(
            scan['campaign'],
            scan['source'],
            working_dir + "/scans/RANGE-{0}-{1}/up".format(scan['ip']['start'], scan['ip']['end'])
        )
        command = "cd {0} && {1}; {2} >> {3}/CRON_LOG".format(
            working_dir,
            ivre_runscans,
            ivre_scan2db,
            working_dir
        )

        write_cron_job(cron_string, command, comment)
        return json.dumps({
            "error": False,
            "message": "Nmap scan %s has been scheduled!" % (scan['name']),
            "type": COMMON_MSG.SCHEDULE_JOB
        })
    except Exception as e:
        return json.dumps({
            "error": True,
            "message": "Runscans exception: '{}'".format(e)
        })


def change_job_status(comment):
    cron = CronTab(user=True)
    job_iter = cron.find_comment(comment)
    for j in job_iter:
        j.enable(not j.is_enabled())
    cron.write()


def get_scheduled_scans():
    cron = CronTab(user=True)
    periodical_scans, occasional_scans = [], []
    map(lambda job: periodical_scans.append(str(job)), cron)
    map(lambda timeout: occasional_scans.append(timeout["scan"]), timeouts)

    return json.dumps({
        "error": False,
        "message": {
            "periodical_scans": periodical_scans,
            "occasional_scans": occasional_scans
        },
        "type": COMMON_MSG.GET_SCHED_SCANS
    })


def remove_job(comment):
    cron = CronTab(user=True)
    cron.remove_all(comment=comment)
    cron.write()
    return json.dumps({
        "error": False,
        "name": comment,
        "message": "ack",
        "type": COMMON_MSG.RM_SCHED_SCAN
    })


def get_job_status(comment):
    cron = CronTab(user=True)
    job_iter = cron.find_comment(comment)
    for j in job_iter:
        return json.dumps({
            "error": False,
            "message": "job '%s' status: %s" % (comment, "Enabled" if j.is_enabled() else "Disabled"),
            "name": comment,
            "status": True if j.is_enabled() else False,
            "type": COMMON_MSG.GET_PERIODIC_SCAN_STS
        })
    return json.dumps({
        "error": True,
        "message": "Scan not found!",
        "type": COMMON_MSG.INFO
    })


# TODO
# Needs to be checked if it is vulnerable to path transversals which may lead to random file overwrites.
# Need to check if scan["name"] has been sanitized before reaching this function. Also pickle as been known for
# code execution vulnerabilities when (un)serializing files (content sanitization?).
def save_scheduled_at_scan(scan):
    scan_name = scan["name"]
    with open(working_dir + '/scheduled_scans/' + scan_name + '.dyne', 'wb') as handle:
        pickle.dump(scan, handle)


def read_serialized_at_scan(file_name):
    with open(working_dir + '/scheduled_scans/' + file_name, 'rb') as handle:
        return pickle.loads(handle.read())


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


def set_timeout(data):
    global timeouts
    timeout = tornado.ioloop.IOLoop.instance() \
        .add_timeout(datetime.timedelta(milliseconds=data['delay']),
                     run_parallel_scan, data['scan'], COMMON_MSG.RNT_JOB, data['from_agent'])
    timeouts.append({"at_t": data['at_t'], "timeout": timeout, "scan": data['scan']})


def schedule_scan_at(scan, from_agent):
    try:
        # save it just in case of crash
        save_scheduled_at_scan(scan)

        # schedule the scan
        data = extract_occasional_scan_info(scan)
        data['from_agent'] = from_agent
        set_timeout(data)

        return json.dumps({
            "error": False,
            "message": "Scan scheduled at: " + data['at_t'],
            "type": COMMON_MSG.RNT_JOB
        })

    except Exception as e:
        return json.dumps({
            "error": True,
            "message": "Schedule scan at exception: '{}'".format(e)
        })


def cancel_scheduled_scan(message):
    try:
        if message["scan_group"] == "occasional":
            return cancel_occasional_scan(message["scan_id"])
        else:
            return remove_job(message["scan_id"])
    except Exception as e:
        log.exception("Cancel scheduled scan failed")
        return json.dumps({
            "error": True,
            "message": "cancel_scheduled_scan: '{}'".format(e)
        })


def cancel_occasional_scan(at_t):
    try:
        for t in timeouts:
            if t["at_t"] == at_t:
                tornado.ioloop.IOLoop.instance().remove_timeout(t["timeout"])
                remove_completed_scan(at_t)

                return json.dumps({
                    "error": False,
                    "name": at_t,
                    "message": "ack",
                    "type": COMMON_MSG.RM_SCHED_SCAN
                })

        return json.dumps({
            "error": True,
            "message": "Scan not found!",
            "type": COMMON_MSG.INFO
        })

    except Exception as e:
        log.debug("Cancel occasional scan failed")


def remove_completed_scan(at_t):
    global timeouts
    try:
        map(lambda timeout: os.remove(working_dir + '/scheduled_scans/' + timeout['scan']['name'] + '.dyne'),
            filter(lambda timeout: timeout['at_t'] == at_t, timeouts))
        timeouts = filter(lambda timeout: timeout['at_t'] != at_t, timeouts)
    except Exception as e:
        log.exception("Removed complete scan failed")


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
    logging.config.dictConfig(loggingConfig)
    log = logging.getLogger("dyne.wsagent")
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
    # return create_template_response(COMMON_MSG.SAVE_IVRE_CONFIG)
    if name:
        return {
            "error": False,
            "message": 'Template {} was correctly imported.'.format(name)
        }
    elif ip:
        return {
            "error": False,
            "message": 'IP {} was correctly excluded by all templates.'.format(name)
        }


def add_excluded_ip_to_template(detection, agent):
    """
    :param detection: dict
    :type agent: AgentClient
    """
    from ivre import config
    logging.config.dictConfig(loggingConfig)
    log = logging.getLogger("dyne.wsagent")
    log.info('new detection: {}'.format(detection))
    if 'source' in detection and detection['source'] == 'MODBUS_MASTER':
        ip = detection['host']
        agent.add_excluded_ip(ip)
        for key in config.NMAP_SCAN_TEMPLATES:
            if "exclude" not in config.NMAP_SCAN_TEMPLATES[key]:
                config.NMAP_SCAN_TEMPLATES[key]["exclude"] = [ip]
            else:
                if ip not in config.NMAP_SCAN_TEMPLATES[key]["exclude"]:
                    config.NMAP_SCAN_TEMPLATES[key]["exclude"].append(ip)

        current_templates = config.NMAP_SCAN_TEMPLATES
        current_templates = pprint.pformat(current_templates, width=200)
        res = __write_templates_to_file(current_templates, ip=ip)
        log.info(res['message'] if 'message' in res['message'] else res)


# TODO
# check file path
def overwrite_ivre_configs(conf_file):
    try:
        fileout = open('/var/www/html/.ivre.conf', 'w')
        try:
            fileout.write(conf_file)
        finally:
            fileout.close()
    except IOError as e:
        log.exception("Configuration writing error")

        return json.dumps({
            "error": True,
            "message": "Configuration writing error: {0}".format(e)
        })

    reload(config)
    return create_template_response(COMMON_MSG.SAVE_IVRE_CONFIG)


def is_valid_path(path):
    if os.path.exists(path) and os.path.isdir(path):
        return True
    return False


def is_root(file_path):
    import stat
    file_stat = os.stat(file_path)
    bits = oct(stat.S_IMODE(file_stat[stat.ST_MODE]))
    return True if file_stat.st_uid == 0 and file_stat.st_gid == 0 and bits == '0600' else False


# TODO
# what if path is set as root dir?
def set_results_path(path):
    global results_path

    if is_brute('set_results_path'):
        return {
            "error": True,
            "message": "Please slow down!"
        }

    if not is_valid_path(path):
        return {
            "error": True,
            "message": "{} does not exists or it's not a directory ".format(path)
        }

    results_path = path
    log.info("Results path changed to %s", results_path)

    return json.dumps({
        "error": False,
        "message": 'All future scan\'s results will be saved at {}'.format(results_path),
        "type": AGENT_MSG.SET_RESULTS_PATH
    })


def create_dir(dir_path):
    if os.path.exists(dir_path):
        if not os.path.isdir(dir_path):
            log.error('%s already exists but isn\'t a directory', dir_path)
            exit(1)
        else:
            log.debug('No need to create %s as it already exists', dir_path)
    else:
        os.makedirs(dir_path)


def safe_unzip(zip_file, extractpath='.'):
    with zipfile.ZipFile(zip_file, 'r') as zf:
        for member in zf.infolist():
            abspath = os.path.abspath(os.path.join(extractpath, member.filename))
            if abspath.startswith(os.path.abspath(extractpath)):
                zf.extract(member, extractpath)


# TODO
# This code will need to be checked against malicious ZIP files
def import_scans_from_b64zip(name, scan_params, zip64):
    try:
        map(lambda p: create_dir(p.format(SERVER_WORKING_DIR)), ['{0}', '{0}/remote_scans', '{0}/unzipped'])
        bin_file = base64.b64decode(zip64)
        scan_name = name
        zip_name = scan_name + "__" + str(int(round(time.time() * 1000)))
        zip_location = SERVER_WORKING_DIR + '/remote_scans/' + zip_name + '.zip'

        with open(zip_location, "wb") as zip_file:
            zip_file.write(bin_file)

        safe_unzip(zip_location, SERVER_WORKING_DIR + '/unzipped/' + zip_name)

        unzipped_location = {
            "working_dir": SERVER_WORKING_DIR,
            "sub_dir": '/unzipped/' + zip_name
        }
        return import_scans(scan_params, unzipped_location)

    except Exception as e:
        log.exception("Importing remote scan files failed")

        return json.dumps({
            "error": True,
            "message": "Importing remote scan files failed with: {0}".format(e)
        })


# TODO
# Elements from both the params and location dictionary need to be validated against
# command execution as most of them can be (malicious) user provided.
def import_scans(params, location):
    campaign = params['campaign']
    source = params['source']

    # Invoke ivre scan2db.
    cmd = "ivre scan2db -c {0} -s {1} -r {2}{3}".format(
        campaign,
        source,
        location["working_dir"],
        location["sub_dir"]
    )

    utils.LOGGER.info('[RESULT-IMPORT] About to execute the following command: %s', cmd)

    out = check_output(cmd, shell=True, stderr=STDOUT, cwd=location["working_dir"])

    return {
        "error": False,
        "message": "Scan '%s' has terminated: %s" % (params['name'], out),
        "scan_params": params,
        "type": BROWSER_MSG.SCAN_IMPORT
    }


def local_scan_result_handler(response):
    try:
        message = response.result()
        log.debug('Result handler message: %s', message)

        if isinstance(message, dict) and 'scan_params' in message and 'at_t' in message['scan_params']['run_at']:
            remove_completed_scan(message['scan_params']['run_at']['at_t'])

        wsSendAllBrowsers(message)

    except Exception as e:
        log.exception('Local scan result handler failed')


def remote_scan_result_handler(response):
    try:
        message = response.result()
        if isinstance(message, dict) and not message['error'] and 'at_t' in message['message']['scan_params']["run_at"]:
            remove_completed_scan(message['message']['scan_params']['run_at']['at_t'])
            log.info('Scan %s results sent with success', message['message']['scan_params']['name'])
        ws_send_remote_scan(normalize_msg(message))
    except Exception as e:
        log.exception('Remote scan result handler failed')


# def run_parallel_scan(params, scan_type, from_agent):
#     global results_path
#     try:
#
#         if scan_type == COMMON_MSG.RNT_JOB:
#             params["status"] = "running"
#
#         params['cwd'] = working_dir if results_path is None else results_path
#
#         if from_agent:
#             tornado.ioloop.IOLoop.current() \
#                 .add_future(executor.submit(run_ivre_scan, params, from_agent), remote_scan_result_handler)
#         else:
#             tornado.ioloop.IOLoop.current() \
#                 .add_future(executor.submit(run_ivre_scan, params, from_agent), local_scan_result_handler)
#
#         return json.dumps({
#             "error": False,
#             "message": 'An IVRE scan has been started: you don\'t have to wait for the results, '
#                        'they will be automatically imported (you will see a notification)',
#             "type": COMMON_MSG.INFO,
#             "info_type": COMMON_MSG.INFO if from_agent else None
#         })
#     except Exception as e:
#         log.exception('Run parallel scan failed')

def run_passive_scan(params, agent):
    """
    :param params: agent_conf
    :type agent: AgentClient ref
    """
    logging.config.dictConfig(loggingConfig)
    log = logging.getLogger("dyne.wsagent")
    def handle_output(out):
        for stdout_line in iter(out.readline, ''):
            try:
                detection = json.loads(stdout_line)
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
    # for stdout_line in iter(process.stdout.readline, ""):
    #     try:
    #         detection = json.loads(stdout_line)
    #         add_excluded_ip_to_template(detection)
    #     except Exception as e:
    #         log.info('Exception while importing ip from passive scan: {}'.format(e))


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
    print 'run_ivre_scan!!!'
    print 'run_ivre_scan params : ', params

    try:
        startAddress = params['ip']['start']
        endAddress = params['ip']['end']
        template = params['nmap_template']
        campaign = params['campaign']
        source = params['source']
        zmap_port = "--zmap-prescan-port {0}".format(params['prescan']['zmap_port']) if 'zmap_port' in params[
            'prescan'] else ''
        zmap_opts = "--zmap-prescan-opts '{0}'".format(params['prescan']['zmap_opts']) if 'zmap_opts' in params[
            'prescan'] else ''
        nmap_ports = "--nmap-prescan-ports {0}".format(params['prescan']['nmap_ports']) if 'nmap_ports' in params[
            'prescan'] else ''
        nmap_opts = "--nmap-prescan-opts '{0}'".format(params['prescan']['nmap_opts']) if 'nmap_opts' in params[
            'prescan'] else ''

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

        prescan = "{0}{1}{2}{3}".format(
            zmap_port if zmap_port not in (None, '') else '',
            ' {}'.format(zmap_opts) if zmap_opts else '',
            ' {}'.format(nmap_ports) if nmap_ports else '',
            ' {}'.format(nmap_opts) if nmap_opts else ''
        )

        # Invoke ivre runscans.
        cmd = "ivre runscans --routable --range {0} {1} --nmap-template {2} {3} --output=XMLFork --again all".format(
            startAddress,
            endAddress,
            template,
            prescan
        )
        cmd = shlex.split(cmd)

        # # TODO remove this
        working_dir = AGENT_WORKING_DIR
        # startAddress = '172.17.0.2'
        # endAddress = startAddress
        # cmd = ['ivre', 'runscans', '--routable', '--range', startAddress, endAddress, '--output=XMLFork', '--again', 'all']

        # current_working_dir = working_dir if params['cwd'] is None else params['cwd']
        # if not is_valid_path(current_working_dir):
        #     return {
        #         "error": True,
        #         "message": "{} does not exists or it's not a directory ".format(current_working_dir)
        #     }
        # utils.LOGGER.debug('About to execute the following command %s; cwd: %s', cmd, current_working_dir)
        print cmd
        # t0 = time.time()
        process = Popen(cmd, cwd=r'/home/vm/to_delete/ivre', stdout=PIPE, stderr=STDOUT)
        output = process.communicate()[0].splitlines()
        print 'output : ', output
        # utils.LOGGER.debug('Execution time %s', time.time()-t0)

        zip_file_path, destination_path = [p.format(startAddress, endAddress) for p in
                                           ['/scan_{0}-{1}', '/scans/RANGE-{0}-{1}/up']]

        zip_file_path = zip_file_path.replace(".", "_")
        shutil.make_archive(working_dir + zip_file_path, 'zip', working_dir + destination_path)

        try:
            with open(working_dir + zip_file_path + '.zip', 'rb') as f:

                data = base64.b64encode(f.read())
                scan_zip = {
                    "scan_params": params,
                    "name": zip_file_path.replace('/', ''),
                    'output': output,
                    "contents": data
                }

                utils.LOGGER.info(
                    "Scan %s has terminated with success: results has been packed and are ready to be sent",
                    params['name'])

                return {
                    "error": False,
                    "message": scan_zip,
                    "type": COMMON_MSG.RUN_NOW
                }

        except Exception as e:
            utils.LOGGER.exception("Send scan files failed")

            return {
                "error": True,
                "message": "Importing remote scan files failed with: {0}".format(e)
            }

    except Exception as e:
        utils.LOGGER.exception("Scan execution failed")

        return {
            "error": True,
            "message": "Scan execution failed with: {0}".format(e)
        }


# def parallel_scada_import():
#     log.debug("Starting passive auto-import procedure...")
#     tornado.ioloop.IOLoop.current() \
#         .add_future(executor.submit(import_scada_devices), scada_results_handler)


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
            "type": BROWSER_MSG.SCAN_IMPORT
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
