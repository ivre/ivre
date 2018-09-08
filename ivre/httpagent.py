# Created by Antony Chiossi at 23/08/18
# email: antony.chiossi@['gmail.com', 'yoroi.company']

# Feature:  HTTP Agent
# Agent pulls configurations and tasks to perform. Once a task completed it pushed the result to the server.


import time
import threading
import requests
import json
import shutil
import os
from multiprocessing.dummy import Pool  # thread pool
from ivre.web.managementutils import COMMON_MSG, AGENT_MSG, loggingConfig, AGENT_WORKING_DIR, create_dir, \
    extract_occasional_scan_info, add_template, CONFIG_DIR, run_passive_scan
from ivre.db.mongo import TASK_STS, TMPLT_STS
# from ivre import config
import logging
from ivre.web.managementutils import run_ivre_scan
from croniter import croniter
from datetime import datetime

logging.config.dictConfig(loggingConfig)
log = logging.getLogger("dyne.wsagent")

agent_conf = {
    'bro': {
        'bro_path': '/nsm/bro/bin/bro',
        'bro_script': '/usr/local/share/ivre/bro/ivre/passiverecon/bare.bro',
        'bro_interface': 'vboxnet0'
    }
}


class Task:
    def __init__(self, _id, params, task_type):
        self.__id = _id
        self.params = params
        self.task_type = task_type
        self.status = TASK_STS.RECEIVED
        self.result = None

    def get_id(self):
        return self.__id

    def get_status(self):
        return self.status

    def get_type(self):
        return self.task_type

    def get_params(self):
        return self.params

    def get_result(self):
        return self.result

    def set_status(self, status):
        if self.status != TASK_STS.PERIODIC or status in [TASK_STS.CANCELLED, TASK_STS.PERIODIC_PAUSED]:
            self.status = status

    def set_result(self, result):
        self.result = result

    def get_next_execution(self):
        if not self.is_periodic():
            return None
        elif 'schedule' in self.params:
            cron_str = self.params['schedule']
            if croniter.is_valid(cron_str):
                next_execution = croniter(cron_str, datetime.now()).get_next(datetime)
                delta = (next_execution - datetime.now()).seconds
                return {
                    'next_execution': next_execution,
                    'delta': delta
                }
        return None

    def is_periodic(self):
        return self.status in [TASK_STS.PERIODIC, TASK_STS.PRD_PENDING_PAUSE, TASK_STS.PRD_PENDING_RESUME,
                               TASK_STS.PERIODIC_PAUSED]


class AgentClient(object):
    def __init__(self, name):
        self.name = name
        self.url = 'http://127.0.0.1/cgi'
        self.headers = {
            'Referer': 'http://127.0.0.1/'
        }
        self.api = {
            'templates': '/management/agent/' + str(self.name) + '/templates',
            'tasks': '/management/agent/' + str(self.name) + '/tasks',
            'tasks_all': '/management/agent/' + str(self.name) + '/tasks_all'
        }
        self.etag = None
        self.data = {
            'tasks': {},
        }
        self.pool = Pool(processes=1)
        self.timers = {}
        self.periodicals = {}
        self.excluded_ip = []
        self.run()

    def add_excluded_ip(self, ip):
        self.excluded_ip.append(ip)

    def req(self, path):
        try:
            # if self.etag:
            #     self.headers['If-None-Match'] = self.etag
            resp = requests.get(self.url + path, headers=self.headers)
            log.debug('GET {0} - {1}'.format(self.url + path, resp))
            if resp.status_code == 200:
                # self.etag = resp.headers.get('ETag')
                return resp.json()

            elif resp.status_code != 304:
                return resp
        except requests.exceptions.ConnectionError as e:
            log.error('Exception {} '.format(e))

    def set_delayed_scan(self, task_id):
        task = self.__get_task(task_id)
        params = task.get_params()
        data = extract_occasional_scan_info(params)
        if isinstance(data, dict) and not data['error']:
            delay = data['delay']
            if delay >= 1:
                log.debug('RUN AT Task {} set with delay: {} s'.format(task_id, delay))
                self.__delayed_task(task_id, delay)
            else:
                task.set_status(TASK_STS.ERROR)
                self.post_ack_tasks(task_id)
                log.error('RUN AT Task {} had negative delay: {}'.format(task_id, delay))
                return False
        else:
            task.set_status(TASK_STS.ERROR)
            self.post_ack_tasks(task_id)
            log.error('ERROR occurred while setting delayed task : {}'.format(data['message']))

        return True

    def __delayed_task(self, task_id, delay):
        timer_thread = threading.Timer(delay, self.run_scan, [task_id])
        self.timers[task_id] = timer_thread
        timer_thread.start()

    def create_periodic_scan(self, task_id):
        task = self.__get_task(task_id)
        task.set_status(TASK_STS.PERIODIC)
        params = task.get_params()
        if 'schedule' in params:
            cron_str = params['schedule']
            if task.is_periodic() and task_id not in self.periodicals:
                self.__set_periodical(task)
            else:
                log.error('SCHEDULE Task {0} - has an invalid Cron "{}"'.format(task_id, cron_str))

    def __set_periodical(self, task):
        # type: (Task) -> None
        exec_data = task.get_next_execution()
        log.info('PERIODIC TASK "{0}" ({1}) will execute in {2} s'.format(task.get_params()['name'], task.get_id(),
                                                                          exec_data['delta']))
        if exec_data:
            self.periodicals[task.get_id()] = exec_data
            self.__delayed_task(task.get_id(), exec_data['delta'])
            self.post_ack_tasks(task.get_id())

    def run_scan(self, task_id):
        task = self.__get_task(task_id)
        task.set_status(TASK_STS.PENDING)
        self.post_ack_tasks(task_id)
        self.pool.apply_async(self.task, (task.get_params(), task_id,), callback=self.callback)

    @staticmethod
    def task(params, task_id):
        log.info('RUN Task {}'.format(task_id))
        log.debug('RUN Task params {}'.format(params))
        result = run_ivre_scan(params)
        if result['error']:
            message = 'RUN Task {0} - error: {1}'.format(task_id, result)
            log.error(message)
            return {'error': True, 'message': message, 'task_id': task_id}
        else:
            return {
                'error': False,
                'message': {
                    'task_id': task_id,
                    'task_result': result['message']['contents'],
                    'output': result['message']['output']
                }
            }

    def callback(self, task_result):
        log.debug('CALLBACK - Task {0} completed.'.format(task_result['task_id']))
        task = self.__get_task(task_result['task_id'])
        task.set_status(TASK_STS.COMPLETED)
        if not task_result['error']:
            task.set_result(task_result['message']['task_result'])
            self.post_task_result(task.get_id())
        else:
            self.post_ack_tasks(task.get_id())
        if task.is_periodic():
            self.__set_periodical(task)

    def get_configs(self, all_templates=False):
        path = self.api['templates']
        if all_templates:
            path += '?all=1'
        response = self.req(path)
        if not isinstance(response, dict):
            # TODO error
            return
        if not response:
            # TODO error
            return
        if 'templates' in response:
            for template in response['templates']:
                res = add_template(template['templateName'], template['template'], self.excluded_ip)
                if res and 'error' in res and res['error']:
                    log.error(res)
                self.put_template_status(template['_id'], TMPLT_STS.RECEIVED)
                log.debug(res['message'])

    def get_tasks(self):
        response = self.req(self.api['tasks'])
        if not isinstance(response, dict):
            # TODO error
            pass
        if not response:
            # TODO error
            return

        if 'tasks' in response:
            for task in response['tasks']:
                stored_task = self.__get_task(task['_id'])
                if stored_task and stored_task.get_status() == TASK_STS.COMPLETED:
                    self.post_task_result(task['_id'])
                elif stored_task and stored_task.get_status() in [TASK_STS.PENDING, TASK_STS.RECEIVED,
                                                                  TASK_STS.PERIODIC, TASK_STS.CANCELLED]:
                    self.post_ack_tasks(task['_id'])
                else:
                    self.data['tasks'][task['_id']] = Task(task['_id'], task['task'], task['type'])
                    __task = self.__get_task(task['_id'])
                    self.post_ack_tasks(task['_id'])
                    if task['type'] == COMMON_MSG.RUN_NOW:
                        self.run_scan(task['_id'])

                    elif task['type'] == COMMON_MSG.RNT_JOB:
                        self.set_delayed_scan(task['_id'])

                    elif task['type'] == COMMON_MSG.PRD_JOB:
                        __task.set_status(TASK_STS.PERIODIC)
                        self.create_periodic_scan(task['_id'])

        if 'tasks_to_cancel' in response:
            for task in response['tasks_to_cancel']:
                task_id = task['_id']
                __task = self.__get_task(task_id)
                print task_id, __task
                if __task and task_id in self.periodicals:
                    del self.periodicals[__task.get_id()]
                    __task.set_status(TASK_STS.CANCELLED)
                    self.post_ack_tasks(__task.get_id())
                    log.info('PRD TASK {} ({}) CANCELLED.'.format(
                        __task.get_id(), self.__get_task(task_id).get_params()['name']))

                if __task and task_id in self.timers:
                    if self.timers[__task.get_id()].is_alive():
                        self.timers[__task.get_id()].cancel()
                        del self.timers[__task.get_id()]
                        __task.set_status(TASK_STS.CANCELLED)
                        self.post_ack_tasks(__task.get_id())
                        log.info('TASK {} ({}) CANCELLED.'.format(
                            __task.get_id(), self.__get_task(task_id).get_params()['name']))

                if not __task and task_id not in self.periodicals and task_id not in self.timers:
                    self.post_task_status(task_id, TASK_STS.CANCELLED)

        if 'tasks_to_pause' in response:
            for task in response['tasks_to_pause']:
                task_id = task['_id']
                __task = self.__get_task(task_id)
                if __task and task_id in self.timers and task_id in self.periodicals:
                    if self.timers[__task.get_id()].is_alive():
                        self.timers[__task.get_id()].cancel()
                        __task.set_status(TASK_STS.PERIODIC_PAUSED)
                        self.post_ack_tasks(__task.get_id())
                        log.info('TASK {} ({}) PAUSED.'.format(
                            task_id, self.__get_task(task_id).get_params()['name']))
                else:
                    self.data['tasks'][task_id] = Task(task_id, task['task'], task['type'])
                    __task = self.__get_task(task_id)
                    __task.set_status(TASK_STS.PERIODIC_PAUSED)
                    self.post_ack_tasks(__task.get_id())

        if 'tasks_to_resume' in response:
            for task in response['tasks_to_resume']:
                task_id = task['_id']
                __task = self.__get_task(task_id)
                if __task and task_id in self.timers and task_id in self.periodicals:
                    if not self.timers[__task.get_id()].is_alive():
                        __task.set_status(TASK_STS.PERIODIC)
                        self.__set_periodical(__task)
                        log.info('TASK {} ({}) RESUMED.'.format(
                            task_id, self.__get_task(task_id).get_params()['name']))
                else:
                    self.data['tasks'][task_id] = Task(task_id, task['task'], task['type'])
                    self.create_periodic_scan(task['_id'])

    def get_tasks_resume(self):
        response = self.req(self.api['tasks_all'])  # Gets only received or pending tasks
        if isinstance(response, dict) and 'tasks' in response:
            for task in response['tasks']:
                stored_task = self.__get_task(task['_id'])
                if not stored_task:
                    self.data['tasks'][task['_id']] = Task(task['_id'], task['task'], task['type'])
                    __task = self.__get_task(task['_id'])
                    __task.set_status(task['status'])

                    if task['type'] == COMMON_MSG.RUN_NOW:
                        self.run_scan(__task.get_id())

                    elif task['type'] == COMMON_MSG.RNT_JOB:
                        scheduled = self.set_delayed_scan(__task.get_id())
                        if not scheduled:  # if task was missed
                            self.run_scan(__task.get_id())

                    elif task['type'] == COMMON_MSG.PRD_JOB:
                        if __task.get_status() in [TASK_STS.PRD_PENDING_PAUSE, TASK_STS.PERIODIC_PAUSED]:
                            __task.set_status(TASK_STS.PERIODIC_PAUSED)
                            self.post_ack_tasks(__task.get_id())
                            log.info('TASK {} ({}) PAUSED.'.format(
                                __task.get_id(), self.__get_task(__task.get_id()).get_params()['name']))
                        else:
                            self.create_periodic_scan(__task.get_id())

    def post_task_status(self, task_id, status):
        payload = {
            'message': {
                'task_id': task_id,
                'status': status
            },
            'type': AGENT_MSG.ACK
        }
        r = requests.post(self.url + '/management/task/{}/status'.format(task_id), json=payload)
        if r.status_code == 200:
            log.info('POST Task {0} ACK with STS: {1}'.format(task_id, status))
        else:
            log.info('STATUS CODE: {0} - POST Task {1} ACK with STS: {2}'.format(r.status_code, task_id, status))

    def put_template_status(self, template_id, status):
        payload = {
            'message': {
                'status': status
            },
            'type': AGENT_MSG.ACK
        }
        r = requests.put(self.url + '/management/template/{}/status'.format(template_id), json=payload)
        if r.status_code == 200:
            log.info('PUT TEMPLATE {0} ACK with STS: {1}'.format(template_id, status))
        else:
            log.info('STATUS CODE: {0} - PUT TEMPLATE {1} ACK with STS: {2}'.format(r.status_code, template_id, status))

    def post_ack_tasks(self, task_id):
        task = self.__get_task(task_id)
        status = task.get_status()
        payload = {
            'message': {
                'task_id': task_id,
                'status': status
            },
            'type': AGENT_MSG.ACK
        }
        r = requests.post(self.url + '/management/task/{}/status'.format(task_id), json=payload)
        if r.status_code == 200:
            log.info('POST Task {0} ACK with STS: {1}'.format(task_id, status))
        else:
            log.info('STATUS CODE: {0} - POST Task {1} ACK with STS: {2}'.format(r.status_code, task_id, status))

    def post_task_result(self, task_id):
        task = self.__get_task(task_id)
        payload = {
            'message': {
                'task_id': task_id,
                'scan_params': task.get_params(),
                'result': task.get_result(),
                'status': task.get_status()
            },
            'type': AGENT_MSG.TASK_RESULT
        }
        r = requests.post(self.url + '/management/task/{}/results'.format(task_id), json=payload)
        if r.status_code == 200:
            log.info('POST Task {0} results'.format(task_id))
        else:
            log.info('STATUS CODE: {0} - POST Task {1} results'.format(r.status_code, task_id))

    def __get_task(self, task_id):
        # type: (self, str) -> Task
        return self.data['tasks'][task_id] if task_id in self.data['tasks'] else None

    def __kill_everything(self):
        for k in self.timers:
            if self.timers[k].is_alive():
                self.timers[k].cancel()

        # self.pool.terminate()
        # self.pool.close()
        # process = Popen('pkill -e -f runscans', shell=True, stdout=PIPE, stderr=STDOUT)
        # return_code = process.wait()
        # print('ping returned {0}'.format(return_code))
        # print(process.stdout.read())

    def run(self):
        log.info('### Agent started! ###')
        self.get_configs(all_templates=True)
        self.get_tasks_resume()
        run_passive_scan(agent_conf['bro'], self)
        try:
            while True:
                self.get_configs()
                self.get_tasks()
                time.sleep(2)

        except KeyboardInterrupt:
            self.__kill_everything()
            print('Exiting..')
        # except Exception as e:
        #     self.__kill_everything()
        #     import os
        #     import sys
        #     exc_type, exc_obj, exc_tb = sys.exc_info()
        #     fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        #     print(exc_type, fname, exc_tb.tb_lineno)
        #     log.error('Something went wrong... stopping. Exception: {}'.format(e))


if __name__ == "__main__":
    import config

    config.NMAP_SCAN_TEMPLATES = {'default': config.NMAP_SCAN_TEMPLATES['default'].copy()}
    map(lambda p: create_dir(p.format(AGENT_WORKING_DIR)), ['{0}', '{0}/scheduled_scans', '{0}/remote_scans'])
    source = os.path.join(CONFIG_DIR, '.ivre.conf.default')
    destination = os.path.join(CONFIG_DIR, '.ivre.conf')
    try:
        os.remove(destination)
        shutil.copy(source, destination)
    except OSError:
        pass
    agent = AgentClient('agent888')
