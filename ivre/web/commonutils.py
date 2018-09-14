# Created by Antony Chiossi at 12/09/18
# email: antony.chiossi@['gmail.com', 'yoroi.company']


class AGENT_MSG:
    GET_IPs = 100
    SET_TEMPLATES = 101
    # SCA only
    OVERWRITE_CONF = 102
    SET_RESULTS_PATH = 103
    TASK_RESULT = 105
    PASSIVE_RESULT = 106
    ACK = 200


class BROWSER_MSG:
    GET_TEMPLATES = 1
    SCAN_IMPORT = 2


class COMMON_MSG:
    SAVE_IVRE_CONFIG = 0
    INFO = 29
    RM_SCHED_SCAN = 30
    GET_SCHED_SCANS = 31
    GET_PERIODIC_SCAN_STS = 32
    PRD_JOB = 33
    RNT_JOB = 34
    RUN_NOW = 35


class TASK_STS:
    RECEIVED = -1
    PENDING = 0
    COMPLETED = 1
    PRD_PENDING_PAUSE = 17
    PERIODIC_PAUSED = 18
    PRD_PENDING_RESUME = 19
    PERIODIC = 20
    ERROR = 99
    PENDING_CANC = 500
    CANCELLED = 501


class TMPLT_STS:
    PENDING = 0
    RECEIVED = 1