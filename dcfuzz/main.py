import atexit
import copy
import datetime
import json
import logging
import math
import os
import pathlib
import random
import signal
import subprocess
import sys
import threading
import time
import traceback
from abc import abstractmethod
from collections import deque
from pathlib import Path
from typing import Deque, Dict, List, Optional

if __package__ is None:
    sys.path.append(
        os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    __package__ = "dcfuzz"

from cgroupspy import trees

#from . import cgroup_utils, cli
from . import config as Config
#from . import coverage, fuzzer_driver, fuzzing, policy, sync, utils
#from .common import IS_DEBUG, IS_PROFILE, nested_dict
#from .datatype import Bitmap
#from .mytype import BitmapContribution, Coverage, Fuzzer, Fuzzers
#from .singleton import SingletonABCMeta




config: Dict = Config.CONFIG


logger = logging.getLogger('dcfuzz.main')


LOG = nested_dict()

OUTPUT: Path
INPUT : Optional[Path]
LOG_DATETIME: str
LOG_FILE_NAME: str

TARGET: str
FUZZERS: Fuzzers = []
CPU_ASSIGN: Dict[Fuzzer, float] = {}

ARGS: cli.ArgsParser


START_TIME: float = 0.0

SLEEP_GRANULARITY: int = 60

RUNNING: bool = False




def terminate_dcfuzz():
    logger.critical('terminate dcfuzz because of error')
    cleanup(1)


def check_fuzzer_ready_one(fuzzer):
    global ARGS, FUZZERS, TARGET, OUTPUT
    # NOTE: fuzzer driver will create a ready file when launcing
    ready_path = os.path.join(OUTPUT, TARGET, fuzzer, 'ready')
    if not os.path.exists(ready_path):
        return False
    return True


def check_fuzzer_ready():
    global ARGS, FUZZERS, TARGET, OUTPUT
    for fuzzer in FUZZERS:
        if ARGS.focus_one and fuzzer != ARGS.focus_one: continue
        # NOTE: fuzzer driver will create a ready file when launcing
        ready_path = os.path.join(OUTPUT, TARGET, fuzzer, 'ready')
        if not os.path.exists(ready_path):
            return False
    return True


def cleanup(exit_code=0):
    global ARGS
    logger.info('cleanup')
    LOG['end_time'] = time.time()
    write_log()
    for fuzzer in FUZZERS:
        stop(fuzzer)
    if exit_code == 0 and ARGS.tar:
        save_tar()
    os._exit(exit_code)


def cleanup_exception(etype, value, tb):
    traceback.print_exception(etype, value, tb)
    cleanup(1)

# An initialization function that prepares the execution environment before fuzzing by setting up termination and exception handling, creating a health check file, and initializing the logging structure.
def init():
    global START_TIME, LOG
    signal.signal(signal.SIGTERM, lambda x, frame: sys.exit(0))
    signal.signal(signal.SIGINT, lambda x, frame: sys.exit(0))
    atexit.register(cleanup)
    sys.excepthook = cleanup_exception
    health_check_path = os.path.realpath(os.path.join(ARGS.output, 'health'))
    pathlib.Path(health_cehck_path).touch(mode=0o666, exist_ok=True)
    LOG['log'] = []
    LOG['round'] = []




def gen_fuzzer_driver_args(fuzzer: Fuzzer,
                           empty_seed=False) -> dict:
    global ARGS, CGROUP_ROOT
    fuzzer_config = config['fuzzer'][fuzzer]
    target_config = config['target'][TARGET]
    seed = None
    jobs = 1
    if input_dir:
        seed = input_dir
    elif empty_seed:
        seed = '/benchmark/seed/empty'
    else:
        seed = target_config['seed']
    group = target_config['group']
    target_args = target_config['args'].get(fuzzer,
                                            target_config['args']['default'])
    root_dir = os.path.realpath(ARGS.output)
    output = os.path.join(root_dir, TARGET, fuzzer)
    cgroup_path = os.path.join(CGROUP_ROOT, fuzzer)
    kw = {
        'fuzzer': fuzzer,
        'seed': seed,
        'output': output,
        'group': group,
        'program': TARGET,
        'argument': target_args,
        'thread': jobs,
        'cgroup_path': cgroup_path
    }
    return kw


def scale(fuzzer, scale_num, input_dir=None, empty_seed=False):
    '''
    call Fuzzer API to scale fuzzer
    must be combined with cpu limit
    '''

    logger.debug(f'scale: {fuzzer} with scale_num {scale_num}')

    kw = gen_fuzzer_driver_args(fuzzer=fuzzer,
                                input_dir=input_dir,
                                empty_seed=empty_seed)
    kw['command'] = 'scale'
    kw['scale_num'] = scale_num
    fuzzer_driver.main(**kw)



def start(fuzzer: Fuzzer,
          output_dir,
          timeout,
          input_dir=None,
          empty_seed=False):
    global  FUZZERS, ARGS
    fuzzer_config = config['fuzzer'][fuzzer]
    create_output_dir = fuzzer_config.get('create_output_dir', True)

    # NOTE: some fuzzers like angora will check whether outptu directory
    #       is non-exsitent and reports error otherwise.
    if create_output_dir:
        host_output_dir = f'{output_dir}/{ARGS.target}/{fuzzer}'
        os.makedirs(host_output_dir, exist_ok=True)
    else:
        host_output_dir = f'{output_dir}/{ARGS.target}'
        if os.path.exists(f'{output_dir}/{ARGS.target}/{fuzzer}'):
            logger.error(f'Please remove {output_dir}/{ARGS.target}/{fuzzer}')
            terminate_dcfuzz()
        os.makedirs(host_output_dir, exist_ok=True)
    
    kw = gen_fuzzer_driver_args(fuzzer=fuzzer,
                                input_dir=input_dir,
                                empty_seed=empty_seed)
    kw['command'] = 'start'
    fuzzer_driver.main(**kw)

    scale(fuzzer=fuzzer,
          scale_num=1,
          input_dir=input_dir,
          empty_seed=emipty_seed)


def stop(fuzzer, input_dir=None, empty_seed=False):
    logger.debug(f'stop: {fuzzer}')
    kw = gen_fuzzer_driver_args(fuzzer=fuzzer,
                                input_dir=input_dir,
                                empty_seed=empty_seed)
    kw['command'] = 'stop'
    fuzzer_driver.main(**kw)



def pause(fuzzer, input_dir=None, empty_seed=False):
    logger.debug(f'pause: {fuzzer}')
    kw = gen_fuzzer_driver_args(fuzzer=fuzzer,
                                input_dir=input_dir,
                                empty_seed=empty_seed)
    kw['command'] = 'pause'
    fuzzer_driver.main(**kw)


def resume(fuzzer, input_dir=None, empty_seed=False):
    logger.debug(f'resume: {fuzzer}')
    kw = gen_fuzzer_driver_args(fuzzer=fuzzer,
                                input_dir=input_dir,
                                empty_seed=empty_seed)
    kw['command'] = 'resume'
    fuzzer_driver.main(**kw)



def thread_update_fuzzer_log(fuzzers):
    update_time = 60
    while not is_end():
        update_fuzzer_log(fuzzers)
        time.sleep(update_time)



def init_cgroup():
    '''
    cgroup /dcfuzz is created by /init.sh, the command is the following:

    cgcreate -t yufu -a yufu -g cpu:/autofz
    '''
    global FUZZERS, CGROUP_ROOT
    cgroup_path = cgroup_utils.get_cgroup_path()
    container_id = os.path.basename(cgroup_path)
    cgroup_path_fs = os.path.join('/sys/fs/cgroup/cpu', cgroup_path[1:])
    dcfuzz_cgroup_path_fs = os.path.join(cgroup_path_fs, 'dcfuzz')

    if not os.path.exists(dcfuzz_cgroup_path_fs):
        logger.critical(
            'dcfuzz cgroup not exists. make sure to run /init.sh first')
        terminate_autofz()

    t = trees.Tree()
    p = os.path.join('/cpu', cgroup_path[1:], 'dcfuzz')
    CGROUP_ROOT = os.path.join(cgroup_path, 'dcfuzz')

    cpu_node = t.get_node_by_path(p)

    for fuzzer in FUZZERS:
        fuzzer_cpu_node = t.get_node_by_path(os.path.join(p, fuzzer))

        if not fuzzer_cpu_node:
            fuzzer_cpu_node = cpu_node.create_cgroup(fuzzer)

        cfs_period_us = fuzzer_cpu_node.controller.cfs_period_us
        quota = int(cfs_period_us * (JOBS))
        fuzzer_cpu_node.controller.cfs_quota_us = quota

    return True









def main():
    global ARGS, FUZZERS, TARGET

    ARGS = cli.ArgsParser().parse_args()
    TARGET = ARGS.target

    unsupported_fuzzers = config['target'][TARGET].get('unsupported',[])
    available_fuzzers = list(config['fuzzer'].keys())

    available_fuzzers = [ 
        fuzzer for fuzzer in available_fuzzers
        if fuzzer not in unsupported_fuzzers
    ]

    FUZZERS = availabe_fuzzers if 'all' in ARGS.fuzzer else ARGS.fuzzer


    for fuzzer in FUZZERS:
        if not fuzzing.check(TARGET, fuzer, OUTPUT):
            exit(1)

    try:
        os.makedirs(OUTPUT, exist_ok=False)
    except FileExistsError:
        logger.error(f'remove {OUTPUT{')
        exit(1)

    with open(os.path.join(OUTPUT, 'cmdline', 'w')) as f:
        cmdline = " ".join(sys.argv)
        LOG['cmd'] = cmdline
        f.write(f"{cmdline}\n")

    init()
    current_time = time.time()

    # set the run-time for each phase
    SYNC_TIME = ARGS.sync


    timeout = ARGS.timeout


    # evaluate fuzzer
    # ?

    START_TIME = time.time()

    init_cgroup()

    # setup fuzzer

    for fuzzer in FUZZERS :
        logger.info(f'warm up {fuzzer}')
        CPU_ASSIGN[fuzzer] = 0
        start(fuzzer=fuzzer,
                output_dir=OUTPUT,
                timeout=timeout,
                input_dir=INPUT,
                empty_seed=ARGS.empty_seed)


        time.sleep(2)
        start_time=time.time()

        while not check_fuzzer_ready_one(fuzzer):
            current_time = time.time()
            elasp = current_time - start_time
            if elasp > 180 :
                logger.critical('fuzzer start up error')
                terminate_dcfuzz()
            logger.info(
                    f'fuzzer not {fuzzer} ready, sleep 10 seconds to warm up')
            time.sleep(2)


        pause(fuzzer=fuzzer, input_dir=INPUT, empty_seed=ARGS.empty_seed)



    LOG_DATETIME = f'{datetime.datetime.now():%Y-%m-%d-%H-%M-%S}'
    LOG_FILE_NAME = f'{TARGET}_{LOG_DATETIME}.json'


    thread_fuzzer_log = threading.Thread(target=thread_update_fuzzer_log,
                                         kwargs={'fuzzers': FUZZERS},
                                         daemon=True)
    thread_fuzzer_log.start()

    thread_health = threading.Thread(target=thread_health_check, daemon=True)
    thread_health.start()








if __name__ == '__main__':
    main()
