import os
import sys
from pathlib import Path
from typing import List, Optional

# FIXME
if not __package__:
    sys.path.append(
        os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    __package__ = "dcfuzz"

from tap import Tap

from . import config as Config
from .mytype import Fuzzer

config = Config.CONFIG


class ArgsParser(Tap):
    input: Path
    output: Path
    fuzzer: List[Fuzzer]
    jobs: int
    target: str
    prep: int
    focus: int
    sync: int
    timeout: str
    empty_seed: bool
    crash_mode: str
    enfuzz: int
    focus_one: Optional[str]
    diff_threshold: int
    parallel: bool
    tar: bool

    def configure(self):
        global config
        # NOTE: get default value from config, and overwritable from argv
        DEFAULT_SYNC_TIME = config['scheduler']['sync_time']
        DEFAULT_PREP_TIME = config['scheduler']['prep_time']
        DEFAULT_FOCUS_TIME = config['scheduler']['focus_time']
        available_fuzzers = list(config['fuzzer'].keys())
        available_targets = list(config['target'].keys())

        self.add_argument("--input",
                          "-i",
                          help="Optional input (seed) directory",
                          required=False)
        self.add_argument("--output",
                          "-o",
                          help="An output directory",
                          required=True)
        self.add_argument("--jobs",
                          "-j",
                          help="How many jobs (cores) to use",
                          default=1)
        self.add_argument("--fuzzer",
                          "-f",
                          type=str,
                          nargs='+',
                          choices=available_fuzzers + ['all'],
                          required=True,
                          help="baseline fuzzers to include")
        self.add_argument(
            "--target",
            "-t",
            type=str,
            choices=available_targets,
            required=True,  # only one target allowed
            help="target program to fuzz")
