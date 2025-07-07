import enum
from pathlib import Path
from typing import Any, Dict, List

Fuzzer = str
Fuzzers = List[Fuzzer]


class FuzzerType(enum.Enum):
    AFLGo = 'aflgo'
    WindRanger = 'windranger'



