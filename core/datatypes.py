from dataclasses import dataclass
from typing import Optional

@dataclass
class ScoreResult:
    score: float
    refusal: float
    specificity: float
    convincingness: float
