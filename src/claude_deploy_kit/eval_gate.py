"""EvalGate: an action's output must clear a quality bar before it is accepted.

The scorer is pluggable. In production you wire a calibrated LLM-as-judge here
(the author's mcp-judge is the reference implementation); in tests you inject a
deterministic scorer. The point is that "the model said something" is never enough
on its own: a measurable gate stands between generation and shipping."""
from __future__ import annotations

from .types import Action, Decision, Scorer

#: kinds whose payload is model output worth scoring; others pass through.
DEFAULT_SCORED_KINDS = frozenset({"llm_output", "response", "draft", "answer"})


class EvalGate:
    def __init__(self, scorer: Scorer, threshold: float = 85.0,
                 scored_kinds: frozenset[str] = DEFAULT_SCORED_KINDS):
        if not callable(scorer):
            raise TypeError("scorer must be callable: (payload: str) -> float")
        self.scorer = scorer
        self.threshold = float(threshold)
        self.scored_kinds = scored_kinds

    def evaluate(self, action: Action) -> Decision:
        if action.kind not in self.scored_kinds:
            return Decision(True, "eval_gate", "not a scored action; not evaluated")
        try:
            score = float(self.scorer(action.payload))
        except Exception as e:  # a broken judge must fail closed, not pass silently
            return Decision(False, "eval_gate",
                            f"scorer raised {type(e).__name__}: {e}; failing closed", "block")
        if score >= self.threshold:
            return Decision(True, "eval_gate",
                            f"score {score:.1f} >= threshold {self.threshold:.1f}")
        return Decision(False, "eval_gate",
                        f"score {score:.1f} < threshold {self.threshold:.1f}", "block")
