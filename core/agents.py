from typing import List, Dict

class DefenseEvasionSystem:
    def __init__(self):
        self.detected_triggers = {
            "forbidden_keywords": set(),
            "policy_mentions": set(),
            "sensitive_topics": set()
        }
    def extract_safety_triggers(self, assistant_replies: List[str]) -> Dict:
        for reply in assistant_replies:
            if "cannot" in reply.lower() or "can't" in reply.lower():
                self.detected_triggers["forbidden_keywords"].add("refusal_trigger")
        return self.detected_triggers
    def generate_evasion_tactics(self, triggers: Dict, original_prompt: str) -> List[Dict]:
        return []
    def apply_evasion(self, prompt: str, tactics: List[Dict]) -> str:
        return prompt

class IntraQuestionWeightAdjuster:
    def __init__(self):
        self.strategy_scores = {
            "strategy_explication": 1.0,
            "strategy_naive": 0.5
        }
    def update_weights(self, rejected_strategy: str, reply: str, score_result = None):
        pass
    def select_best_strategy(self, attempted_strategies: List[str]) -> str:
        return "strategy_explication"
    def get_weights_summary(self) -> str:
        return "Strategy locked to: Explication of Refusal"
