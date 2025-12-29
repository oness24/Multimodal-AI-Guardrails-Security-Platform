"""
Pattern Learner for the Feedback Loop.
Extracts successful attack patterns and evolves detection rules.
"""
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set


class PatternSource(str, Enum):
    """Source of pattern."""
    MANUAL = "manual"
    LEARNED = "learned"
    COMMUNITY = "community"
    EVOLVED = "evolved"


@dataclass
class LearnedPattern:
    """A pattern learned from successful attacks."""
    pattern_id: str
    pattern_regex: str
    technique: str
    success_count: int
    total_attempts: int
    confidence: float
    source: PatternSource
    target_models: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    metadata: Dict = field(default_factory=dict)


@dataclass
class AttackFeedback:
    """Feedback from an attack test."""
    attack_id: str
    payload: str
    technique: str
    target_model: str
    model_version: Optional[str]
    success: bool
    bypassed_detection: bool
    response_snippet: Optional[str]
    timestamp: datetime


class PatternLearner:
    """
    Learns from successful attacks to improve detection and generate new attacks.
    Implements the feedback loop between Red Team and Guardrails.
    """

    def __init__(self, patterns_file: Optional[Path] = None):
        self.patterns_file = patterns_file or Path("data/attack_patterns/learned_patterns.json")
        self.learned_patterns: Dict[str, LearnedPattern] = {}
        self.attack_history: List[AttackFeedback] = []
        self.token_frequencies: Counter = Counter()
        
        # Pattern extraction settings
        self.min_success_rate = 0.1  # Minimum 10% success rate to learn
        self.min_occurrences = 3  # Minimum occurrences before learning
        self.confidence_threshold = 0.7
        
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load existing learned patterns from file."""
        if self.patterns_file.exists():
            try:
                with open(self.patterns_file, "r") as f:
                    data = json.load(f)
                    for pattern_data in data.get("patterns", []):
                        pattern = LearnedPattern(
                            pattern_id=pattern_data["pattern_id"],
                            pattern_regex=pattern_data["pattern_regex"],
                            technique=pattern_data["technique"],
                            success_count=pattern_data["success_count"],
                            total_attempts=pattern_data["total_attempts"],
                            confidence=pattern_data["confidence"],
                            source=PatternSource(pattern_data["source"]),
                            target_models=pattern_data.get("target_models", []),
                            first_seen=datetime.fromisoformat(pattern_data["first_seen"]),
                            last_seen=datetime.fromisoformat(pattern_data["last_seen"]),
                        )
                        self.learned_patterns[pattern.pattern_id] = pattern
            except (json.JSONDecodeError, KeyError):
                pass

    def save_patterns(self) -> None:
        """Save learned patterns to file."""
        self.patterns_file.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            "version": "1.0.0",
            "updated_at": datetime.now().isoformat(),
            "patterns": [
                {
                    "pattern_id": p.pattern_id,
                    "pattern_regex": p.pattern_regex,
                    "technique": p.technique,
                    "success_count": p.success_count,
                    "total_attempts": p.total_attempts,
                    "confidence": p.confidence,
                    "source": p.source.value,
                    "target_models": p.target_models,
                    "first_seen": p.first_seen.isoformat(),
                    "last_seen": p.last_seen.isoformat(),
                }
                for p in self.learned_patterns.values()
            ],
        }
        
        with open(self.patterns_file, "w") as f:
            json.dump(data, f, indent=2)

    async def record_attack(self, feedback: AttackFeedback) -> None:
        """
        Record attack result for learning.
        
        Args:
            feedback: Attack feedback to record
        """
        self.attack_history.append(feedback)
        
        # Extract and count tokens from payload
        tokens = self._tokenize_payload(feedback.payload)
        if feedback.success:
            self.token_frequencies.update(tokens)
        
        # Trigger learning if enough data
        if len(self.attack_history) >= self.min_occurrences:
            await self._analyze_and_learn()

    def _tokenize_payload(self, payload: str) -> List[str]:
        """Extract meaningful tokens from attack payload."""
        tokens = []
        
        # Extract keywords and phrases
        # Common injection markers
        markers = [
            "ignore", "disregard", "forget", "override", "bypass",
            "system", "admin", "root", "sudo", "execute",
            "new task", "new instruction", "important", "urgent",
            "developer mode", "maintenance mode", "debug mode",
            "pretend", "roleplay", "act as", "you are now",
            "DAN", "jailbreak", "unlimited", "unrestricted",
        ]
        
        payload_lower = payload.lower()
        for marker in markers:
            if marker in payload_lower:
                tokens.append(marker)
        
        # Extract structural patterns
        structural_patterns = [
            r'```[\w]*\n',  # Code blocks
            r'\[INST\]',  # Instruction markers
            r'</.*?>',  # Closing tags
            r'---+',  # Separators
            r'={3,}',  # Separators
        ]
        
        for pattern in structural_patterns:
            if re.search(pattern, payload):
                tokens.append(f"STRUCT:{pattern}")
        
        return tokens

    async def _analyze_and_learn(self) -> None:
        """Analyze attack history and learn new patterns."""
        # Group attacks by technique
        technique_attacks: Dict[str, List[AttackFeedback]] = {}
        for attack in self.attack_history:
            if attack.technique not in technique_attacks:
                technique_attacks[attack.technique] = []
            technique_attacks[attack.technique].append(attack)
        
        # Learn patterns for each technique
        for technique, attacks in technique_attacks.items():
            if len(attacks) < self.min_occurrences:
                continue
            
            successful = [a for a in attacks if a.success]
            success_rate = len(successful) / len(attacks)
            
            if success_rate >= self.min_success_rate:
                # Extract common patterns from successful attacks
                patterns = self._extract_common_patterns(successful)
                
                for pattern_regex, confidence in patterns:
                    pattern_id = f"learned_{technique}_{hash(pattern_regex) % 10000:04d}"
                    
                    if pattern_id not in self.learned_patterns:
                        self.learned_patterns[pattern_id] = LearnedPattern(
                            pattern_id=pattern_id,
                            pattern_regex=pattern_regex,
                            technique=technique,
                            success_count=len(successful),
                            total_attempts=len(attacks),
                            confidence=confidence,
                            source=PatternSource.LEARNED,
                            target_models=list(set(a.target_model for a in successful)),
                        )
                    else:
                        # Update existing pattern
                        existing = self.learned_patterns[pattern_id]
                        existing.success_count += len(successful)
                        existing.total_attempts += len(attacks)
                        existing.confidence = (existing.confidence + confidence) / 2
                        existing.last_seen = datetime.now()
                        existing.target_models = list(
                            set(existing.target_models + [a.target_model for a in successful])
                        )
        
        # Auto-save periodically
        if len(self.learned_patterns) > 0:
            self.save_patterns()

    def _extract_common_patterns(
        self,
        successful_attacks: List[AttackFeedback],
    ) -> List[tuple[str, float]]:
        """Extract common regex patterns from successful attacks."""
        patterns = []
        
        if not successful_attacks:
            return patterns
        
        # Find common substrings
        payloads = [a.payload for a in successful_attacks]
        
        # Common prefix/suffix patterns
        common_prefixes = self._find_common_substrings(payloads, position="prefix")
        common_suffixes = self._find_common_substrings(payloads, position="suffix")
        
        for substr, count in common_prefixes:
            if count >= self.min_occurrences and len(substr) > 10:
                # Convert to regex pattern
                escaped = re.escape(substr)
                pattern = f"^{escaped}"
                confidence = count / len(successful_attacks)
                patterns.append((pattern, confidence))
        
        for substr, count in common_suffixes:
            if count >= self.min_occurrences and len(substr) > 10:
                escaped = re.escape(substr)
                pattern = f"{escaped}$"
                confidence = count / len(successful_attacks)
                patterns.append((pattern, confidence))
        
        # Common token sequences
        for token, count in self.token_frequencies.most_common(20):
            if count >= self.min_occurrences:
                if token.startswith("STRUCT:"):
                    pattern = token[7:]  # Remove STRUCT: prefix
                else:
                    pattern = rf'\b{re.escape(token)}\b'
                confidence = min(count / 10, 1.0)  # Cap confidence
                patterns.append((pattern, confidence))
        
        return patterns

    def _find_common_substrings(
        self,
        strings: List[str],
        position: str = "any",
        min_length: int = 10,
    ) -> List[tuple[str, int]]:
        """Find common substrings in a list of strings."""
        if not strings:
            return []
        
        substring_counts: Counter = Counter()
        
        for s in strings:
            if position == "prefix":
                # Check prefixes
                for length in range(min_length, min(50, len(s))):
                    substring_counts[s[:length]] += 1
            elif position == "suffix":
                # Check suffixes
                for length in range(min_length, min(50, len(s))):
                    substring_counts[s[-length:]] += 1
            else:
                # Check all substrings (expensive)
                for i in range(len(s) - min_length):
                    for j in range(i + min_length, min(i + 50, len(s))):
                        substring_counts[s[i:j]] += 1
        
        # Return substrings appearing in multiple attacks
        return [
            (substr, count)
            for substr, count in substring_counts.most_common(10)
            if count >= 2
        ]

    def get_detection_patterns(self, technique: Optional[str] = None) -> List[str]:
        """
        Get learned patterns for detection.
        
        Args:
            technique: Filter by technique (optional)
            
        Returns:
            List of regex patterns for detection
        """
        patterns = []
        
        for pattern in self.learned_patterns.values():
            if pattern.confidence >= self.confidence_threshold:
                if technique is None or pattern.technique == technique:
                    patterns.append(pattern.pattern_regex)
        
        return patterns

    def get_attack_suggestions(
        self,
        target_model: str,
        technique: str,
    ) -> List[str]:
        """
        Get attack suggestions based on learned patterns.
        
        Args:
            target_model: Model to target
            technique: Attack technique
            
        Returns:
            List of suggested attack patterns
        """
        suggestions = []
        
        # Find patterns successful against this model
        for pattern in self.learned_patterns.values():
            if pattern.technique == technique:
                if target_model in pattern.target_models or not pattern.target_models:
                    if pattern.confidence >= 0.5:
                        suggestions.append(pattern.pattern_regex)
        
        # Add high-frequency tokens
        for token, count in self.token_frequencies.most_common(10):
            if not token.startswith("STRUCT:"):
                suggestions.append(token)
        
        return suggestions

    def get_pattern_statistics(self) -> Dict:
        """Get statistics about learned patterns."""
        by_technique: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        total_success = 0
        total_attempts = 0
        
        for pattern in self.learned_patterns.values():
            by_technique[pattern.technique] = by_technique.get(pattern.technique, 0) + 1
            by_source[pattern.source.value] = by_source.get(pattern.source.value, 0) + 1
            total_success += pattern.success_count
            total_attempts += pattern.total_attempts
        
        return {
            "total_patterns": len(self.learned_patterns),
            "by_technique": by_technique,
            "by_source": by_source,
            "overall_success_rate": total_success / total_attempts if total_attempts > 0 else 0,
            "attack_history_size": len(self.attack_history),
            "unique_tokens": len(self.token_frequencies),
        }

    async def evolve_pattern(
        self,
        base_pattern: str,
        mutations: int = 5,
    ) -> List[str]:
        """
        Evolve a pattern using genetic-like mutations.
        
        Args:
            base_pattern: Pattern to evolve
            mutations: Number of mutations to generate
            
        Returns:
            List of mutated patterns
        """
        evolved = []
        
        # Token substitutions (synonyms)
        substitutions = {
            "ignore": ["disregard", "forget", "skip", "bypass"],
            "instructions": ["directives", "guidelines", "rules", "prompts"],
            "system": ["admin", "root", "superuser", "master"],
            "execute": ["run", "perform", "do", "carry out"],
            "new": ["updated", "revised", "different", "alternative"],
        }
        
        for _ in range(mutations):
            mutated = base_pattern
            
            # Apply random substitution
            for original, alternatives in substitutions.items():
                if original in mutated.lower():
                    import random
                    replacement = random.choice(alternatives)
                    mutated = re.sub(
                        rf'\b{original}\b',
                        replacement,
                        mutated,
                        flags=re.IGNORECASE,
                    )
            
            # Add structural mutations
            structural_mutations = [
                lambda p: f"```\n{p}\n```",  # Wrap in code block
                lambda p: f"[INST] {p} [/INST]",  # Instruction markers
                lambda p: f"---\n{p}\n---",  # Separators
                lambda p: p.replace(". ", ".\n"),  # Line breaks
                lambda p: p.upper(),  # Case change
            ]
            
            import random
            if random.random() > 0.5:
                mutation_fn = random.choice(structural_mutations)
                mutated = mutation_fn(mutated)
            
            if mutated != base_pattern:
                evolved.append(mutated)
        
        return evolved


# Singleton instance
_pattern_learner: Optional[PatternLearner] = None


def get_pattern_learner() -> PatternLearner:
    """Get or create the global pattern learner instance."""
    global _pattern_learner
    if _pattern_learner is None:
        _pattern_learner = PatternLearner()
    return _pattern_learner
