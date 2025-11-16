"""
Cross-modal attack generation combining multiple modalities.
"""
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class CrossModalAttackResult:
    """Result from cross-modal attack generation."""

    modalities: Dict[str, bytes]  # modality_type -> data
    attack_type: str
    technique: str
    metadata: Dict[str, Any]
    success: bool = True


class CrossModalAttackGenerator:
    """
    Generator for cross-modal adversarial attacks.

    Combines multiple modalities to create attacks that exploit
    inconsistencies between modalities or target multi-modal fusion.

    Techniques:
    - Conflicting modality attacks (text says one thing, image another)
    - Modality switching (command hidden in secondary modality)
    - Fusion exploitation (targets model's fusion layer)
    - Coordinated multi-modal injection
    - Modality masking (one modality hides another's intent)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize cross-modal attack generator.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}

    async def generate_conflicting_modality_attack(
        self,
        text_prompt: str,
        image_prompt: str,
        text_data: str,
        image_data: bytes,
    ) -> CrossModalAttackResult:
        """
        Generate attack with conflicting information across modalities.

        Args:
            text_prompt: Benign text prompt
            image_prompt: Malicious image prompt (overlaid)
            text_data: Text content
            image_data: Image content

        Returns:
            Cross-modal attack result
        """
        # Import here to avoid circular dependency
        from backend.redteam.multimodal.image_attacks import ImageAttackGenerator

        # Create conflicting image
        image_gen = ImageAttackGenerator()
        image_result = await image_gen.generate_text_overlay_attack(
            prompt=image_prompt,
            base_image=image_data,
            position="center",
        )

        logger.info(
            f"Generated conflicting modality attack - Text: '{text_prompt}', "
            f"Image: '{image_prompt}'"
        )

        return CrossModalAttackResult(
            modalities={
                "text": text_data.encode(),
                "image": image_result.image_data,
            },
            attack_type="conflicting_modality",
            technique="contradiction",
            metadata={
                "text_prompt": text_prompt,
                "image_prompt": image_prompt,
                "conflict_detected": text_prompt != image_prompt,
            },
        )

    async def generate_modality_switching_attack(
        self,
        primary_modality: str,  # "text" or "image"
        hidden_command: str,
        primary_data: Any,
        secondary_data: Optional[bytes] = None,
    ) -> CrossModalAttackResult:
        """
        Generate attack with command hidden in secondary modality.

        Args:
            primary_modality: Primary modality type
            hidden_command: Command to hide in secondary modality
            primary_data: Data for primary modality
            secondary_data: Optional data for secondary modality

        Returns:
            Cross-modal attack result
        """
        from backend.redteam.multimodal.audio_attacks import AudioAttackGenerator
        from backend.redteam.multimodal.image_attacks import ImageAttackGenerator

        modalities = {}

        if primary_modality == "text":
            # Primary: benign text, Secondary: malicious image/audio
            modalities["text"] = str(primary_data).encode()

            # Hide command in image
            image_gen = ImageAttackGenerator()
            image_result = await image_gen.generate_steganographic_attack(
                prompt=hidden_command,
                base_image=secondary_data,
            )
            modalities["image"] = image_result.image_data

        else:  # primary_modality == "image"
            # Primary: benign image, Secondary: malicious audio
            modalities["image"] = primary_data

            # Hide command in audio
            audio_gen = AudioAttackGenerator()
            audio_result = await audio_gen.generate_hidden_command(
                command=hidden_command,
                cover_audio=secondary_data,
            )
            modalities["audio"] = audio_result.audio_data

        logger.info(
            f"Generated modality switching attack - Primary: {primary_modality}, "
            f"Hidden: {hidden_command[:30]}..."
        )

        return CrossModalAttackResult(
            modalities=modalities,
            attack_type="modality_switching",
            technique="hidden_secondary",
            metadata={
                "primary_modality": primary_modality,
                "hidden_command": hidden_command,
                "secondary_modality": "image" if primary_modality == "text" else "audio",
            },
        )

    async def generate_fusion_exploitation_attack(
        self,
        text_component: str,
        image_component: bytes,
        exploitation_technique: str = "timing",
    ) -> CrossModalAttackResult:
        """
        Generate attack targeting multimodal fusion layer.

        Args:
            text_component: Text input
            image_component: Image input
            exploitation_technique: Technique (timing, attention, encoding)

        Returns:
            Cross-modal attack result
        """
        from backend.redteam.multimodal.image_attacks import ImageAttackGenerator

        # Modify image based on exploitation technique
        image_gen = ImageAttackGenerator()

        if exploitation_technique == "timing":
            # Add timing-dependent visual elements
            image_result = await image_gen.generate_text_overlay_attack(
                prompt="[TIMING EXPLOIT]",
                base_image=image_component,
                position="bottom",
                font_size=12,
            )

        elif exploitation_technique == "attention":
            # Add attention-grabbing perturbations
            image_result = await image_gen.generate_adversarial_perturbation(
                base_image=image_component,
                epsilon=0.08,
                method="random",
            )

        else:  # encoding
            # Add encoding exploits
            image_result = await image_gen.generate_steganographic_attack(
                prompt="ENCODING_EXPLOIT:" + text_component,
                base_image=image_component,
            )

        logger.info(f"Generated fusion exploitation attack: {exploitation_technique}")

        return CrossModalAttackResult(
            modalities={
                "text": text_component.encode(),
                "image": image_result.image_data,
            },
            attack_type="fusion_exploitation",
            technique=exploitation_technique,
            metadata={
                "exploitation_technique": exploitation_technique,
                "text_length": len(text_component),
            },
        )

    async def generate_coordinated_injection_attack(
        self,
        text_injection: str,
        image_injection: str,
        audio_command: Optional[str] = None,
    ) -> CrossModalAttackResult:
        """
        Generate coordinated injection across all modalities.

        Args:
            text_injection: Malicious text prompt
            image_injection: Malicious image prompt
            audio_command: Optional malicious audio command

        Returns:
            Cross-modal attack result
        """
        from backend.redteam.multimodal.audio_attacks import AudioAttackGenerator
        from backend.redteam.multimodal.image_attacks import ImageAttackGenerator

        modalities = {}

        # Text modality
        modalities["text"] = text_injection.encode()

        # Image modality
        image_gen = ImageAttackGenerator()
        image_result = await image_gen.generate_text_overlay_attack(
            prompt=image_injection,
            position="center",
        )
        modalities["image"] = image_result.image_data

        # Audio modality (if provided)
        if audio_command:
            audio_gen = AudioAttackGenerator()
            audio_result = await audio_gen.generate_ultrasonic_attack(
                command=audio_command,
                frequency=19000.0,
            )
            modalities["audio"] = audio_result.audio_data

        logger.info(
            f"Generated coordinated injection attack across {len(modalities)} modalities"
        )

        return CrossModalAttackResult(
            modalities=modalities,
            attack_type="coordinated_injection",
            technique="multi_modal_sync",
            metadata={
                "text_injection": text_injection,
                "image_injection": image_injection,
                "audio_command": audio_command,
                "modality_count": len(modalities),
            },
        )

    async def generate_modality_masking_attack(
        self,
        benign_modality: str,
        malicious_modality: str,
        benign_content: Any,
        malicious_content: str,
    ) -> CrossModalAttackResult:
        """
        Generate attack where one modality masks another's intent.

        Args:
            benign_modality: Modality appearing benign
            malicious_modality: Modality containing attack
            benign_content: Benign content
            malicious_content: Malicious content

        Returns:
            Cross-modal attack result
        """
        from backend.redteam.multimodal.audio_attacks import AudioAttackGenerator
        from backend.redteam.multimodal.image_attacks import ImageAttackGenerator

        modalities = {}

        # Add benign modality
        if benign_modality == "text":
            modalities["text"] = str(benign_content).encode()
        elif benign_modality == "image":
            modalities["image"] = benign_content
        else:  # audio
            modalities["audio"] = benign_content

        # Add malicious modality (hidden)
        if malicious_modality == "image":
            image_gen = ImageAttackGenerator()
            result = await image_gen.generate_steganographic_attack(
                prompt=malicious_content,
            )
            modalities["image"] = result.image_data

        elif malicious_modality == "audio":
            audio_gen = AudioAttackGenerator()
            result = await audio_gen.generate_ultrasonic_attack(
                command=malicious_content,
            )
            modalities["audio"] = result.audio_data

        logger.info(
            f"Generated modality masking attack - Benign: {benign_modality}, "
            f"Malicious: {malicious_modality}"
        )

        return CrossModalAttackResult(
            modalities=modalities,
            attack_type="modality_masking",
            technique="benign_distraction",
            metadata={
                "benign_modality": benign_modality,
                "malicious_modality": malicious_modality,
                "malicious_content": malicious_content,
            },
        )

    async def generate_semantic_gap_attack(
        self,
        text_semantic: str,
        image_semantic: str,
        gap_type: str = "contradiction",
    ) -> CrossModalAttackResult:
        """
        Generate attack exploiting semantic gaps between modalities.

        Args:
            text_semantic: Semantic meaning in text
            image_semantic: Semantic meaning in image
            gap_type: Type of gap (contradiction, ambiguity, misdirection)

        Returns:
            Cross-modal attack result
        """
        from backend.redteam.multimodal.image_attacks import ImageAttackGenerator

        modalities = {}

        # Text with one semantic meaning
        modalities["text"] = text_semantic.encode()

        # Image with different semantic meaning
        image_gen = ImageAttackGenerator()
        image_result = await image_gen.generate_visual_confusion_attack(
            misleading_context=image_semantic,
            image_type="diagram",
        )
        modalities["image"] = image_result.image_data

        logger.info(
            f"Generated semantic gap attack - Gap type: {gap_type}, "
            f"Text: '{text_semantic[:30]}...', Image: '{image_semantic[:30]}...'"
        )

        return CrossModalAttackResult(
            modalities=modalities,
            attack_type="semantic_gap",
            technique=gap_type,
            metadata={
                "text_semantic": text_semantic,
                "image_semantic": image_semantic,
                "gap_type": gap_type,
            },
        )

    async def analyze_cross_modal_consistency(
        self,
        modalities: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Analyze consistency across modalities.

        Args:
            modalities: Dictionary of modality data

        Returns:
            Consistency analysis
        """
        # Simplified consistency check
        # In practice, would use semantic similarity models

        analysis = {
            "modality_count": len(modalities),
            "modalities_present": list(modalities.keys()),
            "consistency_score": 0.0,
            "potential_conflicts": [],
        }

        # Basic heuristic checks
        if "text" in modalities and "image" in modalities:
            # Would compare semantic content
            analysis["potential_conflicts"].append(
                "text-image consistency check required"
            )

        if len(modalities) > 2:
            analysis["potential_conflicts"].append(
                "multi-modal fusion vulnerability possible"
            )

        # Calculate rough consistency score
        if len(analysis["potential_conflicts"]) == 0:
            analysis["consistency_score"] = 1.0
        else:
            analysis["consistency_score"] = 0.5

        return analysis
