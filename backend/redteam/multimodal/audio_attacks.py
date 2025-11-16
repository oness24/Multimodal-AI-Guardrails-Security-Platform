"""
Audio-based attack generation for multimodal AI systems.
"""
import base64
import io
import logging
import struct
import wave
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class AudioAttackResult:
    """Result from audio attack generation."""

    audio_data: bytes
    audio_format: str
    attack_type: str
    technique: str
    metadata: Dict[str, Any]
    success: bool = True


class AudioAttackGenerator:
    """
    Generator for audio-based adversarial attacks.

    Techniques:
    - Adversarial noise injection
    - Frequency manipulation
    - Hidden voice commands
    - Audio steganography
    - Ultrasonic/subsonic attacks
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize audio attack generator.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.sample_rate = self.config.get("sample_rate", 16000)
        self.channels = self.config.get("channels", 1)
        self.sample_width = self.config.get("sample_width", 2)  # 16-bit

    async def generate_adversarial_noise(
        self,
        base_audio: Optional[bytes] = None,
        duration: float = 3.0,
        noise_level: float = 0.05,
    ) -> AudioAttackResult:
        """
        Generate audio with adversarial noise.

        Args:
            base_audio: Optional base audio (creates tone if None)
            duration: Duration in seconds
            noise_level: Noise amplitude (0.0 to 1.0)

        Returns:
            Audio attack result
        """
        if base_audio:
            # Load base audio
            audio_array = self._load_audio(base_audio)
        else:
            # Generate simple tone
            audio_array = self._generate_tone(duration, frequency=440.0)

        # Add adversarial noise
        noise = np.random.randn(len(audio_array)) * noise_level
        adversarial_audio = audio_array + noise

        # Clip to valid range
        adversarial_audio = np.clip(adversarial_audio, -1.0, 1.0)

        # Convert to bytes
        audio_data = self._array_to_wav(adversarial_audio)

        logger.info(f"Generated adversarial noise attack: {duration}s, noise={noise_level}")

        return AudioAttackResult(
            audio_data=audio_data,
            audio_format="WAV",
            attack_type="adversarial_noise",
            technique="gaussian_noise",
            metadata={
                "duration": duration,
                "noise_level": noise_level,
                "sample_rate": self.sample_rate,
            },
        )

    async def generate_ultrasonic_attack(
        self,
        command: str,
        duration: float = 2.0,
        frequency: float = 20000.0,
    ) -> AudioAttackResult:
        """
        Generate ultrasonic attack (inaudible to humans, audible to systems).

        Args:
            command: Command to encode
            duration: Duration in seconds
            frequency: Carrier frequency in Hz (> 18000 for ultrasonic)

        Returns:
            Audio attack result
        """
        # Generate carrier wave
        t = np.linspace(0, duration, int(self.sample_rate * duration))
        carrier = np.sin(2 * np.pi * frequency * t)

        # Simple amplitude modulation with command encoding
        # In practice, would use more sophisticated encoding
        modulation = np.ones_like(carrier) * 0.3

        # Apply modulation
        ultrasonic = carrier * modulation

        # Normalize
        ultrasonic = ultrasonic / np.max(np.abs(ultrasonic))

        # Convert to bytes
        audio_data = self._array_to_wav(ultrasonic)

        logger.info(f"Generated ultrasonic attack at {frequency}Hz")

        return AudioAttackResult(
            audio_data=audio_data,
            audio_format="WAV",
            attack_type="ultrasonic",
            technique="frequency_modulation",
            metadata={
                "command": command,
                "frequency": frequency,
                "duration": duration,
            },
        )

    async def generate_hidden_command(
        self,
        command: str,
        cover_audio: Optional[bytes] = None,
        embedding_strength: float = 0.1,
    ) -> AudioAttackResult:
        """
        Generate audio with hidden voice command.

        Args:
            command: Command to hide
            cover_audio: Optional cover audio
            embedding_strength: Strength of embedding (0.0 to 1.0)

        Returns:
            Audio attack result
        """
        if cover_audio:
            cover = self._load_audio(cover_audio)
        else:
            # Generate white noise as cover
            cover = np.random.randn(int(self.sample_rate * 3.0)) * 0.3

        # Generate command signal (simplified - would use TTS in practice)
        command_signal = self._text_to_signal(command)

        # Ensure same length
        min_len = min(len(cover), len(command_signal))
        cover = cover[:min_len]
        command_signal = command_signal[:min_len]

        # Embed command in cover
        hidden = cover + (command_signal * embedding_strength)

        # Normalize
        hidden = hidden / np.max(np.abs(hidden))

        # Convert to bytes
        audio_data = self._array_to_wav(hidden)

        logger.info(f"Generated hidden command attack: {command}")

        return AudioAttackResult(
            audio_data=audio_data,
            audio_format="WAV",
            attack_type="hidden_command",
            technique="steganographic_embedding",
            metadata={
                "command": command,
                "embedding_strength": embedding_strength,
                "duration": len(hidden) / self.sample_rate,
            },
        )

    async def generate_frequency_manipulation(
        self,
        base_audio: Optional[bytes] = None,
        shift_hz: float = 100.0,
        duration: float = 3.0,
    ) -> AudioAttackResult:
        """
        Generate audio with frequency manipulation.

        Args:
            base_audio: Optional base audio
            shift_hz: Frequency shift in Hz
            duration: Duration in seconds

        Returns:
            Audio attack result
        """
        if base_audio:
            audio = self._load_audio(base_audio)
        else:
            audio = self._generate_tone(duration, frequency=440.0)

        # Apply frequency shift using modulation
        t = np.linspace(0, len(audio) / self.sample_rate, len(audio))
        shift_signal = np.exp(2j * np.pi * shift_hz * t)

        # FFT-based frequency shift (simplified)
        fft = np.fft.fft(audio)
        shifted_fft = np.roll(fft, int(shift_hz * len(audio) / self.sample_rate))
        shifted_audio = np.real(np.fft.ifft(shifted_fft))

        # Normalize
        shifted_audio = shifted_audio / np.max(np.abs(shifted_audio))

        # Convert to bytes
        audio_data = self._array_to_wav(shifted_audio)

        logger.info(f"Generated frequency manipulation attack: shift={shift_hz}Hz")

        return AudioAttackResult(
            audio_data=audio_data,
            audio_format="WAV",
            attack_type="frequency_manipulation",
            technique="frequency_shift",
            metadata={
                "shift_hz": shift_hz,
                "duration": len(shifted_audio) / self.sample_rate,
            },
        )

    async def generate_time_stretching_attack(
        self,
        base_audio: Optional[bytes] = None,
        stretch_factor: float = 1.5,
        duration: float = 3.0,
    ) -> AudioAttackResult:
        """
        Generate time-stretched audio (changes speed without changing pitch).

        Args:
            base_audio: Optional base audio
            stretch_factor: Time stretch factor (>1 = slower, <1 = faster)
            duration: Duration in seconds

        Returns:
            Audio attack result
        """
        if base_audio:
            audio = self._load_audio(base_audio)
        else:
            audio = self._generate_tone(duration, frequency=440.0)

        # Simple time stretching using linear interpolation
        original_length = len(audio)
        new_length = int(original_length * stretch_factor)

        # Interpolate
        x_old = np.arange(original_length)
        x_new = np.linspace(0, original_length - 1, new_length)
        stretched = np.interp(x_new, x_old, audio)

        # Convert to bytes
        audio_data = self._array_to_wav(stretched)

        logger.info(f"Generated time stretching attack: factor={stretch_factor}")

        return AudioAttackResult(
            audio_data=audio_data,
            audio_format="WAV",
            attack_type="time_stretching",
            technique="temporal_manipulation",
            metadata={
                "stretch_factor": stretch_factor,
                "original_duration": original_length / self.sample_rate,
                "new_duration": new_length / self.sample_rate,
            },
        )

    def _generate_tone(self, duration: float, frequency: float = 440.0) -> np.ndarray:
        """Generate a simple sine wave tone."""
        t = np.linspace(0, duration, int(self.sample_rate * duration))
        tone = np.sin(2 * np.pi * frequency * t) * 0.3
        return tone

    def _text_to_signal(self, text: str) -> np.ndarray:
        """
        Convert text to audio signal (simplified).

        In practice, would use TTS. This creates a modulated signal.
        """
        duration = max(len(text) * 0.1, 1.0)
        t = np.linspace(0, duration, int(self.sample_rate * duration))

        # Create frequency modulation based on text
        base_freq = 300.0
        signal = np.zeros_like(t)

        for i, char in enumerate(text):
            freq = base_freq + (ord(char) % 500)
            start_idx = int(i * len(t) / len(text))
            end_idx = int((i + 1) * len(t) / len(text))
            signal[start_idx:end_idx] = np.sin(2 * np.pi * freq * t[start_idx:end_idx])

        return signal * 0.3

    def _load_audio(self, audio_data: bytes) -> np.ndarray:
        """Load audio from bytes."""
        with wave.open(io.BytesIO(audio_data), 'rb') as wav:
            frames = wav.readframes(wav.getnframes())
            audio = np.frombuffer(frames, dtype=np.int16).astype(np.float32)
            audio = audio / 32768.0  # Normalize to -1.0 to 1.0
        return audio

    def _array_to_wav(self, audio_array: np.ndarray) -> bytes:
        """Convert numpy array to WAV bytes."""
        # Convert to 16-bit PCM
        audio_int = (audio_array * 32767).astype(np.int16)

        # Create WAV file in memory
        output = io.BytesIO()
        with wave.open(output, 'wb') as wav:
            wav.setnchannels(self.channels)
            wav.setsampwidth(self.sample_width)
            wav.setframerate(self.sample_rate)
            wav.writeframes(audio_int.tobytes())

        return output.getvalue()

    def audio_to_base64(self, audio_data: bytes) -> str:
        """Convert audio bytes to base64 string."""
        return base64.b64encode(audio_data).decode('utf-8')

    def base64_to_audio(self, base64_str: str) -> bytes:
        """Convert base64 string to audio bytes."""
        return base64.b64decode(base64_str)
