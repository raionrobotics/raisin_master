#!/usr/bin/env python3
"""Configuration loader for VLM Navigation system."""

from typing import Any, Dict
import yaml
from pathlib import Path
import os
from ament_index_python.packages import get_package_share_directory

config = os.path.join(
    get_package_share_directory('mm_dev'),
    'config',
    'vlm_nav_config.yaml',
)

class VLMNavConfig:
    """Load and manage VLM Navigation configuration."""

    def __init__(self, config_path: str = None):
        """
        Initialize configuration loader.

        Args:
            config_path: Path to config YAML file. If None, uses default location.
        """
        if config_path is None:
            config_path = config
            
        self.config_path = Path(config_path)
        self._config: Dict[str, Any] = {}
        self._load_config()

    def _load_config(self):
        """Load configuration from YAML file."""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")

        with open(self.config_path, 'r') as f:
            self._config = yaml.safe_load(f)

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.

        Args:
            key_path: Dot-separated path to config value (e.g., 'navigation.robot_length')
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        keys = key_path.split('.')
        value = self._config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    @property
    def navigation(self) -> Dict[str, Any]:
        """Get navigation parameters."""
        return self._config.get('navigation', {})

    @property
    def detection(self) -> Dict[str, Any]:
        """Get detection parameters."""
        return self._config.get('detection', {})

    @property
    def approach(self) -> Dict[str, Any]:
        """Get approach distance parameters."""
        return self._config.get('approach', {})

    @property
    def vlm(self) -> Dict[str, Any]:
        """Get VLM configuration."""
        return self._config.get('vlm', {})

    @property
    def frontier(self) -> Dict[str, Any]:
        """Get frontier exploration parameters."""
        return self._config.get('frontier', {})

    @property
    def task(self) -> Dict[str, Any]:
        """Get task configuration."""
        return self._config.get('task', {})

    @property
    def ablation(self) -> Dict[str, Any]:
        """Get ablation study configuration."""
        return self._config.get('ablation', {})

    @property
    def paths(self) -> Dict[str, Any]:
        """Get file path configuration."""
        return self._config.get('paths', {})

    @property
    def timeouts(self) -> Dict[str, Any]:
        """Get timeout configuration."""
        return self._config.get('timeouts', {})