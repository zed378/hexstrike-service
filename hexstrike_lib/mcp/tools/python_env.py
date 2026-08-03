"""Python environment management — MCP tool registrations."""

import argparse  # noqa: F401
import logging
import os  # noqa: F401
import sys  # noqa: F401
import time  # noqa: F401
from datetime import datetime  # noqa: F401
from typing import Any, Dict, Optional  # noqa: F401

import requests  # noqa: F401

from ..client import (  # noqa: F401
    DEFAULT_HEXSTRIKE_SERVER,
    DEFAULT_REQUEST_TIMEOUT,
    MAX_RETRIES,
    HexStrikeClient,
)
from ..colors import ColoredFormatter, Colors, HexStrikeColors  # noqa: F401

logger = logging.getLogger(__name__)


def register(mcp, hexstrike_client):
    # ============================================================================
    # PYTHON ENVIRONMENT MANAGEMENT
    # ============================================================================

    @mcp.tool()
    def install_python_package(package: str, env_name: str = "default") -> Dict[str, Any]:
        """
        Install a Python package in a virtual environment on the HexStrike server.

        Args:
            package: Name of the Python package to install
            env_name: Name of the virtual environment

        Returns:
            Package installation results
        """
        data = {
            "package": package,
            "env_name": env_name
        }
        logger.info(f"📦 Installing Python package: {package} in env {env_name}")
        result = hexstrike_client.safe_post("api/python/install", data)
        if result.get("success"):
            logger.info(f"✅ Package {package} installed successfully")
        else:
            logger.error(f"❌ Failed to install package {package}")
        return result

    @mcp.tool()
    def execute_python_script(script: str, env_name: str = "default", filename: str = "") -> Dict[str, Any]:
        """
        Execute a Python script in a virtual environment on the HexStrike server.

        Args:
            script: Python script content to execute
            env_name: Name of the virtual environment
            filename: Custom script filename (auto-generated if empty)

        Returns:
            Script execution results
        """
        data = {
            "script": script,
            "env_name": env_name
        }
        if filename:
            data["filename"] = filename

        logger.info(f"🐍 Executing Python script in env {env_name}")
        result = hexstrike_client.safe_post("api/python/execute", data)
        if result.get("success"):
            logger.info(f"✅ Python script executed successfully")
        else:
            logger.error(f"❌ Python script execution failed")
        return result

