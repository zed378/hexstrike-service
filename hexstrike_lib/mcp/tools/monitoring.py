"""System monitoring & telemetry — MCP tool registrations."""

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
    # SYSTEM MONITORING & TELEMETRY
    # ============================================================================

    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        Check the health status of the HexStrike AI server.

        Returns:
            Server health information with tool availability and telemetry
        """
        logger.info(f"🏥 Checking HexStrike AI server health")
        result = hexstrike_client.check_health()
        if result.get("status") == "healthy":
            logger.info(f"✅ Server is healthy - {result.get('total_tools_available', 0)} tools available")
        else:
            logger.warning(f"⚠️  Server health check returned: {result.get('status', 'unknown')}")
        return result

    @mcp.tool()
    def get_cache_stats() -> Dict[str, Any]:
        """
        Get cache statistics from the HexStrike AI server.

        Returns:
            Cache performance statistics
        """
        logger.info(f"💾 Getting cache statistics")
        result = hexstrike_client.safe_get("api/cache/stats")
        if "hit_rate" in result:
            logger.info(f"📊 Cache hit rate: {result.get('hit_rate', 'unknown')}")
        return result

    @mcp.tool()
    def clear_cache() -> Dict[str, Any]:
        """
        Clear the cache on the HexStrike AI server.

        Returns:
            Cache clear operation results
        """
        logger.info(f"🧹 Clearing server cache")
        result = hexstrike_client.safe_post("api/cache/clear", {})
        if result.get("success"):
            logger.info(f"✅ Cache cleared successfully")
        else:
            logger.error(f"❌ Failed to clear cache")
        return result

    @mcp.tool()
    def get_telemetry() -> Dict[str, Any]:
        """
        Get system telemetry from the HexStrike AI server.

        Returns:
            System performance and usage telemetry
        """
        logger.info(f"📈 Getting system telemetry")
        result = hexstrike_client.safe_get("api/telemetry")
        if "commands_executed" in result:
            logger.info(f"📊 Commands executed: {result.get('commands_executed', 0)}")
        return result

