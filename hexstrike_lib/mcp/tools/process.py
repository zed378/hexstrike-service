"""Process management — MCP tool registrations."""

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
    # PROCESS MANAGEMENT TOOLS (v5.0 ENHANCEMENT)
    # ============================================================================

    @mcp.tool()
    def list_active_processes() -> Dict[str, Any]:
        """
        List all active processes on the HexStrike AI server.

        Returns:
            List of active processes with their status and progress
        """
        logger.info("📊 Listing active processes")
        result = hexstrike_client.safe_get("api/processes/list")
        if result.get("success"):
            logger.info(f"✅ Found {result.get('total_count', 0)} active processes")
        else:
            logger.error("❌ Failed to list processes")
        return result

    @mcp.tool()
    def get_process_status(pid: int) -> Dict[str, Any]:
        """
        Get the status of a specific process.

        Args:
            pid: Process ID to check

        Returns:
            Process status information including progress and runtime
        """
        logger.info(f"🔍 Checking status of process {pid}")
        result = hexstrike_client.safe_get(f"api/processes/status/{pid}")
        if result.get("success"):
            logger.info(f"✅ Process {pid} status retrieved")
        else:
            logger.error(f"❌ Process {pid} not found or error occurred")
        return result

    @mcp.tool()
    def terminate_process(pid: int) -> Dict[str, Any]:
        """
        Terminate a specific running process.

        Args:
            pid: Process ID to terminate

        Returns:
            Success status of the termination operation
        """
        logger.info(f"🛑 Terminating process {pid}")
        result = hexstrike_client.safe_post(f"api/processes/terminate/{pid}", {})
        if result.get("success"):
            logger.info(f"✅ Process {pid} terminated successfully")
        else:
            logger.error(f"❌ Failed to terminate process {pid}")
        return result

    @mcp.tool()
    def pause_process(pid: int) -> Dict[str, Any]:
        """
        Pause a specific running process.

        Args:
            pid: Process ID to pause

        Returns:
            Success status of the pause operation
        """
        logger.info(f"⏸️ Pausing process {pid}")
        result = hexstrike_client.safe_post(f"api/processes/pause/{pid}", {})
        if result.get("success"):
            logger.info(f"✅ Process {pid} paused successfully")
        else:
            logger.error(f"❌ Failed to pause process {pid}")
        return result

    @mcp.tool()
    def resume_process(pid: int) -> Dict[str, Any]:
        """
        Resume a paused process.

        Args:
            pid: Process ID to resume

        Returns:
            Success status of the resume operation
        """
        logger.info(f"▶️ Resuming process {pid}")
        result = hexstrike_client.safe_post(f"api/processes/resume/{pid}", {})
        if result.get("success"):
            logger.info(f"✅ Process {pid} resumed successfully")
        else:
            logger.error(f"❌ Failed to resume process {pid}")
        return result

    @mcp.tool()
    def get_process_dashboard() -> Dict[str, Any]:
        """
        Get enhanced process dashboard with visual status indicators.

        Returns:
            Real-time dashboard with progress bars, system metrics, and process status
        """
        logger.info("📊 Getting process dashboard")
        result = hexstrike_client.safe_get("api/processes/dashboard")
        if result.get("success", True) and "total_processes" in result:
            total = result.get("total_processes", 0)
            logger.info(f"✅ Dashboard retrieved: {total} active processes")

            # Log visual summary for better UX
            if total > 0:
                logger.info("📈 Active Processes Summary:")
                for proc in result.get("processes", [])[:3]:  # Show first 3
                    logger.info(f"   ├─ PID {proc['pid']}: {proc['progress_bar']} {proc['progress_percent']}")
        else:
            logger.error("❌ Failed to get process dashboard")
        return result

    @mcp.tool()
    def execute_command(command: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Execute an arbitrary command on the HexStrike AI server with enhanced logging.

        Args:
            command: The command to execute
            use_cache: Whether to use caching for this command

        Returns:
            Command execution results with enhanced telemetry
        """
        try:
            logger.info(f"⚡ Executing command: {command}")
            result = hexstrike_client.execute_command(command, use_cache)
            if "error" in result:
                logger.error(f"❌ Command failed: {result['error']}")
                return {
                    "success": False,
                    "error": result["error"],
                    "stdout": "",
                    "stderr": f"Error executing command: {result['error']}"
                }

            if result.get("success"):
                execution_time = result.get("execution_time", 0)
                logger.info(f"✅ Command completed successfully in {execution_time:.2f}s")
            else:
                logger.warning(f"⚠️  Command completed with errors")

            return result
        except Exception as e:
            logger.error(f"💥 Error executing command '{command}': {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "stdout": "",
                "stderr": f"Error executing command: {str(e)}"
            }

