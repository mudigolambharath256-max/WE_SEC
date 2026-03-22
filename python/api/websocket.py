"""
WebSocket handler for llmrt.

Provides real-time updates for campaign progress, findings, and logs.

Usage:
    Connect to ws://localhost:9999/ws/{campaign_id}
"""

import logging
from typing import Dict, Set
import json
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Manages WebSocket connections for real-time updates.
    
    Handles multiple clients per campaign and broadcasts updates.
    """

    def __init__(self):
        """Initializes connection manager."""
        # campaign_id -> set of WebSocket connections
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        logger.info("WebSocket connection manager initialized")

    async def connect(self, websocket: WebSocket, campaign_id: str):
        """
        Connects client to campaign updates.
        
        Args:
            websocket: WebSocket connection
            campaign_id: Campaign ID to subscribe to
        """
        await websocket.accept()
        
        if campaign_id not in self.active_connections:
            self.active_connections[campaign_id] = set()
        
        self.active_connections[campaign_id].add(websocket)
        
        logger.info(f"Client connected to campaign {campaign_id}. Total: {len(self.active_connections[campaign_id])}")
        
        # Send welcome message
        await self.send_personal_message(
            {
                "type": "connected",
                "campaign_id": campaign_id,
                "timestamp": datetime.utcnow().isoformat(),
                "message": "Connected to llmrt real-time updates"
            },
            websocket
        )

    def disconnect(self, websocket: WebSocket, campaign_id: str):
        """
        Disconnects client from campaign updates.
        
        Args:
            websocket: WebSocket connection
            campaign_id: Campaign ID
        """
        if campaign_id in self.active_connections:
            self.active_connections[campaign_id].discard(websocket)
            
            if not self.active_connections[campaign_id]:
                del self.active_connections[campaign_id]
            
            logger.info(f"Client disconnected from campaign {campaign_id}")

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """
        Sends message to specific client.
        
        Args:
            message: Message dictionary
            websocket: Target WebSocket connection
        """
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Failed to send personal message: {e}")

    async def broadcast(self, message: dict, campaign_id: str):
        """
        Broadcasts message to all clients subscribed to campaign.
        
        Args:
            message: Message dictionary
            campaign_id: Campaign ID
        """
        if campaign_id not in self.active_connections:
            return
        
        disconnected = set()
        
        for connection in self.active_connections[campaign_id]:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Failed to broadcast to client: {e}")
                disconnected.add(connection)
        
        # Remove disconnected clients
        for connection in disconnected:
            self.active_connections[campaign_id].discard(connection)

    async def broadcast_finding(self, finding: dict, campaign_id: str):
        """
        Broadcasts new finding to campaign subscribers.
        
        Args:
            finding: Finding dictionary
            campaign_id: Campaign ID
        """
        message = {
            "type": "finding",
            "campaign_id": campaign_id,
            "timestamp": datetime.utcnow().isoformat(),
            "data": finding
        }
        
        await self.broadcast(message, campaign_id)
        logger.info(f"Broadcasted finding to campaign {campaign_id}")

    async def broadcast_status(self, status: str, campaign_id: str, details: dict = None):
        """
        Broadcasts campaign status update.
        
        Args:
            status: Status string (running, completed, failed)
            campaign_id: Campaign ID
            details: Optional status details
        """
        message = {
            "type": "status",
            "campaign_id": campaign_id,
            "timestamp": datetime.utcnow().isoformat(),
            "status": status,
            "details": details or {}
        }
        
        await self.broadcast(message, campaign_id)
        logger.info(f"Broadcasted status '{status}' to campaign {campaign_id}")

    async def broadcast_log(self, log_message: str, level: str, campaign_id: str):
        """
        Broadcasts log message to campaign subscribers.
        
        Args:
            log_message: Log message
            level: Log level (debug, info, warning, error)
            campaign_id: Campaign ID
        """
        message = {
            "type": "log",
            "campaign_id": campaign_id,
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "message": log_message
        }
        
        await self.broadcast(message, campaign_id)

    async def broadcast_progress(self, progress: int, total: int, campaign_id: str, phase: str = None):
        """
        Broadcasts progress update.
        
        Args:
            progress: Current progress count
            total: Total items
            campaign_id: Campaign ID
            phase: Optional phase name
        """
        percentage = (progress / total * 100) if total > 0 else 0
        
        message = {
            "type": "progress",
            "campaign_id": campaign_id,
            "timestamp": datetime.utcnow().isoformat(),
            "progress": progress,
            "total": total,
            "percentage": round(percentage, 2),
            "phase": phase
        }
        
        await self.broadcast(message, campaign_id)

    async def broadcast_metric(self, metric_name: str, value: float, campaign_id: str):
        """
        Broadcasts metric update.
        
        Args:
            metric_name: Metric name
            value: Metric value
            campaign_id: Campaign ID
        """
        message = {
            "type": "metric",
            "campaign_id": campaign_id,
            "timestamp": datetime.utcnow().isoformat(),
            "metric": metric_name,
            "value": value
        }
        
        await self.broadcast(message, campaign_id)

    def get_connection_count(self, campaign_id: str) -> int:
        """
        Gets number of active connections for campaign.
        
        Args:
            campaign_id: Campaign ID
            
        Returns:
            int: Number of active connections
        """
        return len(self.active_connections.get(campaign_id, set()))

    def get_total_connections(self) -> int:
        """
        Gets total number of active connections.
        
        Returns:
            int: Total connections across all campaigns
        """
        return sum(len(conns) for conns in self.active_connections.values())


# Global connection manager instance
manager = ConnectionManager()


async def websocket_endpoint(websocket: WebSocket, campaign_id: str):
    """
    WebSocket endpoint handler.
    
    Args:
        websocket: WebSocket connection
        campaign_id: Campaign ID to subscribe to
    """
    await manager.connect(websocket, campaign_id)
    
    try:
        while True:
            # Receive messages from client
            data = await websocket.receive_text()
            
            try:
                message = json.loads(data)
                
                # Handle client messages
                if message.get("type") == "ping":
                    await manager.send_personal_message(
                        {"type": "pong", "timestamp": datetime.utcnow().isoformat()},
                        websocket
                    )
                
                elif message.get("type") == "subscribe":
                    # Client wants to subscribe to specific events
                    await manager.send_personal_message(
                        {"type": "subscribed", "events": message.get("events", [])},
                        websocket
                    )
                
                else:
                    logger.warning(f"Unknown message type: {message.get('type')}")
                
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON received: {data}")
                await manager.send_personal_message(
                    {"type": "error", "message": "Invalid JSON"},
                    websocket
                )
    
    except WebSocketDisconnect:
        manager.disconnect(websocket, campaign_id)
        logger.info(f"Client disconnected from campaign {campaign_id}")
    
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket, campaign_id)


# Helper functions for broadcasting from other modules
async def broadcast_finding(finding: dict, campaign_id: str):
    """Broadcasts finding (can be called from other modules)."""
    await manager.broadcast_finding(finding, campaign_id)


async def broadcast_status(status: str, campaign_id: str, details: dict = None):
    """Broadcasts status update (can be called from other modules)."""
    await manager.broadcast_status(status, campaign_id, details)


async def broadcast_log(log_message: str, level: str, campaign_id: str):
    """Broadcasts log message (can be called from other modules)."""
    await manager.broadcast_log(log_message, level, campaign_id)


async def broadcast_progress(progress: int, total: int, campaign_id: str, phase: str = None):
    """Broadcasts progress update (can be called from other modules)."""
    await manager.broadcast_progress(progress, total, campaign_id, phase)


async def broadcast_metric(metric_name: str, value: float, campaign_id: str):
    """Broadcasts metric update (can be called from other modules)."""
    await manager.broadcast_metric(metric_name, value, campaign_id)


logger.info("WebSocket module loaded")
