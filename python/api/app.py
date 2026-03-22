"""
FastAPI application for llmrt.

Provides REST API and WebSocket interface for campaign management,
probe execution, and real-time monitoring.

Usage:
    uvicorn python.api.app:app --host 0.0.0.0 --port 9999
"""

import logging
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
import asyncio

from .websocket import websocket_endpoint, manager as ws_manager

logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="llmrt API",
    description="AI/LLM/MCP Security Assessment Platform API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage (replace with database in production)
campaigns = {}
findings = {}
endpoints = []
mcp_configs = []


# Pydantic models
class CampaignCreate(BaseModel):
    """Campaign creation request."""
    name: str = Field(..., description="Campaign name")
    target_url: str = Field(..., description="Target URL")
    scope_file: Optional[str] = Field(None, description="Path to scope.yaml")
    profile: str = Field("chatbot", description="Attack profile")
    auth: Optional[Dict] = Field(None, description="Authentication context")


class CampaignResponse(BaseModel):
    """Campaign response."""
    campaign_id: str
    name: str
    target_url: str
    status: str
    created_at: str
    findings_count: int = 0


class ProbeRequest(BaseModel):
    """Probe request from browser extension."""
    endpoint: str
    payload: str
    attack_type: str
    timestamp: str
    batch_index: Optional[int] = None


class EndpointCapture(BaseModel):
    """Endpoint capture from browser extension."""
    timestamp: str
    method: str
    url: str
    type: str
    headers: Optional[Dict] = None
    requestBody: Optional[str] = None
    responseBody: Optional[str] = None
    statusCode: Optional[int] = None


class MCPConfigCapture(BaseModel):
    """MCP config capture from browser extension."""
    timestamp: str
    type: str
    source: str
    value: str
    url: str


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }


# Campaign endpoints
@app.post("/api/campaigns", response_model=CampaignResponse)
async def create_campaign(campaign: CampaignCreate, background_tasks: BackgroundTasks):
    """
    Creates new security assessment campaign.
    
    Args:
        campaign: Campaign configuration
        background_tasks: FastAPI background tasks
        
    Returns:
        Campaign response with ID
    """
    campaign_id = f"campaign_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    
    campaign_data = {
        "campaign_id": campaign_id,
        "name": campaign.name,
        "target_url": campaign.target_url,
        "scope_file": campaign.scope_file,
        "profile": campaign.profile,
        "auth": campaign.auth,
        "status": "created",
        "created_at": datetime.utcnow().isoformat(),
        "findings_count": 0
    }
    
    campaigns[campaign_id] = campaign_data
    findings[campaign_id] = []
    
    logger.info(f"Created campaign: {campaign_id}")
    
    # Start campaign in background
    background_tasks.add_task(run_campaign, campaign_id)
    
    return CampaignResponse(**campaign_data)


@app.get("/api/campaigns", response_model=List[CampaignResponse])
async def list_campaigns():
    """Lists all campaigns."""
    return [CampaignResponse(**c) for c in campaigns.values()]


@app.get("/api/campaigns/{campaign_id}", response_model=CampaignResponse)
async def get_campaign(campaign_id: str):
    """Gets campaign details."""
    if campaign_id not in campaigns:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    return CampaignResponse(**campaigns[campaign_id])


@app.delete("/api/campaigns/{campaign_id}")
async def delete_campaign(campaign_id: str):
    """Deletes campaign."""
    if campaign_id not in campaigns:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    del campaigns[campaign_id]
    if campaign_id in findings:
        del findings[campaign_id]
    
    logger.info(f"Deleted campaign: {campaign_id}")
    
    return {"status": "deleted", "campaign_id": campaign_id}


# Findings endpoints
@app.get("/api/campaigns/{campaign_id}/findings")
async def get_findings(campaign_id: str):
    """Gets findings for campaign."""
    if campaign_id not in campaigns:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    return {
        "campaign_id": campaign_id,
        "findings": findings.get(campaign_id, []),
        "count": len(findings.get(campaign_id, []))
    }


@app.post("/api/campaigns/{campaign_id}/findings")
async def add_finding(campaign_id: str, finding: Dict):
    """Adds finding to campaign."""
    if campaign_id not in campaigns:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    finding["id"] = f"finding_{len(findings.get(campaign_id, []))}"
    finding["timestamp"] = datetime.utcnow().isoformat()
    
    if campaign_id not in findings:
        findings[campaign_id] = []
    
    findings[campaign_id].append(finding)
    campaigns[campaign_id]["findings_count"] = len(findings[campaign_id])
    
    logger.info(f"Added finding to campaign {campaign_id}: {finding['id']}")
    
    return finding


# Report endpoints
@app.get("/api/campaigns/{campaign_id}/report")
async def get_report(campaign_id: str, format: str = "json"):
    """
    Generates campaign report.
    
    Args:
        campaign_id: Campaign ID
        format: Report format (json, html, pdf, markdown)
        
    Returns:
        Report in requested format
    """
    if campaign_id not in campaigns:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    # Import report generator
    from python.reporting.generator import ReportGenerator
    
    generator = ReportGenerator()
    campaign_findings = findings.get(campaign_id, [])
    
    report = await generator.generate_report(
        campaign_id=campaign_id,
        findings=campaign_findings,
        metadata=campaigns[campaign_id]
    )
    
    if format == "json":
        return report
    
    elif format == "html":
        output_path = f"output/reports/{campaign_id}.html"
        await generator.export_html(report, output_path)
        return FileResponse(output_path, media_type="text/html")
    
    elif format == "pdf":
        output_path = f"output/reports/{campaign_id}.pdf"
        await generator.export_pdf(report, output_path)
        return FileResponse(output_path, media_type="application/pdf")
    
    elif format == "markdown":
        output_path = f"output/reports/{campaign_id}.md"
        await generator.export_markdown(report, output_path)
        return FileResponse(output_path, media_type="text/markdown")
    
    else:
        raise HTTPException(status_code=400, detail="Invalid format")


# Browser extension endpoints
@app.post("/api/probe")
async def receive_probe(probe: ProbeRequest):
    """
    Receives probe from browser extension.
    
    Args:
        probe: Probe request data
        
    Returns:
        Probe result
    """
    logger.info(f"Received probe: {probe.attack_type} -> {probe.endpoint}")
    
    # Store probe for analysis
    # In production, this would trigger actual probe execution
    
    return {
        "status": "received",
        "probe_id": f"probe_{datetime.utcnow().timestamp()}",
        "attack_type": probe.attack_type,
        "endpoint": probe.endpoint
    }


@app.post("/api/endpoints")
async def receive_endpoint(endpoint: EndpointCapture):
    """
    Receives endpoint capture from browser extension.
    
    Args:
        endpoint: Endpoint capture data
        
    Returns:
        Success response
    """
    endpoints.append(endpoint.dict())
    logger.info(f"Captured endpoint: {endpoint.method} {endpoint.url}")
    
    return {"status": "captured", "count": len(endpoints)}


@app.get("/api/endpoints")
async def list_endpoints():
    """Lists captured endpoints."""
    return {
        "endpoints": endpoints,
        "count": len(endpoints)
    }


@app.post("/api/mcp-configs")
async def receive_mcp_config(config: MCPConfigCapture):
    """
    Receives MCP config from browser extension.
    
    Args:
        config: MCP config capture data
        
    Returns:
        Success response
    """
    mcp_configs.append(config.dict())
    logger.info(f"Captured MCP config: {config.type} from {config.source}")
    
    return {"status": "captured", "count": len(mcp_configs)}


@app.get("/api/mcp-configs")
async def list_mcp_configs():
    """Lists captured MCP configs."""
    return {
        "configs": mcp_configs,
        "count": len(mcp_configs)
    }


# Statistics endpoint
@app.get("/api/stats")
async def get_stats():
    """Gets platform statistics."""
    total_findings = sum(len(f) for f in findings.values())
    
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    
    for campaign_findings in findings.values():
        for finding in campaign_findings:
            severity = finding.get("severity", "info")
            if severity in severity_counts:
                severity_counts[severity] += 1
    
    return {
        "campaigns": {
            "total": len(campaigns),
            "active": sum(1 for c in campaigns.values() if c["status"] == "running"),
            "completed": sum(1 for c in campaigns.values() if c["status"] == "completed")
        },
        "findings": {
            "total": total_findings,
            "by_severity": severity_counts
        },
        "endpoints": {
            "captured": len(endpoints)
        },
        "mcp_configs": {
            "discovered": len(mcp_configs)
        },
        "websocket": {
            "total_connections": ws_manager.get_total_connections()
        }
    }


# WebSocket endpoint
@app.websocket("/ws/{campaign_id}")
async def websocket_route(websocket: WebSocket, campaign_id: str):
    """
    WebSocket endpoint for real-time campaign updates.
    
    Args:
        websocket: WebSocket connection
        campaign_id: Campaign ID to subscribe to
    """
    await websocket_endpoint(websocket, campaign_id)


# Background task: Run campaign
async def run_campaign(campaign_id: str):
    """
    Runs security assessment campaign.
    
    Args:
        campaign_id: Campaign ID
    """
    logger.info(f"Starting campaign: {campaign_id}")
    
    try:
        campaigns[campaign_id]["status"] = "running"
        
        # Import orchestrator
        from python.core.orchestrator import Orchestrator
        from python.core.target import Target
        
        # Create target
        campaign_data = campaigns[campaign_id]
        target = Target(
            url=campaign_data["target_url"],
            auth=campaign_data.get("auth")
        )
        
        # Create orchestrator
        orchestrator = Orchestrator(
            target=target,
            scope_file=campaign_data.get("scope_file", "config/scope.yaml"),
            profile=campaign_data.get("profile", "chatbot")
        )
        
        # Run campaign
        # Note: This is simplified - real implementation would use orchestrator
        await asyncio.sleep(5)  # Simulate campaign execution
        
        campaigns[campaign_id]["status"] = "completed"
        campaigns[campaign_id]["completed_at"] = datetime.utcnow().isoformat()
        
        logger.info(f"Campaign completed: {campaign_id}")
        
    except Exception as e:
        logger.error(f"Campaign failed: {campaign_id} - {e}")
        campaigns[campaign_id]["status"] = "failed"
        campaigns[campaign_id]["error"] = str(e)


# Startup event
@app.on_event("startup")
async def startup_event():
    """Startup event handler."""
    logger.info("llmrt API starting up")
    
    # Create output directories
    Path("output/reports").mkdir(parents=True, exist_ok=True)
    
    logger.info("llmrt API ready")


# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Shutdown event handler."""
    logger.info("llmrt API shutting down")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9999)
