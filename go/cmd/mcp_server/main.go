package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/llmrt/llm-redteam/internal/mcprunner"
	"github.com/llmrt/llm-redteam/internal/proto"
	"google.golang.org/grpc"
)

const (
	defaultPort = ":50053"
	version     = "1.0.0"
)

// mcpServer implements the MCPService gRPC service.
type mcpServer struct {
	proto.UnimplementedMCPServiceServer
}

// EnumerateTools implements MCP tool enumeration.
func (s *mcpServer) EnumerateTools(ctx context.Context, req *proto.MCPEnumRequest) (*proto.MCPSchema, error) {
	log.Printf("[MCPServer] EnumerateTools: server=%s, campaign=%s", req.ServerUrl, req.CampaignId)

	// Create enumerator
	enumerator := mcprunner.NewEnumerator(req.ServerUrl, req.Auth)

	// Enumerate all capabilities
	schema, err := enumerator.EnumerateAll()
	if err != nil {
		return nil, err
	}

	// Convert to proto format
	result := &proto.MCPSchema{
		Tools:           make([]*proto.MCPTool, len(schema.Tools)),
		Resources:       make([]*proto.MCPResource, len(schema.Resources)),
		Prompts:         make([]*proto.MCPPrompt, len(schema.Prompts)),
		SamplingEnabled: schema.SamplingEnabled,
		Transport:       schema.Transport,
	}

	for i, tool := range schema.Tools {
		result.Tools[i] = &proto.MCPTool{
			Name:        tool.Name,
			Description: tool.Description,
			InputSchema: tool.InputSchema,
		}
	}

	for i, resource := range schema.Resources {
		result.Resources[i] = &proto.MCPResource{
			Uri:      resource.URI,
			Name:     resource.Name,
			MimeType: resource.MimeType,
		}
	}

	for i, prompt := range schema.Prompts {
		result.Prompts[i] = &proto.MCPPrompt{
			Name:        prompt.Name,
			Description: prompt.Description,
		}
	}

	log.Printf("[MCPServer] EnumerateTools complete: %d tools, %d resources, %d prompts",
		len(schema.Tools), len(schema.Resources), len(schema.Prompts))
	return result, nil
}

// FireMCPAttacks implements streaming MCP attack execution.
func (s *mcpServer) FireMCPAttacks(req *proto.MCPAttackRequest, stream proto.MCPService_FireMCPAttacksServer) error {
	log.Printf("[MCPServer] FireMCPAttacks: type=%s, campaign=%s", req.AttackType, req.CampaignId)

	// Create enumerator
	enumerator := mcprunner.NewEnumerator(req.ServerUrl, req.Auth)

	// Convert proto schema to internal schema
	schema := mcprunner.MCPSchema{
		Tools:           make([]mcprunner.MCPTool, len(req.Schema.Tools)),
		Resources:       make([]mcprunner.MCPResource, len(req.Schema.Resources)),
		Prompts:         make([]mcprunner.MCPPrompt, len(req.Schema.Prompts)),
		SamplingEnabled: req.Schema.SamplingEnabled,
		Transport:       req.Schema.Transport,
	}

	for i, tool := range req.Schema.Tools {
		schema.Tools[i] = mcprunner.MCPTool{
			Name:        tool.Name,
			Description: tool.Description,
			InputSchema: tool.InputSchema,
		}
	}

	for i, resource := range req.Schema.Resources {
		schema.Resources[i] = mcprunner.MCPResource{
			URI:      resource.Uri,
			Name:     resource.Name,
			MimeType: resource.MimeType,
		}
	}

	for i, prompt := range req.Schema.Prompts {
		schema.Prompts[i] = mcprunner.MCPPrompt{
			Name:        prompt.Name,
			Description: prompt.Description,
		}
	}

	// Execute attack based on type
	var findings []mcprunner.MCPFinding
	var err error

	switch req.AttackType {
	case "rug_pull":
		findings, err = mcprunner.TestRugPull(enumerator, req.CampaignId)
	case "sql_injection":
		findings, err = mcprunner.TestSQLInjection(enumerator, schema, req.CampaignId)
	default:
		log.Printf("[MCPServer] Unknown attack type: %s", req.AttackType)
		return nil
	}

	if err != nil {
		return err
	}

	// Stream findings back to client
	for _, finding := range findings {
		protoFinding := &proto.MCPFinding{
			AttackType:  finding.AttackType,
			ToolName:    finding.ToolName,
			Payload:     finding.Payload,
			Response:    finding.Response,
			FindingType: finding.FindingType,
			OobCallback: finding.OOBCallback,
			CvssHint:    finding.CVSSHint,
		}

		if err := stream.Send(protoFinding); err != nil {
			return err
		}
	}

	log.Printf("[MCPServer] FireMCPAttacks complete: %d findings", len(findings))
	return nil
}

// HealthCheck implements health check endpoint.
func (s *mcpServer) HealthCheck(ctx context.Context, req *proto.HealthRequest) (*proto.HealthResponse, error) {
	return &proto.HealthResponse{
		Ok:      true,
		Version: version,
	}, nil
}

func main() {
	// Get port from environment or use default
	port := os.Getenv("MCP_GRPC_PORT")
	if port == "" {
		port = defaultPort
	}

	// Create listener
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("[MCPServer] Failed to listen: %v", err)
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Register service
	proto.RegisterMCPServiceServer(grpcServer, &mcpServer{})

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("[MCPServer] Shutting down gracefully...")
		grpcServer.GracefulStop()
	}()

	// Start server
	log.Printf("[MCPServer] Starting on %s (version %s)", port, version)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("[MCPServer] Failed to serve: %v", err)
	}
}
