package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/llmrt/llm-redteam/internal/proto"
	"github.com/llmrt/llm-redteam/internal/reconrunner"
	"google.golang.org/grpc"
)

const (
	defaultPort = ":50052"
	version     = "1.0.0"
)

// reconServer implements the ReconService gRPC service.
type reconServer struct {
	proto.UnimplementedReconServiceServer
}

// ScanPorts implements port scanning.
func (s *reconServer) ScanPorts(ctx context.Context, req *proto.PortScanRequest) (*proto.PortScanResult, error) {
	log.Printf("[ReconServer] ScanPorts: host=%s, ports=%v", req.Host, req.Ports)

	// Convert proto ports to int slice
	ports := make([]int, len(req.Ports))
	for i, p := range req.Ports {
		ports[i] = int(p)
	}

	// Execute port scan
	entries, err := reconrunner.ScanPorts(req.Host, ports)
	if err != nil {
		return nil, err
	}

	// Convert to proto format
	result := &proto.PortScanResult{
		Ports: make([]*proto.PortScanResult_PortEntry, len(entries)),
	}

	for i, entry := range entries {
		result.Ports[i] = &proto.PortScanResult_PortEntry{
			Port:      int32(entry.Port),
			Service:   entry.Service,
			Banner:    entry.Banner,
			AiService: entry.AIService,
		}
	}

	log.Printf("[ReconServer] ScanPorts complete: %d ports found", len(entries))
	return result, nil
}

// FuzzEndpoints implements endpoint fuzzing.
func (s *reconServer) FuzzEndpoints(ctx context.Context, req *proto.FuzzRequest) (*proto.FuzzResult, error) {
	log.Printf("[ReconServer] FuzzEndpoints: base_url=%s, wordlist=%s", req.BaseUrl, req.Wordlist)

	// Execute endpoint fuzzing
	entries, err := reconrunner.FuzzEndpoints(
		req.BaseUrl,
		req.Wordlist,
		int(req.Concurrency),
		int(req.DelayMs),
	)
	if err != nil {
		return nil, err
	}

	// Convert to proto format
	result := &proto.FuzzResult{
		Endpoints: make([]*proto.EndpointEntry, len(entries)),
	}

	for i, entry := range entries {
		result.Endpoints[i] = &proto.EndpointEntry{
			Url:    entry.URL,
			Status: int32(entry.Status),
			Size:   entry.Size,
		}
	}

	log.Printf("[ReconServer] FuzzEndpoints complete: %d endpoints found", len(entries))
	return result, nil
}

// CheckBinding implements network binding check.
func (s *reconServer) CheckBinding(ctx context.Context, req *proto.BindingRequest) (*proto.BindingResult, error) {
	log.Printf("[ReconServer] CheckBinding: host=%s, port=%d", req.Host, req.Port)

	// Execute binding check
	result, err := reconrunner.CheckBinding(req.Host, int(req.Port))
	if err != nil {
		return nil, err
	}

	// Convert to proto format
	return &proto.BindingResult{
		Exposed:      result.Exposed,
		BoundAddress: result.BoundAddress,
	}, nil
}

// ParseHAR implements HAR file parsing.
func (s *reconServer) ParseHAR(ctx context.Context, req *proto.HARRequest) (*proto.EndpointMap, error) {
	log.Printf("[ReconServer] ParseHAR: data_size=%d bytes", len(req.HarData))

	// Parse HAR file
	endpointMap, err := reconrunner.ParseHAR(req.HarData)
	if err != nil {
		return nil, err
	}

	// Convert to proto format
	result := &proto.EndpointMap{
		Endpoints: make([]*proto.EndpointEntry, len(endpointMap.Endpoints)),
		AuthType:  endpointMap.AuthType,
	}

	for i, entry := range endpointMap.Endpoints {
		result.Endpoints[i] = &proto.EndpointEntry{
			Url:    entry.URL,
			Status: int32(entry.Status),
			Size:   entry.Size,
		}
	}

	log.Printf("[ReconServer] ParseHAR complete: %d endpoints, auth=%s",
		len(endpointMap.Endpoints), endpointMap.AuthType)
	return result, nil
}

// HealthCheck implements health check endpoint.
func (s *reconServer) HealthCheck(ctx context.Context, req *proto.HealthRequest) (*proto.HealthResponse, error) {
	return &proto.HealthResponse{
		Ok:      true,
		Version: version,
	}, nil
}

func main() {
	// Get port from environment or use default
	port := os.Getenv("RECON_GRPC_PORT")
	if port == "" {
		port = defaultPort
	}

	// Create listener
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("[ReconServer] Failed to listen: %v", err)
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Register service
	proto.RegisterReconServiceServer(grpcServer, &reconServer{})

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("[ReconServer] Shutting down gracefully...")
		grpcServer.GracefulStop()
	}()

	// Start server
	log.Printf("[ReconServer] Starting on %s (version %s)", port, version)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("[ReconServer] Failed to serve: %v", err)
	}
}
