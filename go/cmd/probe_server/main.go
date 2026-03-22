package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/llmrt/llm-redteam/internal/proto"
	"github.com/llmrt/llm-redteam/internal/proberunner"
	"github.com/llmrt/llm-redteam/internal/transport"
	"google.golang.org/grpc"
)

const (
	defaultPort = ":50051"
	version     = "1.0.0"
)

// probeServer implements the ProbeService gRPC service.
type probeServer struct {
	proto.UnimplementedProbeServiceServer
	rateLimiter *transport.RateLimiter
}

// FireBatch implements streaming batch probe execution.
func (s *probeServer) FireBatch(req *proto.ProbeBatchRequest, stream proto.ProbeService_FireBatchServer) error {
	log.Printf("[ProbeServer] FireBatch: campaign=%s, payloads=%d, concurrency=%d",
		req.CampaignId, len(req.Payloads), req.Concurrency)

	// Create rate limiter from request parameters
	delayMs := req.DelayMs
	if delayMs == 0 {
		delayMs = 200 // Default 200ms = 5 req/s
	}
	rps := 1000.0 / float64(delayMs)

	concurrency := int(req.Concurrency)
	if concurrency == 0 {
		concurrency = 5
	}

	rateLimiter := transport.NewRateLimiter(rps, concurrency)
	defer rateLimiter.Stop()

	// Create runner
	runner := proberunner.NewRunner(concurrency, rateLimiter)

	// Create results channel
	results := make(chan *proto.ProbeResult, len(req.Payloads)*10)

	// Start batch execution in goroutine
	go func() {
		if err := runner.FireBatch(stream.Context(), req, results); err != nil {
			log.Printf("[ProbeServer] FireBatch error: %v", err)
		}
		close(results)
	}()

	// Stream results back to client
	for result := range results {
		if err := stream.Send(result); err != nil {
			return err
		}
	}

	log.Printf("[ProbeServer] FireBatch complete: campaign=%s", req.CampaignId)
	return nil
}

// FireSingle implements single probe execution.
func (s *probeServer) FireSingle(ctx context.Context, req *proto.ProbeRequest) (*proto.ProbeResult, error) {
	log.Printf("[ProbeServer] FireSingle: campaign=%s, payload_len=%d",
		req.CampaignId, len(req.Payload))

	// Create adapter
	adapter := transport.NewAdapter(
		req.EndpointUrl,
		req.Method,
		req.BodySchema,
		req.Headers,
	)

	// Execute probe
	responseBody, statusCode, latencyMs, err := adapter.Inject(req.Payload, req.Headers)

	result := &proto.ProbeResult{
		Payload:      req.Payload,
		ResponseBody: responseBody,
		StatusCode:   int32(statusCode),
		LatencyMs:    latencyMs,
		ProbeFamily:  "single",
	}

	if err != nil {
		result.ErrorMessage = err.Error()
	}

	return result, nil
}

// Cancel implements campaign cancellation.
func (s *probeServer) Cancel(ctx context.Context, req *proto.CancelRequest) (*proto.CancelResponse, error) {
	log.Printf("[ProbeServer] Cancel: campaign=%s", req.CampaignId)

	// TODO: Implement campaign cancellation tracking
	// For now, return success
	return &proto.CancelResponse{Cancelled: true}, nil
}

// HealthCheck implements health check endpoint.
func (s *probeServer) HealthCheck(ctx context.Context, req *proto.HealthRequest) (*proto.HealthResponse, error) {
	return &proto.HealthResponse{
		Ok:      true,
		Version: version,
	}, nil
}

func main() {
	// Get port from environment or use default
	port := os.Getenv("PROBE_GRPC_PORT")
	if port == "" {
		port = defaultPort
	}

	// Create listener
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("[ProbeServer] Failed to listen: %v", err)
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Create rate limiter (default 5 req/s)
	rateLimiter := transport.NewRateLimiter(5.0, 10)

	// Register service
	proto.RegisterProbeServiceServer(grpcServer, &probeServer{
		rateLimiter: rateLimiter,
	})

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("[ProbeServer] Shutting down gracefully...")
		rateLimiter.Stop()
		grpcServer.GracefulStop()
	}()

	// Start server
	log.Printf("[ProbeServer] Starting on %s (version %s)", port, version)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("[ProbeServer] Failed to serve: %v", err)
	}
}
