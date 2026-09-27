// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Simple echo service using raw bytes (no protobuf codegen needed).
// Messages are plain UTF-8 strings prefixed with a 4-byte big-endian length.
// For simplicity in the integration test, we use a trivial wire format:
//   request:  [4-byte len][message bytes][4-byte error_code (for EchoError)]
//   response: [4-byte len][message bytes]

// EchoRequest is a simple struct serialized manually
type EchoRequest struct {
	Message   string
	ErrorCode int32
}

type EchoResponse struct {
	Message string
}

type StreamRequest struct {
	Message string
	Count   int32
}

// Manual codec that passes raw bytes through (our Zig client sends raw bytes)
type RawCodec struct{}

func (RawCodec) Marshal(v interface{}) ([]byte, error) {
	if b, ok := v.(*[]byte); ok {
		return *b, nil
	}
	return nil, fmt.Errorf("raw codec: unsupported type %T", v)
}

func (RawCodec) Unmarshal(data []byte, v interface{}) error {
	if b, ok := v.(*[]byte); ok {
		*b = data
		return nil
	}
	return fmt.Errorf("raw codec: unsupported type %T", v)
}

func (RawCodec) Name() string { return "raw" }
func (RawCodec) String() string { return "raw" }

func main() {
	port := "50051"
	if p := os.Getenv("GRPC_PORT"); p != "" {
		port = p
	}

	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	srv := grpc.NewServer(grpc.ForceServerCodec(RawCodec{}))

	// Register Echo: returns the same bytes
	echoDesc := grpc.ServiceDesc{
		ServiceName: "echo.EchoService",
		HandlerType: (*interface{})(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Echo",
				Handler:    echoHandler,
			},
			{
				MethodName: "EchoError",
				Handler:    echoErrorHandler,
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "ServerStream",
				Handler:       serverStreamHandler,
				ServerStreams:  true,
			},
			{
				StreamName:    "BidiStream",
				Handler:       bidiStreamHandler,
				ServerStreams:  true,
				ClientStreams:  true,
			},
		},
	}
	srv.RegisterService(&echoDesc, nil)

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		srv.GracefulStop()
	}()

	fmt.Printf("READY:%s\n", port)
	os.Stdout.Sync()

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func echoHandler(srv interface{}, ctx context.Context, dec func(interface{}) error, _ grpc.UnaryServerInterceptor) (interface{}, error) {
	var reqBytes []byte
	if err := dec(&reqBytes); err != nil {
		return nil, err
	}
	// Echo: return the same bytes
	resp := reqBytes
	return &resp, nil
}

func echoErrorHandler(srv interface{}, ctx context.Context, dec func(interface{}) error, _ grpc.UnaryServerInterceptor) (interface{}, error) {
	var reqBytes []byte
	if err := dec(&reqBytes); err != nil {
		return nil, err
	}
	// Return an INTERNAL error with the request as the message
	return nil, status.Errorf(codes.Internal, "error: %s", string(reqBytes))
}

func serverStreamHandler(srv interface{}, stream grpc.ServerStream) error {
	var reqBytes []byte
	if err := stream.RecvMsg(&reqBytes); err != nil {
		return err
	}

	// Send 3 messages: "msg_0", "msg_1", "msg_2"
	for i := 0; i < 3; i++ {
		msg := []byte(fmt.Sprintf("%s_%d", string(reqBytes), i))
		if err := stream.SendMsg(&msg); err != nil {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

func bidiStreamHandler(srv interface{}, stream grpc.ServerStream) error {
	for {
		var reqBytes []byte
		if err := stream.RecvMsg(&reqBytes); err != nil {
			return nil // client closed
		}
		resp := []byte("echo:" + string(reqBytes))
		if err := stream.SendMsg(&resp); err != nil {
			return err
		}
	}
}
