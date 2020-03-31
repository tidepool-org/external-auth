package main

import (
	"context"
	"log"
	"net"

	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type"
	"github.com/gogo/googleapis/google/rpc"
	"google.golang.org/grpc"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	// SessionTokenHeader is the key of the Tidepool session token header
	SessionTokenHeader = "x-tidepool-session-token"
)

type (
	// TokenData stores the decrypted token data
	TokenData struct {
		IsServer     bool   `json:"isserver"`
		UserID       string `json:"userid"`
		DurationSecs int64  `json:"-"`
	}

	// AuthorizationServer is the authorization server
	AuthorizationServer struct {
		Secret string
	}
)

//UnpackSessionTokenAndVerify unpacks a session token and verifies it signature
func (a *AuthorizationServer) UnpackSessionTokenAndVerify(id string) (*TokenData, error) {
	if id == "" {
		return nil, ErrorNoUserID
	}

	jwtToken, err := jwt.Parse(id, func(t *jwt.Token) ([]byte, error) { return []byte(a.Secret), nil })
	if err != nil {
		return nil, err
	}
	if !jwtToken.Valid {
		return nil, Invalid
	}

	isServer := jwtToken.Claims["svr"] == "yes"
	durationSecs, ok := jwtToken.Claims["dur"].(int64)
	if !ok {
		durationSecs = int64(jwtToken.Claims["dur"].(float64))
	}

	return &TokenData{
		IsServer:     isServer,
		DurationSecs: durationSecs,
		UserID:       userId,
	}, nil
}

// Check injects a header that can be used for future rate limiting
func (a *AuthorizationServer) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
	authHeader, ok := req.Attributes.Request.Http.Headers[SessionTokenHeader]

	if ! ok {
		return &auth.CheckResponse{
			Status: &rpc.Status{
				Code: int32(rpc.OK),
			},
			HttpResponse: &auth.CheckResponse_OkResponse{
				OkResponse: &auth.OkHttpResponse{
					Headers: []*core.HeaderValueOption{
						{
							Header: &core.HeaderValue{
								Key:   "x-ext-auth-unauthenticated",
								Value: "true",
							},
						},
					},
				},
			},
		}, nil
	}

	tokenData, err := UnpackSessionTokenAndVerify(authHeader)

	if err != nil {
		return &auth.CheckResponse{
			Status: &rpc.Status{
				Code: int32(rpc.UNAUTHENTICATED),
			},
			HttpResponse: &auth.CheckResponse_DeniedResponse{
				DeniedResponse: &auth.DeniedHttpResponse{
					Status: &envoy_type.HttpStatus{
						Code: envoy_type.StatusCode_Unauthorized,
					},
					Body: "Invalid session token",
				},
			},
		}, nil
	}

	if tokenData.IsServer {
		return &auth.CheckResponse{
			Status: &rpc.Status{
				Code: int32(rpc.OK),
			},
			HttpResponse: &auth.CheckResponse_OkResponse{
				OkResponse: &auth.OkHttpResponse{
					Headers: []*core.HeaderValueOption{
						{
							Header: &core.HeaderValue{
								Key:   "x-ext-auth-server",
								Value: "true",
							},
						},
					},
				},
			},
		}, nil
	}

	return &auth.CheckResponse{
		Status: &rpc.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &auth.CheckResponse_OkResponse{
			OkResponse: &auth.OkHttpResponse{
				Headers: []*core.HeaderValueOption{
					{
						Header: &core.HeaderValue{
							Key:   "x-ext-auth-userid",
							Value: tokenData.userId,
						},
					},
				},
			},
		},
	}, nil
}

func main() {
	userSecret, found := os.LookupEnv("API_SECRET")

	if !found {
		panic("API Secret is required and is not provided")
	}

	// create a TCP listener on port 4000
	lis, err := net.Listen("tcp", ":4000")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Printf("listening on %s", lis.Addr())

	grpcServer := grpc.NewServer()
	authServer := &AuthorizationServer{ Secret: userSecret }
	auth.RegisterAuthorizationServer(grpcServer, authServer)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
