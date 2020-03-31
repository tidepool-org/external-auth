package main

import (
	"context"
	"errors"
	"log"
	"net"
	"os"

	jwt "github.com/dgrijalva/jwt-go"
	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type"
	"github.com/gogo/googleapis/google/rpc"
	xstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
)

const (
	// SessionTokenHeader is the key of the Tidepool session token header
	SessionTokenHeader = "x-tidepool-session-token"
)

var (
	// ErrNoUserID is provided if there is no user id
	ErrNoUserID = errors.New("Session token is empty")

	// ErrInvalid means that the session token is invalid
	ErrInvalid = errors.New("Session token is invalid")
)

type (
	// Session describes a authenticated session
	Session struct {
		ID        string `json:"-" bson:"_id"`
		IsServer  bool   `json:"isServer" bson:"isServer"`
		ServerID  string `json:"-" bson:"serverId,omitempty"`
		UserID    string `json:"userId,omitempty" bson:"userId,omitempty"`
		Duration  int64  `json:"-" bson:"duration"`
		ExpiresAt int64  `json:"-" bson:"expiresAt"`
		CreatedAt int64  `json:"-" bson:"createdAt"`
		Time      int64  `json:"-" bson:"time"`
	}

	// AuthorizationServer is the authorization server
	AuthorizationServer struct {
		Secret string
	}
)

// UnpackSessionTokenAndVerify unpacks a session token and verifies it signature
func (a *AuthorizationServer) UnpackSessionTokenAndVerify(id string) (*Session, error) {

	session := &Session{}

	if id == "" {
		return nil, ErrNoUserID
	}

	parsedClaims := struct {
		jwt.StandardClaims
		IsServer string  `json:"svr"`
		UserID   string  `json:"usr"`
		Duration float64 `json:"dur"`
	}{}

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return []byte(a.Secret), nil
	}

	_, err := jwt.ParseWithClaims(session.ID, &parsedClaims, keyFunc)
	if err != nil {
		validationError, ok := err.(*jwt.ValidationError)
		if !ok {
			return nil, err
		}
		if validationError.Errors != jwt.ValidationErrorExpired {
			return nil, validationError
		}
	}

	session.IsServer = parsedClaims.IsServer == "yes"
	if session.IsServer {
		session.ServerID = parsedClaims.UserID
	} else {
		session.UserID = parsedClaims.UserID
	}
	session.Duration = int64(parsedClaims.Duration)
	session.ExpiresAt = parsedClaims.ExpiresAt

	session.CreatedAt = session.Time
	return session, nil
}

// Check verifies the identity of the requestor and places that identity in various headers.
// If no identity is claimed, then it injects the "x-ext-auth-unauthenticated" header
// If an identity is claimed, but the cannot be verfied, then it injects the fails the request
// If an identity is claimed and is a server, then it injects the "x-ext-auth-server" header
// If an identity is claimed and is a user, then it injects the "x-ext-auth-userid" header with the userid as the value
func (a *AuthorizationServer) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
	authHeader, ok := req.Attributes.Request.Http.Headers[SessionTokenHeader]

	if !ok {
		return &auth.CheckResponse{
			Status: &xstatus.Status{
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

	session, err := a.UnpackSessionTokenAndVerify(authHeader)

	if err != nil {
		return &auth.CheckResponse{
			Status: &xstatus.Status{
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

	if session.IsServer {
		return &auth.CheckResponse{
			Status: &xstatus.Status{
				Code: int32(rpc.OK),
			},
			HttpResponse: &auth.CheckResponse_OkResponse{
				OkResponse: &auth.OkHttpResponse{
					Headers: []*core.HeaderValueOption{
						{
							Header: &core.HeaderValue{
								Key:   "x-ext-auth-server",
								Value: session.ServerID,
							},
						},
					},
				},
			},
		}, nil
	}

	return &auth.CheckResponse{
		Status: &xstatus.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &auth.CheckResponse_OkResponse{
			OkResponse: &auth.OkHttpResponse{
				Headers: []*core.HeaderValueOption{
					{
						Header: &core.HeaderValue{
							Key:   "x-ext-auth-userid",
							Value: session.UserID,
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
	authServer := &AuthorizationServer{Secret: userSecret}
	auth.RegisterAuthorizationServer(grpcServer, authServer)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
