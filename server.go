package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

	"github.com/more-than-code/identity-provider/constant"
	"github.com/more-than-code/identity-provider/pb"

	"github.com/dgrijalva/jwt-go/v4"
	authHelper "github.com/more-than-code/auth-helper"

	"github.com/kelseyhightower/envconfig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Config struct {
	MinuteAt                        int    `envconfig:"AT_TTL_MINUTE"`
	HourAt                          int    `envconfig:"AT_TTL_HOUR"`
	DayAt                           int    `envconfig:"AT_TTL_DAY"`
	MinuteRt                        int    `envconfig:"RT_TTL_MINUTE"`
	HourRt                          int    `envconfig:"RT_TTL_HOUR"`
	DayRt                           int    `envconfig:"RT_TTL_DAY"`
	Secret                          []byte `envconfig:"TOKEN_SECRET_KEY"`
	CredentialsVerificationEndpoint string `envconfig:"CREDENTIALS_VERIFICATION_ENDPOINT"`
	ServerPort                      string `envconfig:"SERVER_PORT"`
}

type Server struct {
	cfg      *Config
	atHelper *authHelper.Helper
	rtHelper *authHelper.Helper
	pb.UnimplementedAuthServer
}

type CredentialsVerificationRequest struct {
	PhoneOrEmail string
	Password     string
}

type CredentialsVerificationResponse struct {
	Code    int32
	Msg     string
	Payload interface{}
}

func NewServer() error {
	var cfg Config
	err := envconfig.Process("", &cfg)

	if err != nil {
		log.Fatal(err)
	}

	lis, err := net.Listen("tcp", cfg.ServerPort)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	athelper, _ := authHelper.NewHelper(&authHelper.Config{Secret: cfg.Secret, TtlMinute: cfg.MinuteAt, TtlHour: cfg.HourAt, TtlDay: cfg.DayAt})

	rthelper, _ := authHelper.NewHelper(&authHelper.Config{Secret: cfg.Secret, TtlMinute: cfg.MinuteRt, TtlHour: cfg.HourRt, TtlDay: cfg.DayRt})

	var opts []grpc.ServerOption

	grpcServer := grpc.NewServer(opts...)
	pb.RegisterAuthServer(grpcServer, &Server{cfg: &cfg, atHelper: athelper, rtHelper: rthelper})
	err = grpcServer.Serve(lis)

	if err != nil {
		return err
	}

	return nil
}

func (s *Server) AuthenticateUser(ctx context.Context, req *pb.AuthenticateUserRequest) (*pb.AuthenticateUserResponse, error) {
	jsonData, err := json.Marshal(CredentialsVerificationRequest{PhoneOrEmail: req.PhoneOrEmail, Password: req.Password})
	if err != nil {
		fmt.Println("Error marshalling JSON:", err)
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", s.cfg.CredentialsVerificationEndpoint, bytes.NewBuffer(jsonData))

	if err != nil {
		fmt.Println("Error creating request:", err)
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")

	httpRes, err := http.DefaultClient.Do(httpReq)

	if err != nil {
		return nil, err
	}

	defer httpRes.Body.Close()

	body, err := io.ReadAll(httpRes.Body)

	if err != nil {
		return nil, err
	}

	var cvRes CredentialsVerificationResponse
	json.Unmarshal(body, &cvRes)

	res := &pb.AuthenticateUserResponse{AccessToken: "", Msg: cvRes.Msg, ErrCode: cvRes.Code}

	if cvRes.Code != 0 {
		return res, nil
	}

	authStr := cvRes.Payload.(string)
	at, err := s.atHelper.Authenticate(authStr)

	if err != nil {
		fmt.Println(err)
		res.ErrCode = -1
		res.Msg = err.Error()
		return res, nil
	}
	res.AccessToken = at

	rt, _ := s.rtHelper.Authenticate(authStr)
	res.RefreshToken = rt

	return res, nil
}

func (s *Server) RefreshAccessToken(ctx context.Context, req *pb.RefreshAccessTokenRequest) (*pb.RefreshAccessTokenResponse, error) {
	_, err := s.rtHelper.ParseTokenString(req.RefreshToken)

	if err != nil {
		return nil, status.Error(codes.Code(constant.CodeAuthenticationFailure), constant.MsgAuthenticationFailure)
	}

	authStr, err := s.atHelper.ParseTokenString(req.AccessToken)

	if err != nil {
		_, ok := err.(*jwt.TokenExpiredError)

		fmt.Println(err)
		if !ok {
			return nil, status.Error(codes.Code(constant.CodeAuthenticationFailure), constant.MsgAuthenticationFailure)
		}
	}

	at, err := s.atHelper.Authenticate(authStr)

	if err != nil {
		return nil, status.Error(codes.Code(constant.CodeAuthenticationFailure), constant.MsgAuthenticationFailure)
	}

	rt, err := s.rtHelper.Authenticate(authStr)

	if err != nil {
		return nil, status.Error(codes.Code(constant.CodeAuthenticationFailure), constant.MsgAuthenticationFailure)
	}

	return &pb.RefreshAccessTokenResponse{RefreshToken: rt, AccessToken: at}, nil
}
