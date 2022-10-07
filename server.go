package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"mo-service-auth/mo-service-common/global"
	"mo-service-auth/mo-service-common/model"
	"mo-service-auth/mo-service-common/util"
	"mo-service-auth/pb"
	"mo-service-auth/repository"
	"net"

	"github.com/dgrijalva/jwt-go/v4"
	authHelper "github.com/more-than-code/auth-helper"

	"github.com/kelseyhightower/envconfig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Config struct {
	MinuteAt int    `envconfig:"AT_TTL_MINUTE"`
	HourAt   int    `envconfig:"AT_TTL_HOUR"`
	DayAt    int    `envconfig:"AT_TTL_DAY"`
	MinuteRt int    `envconfig:"RT_TTL_MINUTE"`
	HourRt   int    `envconfig:"RT_TTL_HOUR"`
	DayRt    int    `envconfig:"RT_TTL_DAY"`
	Secret   []byte `envconfig:"TOKEN_SECRET_KEY"`
}

type Server struct {
	repo     *repository.Repository
	cfg      *Config
	atHelper *authHelper.Helper
	rtHelper *authHelper.Helper
	pb.UnimplementedAuthServer
}

func NewServer(port int) error {
	var cfg Config
	err := envconfig.Process("", &cfg)

	if err != nil {
		log.Fatal(err)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	repo, err := repository.NewRepository()
	if err != nil {
		return err
	}

	athelper, _ := authHelper.NewHelper(&authHelper.Config{Secret: cfg.Secret, TtlMinute: cfg.MinuteAt, TtlHour: cfg.HourAt, TtlDay: cfg.DayAt})

	rthelper, _ := authHelper.NewHelper(&authHelper.Config{Secret: cfg.Secret, TtlMinute: cfg.MinuteRt, TtlHour: cfg.HourRt, TtlDay: cfg.DayRt})

	var opts []grpc.ServerOption

	grpcServer := grpc.NewServer(opts...)
	pb.RegisterAuthServer(grpcServer, &Server{repo: repo, cfg: &cfg, atHelper: athelper, rtHelper: rthelper})
	err = grpcServer.Serve(lis)

	if err != nil {
		return err
	}

	return nil
}

func (s *Server) AuthenticateUser(ctx context.Context, req *pb.AuthenticateUserRequest) (*pb.AuthenticateUserResponse, error) {
	user, err := s.repo.GetUserByPhoneOrEmail(req.PhoneOrEmail)
	res := &pb.AuthenticateUserResponse{AccessToken: "", Msg: "Authenticated", ErrCode: 0}

	if err != nil {
		fmt.Println(err)
		res.ErrCode = global.CodeWrongEmailOrPassword
		res.Msg = global.MsgWrongEmailOrPassword
		return res, nil
	}

	err = util.CheckPasswordHash(req.Password, user.Password)
	if err != nil {
		fmt.Println(err)
		res.ErrCode = global.CodeWrongEmailOrPassword
		res.Msg = global.MsgWrongEmailOrPassword
		return res, nil
	}

	partialProfile := &model.UserProfile{Id: user.Id, Role: int(user.Role), Level: int(user.Level)}
	bytes, _ := json.Marshal(partialProfile)

	at, err := s.atHelper.Authenticate(string(bytes))

	if err != nil {
		fmt.Println(err)
		res.ErrCode = -1
		res.Msg = err.Error()
		return res, nil
	}
	res.AccessToken = at

	rt, _ := s.rtHelper.Authenticate(user.Id.Hex())
	res.RefreshToken = rt

	res.UserId = user.Id.Hex()

	return res, nil
}

func (s *Server) RefreshAccessToken(ctx context.Context, req *pb.RefreshAccessTokenRequest) (*pb.RefreshAccessTokenResponse, error) {
	userId, err := s.rtHelper.ParseTokenString(req.RefreshToken)

	if err != nil {
		return nil, status.Error(codes.Code(global.CodeAuthenticationFailure), global.MsgAuthenticationFailure)
	}

	// s.repo.DeleteRefreshToken(ctx, userId, req.RefreshToken)

	// if err != nil {
	// 	return nil, status.Error(codes.Code(global.CodeAuthenticationFailure), global.MsgAuthenticationFailure)
	// }

	userProfile, err := s.atHelper.ParseTokenString(req.AccessToken)

	if err != nil {
		_, ok := err.(*jwt.TokenExpiredError)

		fmt.Println(err)
		if !ok {
			return nil, status.Error(codes.Code(global.CodeAuthenticationFailure), global.MsgAuthenticationFailure)
		}
	}

	at, err := s.atHelper.Authenticate(userProfile)

	if err != nil {
		return nil, status.Error(codes.Code(global.CodeAuthenticationFailure), global.MsgAuthenticationFailure)
	}

	rt, err := s.rtHelper.Authenticate(userId)

	if err != nil {
		return nil, status.Error(codes.Code(global.CodeAuthenticationFailure), global.MsgAuthenticationFailure)
	}

	// s.repo.UpdateRefreshToken(ctx, tr)

	return &pb.RefreshAccessTokenResponse{RefreshToken: rt, AccessToken: at, UserId: userId}, nil
}
