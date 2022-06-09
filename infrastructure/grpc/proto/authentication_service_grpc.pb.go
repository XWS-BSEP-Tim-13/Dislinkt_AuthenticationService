// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.20.1
// source: authentication_service.proto

package proto

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// AuthenticationServiceClient is the client API for AuthenticationService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AuthenticationServiceClient interface {
	Login(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*Token, error)
	Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*RegisterResponse, error)
	IsAuthorized(ctx context.Context, in *AuthorizationRequest, opts ...grpc.CallOption) (*AuthorizationResponse, error)
	ForgotPassword(ctx context.Context, in *ForgotPasswordRequest, opts ...grpc.CallOption) (*AuthorizationResponse, error)
	ChangePassword(ctx context.Context, in *ChangePasswordRequest, opts ...grpc.CallOption) (*AuthorizationResponse, error)
	ChangePasswordPage(ctx context.Context, in *ChangePasswordPageRequest, opts ...grpc.CallOption) (*ChangePasswordPageResponse, error)
	GenerateCode(ctx context.Context, in *GenerateCodeRequest, opts ...grpc.CallOption) (*GenerateCodeResponse, error)
	LoginWithCode(ctx context.Context, in *PasswordlessLoginRequest, opts ...grpc.CallOption) (*Token, error)
	SendApiToken(ctx context.Context, in *AuthorizationResponse, opts ...grpc.CallOption) (*AuthorizationResponse, error)
	ActivateAccount(ctx context.Context, in *ActivateAccountRequest, opts ...grpc.CallOption) (*ActivateAccountResponse, error)
	CheckIfUserExist(ctx context.Context, in *CheckIfUserExistsRequest, opts ...grpc.CallOption) (*CheckIfUserExistsResponse, error)
	RegisterToGoogleAuthenticatior(ctx context.Context, in *AuthorizationResponse, opts ...grpc.CallOption) (*QRImageResponse, error)
	CheckMFACode(ctx context.Context, in *ChangePasswordPageRequest, opts ...grpc.CallOption) (*AuthorizationResponse, error)
	ResetSetMFACode(ctx context.Context, in *AuthorizationResponse, opts ...grpc.CallOption) (*AuthorizationResponse, error)
	CheckIfMFAActive(ctx context.Context, in *AuthorizationResponse, opts ...grpc.CallOption) (*CheckIfMFAActiveResponse, error)
}

type authenticationServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAuthenticationServiceClient(cc grpc.ClientConnInterface) AuthenticationServiceClient {
	return &authenticationServiceClient{cc}
}

func (c *authenticationServiceClient) Login(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*Token, error) {
	out := new(Token)
	err := c.cc.Invoke(ctx, "/post.AuthenticationService/Login", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*RegisterResponse, error) {
	out := new(RegisterResponse)
	err := c.cc.Invoke(ctx, "/post.AuthenticationService/Register", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) IsAuthorized(ctx context.Context, in *AuthorizationRequest, opts ...grpc.CallOption) (*AuthorizationResponse, error) {
	out := new(AuthorizationResponse)
	err := c.cc.Invoke(ctx, "/post.AuthenticationService/IsAuthorized", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) ForgotPassword(ctx context.Context, in *ForgotPasswordRequest, opts ...grpc.CallOption) (*AuthorizationResponse, error) {
	out := new(AuthorizationResponse)
	err := c.cc.Invoke(ctx, "/post.AuthenticationService/ForgotPassword", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) ChangePassword(ctx context.Context, in *ChangePasswordRequest, opts ...grpc.CallOption) (*AuthorizationResponse, error) {
	out := new(AuthorizationResponse)
	err := c.cc.Invoke(ctx, "/post.AuthenticationService/ChangePassword", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) ChangePasswordPage(ctx context.Context, in *ChangePasswordPageRequest, opts ...grpc.CallOption) (*ChangePasswordPageResponse, error) {
	out := new(ChangePasswordPageResponse)
	err := c.cc.Invoke(ctx, "/post.AuthenticationService/ChangePasswordPage", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) GenerateCode(ctx context.Context, in *GenerateCodeRequest, opts ...grpc.CallOption) (*GenerateCodeResponse, error) {
	out := new(GenerateCodeResponse)
	err := c.cc.Invoke(ctx, "/post.AuthenticationService/GenerateCode", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) LoginWithCode(ctx context.Context, in *PasswordlessLoginRequest, opts ...grpc.CallOption) (*Token, error) {
	out := new(Token)
	err := c.cc.Invoke(ctx, "/post.AuthenticationService/LoginWithCode", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) SendApiToken(ctx context.Context, in *AuthorizationResponse, opts ...grpc.CallOption) (*AuthorizationResponse, error) {
	out := new(AuthorizationResponse)
	err := c.cc.Invoke(ctx, "/post.AuthenticationService/SendApiToken", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) ActivateAccount(ctx context.Context, in *ActivateAccountRequest, opts ...grpc.CallOption) (*ActivateAccountResponse, error) {
	out := new(ActivateAccountResponse)
	err := c.cc.Invoke(ctx, "/post.AuthenticationService/ActivateAccount", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) CheckIfUserExist(ctx context.Context, in *CheckIfUserExistsRequest, opts ...grpc.CallOption) (*CheckIfUserExistsResponse, error) {
	out := new(CheckIfUserExistsResponse)
	err := c.cc.Invoke(ctx, "/post.AuthenticationService/CheckIfUserExist", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) RegisterToGoogleAuthenticatior(ctx context.Context, in *AuthorizationResponse, opts ...grpc.CallOption) (*QRImageResponse, error) {
	out := new(QRImageResponse)
	err := c.cc.Invoke(ctx, "/post.AuthenticationService/RegisterToGoogleAuthenticatior", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) CheckMFACode(ctx context.Context, in *ChangePasswordPageRequest, opts ...grpc.CallOption) (*AuthorizationResponse, error) {
	out := new(AuthorizationResponse)
	err := c.cc.Invoke(ctx, "/post.AuthenticationService/CheckMFACode", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) ResetSetMFACode(ctx context.Context, in *AuthorizationResponse, opts ...grpc.CallOption) (*AuthorizationResponse, error) {
	out := new(AuthorizationResponse)
	err := c.cc.Invoke(ctx, "/post.AuthenticationService/ResetSetMFACode", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) CheckIfMFAActive(ctx context.Context, in *AuthorizationResponse, opts ...grpc.CallOption) (*CheckIfMFAActiveResponse, error) {
	out := new(CheckIfMFAActiveResponse)
	err := c.cc.Invoke(ctx, "/post.AuthenticationService/CheckIfMFAActive", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AuthenticationServiceServer is the server API for AuthenticationService service.
// All implementations must embed UnimplementedAuthenticationServiceServer
// for forward compatibility
type AuthenticationServiceServer interface {
	Login(context.Context, *LoginRequest) (*Token, error)
	Register(context.Context, *RegisterRequest) (*RegisterResponse, error)
	IsAuthorized(context.Context, *AuthorizationRequest) (*AuthorizationResponse, error)
	ForgotPassword(context.Context, *ForgotPasswordRequest) (*AuthorizationResponse, error)
	ChangePassword(context.Context, *ChangePasswordRequest) (*AuthorizationResponse, error)
	ChangePasswordPage(context.Context, *ChangePasswordPageRequest) (*ChangePasswordPageResponse, error)
	GenerateCode(context.Context, *GenerateCodeRequest) (*GenerateCodeResponse, error)
	LoginWithCode(context.Context, *PasswordlessLoginRequest) (*Token, error)
	SendApiToken(context.Context, *AuthorizationResponse) (*AuthorizationResponse, error)
	ActivateAccount(context.Context, *ActivateAccountRequest) (*ActivateAccountResponse, error)
	CheckIfUserExist(context.Context, *CheckIfUserExistsRequest) (*CheckIfUserExistsResponse, error)
	RegisterToGoogleAuthenticatior(context.Context, *AuthorizationResponse) (*QRImageResponse, error)
	CheckMFACode(context.Context, *ChangePasswordPageRequest) (*AuthorizationResponse, error)
	ResetSetMFACode(context.Context, *AuthorizationResponse) (*AuthorizationResponse, error)
	CheckIfMFAActive(context.Context, *AuthorizationResponse) (*CheckIfMFAActiveResponse, error)
	mustEmbedUnimplementedAuthenticationServiceServer()
}

// UnimplementedAuthenticationServiceServer must be embedded to have forward compatible implementations.
type UnimplementedAuthenticationServiceServer struct {
}

func (UnimplementedAuthenticationServiceServer) Login(context.Context, *LoginRequest) (*Token, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Login not implemented")
}
func (UnimplementedAuthenticationServiceServer) Register(context.Context, *RegisterRequest) (*RegisterResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Register not implemented")
}
func (UnimplementedAuthenticationServiceServer) IsAuthorized(context.Context, *AuthorizationRequest) (*AuthorizationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IsAuthorized not implemented")
}
func (UnimplementedAuthenticationServiceServer) ForgotPassword(context.Context, *ForgotPasswordRequest) (*AuthorizationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ForgotPassword not implemented")
}
func (UnimplementedAuthenticationServiceServer) ChangePassword(context.Context, *ChangePasswordRequest) (*AuthorizationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ChangePassword not implemented")
}
func (UnimplementedAuthenticationServiceServer) ChangePasswordPage(context.Context, *ChangePasswordPageRequest) (*ChangePasswordPageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ChangePasswordPage not implemented")
}
func (UnimplementedAuthenticationServiceServer) GenerateCode(context.Context, *GenerateCodeRequest) (*GenerateCodeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GenerateCode not implemented")
}
func (UnimplementedAuthenticationServiceServer) LoginWithCode(context.Context, *PasswordlessLoginRequest) (*Token, error) {
	return nil, status.Errorf(codes.Unimplemented, "method LoginWithCode not implemented")
}
func (UnimplementedAuthenticationServiceServer) SendApiToken(context.Context, *AuthorizationResponse) (*AuthorizationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendApiToken not implemented")
}
func (UnimplementedAuthenticationServiceServer) ActivateAccount(context.Context, *ActivateAccountRequest) (*ActivateAccountResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ActivateAccount not implemented")
}
func (UnimplementedAuthenticationServiceServer) CheckIfUserExist(context.Context, *CheckIfUserExistsRequest) (*CheckIfUserExistsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CheckIfUserExist not implemented")
}
func (UnimplementedAuthenticationServiceServer) RegisterToGoogleAuthenticatior(context.Context, *AuthorizationResponse) (*QRImageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RegisterToGoogleAuthenticatior not implemented")
}
func (UnimplementedAuthenticationServiceServer) CheckMFACode(context.Context, *ChangePasswordPageRequest) (*AuthorizationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CheckMFACode not implemented")
}
func (UnimplementedAuthenticationServiceServer) ResetSetMFACode(context.Context, *AuthorizationResponse) (*AuthorizationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ResetSetMFACode not implemented")
}
func (UnimplementedAuthenticationServiceServer) CheckIfMFAActive(context.Context, *AuthorizationResponse) (*CheckIfMFAActiveResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CheckIfMFAActive not implemented")
}
func (UnimplementedAuthenticationServiceServer) mustEmbedUnimplementedAuthenticationServiceServer() {}

// UnsafeAuthenticationServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AuthenticationServiceServer will
// result in compilation errors.
type UnsafeAuthenticationServiceServer interface {
	mustEmbedUnimplementedAuthenticationServiceServer()
}

func RegisterAuthenticationServiceServer(s grpc.ServiceRegistrar, srv AuthenticationServiceServer) {
	s.RegisterService(&AuthenticationService_ServiceDesc, srv)
}

func _AuthenticationService_Login_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoginRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).Login(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/post.AuthenticationService/Login",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).Login(ctx, req.(*LoginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_Register_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).Register(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/post.AuthenticationService/Register",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).Register(ctx, req.(*RegisterRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_IsAuthorized_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthorizationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).IsAuthorized(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/post.AuthenticationService/IsAuthorized",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).IsAuthorized(ctx, req.(*AuthorizationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_ForgotPassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ForgotPasswordRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).ForgotPassword(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/post.AuthenticationService/ForgotPassword",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).ForgotPassword(ctx, req.(*ForgotPasswordRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_ChangePassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ChangePasswordRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).ChangePassword(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/post.AuthenticationService/ChangePassword",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).ChangePassword(ctx, req.(*ChangePasswordRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_ChangePasswordPage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ChangePasswordPageRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).ChangePasswordPage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/post.AuthenticationService/ChangePasswordPage",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).ChangePasswordPage(ctx, req.(*ChangePasswordPageRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_GenerateCode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GenerateCodeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).GenerateCode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/post.AuthenticationService/GenerateCode",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).GenerateCode(ctx, req.(*GenerateCodeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_LoginWithCode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PasswordlessLoginRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).LoginWithCode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/post.AuthenticationService/LoginWithCode",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).LoginWithCode(ctx, req.(*PasswordlessLoginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_SendApiToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthorizationResponse)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).SendApiToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/post.AuthenticationService/SendApiToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).SendApiToken(ctx, req.(*AuthorizationResponse))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_ActivateAccount_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ActivateAccountRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).ActivateAccount(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/post.AuthenticationService/ActivateAccount",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).ActivateAccount(ctx, req.(*ActivateAccountRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_CheckIfUserExist_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CheckIfUserExistsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).CheckIfUserExist(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/post.AuthenticationService/CheckIfUserExist",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).CheckIfUserExist(ctx, req.(*CheckIfUserExistsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_RegisterToGoogleAuthenticatior_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthorizationResponse)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).RegisterToGoogleAuthenticatior(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/post.AuthenticationService/RegisterToGoogleAuthenticatior",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).RegisterToGoogleAuthenticatior(ctx, req.(*AuthorizationResponse))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_CheckMFACode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ChangePasswordPageRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).CheckMFACode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/post.AuthenticationService/CheckMFACode",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).CheckMFACode(ctx, req.(*ChangePasswordPageRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_ResetSetMFACode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthorizationResponse)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).ResetSetMFACode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/post.AuthenticationService/ResetSetMFACode",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).ResetSetMFACode(ctx, req.(*AuthorizationResponse))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_CheckIfMFAActive_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthorizationResponse)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).CheckIfMFAActive(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/post.AuthenticationService/CheckIfMFAActive",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).CheckIfMFAActive(ctx, req.(*AuthorizationResponse))
	}
	return interceptor(ctx, in, info, handler)
}

// AuthenticationService_ServiceDesc is the grpc.ServiceDesc for AuthenticationService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AuthenticationService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "post.AuthenticationService",
	HandlerType: (*AuthenticationServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Login",
			Handler:    _AuthenticationService_Login_Handler,
		},
		{
			MethodName: "Register",
			Handler:    _AuthenticationService_Register_Handler,
		},
		{
			MethodName: "IsAuthorized",
			Handler:    _AuthenticationService_IsAuthorized_Handler,
		},
		{
			MethodName: "ForgotPassword",
			Handler:    _AuthenticationService_ForgotPassword_Handler,
		},
		{
			MethodName: "ChangePassword",
			Handler:    _AuthenticationService_ChangePassword_Handler,
		},
		{
			MethodName: "ChangePasswordPage",
			Handler:    _AuthenticationService_ChangePasswordPage_Handler,
		},
		{
			MethodName: "GenerateCode",
			Handler:    _AuthenticationService_GenerateCode_Handler,
		},
		{
			MethodName: "LoginWithCode",
			Handler:    _AuthenticationService_LoginWithCode_Handler,
		},
		{
			MethodName: "SendApiToken",
			Handler:    _AuthenticationService_SendApiToken_Handler,
		},
		{
			MethodName: "ActivateAccount",
			Handler:    _AuthenticationService_ActivateAccount_Handler,
		},
		{
			MethodName: "CheckIfUserExist",
			Handler:    _AuthenticationService_CheckIfUserExist_Handler,
		},
		{
			MethodName: "RegisterToGoogleAuthenticatior",
			Handler:    _AuthenticationService_RegisterToGoogleAuthenticatior_Handler,
		},
		{
			MethodName: "CheckMFACode",
			Handler:    _AuthenticationService_CheckMFACode_Handler,
		},
		{
			MethodName: "ResetSetMFACode",
			Handler:    _AuthenticationService_ResetSetMFACode_Handler,
		},
		{
			MethodName: "CheckIfMFAActive",
			Handler:    _AuthenticationService_CheckIfMFAActive_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "authentication_service.proto",
}
