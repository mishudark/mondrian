// Code generated by protoc-gen-go. DO NOT EDIT.
// source: identity.proto

/*
Package pb is a generated protocol buffer package.

It is generated from these files:
	identity.proto

It has these top-level messages:
	CreateTicketRequest
	CreateTicketReply
	SigningKeyRequest
	SigningKeyReply
*/
package pb

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type CreateTicketRequest struct {
	UserToken string `protobuf:"bytes,1,opt,name=user_token,json=userToken" json:"user_token,omitempty"`
}

func (m *CreateTicketRequest) Reset()                    { *m = CreateTicketRequest{} }
func (m *CreateTicketRequest) String() string            { return proto.CompactTextString(m) }
func (*CreateTicketRequest) ProtoMessage()               {}
func (*CreateTicketRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *CreateTicketRequest) GetUserToken() string {
	if m != nil {
		return m.UserToken
	}
	return ""
}

type CreateTicketReply struct {
	Ticket string `protobuf:"bytes,1,opt,name=ticket" json:"ticket,omitempty"`
}

func (m *CreateTicketReply) Reset()                    { *m = CreateTicketReply{} }
func (m *CreateTicketReply) String() string            { return proto.CompactTextString(m) }
func (*CreateTicketReply) ProtoMessage()               {}
func (*CreateTicketReply) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *CreateTicketReply) GetTicket() string {
	if m != nil {
		return m.Ticket
	}
	return ""
}

type SigningKeyRequest struct {
}

func (m *SigningKeyRequest) Reset()                    { *m = SigningKeyRequest{} }
func (m *SigningKeyRequest) String() string            { return proto.CompactTextString(m) }
func (*SigningKeyRequest) ProtoMessage()               {}
func (*SigningKeyRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

type SigningKeyReply struct {
	// DER-encoded public key used to sign JWTs on this server.
	SigningKey []byte `protobuf:"bytes,1,opt,name=signing_key,json=signingKey,proto3" json:"signing_key,omitempty"`
}

func (m *SigningKeyReply) Reset()                    { *m = SigningKeyReply{} }
func (m *SigningKeyReply) String() string            { return proto.CompactTextString(m) }
func (*SigningKeyReply) ProtoMessage()               {}
func (*SigningKeyReply) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *SigningKeyReply) GetSigningKey() []byte {
	if m != nil {
		return m.SigningKey
	}
	return nil
}

func init() {
	proto.RegisterType((*CreateTicketRequest)(nil), "pb.CreateTicketRequest")
	proto.RegisterType((*CreateTicketReply)(nil), "pb.CreateTicketReply")
	proto.RegisterType((*SigningKeyRequest)(nil), "pb.SigningKeyRequest")
	proto.RegisterType((*SigningKeyReply)(nil), "pb.SigningKeyReply")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for Identity service

type IdentityClient interface {
	// CreateTicket creates a temporary token, called ticket, this has a
	// limited timelife and is used in requests to a service in behalf of the user,
	// the provided ticket should be used to any consecutive call, ideally should
	// be sent on  `ticket` header
	// (authorization header is tipically used by service to service)
	CreateTicket(ctx context.Context, in *CreateTicketRequest, opts ...grpc.CallOption) (*CreateTicketReply, error)
	SigningKey(ctx context.Context, in *SigningKeyRequest, opts ...grpc.CallOption) (*SigningKeyReply, error)
}

type identityClient struct {
	cc *grpc.ClientConn
}

func NewIdentityClient(cc *grpc.ClientConn) IdentityClient {
	return &identityClient{cc}
}

func (c *identityClient) CreateTicket(ctx context.Context, in *CreateTicketRequest, opts ...grpc.CallOption) (*CreateTicketReply, error) {
	out := new(CreateTicketReply)
	err := grpc.Invoke(ctx, "/pb.Identity/CreateTicket", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *identityClient) SigningKey(ctx context.Context, in *SigningKeyRequest, opts ...grpc.CallOption) (*SigningKeyReply, error) {
	out := new(SigningKeyReply)
	err := grpc.Invoke(ctx, "/pb.Identity/SigningKey", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Identity service

type IdentityServer interface {
	// CreateTicket creates a temporary token, called ticket, this has a
	// limited timelife and is used in requests to a service in behalf of the user,
	// the provided ticket should be used to any consecutive call, ideally should
	// be sent on  `ticket` header
	// (authorization header is tipically used by service to service)
	CreateTicket(context.Context, *CreateTicketRequest) (*CreateTicketReply, error)
	SigningKey(context.Context, *SigningKeyRequest) (*SigningKeyReply, error)
}

func RegisterIdentityServer(s *grpc.Server, srv IdentityServer) {
	s.RegisterService(&_Identity_serviceDesc, srv)
}

func _Identity_CreateTicket_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateTicketRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IdentityServer).CreateTicket(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.Identity/CreateTicket",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IdentityServer).CreateTicket(ctx, req.(*CreateTicketRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Identity_SigningKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SigningKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IdentityServer).SigningKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.Identity/SigningKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IdentityServer).SigningKey(ctx, req.(*SigningKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Identity_serviceDesc = grpc.ServiceDesc{
	ServiceName: "pb.Identity",
	HandlerType: (*IdentityServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateTicket",
			Handler:    _Identity_CreateTicket_Handler,
		},
		{
			MethodName: "SigningKey",
			Handler:    _Identity_SigningKey_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "identity.proto",
}

func init() { proto.RegisterFile("identity.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 211 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0xcb, 0x4c, 0x49, 0xcd,
	0x2b, 0xc9, 0x2c, 0xa9, 0xd4, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0x2a, 0x48, 0x52, 0x32,
	0xe1, 0x12, 0x76, 0x2e, 0x4a, 0x4d, 0x2c, 0x49, 0x0d, 0xc9, 0x4c, 0xce, 0x4e, 0x2d, 0x09, 0x4a,
	0x2d, 0x2c, 0x4d, 0x2d, 0x2e, 0x11, 0x92, 0xe5, 0xe2, 0x2a, 0x2d, 0x4e, 0x2d, 0x8a, 0x2f, 0xc9,
	0xcf, 0x4e, 0xcd, 0x93, 0x60, 0x54, 0x60, 0xd4, 0xe0, 0x0c, 0xe2, 0x04, 0x89, 0x84, 0x80, 0x04,
	0x94, 0xb4, 0xb9, 0x04, 0x51, 0x75, 0x15, 0xe4, 0x54, 0x0a, 0x89, 0x71, 0xb1, 0x95, 0x80, 0xb9,
	0x50, 0xf5, 0x50, 0x9e, 0x92, 0x30, 0x97, 0x60, 0x70, 0x66, 0x7a, 0x5e, 0x66, 0x5e, 0xba, 0x77,
	0x6a, 0x25, 0xd4, 0x02, 0x25, 0x23, 0x2e, 0x7e, 0x64, 0x41, 0x90, 0x7e, 0x79, 0x2e, 0xee, 0x62,
	0x88, 0x50, 0x7c, 0x76, 0x6a, 0x25, 0xd8, 0x10, 0x9e, 0x20, 0xae, 0x62, 0xb8, 0x2a, 0xa3, 0x0e,
	0x46, 0x2e, 0x0e, 0x4f, 0xa8, 0x17, 0x84, 0x1c, 0xb8, 0x78, 0x90, 0x9d, 0x20, 0x24, 0xae, 0x57,
	0x90, 0xa4, 0x87, 0xc5, 0x2b, 0x52, 0xa2, 0x98, 0x12, 0x05, 0x39, 0x95, 0x4a, 0x0c, 0x42, 0x56,
	0x5c, 0x5c, 0x08, 0x27, 0x08, 0x81, 0x95, 0x61, 0xb8, 0x53, 0x4a, 0x18, 0x5d, 0x18, 0xac, 0x37,
	0x89, 0x0d, 0x1c, 0x82, 0xc6, 0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xa9, 0xea, 0x33, 0xd6, 0x53,
	0x01, 0x00, 0x00,
}