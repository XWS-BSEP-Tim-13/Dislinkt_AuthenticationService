package application

import (
	"context"
	"errors"
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/tracer"
	"github.com/go-stomp/stomp"
)

type ActiveMQ struct {
	Addr string
}

const TOPIC = "jwt.topic"

func NewActiveMQ(addr string) *ActiveMQ {
	if addr == "" {
		addr = "activemq:61613"
	}
	return &ActiveMQ{addr}
}

func (service *ActiveMQ) Connect(ctx context.Context) (*stomp.Conn, error) {
	span := tracer.StartSpanFromContext(ctx, "Connect")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	fmt.Printf("Address %s\n", service.Addr)
	return stomp.Dial("tcp", "activemq:61613")
}

// Send msg to destination
func (service *ActiveMQ) Send(ctx context.Context, token string) error {
	span := tracer.StartSpanFromContext(ctx, "Send")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	conn, err := service.Connect(ctx)
	if err != nil {
		fmt.Printf("Unable to connect to activemq\n")
		fmt.Printf("%s\n", err)
		return errors.New("unable to connect  to activemq")
	}
	fmt.Printf("Connected to activemq\n")
	defer conn.Disconnect()
	return conn.Send(
		TOPIC,        // destination
		"text/plain", // content-type
		[]byte(token)) // body
}

// Subscribe Message from destination
// func handler handle msg reveived from destination
func (service *ActiveMQ) Subscribe(ctx context.Context, destination string, handler func(err error, msg string)) error {
	span := tracer.StartSpanFromContext(ctx, "Subscribe")
	defer span.Finish()

	ctx = tracer.ContextWithSpan(context.Background(), span)

	conn, err := service.Connect(ctx)
	if err != nil {
		return err
	}
	sub, err := conn.Subscribe(destination, stomp.AckAuto)
	if err != nil {
		return err
	}
	defer conn.Disconnect()
	defer sub.Unsubscribe()
	for {
		m := <-sub.C
		if string(m.Body) != "" {
			handler(m.Err, string(m.Body))
		}
	}
	return err
}
