package application

import (
	"errors"
	"fmt"
	"github.com/go-stomp/stomp"
)

type ActiveMQ struct {
	Addr string
}

const TOPIC = "jwt.topic"

func NewActiveMQ(addr string) *ActiveMQ {
	if addr == "" {
		addr = "activemq:61616"
	}
	return &ActiveMQ{addr}
}

func (service *ActiveMQ) Connect() (*stomp.Conn, error) {
	fmt.Printf("Address %s\n", service.Addr)
	return stomp.Dial("tcp", "localhost:61613")
}

// Send msg to destination
func (service *ActiveMQ) Send(token string) error {
	conn, err := service.Connect()
	if err != nil {
		fmt.Printf("Unable to connect to activemq\n")
		fmt.Printf("%s\n", err)
		return errors.New("unable to connect  to activemq")
	}
	fmt.Printf("Connected to activemq\n")
	defer conn.Disconnect()
	return conn.Send(
		TOPIC,         // destination
		"text/plain",  // content-type
		[]byte(token)) // body
}

// Subscribe Message from destination
// func handler handle msg reveived from destination
func (service *ActiveMQ) Subscribe(destination string, handler func(err error, msg string)) error {

	conn, err := service.Connect()
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
		handler(m.Err, string(m.Body))
	}
	return err
}
