package main

import (
	"fmt"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/startup"
	"github.com/XWS-BSEP-Tim-13/Dislinkt_AuthenticationService/startup/config"
)

func main() {
	config := config.NewConfig()
	server := startup.NewServer(config)
	fmt.Println("Server is starting...")
	server.Start()

	defer server.CloseTracer()
}
