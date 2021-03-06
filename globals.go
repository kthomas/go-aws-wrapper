package awswrapper

import (
	"os"
	"sync"

	"github.com/kthomas/go-logger"
)

var (
	log             *logger.Logger
	awsDefaultVpcID string
	bootstrapOnce   sync.Once
)

func init() {
	bootstrapOnce.Do(func() {
		if os.Getenv("AWS_DEFAULT_VPC_ID") != "" {
			awsDefaultVpcID = os.Getenv("AWS_DEFAULT_VPC_ID")
		}

		lvl := os.Getenv("LOG_LEVEL")
		if lvl == "" {
			lvl = "INFO"
		}
		var endpoint *string
		if os.Getenv("SYSLOG_ENDPOINT") != "" {
			endpt := os.Getenv("SYSLOG_ENDPOINT")
			endpoint = &endpt
		}
		log = logger.NewLogger("awswrapper", lvl, endpoint)
	})
}
