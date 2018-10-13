package awswrapper

import (
	"os"
	"sync"

	"github.com/kthomas/go-logger"
)

var (
	Log             *logger.Logger
	awsDefaultVpcID string
	bootstrapOnce   sync.Once
)

func init() {
	bootstrapOnce.Do(func() {
		lvl := os.Getenv("LOG_LEVEL")
		if lvl == "" {
			lvl = "INFO"
		}
		Log = logger.NewLogger("awswrapper", lvl, true)
	})
}
