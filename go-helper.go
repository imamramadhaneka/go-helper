package gohelper

import (
	"log/syslog"

	log "github.com/sirupsen/logrus"
	logrusSyslog "github.com/sirupsen/logrus/hooks/syslog"
)

func init() {

	// init logger configuration
	log.SetFormatter(&log.JSONFormatter{})
	if syslogOutput, err := logrusSyslog.NewSyslogHook("", "", syslog.LOG_INFO, ""); err == nil {
		log.AddHook(syslogOutput)
	}

}
