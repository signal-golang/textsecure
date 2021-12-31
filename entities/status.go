package entities

import (
	"encoding/json"
	"net/http"
	"path"
	"runtime"

	log "github.com/sirupsen/logrus"
)

type ResponseStatus struct {
	Code     int    `json:"code"    example:"200"`
	Message  string `json:"message" example:"OK"`
	Reason   string `json:"reason"  example:"param error"`
	File     string `json:"file"    example:"param error"`
	Line     int    `json:"line"    example:"param error"`
	FuncName string `json:"func"`
}

func (rs *ResponseStatus) Error() string {
	jsb, _ := json.Marshal(rs)
	log.Errorln(string(jsb))
	return string(jsb)
}

func Status(code int, reason string) error {
	fname, file, line, _ := runtime.Caller(1)
	return &ResponseStatus{
		Code:     code,
		Message:  http.StatusText(code),
		Reason:   reason,
		File:     path.Base(file),
		Line:     line,
		FuncName: path.Base(runtime.FuncForPC(fname).Name()),
	}
}

type Resp struct {
	Obj interface{} `json:"obj"`
}
