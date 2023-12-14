package license

import (
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
)

// 获取当前可执行程序的位置
func getExecPath() string {
	ex, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(ex)
}

var ErrLicenseLimited = &os.PathError{Op: "license", Path: "license", Err: errors.New("limited")}

type AppLicenseInfo struct {
	AppName        string `json:"appname"`         //应用名称
	AppCompany     string `json:"appcompany"`      //应用发布的公司
	AppUUID        string `json:"appuuid"`         //此次发布应用的UUID
	ObjUUID        string `json:"objuuid"`         //目标设备的UUID
	AuthorizedName string `json:"authorized_name"` //授权名称
	LimitedTime    string `json:"limited_time"`    //到期日期
}

func (ali AppLicenseInfo) IsLimited() error {
	// parse time
	t, err := time.ParseInLocation("2006-01-02 15:04:05", ali.LimitedTime, time.Local)
	if err != nil {
		return err
	}
	if time.Now().After(t) {
		return ErrLicenseLimited
	}
	return nil
}
