package license

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/pkg/errors"
)

type AppLicenseInfo struct {
	AppName        string `json:"appname"`         //应用名称
	AppCompany     string `json:"appcompany"`      //应用发布的公司
	AppUUID        string `json:"appuuid"`         //此次发布应用的UUID
	ObjUUID        string `json:"objuuid"`         //目标设备的UUID
	AuthorizedName string `json:"authorized_name"` //授权名称
	LimitedTime    string `json:"limited_time"`    //到期日期
}

// Encode2Base64ByAppinfo 将appinfo内容，通过rsa私钥加密后，返回base64编码后的内容
func Encode2Base64ByAppinfo(appinfo AppLicenseInfo, rsaPrivateKey io.Reader) (string, error) {
	filebytes, err := json.Marshal(appinfo)
	if err != nil {
		return "", errors.Wrap(err, "json marshal error")
	}
	return Encode2Base64(bytes.NewBuffer(filebytes), rsaPrivateKey)
}

// DecodeFromBase64ToAppinfo 将base64编码后的内容，通过rsa公钥解密后，返回appinfo内容
func DecodeFromBase64ToAppinfo(base64Content, rsaPublicKey io.Reader) (AppLicenseInfo, error) {
	outbytes, err := DecodeFromBase64(base64Content, rsaPublicKey)
	if err != nil {
		return AppLicenseInfo{}, err
	}
	conf := AppLicenseInfo{}
	if err := json.Unmarshal(outbytes, &conf); err != nil {
		return AppLicenseInfo{}, errors.Wrap(err, "json unmarshal error")
	}
	return conf, nil
}

// Encode2Base64 将filebody内容，通过rsa私钥加密后，返回base64编码后的内容
func Encode2Base64(filebody, rsaPrivateKey io.Reader) (string, error) {
	contentByte, err := io.ReadAll(filebody)
	if err != nil {
		return "", errors.Wrap(err, "read file error")
	}
	privt, err := parsePKCS8PrivateKey(rsaPrivateKey)
	if err != nil {
		return "", errors.Wrap(err, "parse private key error")
	}
	//进行加密
	trunckSize := 64
	ts := make(truncks, 0)
	for i := 0; i < len(contentByte); i += trunckSize {
		end := i + trunckSize
		if end > len(contentByte) {
			end = len(contentByte)
		}
		tmpText, err := privateEncrypt(privt, contentByte[i:end])
		if err != nil {
			return "", errors.Wrap(err, "private encrypt error")
		}
		ts.Add(tmpText)
	}
	o, _ := json.Marshal(ts)
	return base64.RawStdEncoding.EncodeToString(o), nil
}

// DecodeFromBase64 将base64编码后的内容，通过rsa公钥解密后，返回解密后的内容
func DecodeFromBase64(base64Content, rsaPublicKey io.Reader) ([]byte, error) {
	base64data, err := io.ReadAll(base64Content)
	if err != nil {
		return nil, errors.Wrap(err, "read base64 content error")
	}
	content, err := base64.RawStdEncoding.DecodeString(string(base64data))
	if err != nil {
		return nil, errors.Wrap(err, "base64 decode error")
	}
	var ts truncks
	if err := ts.UnmarshalFromBytes(content); err != nil {
		return nil, errors.Wrap(err, "unmarshal truncks error")
	}
	pubt, err := parseRSAPublicKey(rsaPublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "parse public key error")
	}
	var out bytes.Buffer
	for _, v := range ts {
		data, err := v.Parse()
		if err != nil {
			return nil, errors.Wrap(err, "parse trunck")
		}
		tmp, err := publicDecrypt(pubt, data)
		if err != nil {
			return nil, errors.Wrap(err, "public decrypt error")
		}
		_, err = out.Write(tmp)
		if err != nil {
			return nil, errors.Wrap(err, "write error")
		}

	}
	return out.Bytes(), nil
}

type trunck struct {
	Size int    `json:"s"`
	Data string `json:"d"`
}

func (t trunck) Parse() ([]byte, error) {
	return hex.DecodeString(t.Data)
}

type truncks []trunck

func (t *truncks) Add(data []byte) {
	*t = append(*t, trunck{Size: len(data), Data: hex.EncodeToString(data)})
}

func (t truncks) MarshalToString() string {
	o, _ := json.Marshal(t)
	return string(o)
}

func (t *truncks) UnmarshalFromBytes(s []byte) error {
	return json.Unmarshal(s, t)
}
