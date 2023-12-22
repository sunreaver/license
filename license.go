package license

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	mid "github.com/denisbrodbeck/machineid"
	"github.com/pkg/errors"
)

// 开启检测.
// pemPubkey: 公钥内容
// appid: 应用id，注意应用id是生成machineid时传入的id
func Load(pemPubkey, appid string) {
	LoadWithMachineID(pemPubkey, appid, true)
	return
}

func LoadWithMachineID(pemPubkey, appid string, needcheckmahine bool) {
	licensefile := filepath.Join(getExecPath(), "license")
	f, err := os.OpenFile(licensefile, os.O_RDONLY, 0666)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer f.Close()
	appinfo, err := DecodeFromBase64ToAppinfo(f, strings.NewReader(pemPubkey))
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	check := func() {
		err := appinfo.IsLimited()
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		if appinfo.AppUUID != appid {
			fmt.Println("app id is not match")
			os.Exit(1)
		}
		if needcheckmahine {
			machineid, err := mid.ProtectedID(appid)
			if err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}
			if machineid != appinfo.ObjUUID {
				fmt.Println("machine id is not match")
				os.Exit(1)
			}
		}
	}
	go func() {
		for {
			check()
			time.Sleep(time.Second)
		}
	}()
	return
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
