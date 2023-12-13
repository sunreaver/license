package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	mid "github.com/denisbrodbeck/machineid"
	l "github.com/sunreaver/license"
)

func main() {
	var (
		machineid string
		license   string
		private   string
		public    string
		delicense string
	)
	flag.StringVar(&license, "license", "", "根据此json文件，生成license，需要同时指定pem私钥")
	flag.StringVar(&private, "private", "", "指定pem私钥")
	flag.StringVar(&delicense, "delicense", "", "解码license")
	flag.StringVar(&public, "public", "", "指定pem公钥")
	flag.StringVar(&machineid, "machineid", "", "展示本机的机器id，指定项目编码")
	flag.Parse()

	if license != "" {
		filebytes, err := os.ReadFile(license)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(filebytes))
		rsaPrivateKey, err := os.ReadFile(private)
		if err != nil {
			panic(err)
		}
		licenseStr, err := l.Encode2Base64(bytes.NewBuffer(filebytes), bytes.NewBuffer(rsaPrivateKey))
		if err != nil {
			panic(err)
		}
		log.Printf("license:\n%v", licenseStr)
		return
	}

	if delicense != "" {
		filebytes, err := os.ReadFile(delicense)
		if err != nil {
			panic(err)
		}
		rsaPublicKey, err := os.ReadFile(public)
		if err != nil {
			panic(err)
		}
		appinfo, err := l.DecodeFromBase64ToAppinfo(bytes.NewBuffer(filebytes), bytes.NewBuffer(rsaPublicKey))
		if err != nil {
			panic(err)
		}
		out, _ := json.MarshalIndent(appinfo, "", "  ")
		log.Printf("appinfo:\n%v", string(out))
		return
	}

	if machineid != "" {
		machineid, err := mid.ProtectedID(machineid)
		if err != nil {
			panic(err)
		}
		log.Printf("machine id:\n%v", machineid)
		return
	}
}
