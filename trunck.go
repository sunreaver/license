package license

import (
	"encoding/hex"
	"encoding/json"
)

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
