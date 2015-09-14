// +build gofuzz

package ubjson

import (
	"encoding/json"
	"fmt"
)

func Fuzz(data []byte) int {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return -1
	}
	b, err := Marshal(&v)
	if err != nil {
		fmt.Println("Failed to marshal")
		panic(err)
	}
	if err := Unmarshal(b, &v); err != nil {
		fmt.Printf("Failed to unmarshal %#v\n", string(b))
		panic(err)
	}
	return 0
}
