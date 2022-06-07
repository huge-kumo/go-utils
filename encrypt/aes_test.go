package encrypt

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestEncryptAes(t *testing.T) {
	ori := []byte("12345")

	en, err := encryptByCBC(ori, []byte("jfhf432432343212"), []byte("jfhf432432343212"))
	if err != nil {
		panic(err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(en))

	de, err := decryptByCBC(en, []byte("jfhf432432343212"), []byte("jfhf432432343212"))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(de))
}

func TestPadding(t *testing.T) {
	var data, raw []byte
	var err error
	raw = []byte{1, 2, 3, 4, 5}

	// PKCS#5
	data, err = PKCS5Padding(raw, 8)
	if err != nil {
		panic(err)
	}
	fmt.Printf("PKCS#5:\t%v\n", data)
	data, err = PKCS5UnPadding(data, 8)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%v\n\n", data)

	// PKCS#7
	data, err = PKCS7Padding(raw, 8)
	if err != nil {
		panic(err)
	}
	fmt.Printf("PKCS#7:\t%v\n", data)
	data, err = PKCS7UnPadding(data, 8)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%v\n\n", data)

	// zero
	data = ZerosPadding(raw, 8)
	fmt.Printf("ZERO:\t%v\n", data)
	data = ZerosUnPadding(data)
	fmt.Printf("%v\n\n", data)
}
