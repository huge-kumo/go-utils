package encrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

func encryptByCBC(origData, key, iv []byte) (encrypted []byte, err error) {
	var block cipher.Block
	block, err = aes.NewCipher(key)
	if err != nil {
		return
	}

	blockSize := block.BlockSize()
	origData, err = PKCS7Padding(origData, blockSize)
	if err != nil {
		return
	}

	blockMode := cipher.NewCBCEncrypter(block, iv)
	encrypted = make([]byte, len(origData))
	blockMode.CryptBlocks(encrypted, origData)
	return encrypted, nil
}

func decryptByCBC(encrypted, key, iv []byte) (origData []byte, err error) {
	var block cipher.Block
	block, err = aes.NewCipher(key)
	if err != nil {
		return
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData = make([]byte, len(encrypted))
	blockMode.CryptBlocks(origData, encrypted)

	blockSize := block.BlockSize()
	origData, err = PKCS7UnPadding(origData, blockSize)
	if err != nil {
		return
	}
	return origData, nil
}

// PKCS5Padding PKCS#5 padding is defined for 8-byte block sizes.
func PKCS5Padding(data []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 8 {
		return nil, fmt.Errorf("pkcs5: Invalid block size %d", blockSize)
	} else {
		padLen := blockSize - len(data)%blockSize
		padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
		return append(data, padding...), nil
	}
}

// PKCS5UnPadding remove pkcs5 padding.
func PKCS5UnPadding(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("pkcs5: Data is empty")
	}
	if length%blockSize != 0 {
		return nil, errors.New("pkcs5: Data is not block-aligned")
	}
	padLen := int(data[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(data, ref) {
		return nil, errors.New("pkcs5: Invalid padding")
	}
	return data[:length-padLen], nil
}

// PKCS7Padding PKCS#7 padding would work for any block size from 1 to 255 bytes.
func PKCS7Padding(data []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 255 {
		return nil, fmt.Errorf("pkcs7: Invalid block size %d", blockSize)
	} else {
		padLen := blockSize - len(data)%blockSize
		padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
		return append(data, padding...), nil
	}
}

// PKCS7UnPadding remove pkcs7 padding.
func PKCS7UnPadding(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("pkcs7: Data is empty")
	}
	if length%blockSize != 0 {
		return nil, errors.New("pkcs7: Data is not block-aligned")
	}
	padLen := int(data[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(data, ref) {
		return nil, errors.New("pkcs7: Invalid padding")
	}
	return data[:length-padLen], nil
}

// ZerosPadding All the bytes that are required to be padded are padded with zero.
func ZerosPadding(data []byte, blockSize int) []byte {
	paddingCount := blockSize - len(data)%blockSize
	if paddingCount == 0 {
		return data
	} else {
		return append(data, bytes.Repeat([]byte{byte(0)}, paddingCount)...)
	}
}

// ZerosUnPadding remove zero padding.
func ZerosUnPadding(data []byte) []byte {
	for i := len(data) - 1; ; i-- {
		if data[i] != 0 {
			return data[:i+1]
		}
	}
}
