package main

import (
	"CryptoCode/rsa_crypto"
	"fmt"
)

func main(){

	//hello := "hello world"
	//enbyte := base_64.Base64Encode([]byte(hello))
	//
	//fmt.Println(string(enbyte))
	//
	//debyte, err := base_64.Base64Decode(enbyte)
	//if err != nil {
	//	fmt.Println(err.Error())
	//}
	//fmt.Println(string(debyte))
	//
	//if hello != string(debyte) {
	//	fmt.Println("hello is not equal to enbyte")
	//}
	//
	//fmt.Println(string(debyte))

	text := "Hello China, Hello World"
	crypTxt,err := rsa_crypto.RsaEncrypt([]byte(text))
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(fmt.Sprintf("%x\n",crypTxt))

	originTxt,err := rsa_crypto.RsaDecrypt(crypTxt)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(string(originTxt))

	signText,err := rsa_crypto.RSASign([]byte(text))

	err =rsa_crypto.RSAVerify([]byte(text),signText)
	if err != nil {
		fmt.Println(err.Error())
	}else {
		fmt.Println("vertify success")
	}
}
