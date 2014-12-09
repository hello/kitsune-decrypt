package main

import (
	"fmt"
	"github.com/crowdmob/goamz/aws"
	"github.com/crowdmob/goamz/dynamodb"
	"log"
)

type KeyPairUploader interface {
	Upload(blob InfoBlob) error
}

type DynamoDBKeyUploader struct {
	table *dynamodb.Table
}

func (u *DynamoDBKeyUploader) Upload(blob InfoBlob) error {
	deviceId := fmt.Sprintf("%X", blob.DeviceId)
	aesKey := fmt.Sprintf("%X", blob.Key)

	attrs := []dynamodb.Attribute{
		*dynamodb.NewStringAttribute("aes_key", aesKey),
	}
	ok, err := u.table.PutItem(deviceId, "", attrs)
	if !ok {
		log.Println("not ok")
	}
	return err
}

func NewDynamoDBKeyUploader(auth aws.Auth, region aws.Region, tableName string) *DynamoDBKeyUploader {
	server := dynamodb.New(auth, region)
	primary := dynamodb.NewStringAttribute("device_id", "")

	key := dynamodb.PrimaryKey{primary, nil}
	table := server.NewTable("key_store", key)

	return &DynamoDBKeyUploader{table: table}
}

type InfoBlob struct {
	DeviceId    []byte
	Key         []byte
	Pad         []byte
	Sha         []byte
	ComputedSha []byte
}

func (i *InfoBlob) String() string {
	return fmt.Sprintf("Pad: %X\nDeviceId: %X\nKey: %X\n Sha:%X\nComputedSha: %X\n",
		i.Pad, i.DeviceId, i.Key, i.Sha, i.ComputedSha)
}
