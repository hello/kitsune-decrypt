package main

import (
	"crypto/sha1"
	"errors"
	"flag"
	"fmt"
	"github.com/crowdmob/goamz/aws"
	"github.com/mitchellh/cli"
	"io/ioutil"
	// "log"
	"os"
	"os/exec"
	"strings"
)

type DecryptCommand struct {
	Ui       cli.Ui
	Uploader KeyPairUploader
}

func (c *DecryptCommand) Help() string {
	helpText := `
Usage: kitsune decrypt 
  attempts to decrypt all files in the specified directory
  kitsune check -dir=my_dir -debug
Options:
  -debug        output verbose logs
  -dir=my_dir   lists the files inside the directory specified
  -upload       uploads the results to Hello servers       
`
	return strings.TrimSpace(helpText)
}

var (
	errInvalidSha = errors.New("Invalid sha")
)

func parse(out []byte) (InfoBlob, error) {
	pad := out[:80]
	key := out[81:97]
	deviceId := out[98:106]
	sha := out[107 : len(out)-2]

	h := sha1.New()
	h.Write(key)
	h.Write([]byte{0})
	h.Write(deviceId)
	h.Write([]byte{0})
	hash := h.Sum(nil)

	var err error
	for i := 0; i < len(sha); i++ {
		if sha[i] != hash[i] {
			err = errInvalidSha
		}
	}

	infoBlob := InfoBlob{DeviceId: deviceId, Pad: pad, Key: key, ComputedSha: hash, Sha: sha}
	return infoBlob, err
}

func (c *DecryptCommand) Run(args []string) int {

	cmdFlags := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	cmdFlags.Usage = func() { c.Ui.Output(c.Help()) }
	var debug = cmdFlags.Bool("debug", false, "Output verbose debug logs")
	var dir = cmdFlags.String("dir", "blobs/", "Directory containing individual blobs to be decrypted")

	var upload = cmdFlags.Bool("upload", false, "Uploads data to Hello servers.")

	if err := cmdFlags.Parse(args); err != nil {
		return 1
	}

	directory := "./" + *dir
	files, _ := ioutil.ReadDir(directory)

	ok := 0
	uploaded := 0

	for _, f := range files {
		fname := directory + f.Name()

		if f.IsDir() {
			c.Ui.Output(fmt.Sprintf("Skipping directory %s", fname))
			continue
		}

		if *debug {
			c.Ui.Output(fmt.Sprintf("Processing file: %s", fname))
		}

		out, err := exec.Command("openssl", "rsautl", "-decrypt", "-raw", "-inkey", "kitsune.pem", "-in", fname).CombinedOutput()
		if err != nil {
			c.Ui.Error(fmt.Sprintf("Openssl failed reading %s: %v", fname, err))
			return 1
		}

		infoBlob, err := parse(out)
		if err != nil {
			c.Ui.Error(fmt.Sprintf("[FAIL] Sha doesn't match for file: %s", f.Name()))
			c.Ui.Error(fmt.Sprintf("\t-> Device_id: %X", infoBlob.DeviceId))
			c.Ui.Error(fmt.Sprintf("\t-> Computed sha: %X", infoBlob.ComputedSha))
			c.Ui.Error(fmt.Sprintf("\t-> Provided sha: %X", infoBlob.Sha))
			continue
		}

		c.Ui.Info(fmt.Sprintf("[OK] %s", f.Name()))
		if *debug {
			c.Ui.Info(fmt.Sprintf("\tPad: %x", infoBlob.Pad))
			c.Ui.Info(fmt.Sprintf("\tKey: %XXXXX%X", infoBlob.Key[:4], infoBlob.Key[len(infoBlob.Key)-4:]))
			c.Ui.Info(fmt.Sprintf("\tDevice_id: %X", infoBlob.DeviceId))
			c.Ui.Info(fmt.Sprintf("\tSha: %X", infoBlob.Sha))
		}
		ok += 1
		if *upload {
			err := c.Uploader.Upload(infoBlob)
			if err != nil {
				c.Ui.Error(fmt.Sprintf("Failed to upload: %v", err))
				return 1
			}
			uploaded += 1

		}

	}

	c.Ui.Info(fmt.Sprintf("\nSuccessfully decoded %d files", ok))
	c.Ui.Info(fmt.Sprintf("Successfully uploaded: %d key pairs", ok))

	return 0
}

func (c *DecryptCommand) Synopsis() string {
	return "iterates through all the files in the specified directory and optionally uploads them to Hello servers"
}

func DecryptCommandFactory() (DecryptCommand, error) {
	return DecryptCommand{}, nil
}

type VersionCommand struct {
	Ui      cli.Ui
	version string
}

func (c *VersionCommand) Synopsis() string {
	return "version"
}

func (c *VersionCommand) Run(args []string) int {
	c.Ui.Output(fmt.Sprintf("Version = %s", c.version))
	return 0
}

func (c *VersionCommand) Help() string {
	return ""
}

// Commands is the mapping of all the available Spark commands.
var Commands map[string]cli.CommandFactory

func init() {
	ui := &cli.ColoredUi{
		InfoColor:  cli.UiColorGreen,
		ErrorColor: cli.UiColorRed,
		Ui: &cli.BasicUi{
			Writer: os.Stdout,
			Reader: os.Stdin,
		},
	}

	// auth, err := aws.EnvAuth()
	auth := aws.Auth{AccessKey: "AKIAJBWHHEWJW2PSKOJA", SecretKey: "DBR50Q9zv2HK2TtbH3oPzCs19ew1tHU/s2Du/qMm"}
	// if err != nil {
	// 	log.Fatal("Credentials for uploading haven't been found in your environment")
	// }

	region := aws.USEast
	server := NewDynamoDBKeyUploader(auth, region, "key_store")
	// AKIAJBWHHEWJW2PSKOJA
	// Secret Access Key:
	// DBR50Q9zv2HK2TtbH3oPzCs19ew1tHU/s2Du/qMm
	Commands = map[string]cli.CommandFactory{
		"decrypt": func() (cli.Command, error) {
			return &DecryptCommand{
				Ui:       ui,
				Uploader: server,
			}, nil
		},
		"version": func() (cli.Command, error) {
			return &VersionCommand{
				Ui:      ui,
				version: "0.0.1",
			}, nil
		},
	}
}
