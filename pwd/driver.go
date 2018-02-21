package pwd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/docker/machine/libmachine/cert"
	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/mcnutils"
	"github.com/docker/machine/libmachine/state"
	"github.com/google/uuid"
)

type Driver struct {
	*drivers.BaseDriver
	SessionId    string
	Hostname     string
	SSLPort      string
	Port         string
	URL          string
	Scheme       string
	Created      bool
	InstanceName string
}

type instance struct {
	Name string
	IP   string
}

type instanceConfig struct {
	Alias      string
	ServerCert []byte
	ServerKey  []byte
	CACert     []byte
	Cert       []byte
	Key        []byte
}

type apiReply struct {
	SessionId string `json:"session_id"`
	Hostname  string `json:"hostname"`
	Status    string `json:"status, omitempty"`
}

var notImplemented error = errors.New("Not implemented")

func dump(infos ...interface{}) {
	spew.Fdump(os.Stderr, infos)
}

func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:   "pwd-url",
			Usage:  "PWD session URL",
			EnvVar: "PWD_URL",
		},
		mcnflag.StringFlag{
			Name:   "pwd-ssl-port",
			Usage:  "pwd ssl port to connect to the daemon",
			EnvVar: "PWD_SSL_PORT",
			Value:  "443",
		},
		mcnflag.StringFlag{
			Name:   "pwd-port",
			Usage:  "pwd port to connect to the API",
			EnvVar: "PWD_PORT",
			Value:  "80",
		},
	}
}

func (d *Driver) Create() error {
	sessionPrefix := d.SessionId[:8]
	alias := strings.Replace(uuid.New().String(), "-", "", -1)

	host := fmt.Sprintf("pwd%s-%s-2375.%s", alias, sessionPrefix, d.Hostname)

	conf := instanceConfig{Alias: alias}
	err := setupCerts(d, host, &conf)
	if err != nil {
		return fmt.Errorf("Error configuring PWD certs: %v ", err)
	}

	b, jsonErr := json.Marshal(conf)
	if jsonErr != nil {
		return jsonErr
	}

	//careful on using the right scheme and the right port (a PWD that starts with http or https is not the same)
	var pURL string
	if d.Scheme == "http" {
		pURL = fmt.Sprintf("%s://%s:%s/sessions/%s/instances", d.Scheme, d.Hostname, d.Port, d.SessionId)
	} else {
		pURL = fmt.Sprintf("%s://%s:%s/sessions/%s/instances", d.Scheme, d.Hostname, d.SSLPort, d.SessionId)
	}
	//resp, err := http.Post(pURL, "", bytes.NewReader(b))
	resp, err := http.Post(pURL, "", nil)

	if err != nil || resp.StatusCode != http.StatusOK {
		dump(pURL, b)
		return fmt.Errorf("Could not create instance %v %v", err, resp)
	}

	defer resp.Body.Close()

	i := &instance{}

	json.NewDecoder(resp.Body).Decode(i)

	d.IPAddress = i.IP
	d.InstanceName = i.Name
	d.URL = fmt.Sprintf("tcp://%s:%s", host, d.SSLPort)
	d.Created = true
	d.SSLPort = "1022"
	d.SSHUser = fmt.Sprintf("%s-%s", strings.Replace(i.IP, ".", "-", -1), sessionPrefix)

	if err = generatePrivateKey(d.GetSSHKeyPath()); err != nil {
		return fmt.Errorf("Could not create private key %v", err)
		return err
	}
	return nil

}

func setupCerts(d *Driver, host string, c *instanceConfig) error {

	hosts := append([]string{}, host, "localhost")
	bits := 2048
	machineName := d.GetMachineName()
	org := mcnutils.GetUsername() + "." + machineName
	caPath := filepath.Join(d.StorePath, "certs", "ca.pem")
	caKeyPath := filepath.Join(d.StorePath, "certs", "ca-key.pem")

	clientCertPath := filepath.Join(d.StorePath, "certs", "cert.pem")
	clientKeyPath := filepath.Join(d.StorePath, "certs", "key.pem")

	serverCertPath := d.ResolveStorePath("server.pem")
	serverKeyPath := d.ResolveStorePath("server-key.pem")

	if err := mcnutils.CopyFile(caPath, d.ResolveStorePath("ca.pem")); err != nil {
		return fmt.Errorf("Copying ca.pem to machine dir failed: %s", err)
	}

	if err := mcnutils.CopyFile(clientCertPath, d.ResolveStorePath("cert.pem")); err != nil {
		return fmt.Errorf("Copying cert.pem to machine dir failed: %s", err)
	}

	if err := mcnutils.CopyFile(clientKeyPath, d.ResolveStorePath("key.pem")); err != nil {
		return fmt.Errorf("Copying key.pem to machine dir failed: %s", err)
	}

	err := cert.GenerateCert(&cert.Options{
		Hosts:       hosts,
		CertFile:    serverCertPath,
		KeyFile:     serverKeyPath,
		CAFile:      caPath,
		CAKeyFile:   caKeyPath,
		Org:         org,
		Bits:        bits,
		SwarmMaster: false,
	})

	if err != nil {
		return fmt.Errorf("error generating server cert: %s", err)
	}

	serverCert, err := ioutil.ReadFile(serverCertPath)
	if err != nil {
		log.Println(err)
		return fmt.Errorf("Error reading file: %s", serverCertPath)
	}
	serverKey, err := ioutil.ReadFile(serverKeyPath)
	if err != nil {
		log.Println(err)
		return fmt.Errorf("Error reading file: %s", serverCertPath)
	}
	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		log.Println(err)
		return fmt.Errorf("Error reading file: %s", caPath)
	}
	cert, err := ioutil.ReadFile(clientCertPath)
	if err != nil {
		log.Println(err)
		return fmt.Errorf("Error reading file: %s", clientCertPath)
	}
	key, err := ioutil.ReadFile(clientKeyPath)
	if err != nil {
		log.Println(err)
		return fmt.Errorf("Error reading file: %s", clientKeyPath)
	}
	c.ServerCert = serverCert
	c.ServerKey = serverKey
	c.CACert = caCert
	c.Cert = cert
	c.Key = key

	return nil
}

var counter int = 0

func (d *Driver) DriverName() string {
	defer func() { counter++ }()
	// Only after creation and when driver is queried for provisioning return "none".
	// This is a hack to avoid SSH provisioning while keeping "pwd" as the machine driver
	if d.Created && counter == 1 {
		return "none"
	}
	return "pwd"
}

func (d *Driver) GetIP() (string, error) {
	return d.IPAddress, nil
}

func (d *Driver) GetMachineName() string {
	return d.MachineName
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.Hostname, nil
}

func (d *Driver) GetSSHPort() (int, error) {
	return strconv.Atoi(d.SSLPort)
}

func (d *Driver) GetSSHUsername() string {
	return d.SSHUser
}

func (d *Driver) GetURL() (string, error) {
	return d.URL, nil
}

func (d *Driver) GetState() (state.State, error) {
	return state.Running, nil
}

func (d *Driver) Kill() error {
	return notImplemented
}

func (d *Driver) PreCreateCheck() error {
	/*
		if d.StorePath == filepath.Join(mcnutils.GetHomeDir(), ".docker", "machine") {
			return errors.New("Default storage path is discouraged when using PWD driver. Use -s flag or MACHINE_STORAGE_PATH env variable to set one")
		}
	*/
	if d.SessionId == "" {
		return errors.New("Session Id must be specified")
	}
	return nil
}

func (d *Driver) Remove() error {
	var pURL string
	if d.Scheme == "http" {
		pURL = fmt.Sprintf("%s:%s/sessions/%s/instances", d.Scheme, d.Hostname, d.Port, d.SessionId)
	} else {
		pURL = fmt.Sprintf("%s:%s/sessions/%s/instances", d.Scheme, d.Hostname, d.SSLPort, d.SessionId)
	}
	log.Println("deleting your sandbox: ", d.InstanceName, ", from session: ", pURL)
	r, _ := http.NewRequest("DELETE", fmt.Sprintf("%s/%s", pURL, d.InstanceName), nil)
	resp, err := http.DefaultClient.Do(r)
	if err != nil || resp.StatusCode != http.StatusOK {
		log.Println(err, resp)
		return errors.New("Error removing instance")
	}
	return nil
}

func (d *Driver) Restart() error {
	return notImplemented
}

func (d *Driver) SetConfigFromFlags(opts drivers.DriverOptions) error {
	dump(opts)
	d.SSLPort = opts.String("pwd-ssl-port")
	d.Port = opts.String("pwd-port")
	pwdUrl, err := url.Parse(opts.String("pwd-url"))
	if err != nil {
		return errors.New("Incorrect PWD URL")
	}
	d.Scheme = pwdUrl.Scheme
	d.Hostname = pwdUrl.Host
	if !strings.Contains(pwdUrl.Path, "/p/") {
		//try to create a new session on the pwd before failing
		var pURL string
		if d.Scheme == "http" {
			pURL = fmt.Sprintf("%s:%s/", d.Hostname, d.Port)
		} else {
			pURL = fmt.Sprintf("%s:%s/", d.Hostname, d.SSLPort)
		}
		r, _ := http.NewRequest("POST", pURL, nil)
		//the playground does a redirect on the first POST, need to handle it (otherwise the resp.Body will be empty)
		client := http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		resp, err := client.Do(r)
		if err != nil || resp.StatusCode >= http.StatusBadRequest {
			log.Println(err, resp)
			return errors.New("Error creating new session: " + err.Error())
		}
		//read the reply from playground, which is of type apiReply
		var s apiReply
		err = json.NewDecoder(resp.Body).Decode(&s)
		if err != nil {
			log.Println(err)
			return errors.New("Error parsing playground api reply: " + err.Error())
		}
		d.SessionId = s.SessionId
		log.Println("Created a new session for you: ", s.SessionId, ". You can connect to ", fmt.Sprintf("%s://%s:%s/p/%s", d.Scheme, d.Hostname, d.Port, d.SessionId))
	} else {
		if d.SessionId = strings.TrimPrefix(pwdUrl.Path, "/p/"); len(d.SessionId) == 0 {
			//there was a problem parsing this session that's provided
			log.Println(err)
			return errors.New("Error reading session ID (empty ?)")
		}
		//see if the session actually exists
		var pURL string
		if d.Scheme == "http" {
			pURL = fmt.Sprintf("%s://%s:%s/sessions/%s", d.Scheme, d.Hostname, d.Port, d.SessionId)
		} else {
			pURL = fmt.Sprintf("%s://%s:%s/sessions/%s", d.Scheme, d.Hostname, d.SSLPort, d.SessionId)
		}
		r, _ := http.NewRequest("GET", pURL, nil)
		resp, err := http.DefaultClient.Do(r)
		if err != nil || resp.StatusCode >= http.StatusBadRequest {
			log.Println(err, resp)
			return errors.New("Session " + d.SessionId + " does not exist")
		}
	}
	return nil
}

func (d *Driver) Start() error {
	return notImplemented
}

func (d *Driver) Stop() error {
	return notImplemented
}

func generatePrivateKey(keyPath string) error {
	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		return err
	}

	outFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	if err != nil {
		return err
	}
	return nil
}
