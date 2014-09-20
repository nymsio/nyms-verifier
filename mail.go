package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"strings"

	"github.com/miekg/dns"
	"github.com/nymsio/nyms-verifier/smtp"
)

func processMail(rawMail []byte, sender *mail.Address, config *Config) error {
	mxs, err := getMXForSender(sender)
	if err != nil {
		return err
	}

	dkim, err := getMessageDKIMKey(rawMail)
	if err != nil {
		logger.Warning("DKIM: %v", err)
	}

	client := dialSMTP(mxs)
	if client == nil {
		_, d := getDomain(sender)
		return fmt.Errorf("Failed to connect to any MX for domain '%s'", d)
	}
	data := new(verifyData)
	data.sender = sender
	data.rawMail = rawMail
	data.mxlist = mxs
	data.dkimkey = dkim
	data.certs = client.TLSState.PeerCertificates
	response, err := createResponse(config, data)
	if err != nil {
		client.Quit()
		return err
	}

	if *debugArg {
		client.Quit()
		fmt.Println(response)
		return nil
	}

	err = transmitMail(client, config.VerifyEmail, sender.Address, []byte(response))
	client.Quit()
	return err
}

func transmitMail(c *smtp.Client, from, to string, mail []byte) error {
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	_, err = w.Write(mail)
	if err != nil {
		return err
	}
	return w.Close()
}

func getMXForSender(sender *mail.Address) ([]*net.MX, error) {
	domain, err := getDomain(sender)
	if err != nil {
		return nil, fmt.Errorf("could not get domain for sender: %v", err)
	}
	mxs, err := net.LookupMX(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup MX for domain (%s): %v", domain, err)
	}
	return mxs, nil
}

func getDomain(address *mail.Address) (string, error) {
	parts := strings.Split(address.Address, "@")
	if len(parts) < 2 {
		return "", fmt.Errorf("no @ character in address '%s'", address.Address)
	} else if len(parts) > 2 {
		return "", fmt.Errorf("too many @ characters in address '%s'", address.Address)
	} else {
		return parts[1], nil
	}
}

func dialSMTP(mxs []*net.MX) *smtp.Client {
	for _, mx := range mxs {
		host := mxToHostname(mx)
		client, _ := connectTo(host)
		if client != nil {
			return client
		}
	}
	return nil
}

func mxToHostname(mx *net.MX) string {
	hl := len(mx.Host)
	if hl > 0 && mx.Host[hl-1] == '.' {
		return mx.Host[:hl-1]
	}
	return mx.Host
}

func connectTo(hostname string) (*smtp.Client, error) {
	client, err := smtp.Dial(hostname + ":25")
	if err != nil {
		return nil, err
	}
	if ok, _ := client.Extension("STARTTLS"); ok {
		config := &tls.Config{ServerName: hostname}
		if err = client.StartTLS(config); err != nil {
			client.Close()
			return nil, err
		}
	}
	return client, nil
}

func getMessageDKIMKey(rawMail []byte) (string, error) {

	msg, err := mail.ReadMessage(bytes.NewReader(rawMail))
	if err != nil {
		return "", fmt.Errorf("Could not extract DKIM selector because mail could not be parsed: %v", err)
	}
	params := getDKIMParams(msg)

	if params == nil || params["s"] == "" || params["d"] == "" {
		return "", nil
	}
	selector := params["s"]
	domain := params["d"]
	return lookupDKIM(selector, domain)
}

func lookupDKIM(selector, domain string) (string, error) {
	// We do this the hard way with a low level library because:
	//  https://code.google.com/p/go/issues/detail?id=8540
	serv, err := getDNSServerAddress()
	if err != nil {
		return "", err
	}
	m := createDKIMQuery(selector, domain)
	r, err := dns.Exchange(m, serv)
	if err != nil {
		return "", fmt.Errorf("failed TXT lookup s=%s d=%s: %v", selector, domain, err)
	}
	return processDKIMResponse(selector, domain, r)
}

func getDNSServerAddress() (string, error) {
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("failed to load DNS config from /etc/resolv.conf: %v", err)
	}
	return net.JoinHostPort(conf.Servers[0], conf.Port), nil
}

func createDKIMQuery(selector, domain string) *dns.Msg {
	q := fmt.Sprintf("%s._domainkey.%s", selector, domain)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(q), dns.TypeTXT)
	m.RecursionDesired = true
	return m
}

func processDKIMResponse(selector, domain string, r *dns.Msg) (string, error) {
	if r.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("lookup response s=%s d=%s, Rcode is not RcodeSuccess as expected: Rcode=%d", selector, domain, r.Rcode)
	}
	if len(r.Answer) == 0 {
		return "", fmt.Errorf("lookup s=%s d=%s response has empty answer section")
	} else if len(r.Answer) > 1 {
		logger.Warning("lookup s=%s d=%s returned %d answers, expecting 1.  Ignoring extra responses", selector, domain, len(r.Answer))
	}
	txt, ok := r.Answer[0].(*dns.TXT)
	if !ok {
		return "", fmt.Errorf("answer RR for lookup s=%s d=%s is not a TXT record", selector, domain)
	}
	result := ""
	for _, s := range txt.Txt {
		result += s
	}
	return result, nil
}

func getDKIMParams(msg *mail.Message) map[string]string {
	for _, h := range []string{"Dkim-Signature", "X-Google-Dkim-Signature"} {
		val := msg.Header.Get(h)
		if val != "" {
			return parseDKIM(val)
		}
	}
	return nil
}

func parseDKIM(dkim string) map[string]string {
	dm := make(map[string]string)
	for _, pair := range strings.Split(dkim, ";") {
		kv := strings.Split(strings.TrimSpace(pair), "=")
		if len(kv) == 2 {
			dm[kv[0]] = kv[1]
		}
	}
	return dm
}
