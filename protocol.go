package smtpd

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

type command struct {
	line   string
	action string
	fields []string
	params []string
}

func parseLine(line string) command {
	cmd := command{
		line:   line,
		fields: strings.Fields(line),
	}
	if len(cmd.fields) > 0 {
		cmd.action = strings.ToUpper(cmd.fields[0])
		if len(cmd.fields) > 1 {
			cmd.params = strings.Split(cmd.fields[1], ":")
		}
	}
	return cmd
}

func (session *session) handle(line string) {
	cmd := parseLine(line)

	// Commands are dispatched to the appropriate handler functions.
	// If a network error occurs during handling, the handler should
	// just return and let the error be handled on the next read.
	switch cmd.action {
	case "HELO":
		session.handleHELO(cmd)
	case "EHLO":
		session.handleEHLO(cmd)
	case "MAIL":
		session.handleMAIL(cmd)
	case "RCPT":
		session.handleRCPT(cmd)
	case "STARTTLS":
		session.handleSTARTTLS(cmd)
	case "DATA":
		session.handleDATA(cmd)
	case "RSET":
		session.handleRSET(cmd)
	case "NOOP":
		session.handleNOOP(cmd)
	case "QUIT":
		session.handleQUIT(cmd)
	case "AUTH":
		session.handleAUTH(cmd)
	case "XCLIENT":
		session.handleXCLIENT(cmd)
	default:
		session.reply(502, "Unsupported command.")
	}
}

func (session *session) handleHELO(cmd command) {
	if len(cmd.fields) < 2 {
		session.reply(502, "Missing parameter")
		return
	}
	if session.peer.HeloName != "" {
		// Reset envelope in case of duplicate HELO
		session.reset()
	}

	if session.server.HeloChecker != nil {
		err := session.server.HeloChecker(session.peer, cmd.fields[1])
		if err != nil {
			session.error(err)
			return
		}
	}

	session.peer.HeloName = cmd.fields[1]
	session.peer.Protocol = SMTP
	session.reply(250, "Go ahead")
}

func (session *session) handleEHLO(cmd command) {
	if len(cmd.fields) < 2 {
		session.reply(502, "Missing parameter")
		return
	}

	if session.peer.HeloName != "" {
		// Reset envelope in case of duplicate EHLO
		session.reset()
	}

	if session.server.HeloChecker != nil {
		err := session.server.HeloChecker(session.peer, cmd.fields[1])
		if err != nil {
			session.error(err)
			return
		}
	}

	session.peer.HeloName = cmd.fields[1]
	session.peer.Protocol = ESMTP

	fmt.Fprintf(session.writer, "250-%s\r\n", session.server.Hostname)

	extensions := session.extensions()
	if len(extensions) > 1 {
		for _, ext := range extensions[:len(extensions)-1] {
			fmt.Fprintf(session.writer, "250-%s\r\n", ext)
		}
	}

	session.reply(250, extensions[len(extensions)-1])
}

func (session *session) handleMAIL(cmd command) {
	if len(cmd.params) < 2 || !strings.EqualFold(cmd.params[0], "from") {
		session.reply(502, "invalid command")
	}
	if session.peer.HeloName == "" {
		session.reply(502, "Please introduce yourself first.")
		return
	}

	if !session.tls && session.server.ForceTLS {
		session.reply(502, "Please turn on TLS by issuing a STARTTLS command.")
		return
	}

	if session.envelope != nil {
		session.reply(502, "Duplicate MAIL")
		return
	}

	addr, err := parseAddress(cmd.params[1])
	if err != nil {
		session.reply(502, "Ill-formatted e-mail address")
		return
	}

	if session.server.SenderChecker != nil {
		err = session.server.SenderChecker(session.peer, addr)
		if err != nil {
			session.error(err)
			return
		}
	}

	session.envelope = &Envelope{
		Sender: addr,
	}
	session.reply(250, "Go ahead")
}

func (session *session) handleRCPT(cmd command) {
	if len(cmd.params) < 2 || !strings.EqualFold(cmd.params[0], "to") {
		session.reply(502, "invalid command")
	}
	if session.envelope == nil {
		session.reply(502, "Missing MAIL FROM command.")
		return
	}
	if len(session.envelope.Recipients) >= session.server.MaxRecipients {
		session.reply(452, "Too many recipients")
		return
	}

	addr, err := parseAddress(cmd.params[1])
	if err != nil {
		session.reply(502, "Ill-formatted e-mail address")
		return
	}

	if session.server.RecipientChecker != nil {
		err = session.server.RecipientChecker(session.peer, addr)
		if err != nil {
			session.error(err)
			return
		}
	}

	session.envelope.Recipients = append(session.envelope.Recipients, addr)
	session.reply(250, "Go ahead")
}

func (session *session) handleSTARTTLS(cmd command) {
	if session.tls {
		session.reply(502, "Already running in TLS")
		return
	}

	if session.server.TLSConfig == nil {
		session.reply(502, "TLS not supported")
		return
	}

	tlsConn := tls.Server(session.conn, session.server.TLSConfig)
	session.reply(220, "Go ahead")

	if err := tlsConn.Handshake(); err != nil {
		session.reply(550, "Handshake error")
		return
	}

	// Reset envelope as a new EHLO/HELO is required after STARTTLS.
	session.reset()

	// Reset deadlines on the underlying connection before I replace it
	// with a TLS connection.
	session.conn.SetDeadline(time.Time{})

	// Replace connection with a TLS connection.
	session.conn = tlsConn
	session.reader = bufio.NewReader(tlsConn)
	session.writer = bufio.NewWriter(tlsConn)
	session.scanner = bufio.NewScanner(session.reader)
	session.tls = true

	// Save connection state on peer.
	state := tlsConn.ConnectionState()
	session.peer.TLS = &state

	// Flush the connection to set new timeout deadlines.
	session.flush()
}

func (session *session) handleDATA(cmd command) {
	if session.envelope == nil || len(session.envelope.Recipients) == 0 {
		session.reply(502, "Missing RCPT TO command.")
		return
	}

	session.reply(354, "Go ahead. End your data with <CR><LF>.<CR><LF>")
	session.conn.SetDeadline(time.Now().Add(session.server.DataTimeout))

	data := &bytes.Buffer{}
	reader := textproto.NewReader(session.reader).DotReader()

	_, err := io.CopyN(data, reader, int64(session.server.MaxMessageSize))
	if err == io.EOF {
		// EOF was reached before MaxMessageSize
		// Accept and deliver message
		session.envelope.Data = data.Bytes()

		if err := session.deliver(); err != nil {
			session.error(err)
		} else {
			session.reply(250, "Thank you.")
		}

		session.reset()
	}
	// TODO(kardianos): handle these network errors.
	if err != nil {
		// Network error, ignore.
		return
	}

	// Discard the rest and report an error.
	_, err = io.Copy(ioutil.Discard, reader)
	if err != nil {
		// Network error, ignore.
		return
	}

	session.reply(552, fmt.Sprintf(
		"Message exceeded max message size of %d bytes",
		session.server.MaxMessageSize,
	))
	session.reset()
}

func (session *session) handleRSET(cmd command) {
	session.reset()
	session.reply(250, "Go ahead")
}

func (session *session) handleNOOP(cmd command) {
	session.reply(250, "Go ahead")
}

func (session *session) handleQUIT(cmd command) {
	session.reply(221, "OK, bye")
	session.close()
}

func (session *session) handleAUTH(cmd command) {
	if len(cmd.fields) < 2 {
		session.reply(502, "invalid auth")
		return
	}
	if session.server.Authenticator == nil {
		session.reply(502, "AUTH not supported.")
		return
	}
	if session.peer.HeloName == "" {
		session.reply(502, "Please introduce yourself first.")
		return
	}
	if !session.tls {
		session.reply(502, "Cannot AUTH in plain text mode. Use STARTTLS.")
		return
	}

	mechanism := strings.ToUpper(cmd.fields[1])

	username := ""
	password := ""

	switch mechanism {
	default:
		session.reply(502, "Unknown authentication mechanism")
		return
	case "PLAIN":
		auth := ""

		if len(cmd.fields) < 3 {
			session.reply(334, "Give me your credentials")
			if !session.scanner.Scan() {
				return
			}
			auth = session.scanner.Text()
		} else {
			auth = cmd.fields[2]
		}

		data, err := base64.StdEncoding.DecodeString(auth)
		if err != nil {
			session.reply(502, "Couldn't decode your credentials")
			return
		}

		parts := bytes.Split(data, []byte{0})
		if len(parts) != 3 {
			session.reply(502, "Couldn't decode your credentials")
			return
		}

		username = string(parts[1])
		password = string(parts[2])

	case "LOGIN":
		session.reply(334, "VXNlcm5hbWU6")
		if !session.scanner.Scan() {
			return
		}

		byteUsername, err := base64.StdEncoding.DecodeString(session.scanner.Text())
		if err != nil {
			session.reply(502, "Couldn't decode your credentials")
			return
		}

		session.reply(334, "UGFzc3dvcmQ6")
		if !session.scanner.Scan() {
			return
		}

		bytePassword, err := base64.StdEncoding.DecodeString(session.scanner.Text())
		if err != nil {
			session.reply(502, "Couldn't decode your credentials")
			return
		}

		username = string(byteUsername)
		password = string(bytePassword)
	}

	err := session.server.Authenticator(session.peer, username, password)
	if err != nil {
		session.error(err)
		return
	}

	session.peer.Username = username
	session.peer.Password = password
	session.reply(235, "authenticated")
}

func (session *session) handleXCLIENT(cmd command) {
	if len(cmd.fields) < 2 {
		session.reply(502, "invalid XCLIENT")
		return
	}
	if !session.server.EnableXCLIENT {
		session.reply(550, "XCLIENT not enabled")
		return
	}

	tcpAddr, ok := session.peer.Addr.(*net.TCPAddr)
	if !ok {
		session.reply(502, "Unsupported network connection")
		return
	}

	for _, item := range cmd.fields[1:] {
		parts := strings.Split(item, "=")
		if len(parts) != 2 {
			session.reply(502, "invalid XCLIENT field")
			return
		}

		name := parts[0]
		value := parts[1]
		switch name {
		default:
			session.reply(502, "Couldn't decode the command.")
			return
		case "NAME":
			// Not used.
		case "HELO":
			session.peer.HeloName = value
		case "ADDR":
			tcpAddr.IP = net.ParseIP(value)
		case "PORT":
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				session.reply(502, "Couldn't decode the command.")
				return
			}
			tcpAddr.Port = int(port)
		case "LOGIN":
			session.peer.Username = value
		case "PROTO":
			switch value {
			default:
				session.reply(502, "unknown proto")
			case "SMTP":
				session.peer.Protocol = SMTP
			case "ESMTP":
				session.peer.Protocol = ESMTP
			}
		}
	}

	session.welcome()
}
