package mail

import (
	"errors"
	"fmt"
	"mime"
	nm "net/mail"
	"os"
)

// EMLToMsg will open an parse a .eml file at a provided file path and return a
// pre-filled Msg pointer
func EMLToMsg(fp string) (*Msg, error) {
	m := &Msg{
		addrHeader:    make(map[AddrHeader][]*nm.Address),
		genHeader:     make(map[Header][]string),
		preformHeader: make(map[Header]string),
		mimever:       Mime10,
	}

	pm, err := readEML(fp)
	if err != nil || pm == nil {
		return m, fmt.Errorf("failed to parse EML file: %w", err)
	}

	// Parse the header
	if err := parseEMLHeaders(&pm.Header, m); err != nil {
		return m, fmt.Errorf("failed to parse EML headers: %w", err)
	}

	// Extract the transfer encoding of the body
	mi, ar, err := mime.ParseMediaType(pm.Header.Get(HeaderContentType.String()))
	if err != nil {
		return m, fmt.Errorf("failed to extract content type: %w", err)
	}
	if v, ok := ar["charset"]; ok {
		m.SetCharset(Charset(v))
	}
	fmt.Printf("Encoding: %s\n", mi)
	fmt.Printf("Params: %+v\n", ar)

	return m, nil
}

// readEML opens an EML file and uses net/mail to parse the header and body
func readEML(fp string) (*nm.Message, error) {
	fh, err := os.Open(fp)
	if err != nil {
		return nil, fmt.Errorf("failed to open EML file: %w", err)
	}
	defer func() {
		_ = fh.Close()
	}()
	pm, err := nm.ReadMessage(fh)
	if err != nil {
		return pm, fmt.Errorf("failed to parse EML: %w", err)
	}
	return pm, nil
}

// parseEMLHeaders will check the EML headers for the most common headers and set the
// according settings in the Msg
func parseEMLHeaders(mh *nm.Header, m *Msg) error {
	commonHeaders := []Header{
		HeaderContentType, HeaderImportance, HeaderInReplyTo, HeaderListUnsubscribe,
		HeaderListUnsubscribePost, HeaderMessageID, HeaderMIMEVersion, HeaderOrganization,
		HeaderPrecedence, HeaderPriority, HeaderSubject, HeaderUserAgent, HeaderXMailer,
		HeaderXMSMailPriority, HeaderXPriority,
	}

	// Extract address headers
	if v := mh.Get(HeaderFrom.String()); v != "" {
		if err := m.From(v); err != nil {
			return fmt.Errorf(`failed to parse "From:" header: %w`, err)
		}
	}
	ahl := map[AddrHeader]func(...string) error{
		HeaderTo:  m.To,
		HeaderCc:  m.Cc,
		HeaderBcc: m.Bcc,
	}
	for h, f := range ahl {
		if v := mh.Get(h.String()); v != "" {
			var als []string
			pal, err := nm.ParseAddressList(v)
			if err != nil {
				return fmt.Errorf(`failed to parse address list: %w`, err)
			}
			for _, a := range pal {
				als = append(als, a.String())
			}
			if err := f(als...); err != nil {
				return fmt.Errorf(`failed to parse "To:" header: %w`, err)
			}
		}
	}

	// Extract date from message
	d, err := mh.Date()
	if err != nil {
		switch {
		case errors.Is(err, nm.ErrHeaderNotPresent):
			m.SetDate()
		default:
			return fmt.Errorf("failed to parse EML date: %w", err)
		}
	}
	if err == nil {
		m.SetDateWithValue(d)
	}

	// Extract common headers
	for _, h := range commonHeaders {
		if v := mh.Get(h.String()); v != "" {
			m.SetGenHeader(h, v)
		}
	}

	return nil
}
