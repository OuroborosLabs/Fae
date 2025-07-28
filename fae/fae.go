package fae

/*
#cgo CFLAGS: -I/home/anirudh/fae/boringssl/include
#cgo LDFLAGS: -L/home/anirudh/fae/boringssl/build/ssl -L/home/anirudh/fae/boringssl/build -lssl -lcrypto -lstdc++

#include "fae.h"
*/
import "C"
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unsafe"
)

// Fingerprint defines the structure for parsing the detailed Wireshark-like JSON.
type Fingerprint struct {
	TlsLayer struct {
		CipherSuites []string `json:"cipher_suites"`
		Extensions   struct {
			SupportedGroups     []string `json:"supported_groups"`
			SignatureAlgorithms []string `json:"signature_algorithms"`
			AlpnProtocols       []string `json:"alpn_protocols"`
			SupportedVersions   []string `json:"supported_versions"`
		} `json:"extensions"`
	} `json:"tls_layer"`
}

// FaeContext holds the configured BoringSSL context.
type FaeContext struct {
	sslCtx *C.SSL_CTX
}

// A map to convert TLS curve names from IANA/Wireshark format to BoringSSL format.
var curveNameMapping = map[string]string{
	"secp256r1": "P-256",
	"secp384r1": "P-384",
	"secp521r1": "P-521",
	"x25519":    "X25519",
}

// A map to convert version strings from the JSON to the C constants.
var tlsVersionMap = map[string]C.uint16_t{
	"TLS 1.2": C.TLS1_2_VERSION,
	"TLS 1.3": C.TLS1_3_VERSION,
}

// parseValueList extracts the primary name from strings like "name (0xcode)".
// It filters out any entries containing "GREASE".
func parseValueList(raw []string, mapping map[string]string) string {
	var cleaned []string
	for _, item := range raw {
		if strings.Contains(item, "GREASE") {
			continue
		}
		parts := strings.SplitN(item, " (", 2)
		name := strings.TrimSpace(parts[0])
		if mapping != nil {
			if mappedName, ok := mapping[name]; ok {
				name = mappedName
			}
		}
		cleaned = append(cleaned, name)
	}
	return strings.Join(cleaned, ":")
}

// parseVersions determines the min and max TLS versions from the list.
func parseVersions(raw []string) (min C.uint16_t, max C.uint16_t) {
	var versionsFound []C.uint16_t
	for _, item := range raw {
		for name, val := range tlsVersionMap {
			if strings.Contains(item, name) {
				versionsFound = append(versionsFound, val)
				break
			}
		}
	}

	if len(versionsFound) == 0 {
		return 0, 0
	}

	min, max = versionsFound[0], versionsFound[0]
	for _, v := range versionsFound {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	return min, max
}

// buildALPN converts a Go slice of strings to the wire format.
func buildALPN(protos []string) []byte {
	var buf bytes.Buffer
	for _, proto := range protos {
		buf.WriteByte(byte(len(proto)))
		buf.WriteString(proto)
	}
	return buf.Bytes()
}

// NewFaeContext creates and configures a new TLS context from a fingerprint file.
func NewFaeContext(fingerprintPath string) (*FaeContext, error) {
	fingerprintFile, err := os.ReadFile(fingerprintPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read fingerprint file: %w", err)
	}

	var fp Fingerprint
	if err := json.Unmarshal(fingerprintFile, &fp); err != nil {
		return nil, fmt.Errorf("failed to parse fingerprint file: %w", err)
	}

	cipherList := parseValueList(fp.TlsLayer.CipherSuites, nil)
	sigalgsList := parseValueList(fp.TlsLayer.Extensions.SignatureAlgorithms, nil)
	curvesList := parseValueList(fp.TlsLayer.Extensions.SupportedGroups, curveNameMapping)
	minVersion, maxVersion := parseVersions(fp.TlsLayer.Extensions.SupportedVersions)
	alpnBytes := buildALPN(fp.TlsLayer.Extensions.AlpnProtocols)

	C.SSL_library_init()
	C.SSL_load_error_strings()

	ctx := C.SSL_CTX_new(C.SSLv23_client_method())
	if ctx == nil {
		return nil, fmt.Errorf("failed to create SSL_CTX")
	}

	cCiphers := C.CString(cipherList)
	defer C.free(unsafe.Pointer(cCiphers))

	cSigalgs := C.CString(sigalgsList)
	defer C.free(unsafe.Pointer(cSigalgs))

	cCurves := C.CString(curvesList)
	defer C.free(unsafe.Pointer(cCurves))

	cAlpn := (*C.uchar)(unsafe.Pointer(&alpnBytes[0]))
	cAlpnLen := C.size_t(len(alpnBytes))

	success := C.configure_ssl_ctx(ctx, cCiphers, cCurves, cSigalgs, cAlpn, cAlpnLen, minVersion, maxVersion)
	if success == 0 {
		C.SSL_CTX_free(ctx)
		return nil, fmt.Errorf("failed to configure SSL_CTX from C")
	}

	fmt.Println("Configuration successful. The SSL_CTX is now ready.")
	return &FaeContext{sslCtx: ctx}, nil
}

// Get performs a TLS GET request using the configured context.
func (c *FaeContext) Get(ctx context.Context, url string) (error, string) {
	select {
	case <-ctx.Done():
		return ctx.Err(), ""
	default:
	}

	parts := strings.SplitN(url, "/", 2)
	hostPort := parts[0]
	path := "/"
	if len(parts) > 1 {
		path = "/" + parts[1]
	}

	hostParts := strings.Split(hostPort, ":")
	host := hostParts[0]
	port := 443 // Default to 443 for HTTPS
	if len(hostParts) > 1 {
		fmt.Sscanf(hostParts[1], "%d", &port)
	}

	cHost := C.CString(host)
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cHost))
	defer C.free(unsafe.Pointer(cPath))

	resp := C.tls_get_request(c.sslCtx, cHost, C.int(port), cPath)

	if resp.error_res == 0 {
		return nil, C.GoString(resp.response)
	}
	return fmt.Errorf("TLS request failed with error code %d", resp.error_res), "Error in making GET Request"
}

// Close frees the underlying SSL_CTX.
func (c *FaeContext) Close() {
	if c.sslCtx != nil {
		C.SSL_CTX_free(c.sslCtx)
	}
}
