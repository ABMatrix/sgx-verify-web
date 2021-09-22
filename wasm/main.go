package main

import (
	"bytes"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"syscall/js"
	"time"

	"github.com/pkg/errors"
)

func main() {
	done := make(chan struct{}, 0)
	global := js.Global()
	global.Set("wasmVerifyMraCert", js.FuncOf(verifyMraCert))
	<-done
}

func verifyMraCert(this js.Value, args []js.Value) interface{} {
	rawCert, err := hex.DecodeString(args[0].String())
	if err != nil {
		return format_result(err.Error(), false)
	}
	// printCert(rawCert)

	// get the pubkey and payload from raw data
	pub_k, payload, err := unmarshalCert(rawCert)
	if err != nil {
		return format_result(err.Error(), false)
	}

	// Load Intel CA, Verify Cert and Signature
	attn_report_raw, err := verifyCert(payload)
	if err != nil {
		return format_result(err.Error(), false)
	}

	// Verify attestation report
	result, err := verifyAttReport(attn_report_raw, pub_k)
	if err != nil {
		return format_result(err.Error(), false)
	}

	return format_result(result, true)
}

func unmarshalCert(rawbyte []byte) ([]byte, []byte, error) {
	// Search for Public Key prime256v1 OID
	prime256v1_oid := []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
	index := bytes.Index(rawbyte, prime256v1_oid)

	if index == -1 {
		return []byte{}, []byte{}, errors.New("Can not get sgx pubkey from cert")
	}

	offset := uint(index)
	offset += 11 // 10 + TAG (0x03)

	// Obtain Public Key length
	length := uint(rawbyte[offset])
	if length > 0x80 {
		length = uint(rawbyte[offset+1])*uint(0x100) + uint(rawbyte[offset+2])
		offset += 2
	}

	// Obtain Public Key
	offset += 1
	pub_k := rawbyte[offset+2 : offset+length] // skip "00 04"

	// Search for Netscape Comment OID
	ns_cmt_oid := []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x01, 0x0D}
	offset = uint(bytes.Index(rawbyte, ns_cmt_oid))
	offset += 12 // 11 + TAG (0x04)

	// Obtain Netscape Comment length
	length = uint(rawbyte[offset])
	if length > 0x80 {
		length = uint(rawbyte[offset+1])*uint(0x100) + uint(rawbyte[offset+2])
		offset += 2
	}

	// Obtain Netscape Comment
	offset += 1
	payload := rawbyte[offset : offset+length]
	return pub_k, payload, nil
}

func verifyCert(payload []byte) ([]byte, error) {
	// Extract each field
	pl_split := bytes.Split(payload, []byte{0x7C})
	attn_report_raw := pl_split[0]

	if len(pl_split) < 3 {
		return nil, errors.New("Failed to get attest report from cert")
	}
	sig_raw := pl_split[1]

	var sig, sig_cert_dec []byte
	sig, err := base64.StdEncoding.DecodeString(string(sig_raw))
	if err != nil {
		return nil, err
	}

	sig_cert_raw := pl_split[2]
	sig_cert_dec, err = base64.StdEncoding.DecodeString(string(sig_cert_raw))
	if err != nil {
		return nil, err
	}

	certServer, err := x509.ParseCertificate(sig_cert_dec)
	if err != nil {
		return nil, err
	}

	roots := x509.NewCertPool()
	cacert, err := readFile()
	if err != nil {
		return nil, err
	}
	ok := roots.AppendCertsFromPEM([]byte(cacert))
	if !ok {
		panic("Failed to parse root certificate")
	}

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := certServer.Verify(opts); err != nil {
		return nil, err
	} else {
		fmt.Println("Cert is good")
	}

	// Verify the signature against the signing cert
	err = certServer.CheckSignature(certServer.SignatureAlgorithm, attn_report_raw, sig)
	if err != nil {
		return nil, err
	} else {
		fmt.Println("Signature good")
	}
	return attn_report_raw, nil
}

func verifyAttReport(attn_report_raw []byte, pub_k []byte) (string, error) {
	var qr QuoteReport
	err := json.Unmarshal(attn_report_raw, &qr)
	if err != nil {
		return "", err
	}

	// 1. Check timestamp is within 24H
	if qr.Timestamp != "" {
		//timeFixed := qr.Timestamp + "+0000"
		timeFixed := qr.Timestamp + "Z"
		ts, _ := time.Parse(time.RFC3339, timeFixed)
		now := time.Now().Unix()
		fmt.Println("Time diff = ", now-ts.Unix())
	} else {
		return "", errors.New("Failed to fetch timestamp from attestation report")
	}

	// 2. Verify quote status (mandatory field)
	if qr.IsvEnclaveQuoteStatus != "" {
		fmt.Println("isvEnclaveQuoteStatus = ", qr.IsvEnclaveQuoteStatus)
		switch qr.IsvEnclaveQuoteStatus {
		case "OK":
			break
		case "GROUP_OUT_OF_DATE", "GROUP_REVOKED", "CONFIGURATION_NEEDED":
			// Verify platformInfoBlob for further info if status not OK
			if qr.PlatformInfoBlob != "" {
				platInfo, err := hex.DecodeString(qr.PlatformInfoBlob)
				if err != nil && len(platInfo) != 105 {
					return "", errors.New("Illegal PlatformInfoBlob")
				}
				platInfo = platInfo[4:]

				piBlob := parsePlatform(platInfo)
				piBlobJson, err := json.Marshal(piBlob)
				if err != nil {
					return "", err
				}
				fmt.Println("Platform info is: " + string(piBlobJson))
			} else {
				return "", errors.New("Failed to fetch platformInfoBlob from attestation report")
			}
		default:
			return "", errors.New("SGX_ERROR_UNEXPECTED")
		}
	} else {
		err := errors.New("Failed to fetch isvEnclaveQuoteStatus from attestation report")
		return "", err
	}

	// 3. Verify quote body
	if qr.IsvEnclaveQuoteBody != "" {
		qb, err := base64.StdEncoding.DecodeString(qr.IsvEnclaveQuoteBody)
		if err != nil {
			return "", err
		}

		var quoteBytes, quoteHex, pubHex string
		for _, b := range qb {
			quoteBytes += fmt.Sprint(int(b), ", ")
			quoteHex += fmt.Sprintf("%02x", int(b))
		}

		for _, b := range pub_k {
			pubHex += fmt.Sprintf("%02x", int(b))
		}

		qrData := parseReport(qb, quoteHex)

		// fmt.Println("Quote = [" + quoteBytes[:len(quoteBytes)-2] + "]")
		// fmt.Println("sgx quote version = ", qrData.Version)
		// fmt.Println("sgx quote signature type = ", qrData.SignType)
		// fmt.Println("sgx quote report_data = ", qrData.ReportBody.ReportData)
		// fmt.Println("sgx quote mr_enclave = ", qrData.ReportBody.MrEnclave)
		// fmt.Println("sgx quote mr_signer = ", qrData.ReportBody.MrSigner)
		// fmt.Println("Anticipated public key = ", pubHex)

		if qrData.ReportBody.ReportData == pubHex {
			fmt.Println("ue RA done!")
		}
		result, err := json.Marshal(qrData)
		if err != nil {
			err := errors.New("Failed to strinify result")
			return "", err
		}
		return string(result), nil
	} else {
		err := errors.New("Failed to fetch isvEnclaveQuoteBody from attestation report")
		return "", err
	}
}

func format_result(data string, success bool) string {
	var resultData ResultData
	fmt.Println("Result: ", data)
	if success {
		resultData = ResultData{"success", data}
	} else {
		resultData = ResultData{"error", data}
	}
	result, _ := json.Marshal(resultData)
	return string(result)
}

func printCert(rawByte []byte) {
	print("--received-server cert: [Certificate(b\"")
	for _, b := range rawByte {
		if b == '\n' {
			print("\\n")
		} else if b == '\r' {
			print("\\r")
		} else if b == '\t' {
			print("\\t")
		} else if b == '\\' || b == '"' {
			print("\\", string(rune(b)))
		} else if b >= 0x20 && b < 0x7f {
			print(string(rune(b)))
		} else {
			fmt.Printf("\\x%02x", int(b))
		}
	}
	println("\")]")
}

//go:embed AttestationReportSigningCACert.pem
var global embed.FS

func readFile() (string, error) {
	var filePath = "AttestationReportSigningCACert.pem"
	content, err := global.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

type ResultData struct {
	Result string `json:"result"`
	Data   string `json:"data"`
}

type QuoteReport struct {
	ID                    string `json:"id"`
	Timestamp             string `json:"timestamp"`
	Version               int    `json:"version"`
	IsvEnclaveQuoteStatus string `json:"isvEnclaveQuoteStatus"`
	PlatformInfoBlob      string `json:"platformInfoBlob"`
	IsvEnclaveQuoteBody   string `json:"isvEnclaveQuoteBody"`
}

//TODO: add more origin field if needed
type QuoteReportData struct {
	Version    int             `json:"version"`
	SignType   int             `json:"signType"`
	ReportBody QuoteReportBody `json:"quoteReportBody"`
}

//TODO: add more origin filed if needed
type QuoteReportBody struct {
	MrEnclave  string `json:"mrEnclave"`
	MrSigner   string `json:"mrsigner"`
	ReportData string `json:"reportData"`
}

type PlatformInfoBlob struct {
	Sgx_epid_group_flags       uint8             `json:"sgx_epid_group_flags"`
	Sgx_tcb_evaluation_flags   uint32            `json:"sgx_tcb_evaluation_flags"`
	Pse_evaluation_flags       uint32            `json:"pse_evaluation_flags"`
	Latest_equivalent_tcb_psvn string            `json:"latest_equivalent_tcb_psvn"`
	Latest_pse_isvsvn          string            `json:"latest_pse_isvsvn"`
	Latest_psda_svn            string            `json:"latest_psda_svn"`
	Xeid                       uint32            `json:"xeid"`
	Gid                        uint32            `json:"gid"`
	Sgx_ec256_signature_t      SGXEC256Signature `json:"sgx_ec256_signature_t"`
}

type SGXEC256Signature struct {
	Gx string `json:"gx"`
	Gy string `json:"gy"`
}

// directly read from []byte
func parseReport(quoteBytes []byte, quoteHex string) *QuoteReportData {
	qrData := &QuoteReportData{ReportBody: QuoteReportBody{}}
	qrData.Version = int(quoteBytes[0])
	qrData.SignType = int(quoteBytes[2])
	qrData.ReportBody.MrEnclave = quoteHex[224:288]
	qrData.ReportBody.MrSigner = quoteHex[352:416]
	qrData.ReportBody.ReportData = quoteHex[736:864]
	return qrData
}

// directly read from []byte
func parsePlatform(piBlobByte []byte) *PlatformInfoBlob {
	piBlob := &PlatformInfoBlob{Sgx_ec256_signature_t: SGXEC256Signature{}}
	piBlob.Sgx_epid_group_flags = uint8(piBlobByte[0])
	piBlob.Sgx_tcb_evaluation_flags = computeDec(piBlobByte[1:3])
	piBlob.Pse_evaluation_flags = computeDec(piBlobByte[3:5])
	piBlob.Latest_equivalent_tcb_psvn = bytesToString(piBlobByte[5:23])
	piBlob.Latest_pse_isvsvn = bytesToString(piBlobByte[23:25])
	piBlob.Latest_psda_svn = bytesToString(piBlobByte[25:29])
	piBlob.Xeid = computeDec(piBlobByte[29:33])
	piBlob.Gid = computeDec(piBlobByte[33:37])
	piBlob.Sgx_ec256_signature_t.Gx = bytesToString(piBlobByte[37:69])
	piBlob.Sgx_ec256_signature_t.Gy = bytesToString(piBlobByte[69:])

	return piBlob
}

func computeDec(piBlobSlice []byte) uint32 {
	var hexString string
	for i := len(piBlobSlice) - 1; i >= 0; i-- {
		hexString += fmt.Sprintf("%02x", piBlobSlice[i])
	}
	s, _ := strconv.ParseInt(hexString, 16, 32)

	return uint32(s)
}

func bytesToString(byteSlice []byte) string {
	var byteString string
	for i := 0; i < len(byteSlice); i++ {
		byteString += strconv.Itoa(int(byteSlice[i])) + ", "
	}
	byteString = "[" + byteString[:len(byteString)-2] + "]"
	return byteString
}
