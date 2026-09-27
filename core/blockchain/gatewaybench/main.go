// Persistent Fabric Gateway benchmark server.
// Opens Gateway connections once per identity and serves concurrent /invoke.
package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type cfg struct {
	PeerEndpoint string `json:"peer_endpoint"`
	PeerTLSCA    string `json:"peer_tls_ca"`
	SSLOverride  string `json:"ssl_target_name_override"`
	MSPID        string `json:"mspid"`
	CertPath     string `json:"cert_path"`
	KeyPath      string `json:"key_path"`
	Channel      string `json:"channel"`
	Chaincode    string `json:"chaincode"`
}

type identityHandle struct {
	gw       *client.Gateway
	conn     *grpc.ClientConn
	contract *client.Contract
}

type server struct {
	mu   sync.RWMutex
	ids  map[string]*identityHandle
	addr string
}

type invokeReq struct {
	Identity string   `json:"identity"`
	Fn       string   `json:"fn"`
	Args     []string `json:"args"`
	Mode     string   `json:"mode"` // submit (default) | evaluate
}

type invokeResp struct {
	OK            bool   `json:"ok"`
	Status        string `json:"status"`
	TxID          string `json:"tx_id,omitempty"`
	BlockNumber   uint64 `json:"block_number,omitempty"`
	Payload       string `json:"payload,omitempty"`
	Error         string `json:"error,omitempty"`
	Code          string `json:"code,omitempty"`
	SubmitUnixNs  int64  `json:"submit_unix_ns"`
	CommitUnixNs  int64  `json:"commit_unix_ns"`
	LatencyNs     int64  `json:"latency_ns"`
}

func main() {
	cfgDir := flag.String("config-dir", "", "directory with gateway.json / authority.json / admin.json")
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	flag.Parse()
	if *cfgDir == "" {
		log.Fatal("-config-dir required")
	}
	s := &server{ids: map[string]*identityHandle{}}
	for _, name := range []string{"gateway", "authority", "admin"} {
		path := filepath.Join(*cfgDir, name+".json")
		if _, err := os.Stat(path); err != nil {
			continue
		}
		c, err := loadCfg(path)
		must(err)
		h, err := connect(c)
		must(err)
		s.ids[name] = h
		log.Printf("loaded identity %s", name)
	}
	if len(s.ids) == 0 {
		log.Fatal("no identities loaded")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "identities": keys(s.ids)})
	})
	mux.HandleFunc("/invoke", s.handleInvoke)

	ln, err := net.Listen("tcp", *addr)
	must(err)
	s.addr = ln.Addr().String()
	fmt.Printf("READY %s\n", s.addr)
	_ = os.Stdout.Sync()
	log.Printf("listening on %s", s.addr)
	must(http.Serve(ln, mux))
}

func (s *server) handleInvoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req invokeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if req.Mode == "" {
		req.Mode = "submit"
	}
	idName := mapIdentity(req.Identity)
	s.mu.RLock()
	h := s.ids[idName]
	s.mu.RUnlock()
	if h == nil {
		_ = json.NewEncoder(w).Encode(invokeResp{OK: false, Status: "INVALID", Error: "unknown identity " + idName})
		return
	}

	submitAt := time.Now()
	resp := invokeResp{SubmitUnixNs: submitAt.UnixNano()}
	switch req.Mode {
	case "evaluate":
		out, err := h.contract.EvaluateTransaction(req.Fn, req.Args...)
		commitAt := time.Now()
		resp.CommitUnixNs = commitAt.UnixNano()
		resp.LatencyNs = commitAt.Sub(submitAt).Nanoseconds()
		if err != nil {
			resp.OK = false
			resp.Status = classify(err)
			resp.Error = err.Error()
			resp.Code = resp.Status
		} else {
			resp.OK = true
			resp.Status = "VALID"
			resp.Payload = string(out)
		}
	default: // submit
		_, commit, err := h.contract.SubmitAsync(req.Fn, client.WithArguments(req.Args...))
		if err != nil {
			commitAt := time.Now()
			resp.CommitUnixNs = commitAt.UnixNano()
			resp.LatencyNs = commitAt.Sub(submitAt).Nanoseconds()
			resp.OK = false
			resp.Status = classify(err)
			resp.Error = err.Error()
			resp.Code = resp.Status
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		st, err := commit.Status()
		commitAt := time.Now()
		resp.CommitUnixNs = commitAt.UnixNano()
		resp.LatencyNs = commitAt.Sub(submitAt).Nanoseconds()
		resp.TxID = commit.TransactionID()
		if err != nil {
			resp.OK = false
			resp.Status = classify(err)
			resp.Error = err.Error()
			resp.Code = resp.Status
		} else if !st.Successful {
			resp.OK = false
			resp.Status = mapCode(fmt.Sprintf("%v", st.Code))
			resp.Code = resp.Status
			resp.BlockNumber = st.BlockNumber
			resp.Error = fmt.Sprintf("commit unsuccessful code=%v", st.Code)
		} else {
			resp.OK = true
			resp.Status = "VALID"
			resp.BlockNumber = st.BlockNumber
		}
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func mapIdentity(s string) string {
	low := strings.ToLower(strings.TrimSpace(s))
	switch {
	case low == "" || low == "gw" || low == "gateway" || strings.HasPrefix(low, "gateway"):
		return "gateway"
	case low == "aa" || low == "authority" || low == "rm" || low == "ca" || strings.HasPrefix(low, "authority"):
		return "authority"
	case low == "admin":
		return "admin"
	default:
		return "gateway"
	}
}

func resolvePath(baseDir, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Clean(filepath.Join(baseDir, p))
}

func loadCfg(path string) (cfg, error) {
	var c cfg
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	base := filepath.Dir(path)
	c.PeerTLSCA = resolvePath(base, c.PeerTLSCA)
	c.CertPath = resolvePath(base, c.CertPath)
	c.KeyPath = resolvePath(base, c.KeyPath)
	if c.MSPID == "" {
		c.MSPID = "Org1MSP"
	}
	if c.Channel == "" {
		c.Channel = "hierastream-channel"
	}
	if c.Chaincode == "" {
		c.Chaincode = "hierastream"
	}
	return c, nil
}

func connect(c cfg) (*identityHandle, error) {
	certPEM, err := os.ReadFile(c.CertPath)
	if err != nil {
		return nil, err
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, err
	}
	id, err := identity.NewX509Identity(c.MSPID, cert)
	if err != nil {
		return nil, err
	}
	keyPath := c.KeyPath
	if fi, err := os.Stat(keyPath); err == nil && fi.IsDir() {
		ents, _ := os.ReadDir(keyPath)
		for _, e := range ents {
			if !e.IsDir() {
				keyPath = filepath.Join(keyPath, e.Name())
				break
			}
		}
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	pk, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	sign, err := identity.NewPrivateKeySign(pk)
	if err != nil {
		return nil, err
	}
	tlsPEM, err := os.ReadFile(c.PeerTLSCA)
	if err != nil {
		return nil, err
	}
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(tlsPEM) {
		if block, _ := pem.Decode(tlsPEM); block != nil {
			if crt, err := x509.ParseCertificate(block.Bytes); err == nil {
				cp.AddCert(crt)
			}
		}
	}
	tc := credentials.NewClientTLSFromCert(cp, c.SSLOverride)
	conn, err := grpc.NewClient(c.PeerEndpoint, grpc.WithTransportCredentials(tc))
	if err != nil {
		return nil, err
	}
	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithHash(hash.SHA256),
		client.WithClientConnection(conn),
		client.WithEvaluateTimeout(30*time.Second),
		client.WithEndorseTimeout(30*time.Second),
		client.WithSubmitTimeout(30*time.Second),
		client.WithCommitStatusTimeout(90*time.Second),
	)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	network := gw.GetNetwork(c.Channel)
	contract := network.GetContract(c.Chaincode)
	return &identityHandle{gw: gw, conn: conn, contract: contract}, nil
}

func mapCode(code string) string {
	u := strings.ToUpper(code)
	switch {
	case strings.Contains(u, "MVCC"):
		return "MVCC_READ_CONFLICT"
	case strings.Contains(u, "ENDORSE"):
		return "ENDORSEMENT_FAIL"
	case u == "VALID":
		return "VALID"
	default:
		// Keep raw validation code when informative (e.g. VSCC failures).
		if u != "" && u != "<NIL>" {
			return u
		}
		return "INVALID"
	}
}

func classify(err error) string {
	s := strings.ToUpper(err.Error())
	switch {
	case strings.Contains(s, "MVCC"):
		return "MVCC_READ_CONFLICT"
	case strings.Contains(s, "ENDORSE"):
		return "ENDORSEMENT_FAIL"
	case strings.Contains(s, "ACL"), strings.Contains(s, "DENIED"), strings.Contains(s, "UNAUTHORIZED"):
		return "ACL_DENIED"
	case strings.Contains(s, "DEADLINE"), strings.Contains(s, "TIMEOUT"), strings.Contains(s, "TIMED OUT"):
		return "TIMEOUT"
	case strings.Contains(s, "CONNECTION"), strings.Contains(s, "UNAVAILABLE"), strings.Contains(s, "TRANSPORT"):
		return "CONNECTION_ERROR"
	case strings.Contains(s, "CHAINCODE"):
		return "CHAINCODE_REJECT"
	default:
		return "GATEWAY_ERROR"
	}
}

func keys(m map[string]*identityHandle) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
