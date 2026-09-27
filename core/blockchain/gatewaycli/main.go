// HieraStream live Fabric Gateway CLI.
// Python gateway_adapter shells out to this binary.
package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

type result struct {
	OK          bool   `json:"ok"`
	Status      string `json:"status"`
	TxID        string `json:"tx_id"`
	BlockNumber uint64 `json:"block_number,omitempty"`
	Payload     string `json:"payload,omitempty"`
	Error       string `json:"error,omitempty"`
	Code        string `json:"code,omitempty"`
}

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: hs-gateway-cli <config.json> <submit|evaluate|endorse|submit_endorsed> <fn> [args...]")
		os.Exit(2)
	}
	cfgPath, mode, fn := os.Args[1], os.Args[2], os.Args[3]
	args := os.Args[4:]
	c, err := loadCfg(cfgPath)
	mustOK(err)
	gw, conn, err := connect(c)
	mustOK(err)
	defer conn.Close()
	defer gw.Close()

	network := gw.GetNetwork(c.Channel)
	contract := network.GetContract(c.Chaincode)

	switch mode {
	case "evaluate":
		out, err := contract.EvaluateTransaction(fn, args...)
		if err != nil {
			fail(err, "")
		}
		emit(result{OK: true, Status: "VALID", Payload: string(out)})
	case "submit":
		_, commit, err := contract.SubmitAsync(fn, client.WithArguments(args...))
		if err != nil {
			fail(err, "")
		}
		waitCommit(commit)
	case "endorse":
		proposal, err := contract.NewProposal(fn, client.WithArguments(args...))
		mustOK(err)
		txn, err := proposal.Endorse()
		if err != nil {
			fail(err, "")
		}
		raw, err := txn.Bytes()
		mustOK(err)
		path := os.Getenv("HIERASTREAM_ENDORSED_TX_PATH")
		if path == "" {
			path = filepath.Join(os.TempDir(), "hs-endorsed-"+txn.TransactionID()+".bin")
		}
		mustOK(os.WriteFile(path, raw, 0o600))
		emit(result{OK: true, Status: "PENDING", TxID: txn.TransactionID(), Payload: path})
	case "submit_endorsed":
		if len(args) < 1 {
			fail(fmt.Errorf("submit_endorsed requires endorsed bytes path"), "")
		}
		raw, err := os.ReadFile(args[0])
		mustOK(err)
		txn, err := gw.NewTransaction(raw)
		if err != nil {
			fail(err, "")
		}
		commit, err := txn.Submit()
		if err != nil {
			fail(err, txn.TransactionID())
		}
		waitCommit(commit)
	default:
		fail(fmt.Errorf("unknown mode %s", mode), "")
	}
}

func waitCommit(commit *client.Commit) {
	st, err := commit.Status()
	if err != nil {
		fail(err, commit.TransactionID())
	}
	if !st.Successful {
		emit(result{
			OK: false, Status: mapCode(fmt.Sprintf("%v", st.Code)),
			TxID: commit.TransactionID(), BlockNumber: st.BlockNumber,
			Code: fmt.Sprintf("%v", st.Code),
			Error: fmt.Sprintf("commit unsuccessful code=%v", st.Code),
		})
		os.Exit(1)
	}
	emit(result{OK: true, Status: "VALID", TxID: commit.TransactionID(), BlockNumber: st.BlockNumber})
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

func connect(c cfg) (*client.Gateway, *grpc.ClientConn, error) {
	certPEM, err := os.ReadFile(c.CertPath)
	if err != nil {
		return nil, nil, err
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, nil, err
	}
	id, err := identity.NewX509Identity(c.MSPID, cert)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, err
	}
	pk, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, nil, err
	}
	sign, err := identity.NewPrivateKeySign(pk)
	if err != nil {
		return nil, nil, err
	}
	tlsPEM, err := os.ReadFile(c.PeerTLSCA)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, err
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
	return gw, conn, err
}

func mapCode(code string) string {
	u := strings.ToUpper(code)
	switch {
	case strings.Contains(u, "MVCC"):
		return "MVCC_READ_CONFLICT"
	case strings.Contains(u, "ENDORSEMENT"):
		return "INVALID"
	default:
		return "INVALID"
	}
}

func classify(err error) string {
	s := strings.ToUpper(err.Error())
	switch {
	case strings.Contains(s, "MVCC"):
		return "MVCC_READ_CONFLICT"
	case strings.Contains(s, "ACL"), strings.Contains(s, "DENIED"), strings.Contains(s, "PERMISSION"):
		return "ACL_DENIED"
	default:
		return "INVALID"
	}
}

func fail(err error, txid string) {
	emit(result{OK: false, Status: classify(err), Error: err.Error(), TxID: txid, Code: classify(err)})
	os.Exit(1)
}

func mustOK(err error) {
	if err != nil {
		fail(err, "")
	}
}

func emit(r result) {
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
}
