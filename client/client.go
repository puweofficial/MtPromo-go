// Package client provides the top-level MTProto client.
// It manages a single authenticated session, handles encrypted message
// framing, sequence numbers, and exposes high-level RPC helpers.
package client

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/puweofficial/MtPromo-go/auth"
	"github.com/puweofficial/MtPromo-go/crypto"
	"github.com/puweofficial/MtPromo-go/transport"
	"github.com/puweofficial/MtPromo-go/types"
)

// DC address table (production).
var dcAddresses = map[int]string{
	1: "149.154.175.53:443",
	2: "149.154.167.51:443",
	3: "149.154.175.100:443",
	4: "149.154.167.91:443",
	5: "91.108.56.130:443",
}

// Config holds all parameters needed to initialise a Client.
type Config struct {
	// AppID and AppHash are obtained from https://my.telegram.org
	AppID   int
	AppHash string
	// DCID is the data-centre to connect to (1-5, default 2).
	DCID int
	// SessionFile is the path to persist auth key & session data.
	// If empty, session is not saved to disk.
	SessionFile string
	// Phone is required for user-auth flows.
	Phone string
}

// Client is an MTProto session.
type Client struct {
	cfg     Config
	conn    *transport.Conn
	authKey *auth.AuthKey

	seqNo     int32
	msgSeqN   int32 // content-related sequence counter
	sessionID int64

	pending   map[int64]chan []byte
	pendingMu sync.Mutex

	closed int32 // atomic bool
}

// sessionState is persisted to disk between runs.
type sessionState struct {
	AuthKey   []byte `json:"auth_key"`
	KeyID     []byte `json:"key_id"`
	Salt      int64  `json:"salt"`
	DcID      int    `json:"dc_id"`
	SessionID int64  `json:"session_id"`
}

// New creates and connects a new Client.  It will reuse a saved session if
// SessionFile exists and is readable.
func New(cfg Config) (*Client, error) {
	if cfg.DCID == 0 {
		cfg.DCID = 2
	}
	addr, ok := dcAddresses[cfg.DCID]
	if !ok {
		return nil, fmt.Errorf("client: unknown DC %d", cfg.DCID)
	}

	conn, err := transport.Dial(addr)
	if err != nil {
		return nil, err
	}

	c := &Client{
		cfg:       cfg,
		conn:      conn,
		sessionID: rand.Int63(),
		pending:   make(map[int64]chan []byte),
	}

	// Try to load existing session
	if cfg.SessionFile != "" {
		if ak, err := c.loadSession(); err == nil {
			c.authKey = ak
			fmt.Printf("[mtproto] Loaded existing session for DC%d\n", ak.DcID)
			// Start receiver goroutine
			go c.receiveLoop()
			return c, nil
		}
	}

	// Create new auth key
	ak, err := auth.GenerateAuthKey(conn, cfg.DCID)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("client: key exchange: %w", err)
	}
	c.authKey = ak

	if cfg.SessionFile != "" {
		_ = c.saveSession()
	}

	go c.receiveLoop()
	return c, nil
}

// Close gracefully shuts down the client.
func (c *Client) Close() {
	atomic.StoreInt32(&c.closed, 1)
	c.conn.Close()
}

// ─── Session persistence ─────────────────────────────────────────────────────

func (c *Client) saveSession() error {
	s := sessionState{
		AuthKey:   c.authKey.Key,
		KeyID:     c.authKey.KeyID,
		Salt:      c.authKey.Salt,
		DcID:      c.authKey.DcID,
		SessionID: c.sessionID,
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(c.cfg.SessionFile, data, 0600)
}

func (c *Client) loadSession() (*auth.AuthKey, error) {
	data, err := os.ReadFile(c.cfg.SessionFile)
	if err != nil {
		return nil, err
	}
	var s sessionState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	if len(s.AuthKey) != 256 {
		return nil, errors.New("invalid session: bad key length")
	}
	c.sessionID = s.SessionID
	return &auth.AuthKey{
		Key:   s.AuthKey,
		KeyID: s.KeyID,
		Salt:  s.Salt,
		DcID:  s.DcID,
	}, nil
}

// ─── Encrypted message framing ───────────────────────────────────────────────

// nextSeqNo returns the next content-related sequence number (always odd).
func (c *Client) nextSeqNo(content bool) int32 {
	if content {
		n := atomic.AddInt32(&c.msgSeqN, 1)
		return n*2 - 1
	}
	return atomic.LoadInt32(&c.msgSeqN) * 2
}

// SendEncrypted encrypts a TL payload and sends it over the wire.
// Returns the message_id which can be used to match the server reply.
func (c *Client) SendEncrypted(payload []byte) (int64, error) {
	msgID := generateMsgID()
	seqNo := c.nextSeqNo(true)

	// Build MTProto message body
	body := types.NewTLBuffer()
	body.WriteInt64(c.authKey.Salt)
	body.WriteInt64(c.sessionID)
	body.WriteInt64(msgID)
	body.WriteInt32(seqNo)
	body.WriteInt32(int32(len(payload)))
	buf := body.Bytes()
	buf = append(buf, payload...)

	// Pad to multiple of 16 with at least 12 bytes of padding
	pad := 12 + rand.Intn(64)
	for (len(buf)+pad)%16 != 0 {
		pad++
	}
	paddingBytes := make([]byte, pad)
	rand.Read(paddingBytes) //nolint:errcheck
	buf = append(buf, paddingBytes...)

	msgKey := crypto.MessageKey(c.authKey.Key, buf, true)
	aesKey, aesIV := crypto.DeriveKeys(c.authKey.Key, msgKey, true)
	encrypted, err := crypto.AesIgeEncrypt(buf, aesKey, aesIV)
	if err != nil {
		return 0, err
	}

	// Build outer frame: auth_key_id + msg_key + encrypted
	frame := types.NewTLBuffer()
	frame.WriteBytes(c.authKey.KeyID)
	frame.WriteBytes(msgKey)
	outer := frame.Bytes()
	outer = append(outer, encrypted...)

	// Pad to multiple of 4 for TCP transport
	for len(outer)%4 != 0 {
		outer = append(outer, 0)
	}

	if err := c.conn.Send(outer); err != nil {
		return 0, err
	}
	return msgID, nil
}

// ─── Receive loop ────────────────────────────────────────────────────────────

func (c *Client) receiveLoop() {
	for atomic.LoadInt32(&c.closed) == 0 {
		frame, err := c.conn.Recv()
		if err != nil {
			if atomic.LoadInt32(&c.closed) == 0 {
				fmt.Fprintf(os.Stderr, "[mtproto] recv error: %v\n", err)
			}
			return
		}
		if err := c.handleFrame(frame); err != nil {
			fmt.Fprintf(os.Stderr, "[mtproto] handle frame: %v\n", err)
		}
	}
}

func (c *Client) handleFrame(frame []byte) error {
	if len(frame) < 24 {
		return errors.New("frame too short")
	}
	// auth_key_id (8) + msg_key (16)
	msgKey := frame[8:24]
	encData := frame[24:]

	aesKey, aesIV := crypto.DeriveKeys(c.authKey.Key, msgKey, false)
	decrypted, err := crypto.AesIgeDecrypt(encData, aesKey, aesIV)
	if err != nil {
		return err
	}
	// Unpack: salt(8) + session(8) + msg_id(8) + seq_no(4) + msg_len(4) + body
	if len(decrypted) < 32 {
		return errors.New("decrypted too short")
	}
	msgID := int64(binary.LittleEndian.Uint64(decrypted[16:24]))
	msgLen := int(binary.LittleEndian.Uint32(decrypted[28:32]))
	if 32+msgLen > len(decrypted) {
		return errors.New("msg_len overflow")
	}
	body := decrypted[32 : 32+msgLen]

	c.pendingMu.Lock()
	ch, ok := c.pending[msgID]
	c.pendingMu.Unlock()
	if ok {
		ch <- body
	}
	return nil
}

// ─── High-level RPC ──────────────────────────────────────────────────────────

// Call sends an encrypted RPC and waits for the reply (up to 30 s).
func (c *Client) Call(payload []byte) ([]byte, error) {
	ch := make(chan []byte, 1)
	msgID, err := c.SendEncrypted(payload)
	if err != nil {
		return nil, err
	}
	c.pendingMu.Lock()
	c.pending[msgID] = ch
	c.pendingMu.Unlock()
	defer func() {
		c.pendingMu.Lock()
		delete(c.pending, msgID)
		c.pendingMu.Unlock()
	}()

	select {
	case resp := <-ch:
		return resp, nil
	case <-time.After(30 * time.Second):
		return nil, errors.New("rpc: timeout")
	}
}

func generateMsgID() int64 {
	now := time.Now().UnixNano() / 1e9
	return (now << 32) | int64(rand.Int31()&^3|3)
}
