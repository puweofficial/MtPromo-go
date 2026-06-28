package client

import (
	"bufio"
	"crypto/md5" //nolint:gosec
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/puweofficial/MtPromo-go/types"
)

// ─── Authentication (user flow) ──────────────────────────────────────────────

// SendCode requests a login code to be sent to the phone number.
func (c *Client) SendCode() (phoneCodeHash string, err error) {
	buf := types.NewTLBuffer()
	buf.WriteUInt32(0xa677244f) // auth.sendCode
	buf.WriteString(c.cfg.Phone)
	buf.WriteInt32(int32(c.cfg.AppID))
	buf.WriteString(c.cfg.AppHash)
	// settings (codeSettings, empty)
	buf.WriteUInt32(0xad253d78)
	buf.WriteInt32(0)

	resp, err := c.Call(buf.Bytes())
	if err != nil {
		return "", err
	}
	// Parse auth.sentCode
	rb := types.NewTLBufferFrom(resp)
	cid, _ := rb.ReadUInt32()
	if cid != 0x5e002502 {
		return "", fmt.Errorf("sendCode: unexpected %08x", cid)
	}
	rb.ReadUInt32()            // type (auth.codeTypeSms etc)
	rb.ReadBytes()             // phone_number
	hash, _ := rb.ReadString() // phone_code_hash
	return hash, nil
}

// SignIn completes phone-number auth using the code from Telegram.
func (c *Client) SignIn(phoneCodeHash, code string) error {
	buf := types.NewTLBuffer()
	buf.WriteUInt32(0x80eee427) // auth.signIn
	buf.WriteString(c.cfg.Phone)
	buf.WriteString(phoneCodeHash)
	buf.WriteString(code)

	resp, err := c.Call(buf.Bytes())
	if err != nil {
		return err
	}
	rb := types.NewTLBufferFrom(resp)
	cid, _ := rb.ReadUInt32()
	// 0xcd050916 = auth.authorization, 0x44747e9a = auth.authorizationSignUpRequired
	if cid != 0xcd050916 {
		return fmt.Errorf("signIn: unexpected %08x", cid)
	}
	_ = c.saveSession()
	return nil
}

// PhoneAuthFlow is a convenience wrapper that handles the interactive
// sign-in loop: send code → read from stdin → sign in.
func (c *Client) PhoneAuthFlow() error {
	hash, err := c.SendCode()
	if err != nil {
		return fmt.Errorf("SendCode: %w", err)
	}
	fmt.Print("Enter the code sent to your phone: ")
	reader := bufio.NewReader(os.Stdin)
	code, _ := reader.ReadString('\n')
	code = strings.TrimSpace(code)
	if err := c.SignIn(hash, code); err != nil {
		return fmt.Errorf("SignIn: %w", err)
	}
	fmt.Println("[mtproto] Signed in successfully.")
	return nil
}

// ─── User / bot info ─────────────────────────────────────────────────────────

// User represents a minimal Telegram user object.
type User struct {
	ID        int64
	Username  string
	FirstName string
	LastName  string
	IsBot     bool
}

// GetMe returns the account of the current authorised user/bot.
func (c *Client) GetMe() (*User, error) {
	buf := types.NewTLBuffer()
	buf.WriteUInt32(0xece9f400) // users.getUsers with [inputUserSelf]
	buf.WriteUInt32(0x1cb5c415) // vector
	buf.WriteInt32(1)
	buf.WriteUInt32(0x7da07ec9) // inputUserSelf

	resp, err := c.Call(buf.Bytes())
	if err != nil {
		return nil, err
	}
	rb := types.NewTLBufferFrom(resp)
	rb.ReadUInt32() // vector
	count, _ := rb.ReadInt32()
	if count == 0 {
		return nil, fmt.Errorf("getMe: empty result")
	}
	cid, _ := rb.ReadUInt32()
	if cid != 0xab0f6b1e { // user#ab0f6b1e
		return nil, fmt.Errorf("getMe: unexpected %08x", cid)
	}
	flags, _ := rb.ReadInt32()
	id, _ := rb.ReadInt64()
	u := &User{ID: id, IsBot: flags&0x400 != 0}
	if flags&0x4 != 0 {
		u.Username, _ = rb.ReadString()
	}
	if flags&0x2 != 0 {
		u.FirstName, _ = rb.ReadString()
	}
	if flags&0x8 != 0 {
		u.LastName, _ = rb.ReadString()
	}
	return u, nil
}

// ─── Messaging ───────────────────────────────────────────────────────────────

// SendMessage sends a plain-text message to a peer by username.
func (c *Client) SendMessage(username, text string) (int32, error) {
	peer, err := c.resolveUsername(username)
	if err != nil {
		return 0, err
	}

	buf := types.NewTLBuffer()
	buf.WriteUInt32(0x280d096f) // messages.sendMessage
	flags := int32(0)
	buf.WriteInt32(flags)
	// peer = inputPeerUser
	buf.WriteUInt32(0x7b8e7de6)
	buf.WriteInt64(peer.UserID)
	buf.WriteInt64(peer.AccessHash)
	buf.WriteString(text)
	buf.WriteInt64(rand.Int63()) // random_id
	buf.WriteInt32(0)            // reply_to_msg_id
	buf.WriteUInt32(0x00000000)  // entities (empty)

	resp, err := c.Call(buf.Bytes())
	if err != nil {
		return 0, err
	}
	// Parse updates to extract message id
	rb := types.NewTLBufferFrom(resp)
	rb.ReadUInt32() // updates constructor
	rb.ReadUInt32() // updates vector
	count, _ := rb.ReadInt32()
	if count == 0 {
		return 0, nil
	}
	// First update is usually updateMessageID
	rb.ReadUInt32()
	msgID, _ := rb.ReadInt32()
	return msgID, nil
}

// ─── File upload & sending ───────────────────────────────────────────────────

// UploadFile uploads a local file to Telegram's servers and returns a
// usable InputFile reference.
func (c *Client) UploadFile(path string) (*InputFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("upload: open: %w", err)
	}
	defer f.Close()

	stat, _ := f.Stat()
	size := stat.Size()
	name := filepath.Base(path)

	fileID := rand.Int63()
	const partSize = 512 * 1024 // 512 KB
	parts := int((size + partSize - 1) / partSize)

	md5h := md5.New() //nolint:gosec

	for part := 0; part < parts; part++ {
		chunk := make([]byte, partSize)
		n, err := io.ReadFull(f, chunk)
		if err != nil && err != io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("upload: read part %d: %w", part, err)
		}
		chunk = chunk[:n]
		md5h.Write(chunk)

		if err := c.saveFilePart(fileID, part, chunk); err != nil {
			return nil, fmt.Errorf("upload: part %d: %w", part, err)
		}
		fmt.Printf("\r[upload] %d/%d parts (%.1f%%)", part+1, parts, float64(part+1)/float64(parts)*100)
	}
	fmt.Println()

	md5sum := fmt.Sprintf("%x", md5h.Sum(nil))
	return &InputFile{
		ID:    fileID,
		Parts: parts,
		Name:  name,
		MD5:   md5sum,
	}, nil
}

// InputFile is a server-side reference to an uploaded file.
type InputFile struct {
	ID    int64
	Parts int
	Name  string
	MD5   string // for files < 10 MB; empty otherwise
}

func (c *Client) saveFilePart(fileID int64, part int, data []byte) error {
	buf := types.NewTLBuffer()
	buf.WriteUInt32(0xb304a621) // upload.saveFilePart
	buf.WriteInt64(fileID)
	buf.WriteInt32(int32(part))
	buf.WriteBytes(data)
	resp, err := c.Call(buf.Bytes())
	if err != nil {
		return err
	}
	// Should return boolTrue (0x997275b5)
	rb := types.NewTLBufferFrom(resp)
	cid, _ := rb.ReadUInt32()
	if cid != 0x997275b5 {
		return fmt.Errorf("saveFilePart: unexpected %08x", cid)
	}
	return nil
}

// SendFile sends an uploaded file to a peer.  caption may be empty.
// fileType should be "document", "photo", or "audio".
func (c *Client) SendFile(username, filePath, caption, fileType string) (int32, error) {
	inputFile, err := c.UploadFile(filePath)
	if err != nil {
		return 0, err
	}
	peer, err := c.resolveUsername(username)
	if err != nil {
		return 0, err
	}
	return c.sendMedia(peer, inputFile, caption, fileType)
}

func (c *Client) sendMedia(peer *resolvedPeer, inputFile *InputFile, caption, fileType string) (int32, error) {
	buf := types.NewTLBuffer()
	buf.WriteUInt32(0x72ccc23d) // messages.sendMedia
	buf.WriteInt32(0)           // flags
	// peer
	buf.WriteUInt32(0x7b8e7de6)
	buf.WriteInt64(peer.UserID)
	buf.WriteInt64(peer.AccessHash)
	buf.WriteInt32(0) // reply_to_msg_id

	// media = inputMediaUploadedDocument / inputMediaUploadedPhoto
	switch fileType {
	case "photo":
		buf.WriteUInt32(0x1e287d04) // inputMediaUploadedPhoto
		buf.WriteInt32(0)           // flags
		// inputFile
		buf.WriteUInt32(0xf52ff27f)
		buf.WriteInt64(inputFile.ID)
		buf.WriteInt32(int32(inputFile.Parts))
		buf.WriteString(inputFile.Name)
		buf.WriteString(inputFile.MD5)
		// stickers (empty vector)
		buf.WriteUInt32(0x1cb5c415)
		buf.WriteInt32(0)
		// ttl_seconds
		buf.WriteInt32(0)
	default: // document
		buf.WriteUInt32(0x5b38c6c1) // inputMediaUploadedDocument
		buf.WriteInt32(0)           // flags
		buf.WriteInt32(0)           // nosound_video flag
		// inputFile
		buf.WriteUInt32(0xf52ff27f)
		buf.WriteInt64(inputFile.ID)
		buf.WriteInt32(int32(inputFile.Parts))
		buf.WriteString(inputFile.Name)
		buf.WriteString(inputFile.MD5)
		// thumb (inputFileEmpty)
		buf.WriteUInt32(0x1e287d04)
		// mime_type
		buf.WriteString(guessMIME(inputFile.Name))
		// attributes (empty)
		buf.WriteUInt32(0x1cb5c415)
		buf.WriteInt32(0)
		// stickers (empty)
		buf.WriteUInt32(0x1cb5c415)
		buf.WriteInt32(0)
		buf.WriteInt32(0) // ttl_seconds
	}

	buf.WriteString(caption)     // message (caption)
	buf.WriteInt64(rand.Int63()) // random_id
	// reply_markup = replyKeyboardHide (absent, flags bit not set)
	// entities (absent)
	// schedule_date (absent)

	resp, err := c.Call(buf.Bytes())
	if err != nil {
		return 0, err
	}
	rb := types.NewTLBufferFrom(resp)
	rb.ReadUInt32() // updates
	rb.ReadUInt32() // vector
	count, _ := rb.ReadInt32()
	if count == 0 {
		return 0, nil
	}
	rb.ReadUInt32()
	msgID, _ := rb.ReadInt32()
	return msgID, nil
}

// ─── Username resolver ───────────────────────────────────────────────────────

type resolvedPeer struct {
	UserID     int64
	AccessHash int64
}

func (c *Client) resolveUsername(username string) (*resolvedPeer, error) {
	username = strings.TrimPrefix(username, "@")
	buf := types.NewTLBuffer()
	buf.WriteUInt32(0xf5b399ac) // contacts.resolveUsername
	buf.WriteString(username)

	resp, err := c.Call(buf.Bytes())
	if err != nil {
		return nil, err
	}
	rb := types.NewTLBufferFrom(resp)
	cid, _ := rb.ReadUInt32()
	if cid != 0x7f077ad9 { // contacts.resolvedPeer
		return nil, fmt.Errorf("resolveUsername: unexpected %08x", cid)
	}
	// peer (peerUser)
	rb.ReadUInt32() // constructor
	userID, _ := rb.ReadInt64()
	// chats vector
	rb.ReadUInt32()
	chatCount, _ := rb.ReadInt32()
	for i := 0; i < int(chatCount); i++ {
		rb.ReadBytes() // skip
	}
	// users vector
	rb.ReadUInt32()
	rb.ReadInt32()  // user count
	rb.ReadUInt32() // user constructor
	rb.ReadInt32()  // flags
	rb.ReadInt64()  // id
	accessHash, _ := rb.ReadInt64()
	return &resolvedPeer{UserID: userID, AccessHash: accessHash}, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func guessMIME(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	m := map[string]string{
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".gif":  "image/gif",
		".webp": "image/webp",
		".mp4":  "video/mp4",
		".mov":  "video/quicktime",
		".mp3":  "audio/mpeg",
		".ogg":  "audio/ogg",
		".pdf":  "application/pdf",
		".zip":  "application/zip",
	}
	if mime, ok := m[ext]; ok {
		return mime
	}
	return "application/octet-stream"
}

// Keepalive sends a periodic ping to keep the connection alive.
// Call it in a goroutine: go c.Keepalive().
func (c *Client) Keepalive() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if c.closed != 0 {
			return
		}
		buf := types.NewTLBuffer()
		buf.WriteUInt32(0x7abe77ec) // ping
		buf.WriteInt64(rand.Int63())
		_, _ = c.Call(buf.Bytes())
	}
}
