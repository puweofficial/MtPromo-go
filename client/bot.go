package client

import (
	"fmt"
	"time"

	"github.com/puweofficial/mtproto-go/types"
)

// Message holds a parsed incoming Telegram message.
type Message struct {
	ID           int32
	Text         string
	FromID       int64
	FromUsername string
	ChatID       int64
}

// Update wraps a Telegram update object.
type Update struct {
	ID      int32
	Message *Message
}

// BotSignIn authenticates a bot using its token via auth.importBotAuthorization.
func (c *Client) BotSignIn(token string) error {
	buf := types.NewTLBuffer()
	buf.WriteUInt32(0x67a3ff2c) // auth.importBotAuthorization
	buf.WriteInt32(0)            // flags
	buf.WriteInt32(int32(c.cfg.AppID))
	buf.WriteString(c.cfg.AppHash)
	buf.WriteString(token)

	resp, err := c.Call(buf.Bytes())
	if err != nil {
		return fmt.Errorf("BotSignIn: %w", err)
	}

	rb := types.NewTLBufferFrom(resp)
	cid, _ := rb.ReadUInt32()
	if cid != 0xcd050916 { // auth.authorization
		return fmt.Errorf("BotSignIn: unexpected constructor %08x", cid)
	}
	_ = c.saveSession()
	return nil
}

// ─── Polling ─────────────────────────────────────────────────────────────────

var lastUpdateID int32

// GetUpdates uses updates.getState + updates.getDifference to receive new
// messages.  For simplicity this is a blocking call; wrap in a loop.
func (c *Client) GetUpdates() ([]*Update, error) {
	// 1. Get current state
	state, err := c.getUpdatesState()
	if err != nil {
		return nil, err
	}

	time.Sleep(500 * time.Millisecond) // rate-limit friendly

	// 2. Get difference since last known pts/date/qts
	return c.getUpdatesDifference(state)
}

type updatesState struct {
	pts  int32
	qts  int32
	date int32
	seq  int32
}

func (c *Client) getUpdatesState() (*updatesState, error) {
	buf := types.NewTLBuffer()
	buf.WriteUInt32(0xedd4882a) // updates.getState

	resp, err := c.Call(buf.Bytes())
	if err != nil {
		return nil, err
	}
	rb := types.NewTLBufferFrom(resp)
	cid, _ := rb.ReadUInt32()
	if cid != 0xa56c2a3e { // updates.state
		return nil, fmt.Errorf("getUpdatesState: unexpected %08x", cid)
	}
	pts, _ := rb.ReadInt32()
	qts, _ := rb.ReadInt32()
	date, _ := rb.ReadInt32()
	seq, _ := rb.ReadInt32()
	return &updatesState{pts: pts, qts: qts, date: date, seq: seq}, nil
}

func (c *Client) getUpdatesDifference(s *updatesState) ([]*Update, error) {
	buf := types.NewTLBuffer()
	buf.WriteUInt32(0x25939651) // updates.getDifference
	buf.WriteInt32(s.pts)
	buf.WriteInt32(0)      // pts_limit (absent, flags)
	buf.WriteInt32(s.date)
	buf.WriteInt32(s.qts)

	resp, err := c.Call(buf.Bytes())
	if err != nil {
		return nil, err
	}

	rb := types.NewTLBufferFrom(resp)
	cid, _ := rb.ReadUInt32()

	// updates.differenceEmpty — nothing new
	if cid == 0x5d75a138 {
		return nil, nil
	}
	// updates.difference or updates.differenceSlice
	if cid != 0x00f49ca0 && cid != 0xa8fb1981 {
		return nil, fmt.Errorf("getDifference: unexpected %08x", cid)
	}

	var updates []*Update

	// new_messages (vector of Message)
	rb.ReadUInt32() // vector
	msgCount, _ := rb.ReadInt32()
	for i := 0; i < int(msgCount); i++ {
		msg := parseMessage(rb)
		if msg != nil {
			updates = append(updates, &Update{Message: msg})
		}
	}
	return updates, nil
}

func parseMessage(rb *types.TLBuffer) *Message {
	cid, err := rb.ReadUInt32()
	if err != nil {
		return nil
	}
	// message#38116ee0 or message#1c9b1027
	if cid != 0x38116ee0 && cid != 0x1c9b1027 {
		return nil
	}
	flags, _ := rb.ReadInt32()
	id, _ := rb.ReadInt32()
	// from_id (optional)
	var fromID int64
	if flags&0x100 != 0 {
		rb.ReadUInt32() // peerUser constructor
		fromID, _ = rb.ReadInt64()
	}
	rb.ReadUInt32() // peer_id
	rb.ReadInt64()  // peer value
	// reply_to (optional)
	if flags&0x8 != 0 {
		rb.ReadUInt32() // messageReplyHeader
		rb.ReadInt32()
	}
	rb.ReadInt32() // date
	text, _ := rb.ReadString()
	return &Message{
		ID:     id,
		Text:   text,
		FromID: fromID,
	}
}
