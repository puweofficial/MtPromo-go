// bot demonstrates running a Telegram bot entirely via MTProto
// (no HTTP Bot API, no third-party bot library).
//
// Usage:
//
//	go run ./examples/bot \
//	    -app-id=123456 \
//	    -app-hash=abcdef \
//	    -token=1234567890:AAAA... \
//	    -session=bot_session.json
//
// The bot will respond to any message with an echo and can receive /file
// commands to send back a document.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/puweofficial/MtPromo-go/client"
)

// BotToken auth: call auth.importBotAuthorization using the token.
// This is handled transparently by BotSignIn below.

func main() {
	appID := flag.Int("app-id", 0, "App ID")
	appHash := flag.String("app-hash", "", "App Hash")
	token := flag.String("token", "", "Bot token from @BotFather")
	session := flag.String("session", "bot_session.json", "Session file")
	flag.Parse()

	if *appID == 0 || *appHash == "" || *token == "" {
		log.Fatal("app-id, app-hash, and token are required")
	}

	cfg := client.Config{
		AppID:       *appID,
		AppHash:     *appHash,
		SessionFile: *session,
		DCID:        2,
	}

	log.Println("Connecting…")
	c, err := client.New(cfg)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer c.Close()

	// Authenticate bot via token
	if err := c.BotSignIn(*token); err != nil {
		log.Fatalf("bot sign-in: %v", err)
	}
	me, _ := c.GetMe()
	log.Printf("Bot started: @%s (id=%d)", me.Username, me.ID)

	go c.Keepalive()

	log.Println("Polling for updates… (press Ctrl+C to stop)")
	// UpdatesGetDifference / getUpdates loop
	for {
		updates, err := c.GetUpdates()
		if err != nil {
			log.Printf("getUpdates error: %v", err)
			continue
		}
		for _, upd := range updates {
			handleUpdate(c, upd)
		}
	}
}

func handleUpdate(c *client.Client, upd *client.Update) {
	if upd.Message == nil {
		return
	}
	msg := upd.Message
	text := msg.Text
	senderUsername := msg.FromUsername

	log.Printf("Message from @%s: %s", senderUsername, text)

	switch {
	case strings.HasPrefix(text, "/start"):
		c.SendMessage(senderUsername, fmt.Sprintf("Hello! I'm a pure MTProto bot. Send /file to get a demo file."))

	case strings.HasPrefix(text, "/file"):
		// Send a demo text file
		err := sendDemoFile(c, senderUsername)
		if err != nil {
			log.Printf("sendDemoFile: %v", err)
		}

	default:
		// Echo
		c.SendMessage(senderUsername, "You said: "+text)
	}
}

func sendDemoFile(c *client.Client, username string) error {
	// Create a temporary text file
	tmpDir := os.TempDir()
	tmpFile := filepath.Join(tmpDir, "demo.txt")
	content := "This file was sent via pure MTProto — no Bot API, no extra libraries!\n"
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile)
	_, sendErr := c.SendFile(username, tmpFile, "Demo file via MTProto!", "document")
	return sendErr
}
