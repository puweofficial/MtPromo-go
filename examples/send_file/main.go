// send_file demonstrates how to authenticate a user account and send a file
// (document or photo) to another user or bot via MTProto.
//
// Usage:
//
//	go run ./examples/send_file \
//	    -app-id=123456 \
//	    -app-hash=abcdef1234567890abcdef1234567890 \
//	    -phone=+380501234567 \
//	    -to=@someuser \
//	    -file=/path/to/file.pdf \
//	    -caption="Here is your document"
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/puweofficial/MtPromo-go/client"
)

func main() {
	appID := flag.Int("app-id", 0, "Telegram App ID (from my.telegram.org)")
	appHash := flag.String("app-hash", "", "Telegram App Hash")
	phone := flag.String("phone", "", "Your phone number with country code (+380...)")
	to := flag.String("to", "", "Recipient username (e.g. @username)")
	file := flag.String("file", "", "Path to file to send")
	caption := flag.String("caption", "", "Caption for the file")
	fileType := flag.String("type", "document", "File type: document | photo")
	session := flag.String("session", "session.json", "Path to session file")
	flag.Parse()

	if *appID == 0 || *appHash == "" || *phone == "" {
		fmt.Fprintln(os.Stderr, "Error: -app-id, -app-hash, and -phone are required")
		flag.Usage()
		os.Exit(1)
	}
	if *to == "" || *file == "" {
		fmt.Fprintln(os.Stderr, "Error: -to and -file are required")
		flag.Usage()
		os.Exit(1)
	}

	cfg := client.Config{
		AppID:       *appID,
		AppHash:     *appHash,
		Phone:       *phone,
		SessionFile: *session,
		DCID:        2,
	}

	log.Println("Connecting to Telegram (DC2)…")
	c, err := client.New(cfg)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer c.Close()

	// If not yet signed in, run the interactive phone auth flow
	me, err := c.GetMe()
	if err != nil {
		log.Println("Not signed in, starting auth flow…")
		if err := c.PhoneAuthFlow(); err != nil {
			log.Fatalf("auth: %v", err)
		}
		me, err = c.GetMe()
		if err != nil {
			log.Fatalf("getMe after auth: %v", err)
		}
	}

	log.Printf("Signed in as %s %s (id=%d, bot=%v)",
		me.FirstName, me.LastName, me.ID, me.IsBot)

	// Keep connection alive in the background
	go c.Keepalive()

	log.Printf("Uploading %s to %s…", *file, *to)
	msgID, err := c.SendFile(*to, *file, *caption, *fileType)
	if err != nil {
		log.Fatalf("SendFile: %v", err)
	}
	log.Printf("File sent! message_id=%d", msgID)
}
