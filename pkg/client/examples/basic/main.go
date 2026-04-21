// Basic end-to-end example of the whisper Go SDK: store a text secret, read
// it back, watch the second read fail, then do the same with a file.
//
// Run from the repo root:
//
//	go run ./pkg/client/examples/basic -url https://whisper.example.com
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/nckslvrmn/whisper/pkg/client"
)

func main() {
	url := flag.String("url", "http://localhost:8080", "whisper server base URL")
	flag.Parse()

	c := client.New(*url)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Store a text secret: 1 view, expires in 10 minutes.
	stored, err := c.StoreText(ctx, "the eagle has landed", &client.StoreOptions{
		ViewCount: client.Views(1),
		Expiry:    client.ExpireIn(10 * time.Minute),
	})
	if err != nil {
		log.Fatalf("store: %v", err)
	}

	fmt.Println("Stored secret:")
	fmt.Println("  URL:       ", stored.URL)
	fmt.Println("  Secret ID: ", stored.SecretID)
	fmt.Println("  Passphrase:", stored.DisplayPassphrase)

	// 2. Retrieve it back (this will consume the single view).
	got, err := c.Retrieve(ctx, stored.SecretID, stored.DisplayPassphrase)
	if err != nil {
		log.Fatalf("retrieve: %v", err)
	}
	fmt.Println("\nRetrieved text:", got.Text)

	// 3. A second retrieval should fail with 404 (view count exhausted).
	if _, err := c.Retrieve(ctx, stored.SecretID, stored.DisplayPassphrase); err != nil {
		fmt.Println("\nSecond retrieval (expected to fail):", err)
	} else {
		fmt.Println("\nSecond retrieval unexpectedly succeeded")
	}

	// 4. File round-trip.
	data := []byte("pretend this is a file\n")
	storedFile, err := c.StoreFile(ctx, "note.txt", "text/plain", data, &client.StoreOptions{
		ViewCount: client.Views(1),
		Expiry:    client.ExpireIn(10 * time.Minute),
	})
	if err != nil {
		log.Fatalf("store file: %v", err)
	}
	fmt.Println("\nStored file at:", storedFile.URL)

	gotFile, err := c.Retrieve(ctx, storedFile.SecretID, storedFile.DisplayPassphrase)
	if err != nil {
		log.Fatalf("retrieve file: %v", err)
	}
	fmt.Printf("Retrieved file: name=%q type=%q bytes=%d\n",
		gotFile.File.Name, gotFile.File.ContentType, len(gotFile.File.Data))
	fmt.Printf("Content: %s", gotFile.File.Data)
}
