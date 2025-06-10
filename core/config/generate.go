package config

import (
	"encoding/json"
	"fmt"
	"goProxy/core/domains"
	"goProxy/core/utils"
	"io/ioutil"
	"net/http"
)

func Generate() {
	// Create a default configuration (similar to what you'd have in a default config.json)
	defaultConfig := domains.Configuration{
		Proxy: domains.Proxy{
			Secrets: map[string]string{
				"cookie":     "CHANGE_ME_COOKIE_SECRET",
				"javascript": "CHANGE_ME_JS_SECRET",
				"captcha":    "CHANGE_ME_CAPTCHA_SECRET",
			},
			AdminSecret: "CHANGE_ME_ADMIN_SECRET",
			APISecret:   "CHANGE_ME_API_SECRET",
			Timeout: domains.TimeoutSettings{
				Idle:       120,
				Read:       10,
				ReadHeader: 5,
				Write:      10,
			},
			RatelimitWindow: 10,
			Ratelimits: map[string]int{
				"requests":           1000,
				"unknownFingerprint": 50,
				"challengeFailures":  5,
				"noRequestsSent":     10,
			},
		},
		Domains: []domains.Domain{}, // No domains initially, AddDomain will handle this
	}

	// Set the global config variable
	domains.Config = &defaultConfig

	// Save the default config to MongoDB
	err := Save(*domains.Config)
	if err != nil {
		panic(fmt.Errorf("failed to save generated config to MongoDB: %v", err))
	}
	fmt.Println("[ " + utils.PrimaryColor("+") + " ] [ Default configuration generated and saved to MongoDB. Please update secrets! ]")
}

func AddDomain() {
	fmt.Println("[ " + utils.PrimaryColor("!") + " ] [ No domains configured. Please add a domain. ]")
	// Example of adding a default domain. In a real application, you'd likely
	// prompt the user for input or have a more sophisticated domain addition process.
	exampleDomain := domains.Domain{
		Name:        "example.com",
		Scheme:      "http",
		Backend:     "localhost:8080",
		Certificate: "", // Leave empty if Cloudflare is used or if you don't have one yet
		Key:         "", // Leave empty if Cloudflare is used or if you don't have one yet
		Webhook: domains.WebhookSettings{
			URL:            "",
			Name:           "goProxy",
			Avatar:         "",
			AttackStartMsg: "Attack started on example.com!",
			AttackStopMsg:  "Attack stopped on example.com!",
		},
		Stage2Difficulty: 5,
	}

	domains.Config.Domains = append(domains.Config.Domains, exampleDomain)
	domains.Domains = append(domains.Domains, exampleDomain.Name) // Update the global domains slice

	err := Save(*domains.Config)
	if err != nil {
		panic(fmt.Errorf("failed to save domain after adding: %v", err))
	}
	fmt.Println("[ " + utils.PrimaryColor("+") + " ] [ Added default domain 'example.com'. ]")
}

func GetFingerprints(url string, target interface{}) {
	resp, err := http.Get(url)
	if err != nil {
		panic(fmt.Errorf("failed to fetch fingerprints from %s: %v", url, err))
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Errorf("failed to read fingerprint response body from %s: %v", url, err))
	}

	err = json.Unmarshal(body, target)
	if err != nil {
		panic(fmt.Errorf("failed to unmarshal fingerprints from %s: %v", url, err))
	}
	fmt.Printf("[ %s ] [ Loaded fingerprints from %s ]\n", utils.PrimaryColor("+"), url)
}
