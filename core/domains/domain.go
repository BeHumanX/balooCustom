package domains

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/kor44/gofilter"
)

var (
	Domains     = []string{}              // Slice of domain names, primarily for quick iteration or initial setup
	DomainsMap  sync.Map                  // Concurrent map for storing DomainSettings by domain name (runtime cache)
	DomainsData = map[string]DomainData{} // Map for storing runtime domain data (statistics, stage, etc.)
	Config      *Configuration            // Global configuration loaded from MongoDB
)

// Configuration represents the overall structure of the proxy's settings,
// intended to be stored as a single document in MongoDB.
type Configuration struct {
	ID      string   `bson:"_id,omitempty"` // MongoDB document ID; omitempty allows MongoDB to generate if not set
	Proxy   Proxy    `bson:"proxy"`
	Domains []Domain `bson:"domains"`
}

// Domain represents settings for a single domain, as stored in MongoDB.
type Domain struct {
	Name                string          `bson:"name"`
	Backend             string          `bson:"backend"`
	Scheme              string          `bson:"scheme"`
	Certificate         string          `bson:"certificate,omitempty"` // omitempty if it can be empty (e.g., when Cloudflare is used)
	Key                 string          `bson:"key,omitempty"`         // omitempty if it can be empty
	Webhook             WebhookSettings `bson:"webhook"`
	FirewallRules       []JsonRule      `bson:"firewallRules"`
	BypassStage1        int             `bson:"bypassStage1"`
	BypassStage2        int             `bson:"bypassStage2"`
	Stage2Difficulty    int             `bson:"stage2Difficulty"`
	DisableBypassStage3 int             `bson:"disableBypassStage3"`
	DisableRawStage3    int             `bson:"disableRawStage3"`
	DisableBypassStage2 int             `bson:"disableBypassStage2"`
	DisableRawStage2    int             `bson:"disableRawStage2"`
}

// DomainSettings holds the runtime configuration for a domain, built from Domain.
// This struct is not directly marshaled/unmarshaled to/from MongoDB.
type DomainSettings struct {
	Name string

	CustomRules    []Rule     // Parsed gofilter rules
	RawCustomRules []JsonRule // Original JSON rules (for persistence/display)

	DomainProxy        *httputil.ReverseProxy
	DomainCertificates tls.Certificate
	DomainWebhooks     WebhookSettings // Webhook settings for this specific domain

	BypassStage1        int
	BypassStage2        int
	DisableBypassStage3 int
	DisableRawStage3    int
	DisableBypassStage2 int
	DisableRawStage2    int
}

// DomainLog captures details of a single request log for a domain.
// Not directly stored in the main config document, likely in a separate log collection.
type DomainLog struct {
	Time      string `bson:"time"`
	IP        string `bson:"ip"`
	BrowserFP string `bson:"browserFP"`
	BotFP     string `bson:"botFP"`
	TLSFP     string `bson:"tlsFP"`
	Useragent string `bson:"useragent"`
	Path      string `bson:"path"`
}

// DomainData holds real-time operational data and statistics for a domain.
// This is runtime data and not meant to be directly stored in the main config document.
// It's likely managed in memory and potentially persisted to a separate metrics/logs collection.
type DomainData struct {
	Name             string `bson:"name"` // Though this might be the _id for a metrics document
	Stage            int    `bson:"stage"`
	StageManuallySet bool   `bson:"stageManuallySet"`
	Stage2Difficulty int    `bson:"stage2Difficulty"`
	RawAttack        bool   `bson:"rawAttack"`
	BypassAttack     bool   `bson:"bypassAttack"`
	BufferCooldown   int    `bson:"bufferCooldown"`

	LastLogs []DomainLog `bson:"lastLogs,omitempty"` // Use omitempty if logs are not always present

	TotalRequests    int `bson:"totalRequests"`
	BypassedRequests int `bson:"bypassedRequests"`

	PrevRequests int `bson:"prevRequests"`
	PrevBypassed int `bson:"prevBypassed"`

	RequestsPerSecond             int          `bson:"requestsPerSecond"`
	RequestsBypassedPerSecond     int          `bson:"requestsBypassedPerSecond"`
	PeakRequestsPerSecond         int          `bson:"peakRequestsPerSecond"`
	PeakRequestsBypassedPerSecond int          `bson:"peakRequestsBypassedPerSecond"`
	RequestLogger                 []RequestLog `bson:"requestLogger,omitempty"` // Use omitempty
}

// Proxy holds the global proxy-wide settings.
type Proxy struct {
	Cloudflare      bool              `bson:"cloudflare"`
	AdminSecret     string            `bson:"adminSecret"`
	APISecret       string            `bson:"apiSecret"`
	Secrets         map[string]string `bson:"secrets"` // Map of secret names to their values
	Timeout         TimeoutSettings   `bson:"timeout"`
	RatelimitWindow int               `bson:"ratelimitWindow"`
	Ratelimits      map[string]int    `bson:"ratelimits"` // Map of ratelimit types to their values
	Colors          []string          `bson:"colors"`     // Array of color strings
}

// TimeoutSettings defines various timeout durations for the HTTP server.
type TimeoutSettings struct {
	Idle       int `bson:"idle"`
	Read       int `bson:"read"`
	Write      int `bson:"write"`
	ReadHeader int `bson:"readHeader"`
}

// WebhookSettings defines parameters for webhook notifications.
type WebhookSettings struct {
	URL            string `bson:"url"`
	Name           string `bson:"name"`
	Avatar         string `bson:"avatar"`
	AttackStartMsg string `bson:"attackStartMsg"`
	AttackStopMsg  string `bson:"attackStopMsg"`
}

// JsonRule represents a firewall rule as it's typically defined in JSON (and stored in MongoDB).
// This is the raw, unparsed form.
type JsonRule struct {
	Expression string `bson:"expression"`
	Action     string `bson:"action"`
}

// Rule holds a compiled gofilter.Filter and its associated action.
// This is a runtime representation and not directly stored in MongoDB.
type Rule struct {
	Filter *gofilter.Filter // Compiled filter for efficient rule matching
	Action string
}

// RequestLog captures per-second request statistics.
// This is runtime data and not meant to be directly stored in the main config document.
// It's likely managed in memory and potentially persisted to a separate metrics/logs collection.
type RequestLog struct {
	Time     time.Time `bson:"time"`
	Allowed  int       `bson:"allowed"`
	Total    int       `bson:"total"`
	CpuUsage string    `bson:"cpuUsage"` // Representing CPU usage as a string (e.g., "1.5%")
}

// CacheResponse is for caching HTTP responses.
// This is also runtime data and not part of the persistent configuration.
type CacheResponse struct {
	Domain    string      `bson:"domain"`
	Timestamp int         `bson:"timestamp"` // Unix timestamp
	Status    int         `bson:"status"`
	Headers   http.Header `bson:"headers"` // http.Header is a map[string][]string, can be BSON marshaled
	Body      []byte      `bson:"body"`
}
