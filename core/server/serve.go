package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"goProxy/core/domains"
	"goProxy/core/firewall"
	"goProxy/core/pnc"
	"goProxy/core/proxy"
	"html/template"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

var (
	transportMap = sync.Map{}
	bufferPool   = sync.Pool{
		New: func() interface{} {
			return &bytes.Buffer{}
		},
	}
)

func Serve() {

	defer pnc.PanicHndl()
	mux := http.NewServeMux()
	mux.HandleFunc("/gh/41Baloo/balooPow@main/balooPow.min.js", func(w http.ResponseWriter, r *http.Request) {
		targetURL := "https://cdn.jsdelivr.net" + r.URL.Path
		// Consider using a dedicated http.Client for these static fetches
		resp, err := http.Get(targetURL)
		if err != nil {
			http.Error(w, "Failed to fetch BalooPow JS from CDN: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})
	mux.HandleFunc("/ajax/libs/crypto-js/4.0.0/crypto-js.min.js", func(w http.ResponseWriter, r *http.Request) {
		targetURL := "https://cdnjs.cloudflare.com" + r.URL.Path
		// Consider using a dedicated http.Client for these static fetches
		resp, err := http.Get(targetURL)
		if err != nil {
			http.Error(w, "Failed to fetch Crypto-JS from CDN: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})
	if domains.Config.Proxy.Cloudflare {

		service := &http.Server{
			IdleTimeout:       proxy.IdleTimeoutDuration,
			ReadTimeout:       proxy.ReadTimeoutDuration,
			WriteTimeout:      proxy.WriteTimeoutDuration,
			ReadHeaderTimeout: proxy.ReadHeaderTimeoutDuration,
			Addr:              ":80",
			MaxHeaderBytes:    1 << 20,
		}

		http2.ConfigureServer(service, &http2.Server{})
		service.SetKeepAlivesEnabled(true)
		service.Handler = http.HandlerFunc(Middleware)

		if err := service.ListenAndServe(); err != nil {
			panic(err)
		}
	} else {

		service := &http.Server{
			IdleTimeout:       proxy.IdleTimeoutDuration,
			ReadTimeout:       proxy.ReadTimeoutDuration,
			WriteTimeout:      proxy.WriteTimeoutDuration,
			ReadHeaderTimeout: proxy.ReadHeaderTimeoutDuration,
			ConnState:         firewall.OnStateChange,
			Addr:              ":80",
			MaxHeaderBytes:    1 << 20,
		}
		serviceH := &http.Server{
			IdleTimeout:       proxy.IdleTimeoutDuration,
			ReadTimeout:       proxy.ReadTimeoutDuration,
			WriteTimeout:      proxy.WriteTimeoutDuration,
			ReadHeaderTimeout: proxy.ReadHeaderTimeoutDuration,
			ConnState:         firewall.OnStateChange,
			Addr:              ":443",
			TLSConfig: &tls.Config{
				GetConfigForClient: firewall.Fingerprint,
				GetCertificate:     domains.GetCertificate,
				Renegotiation:      tls.RenegotiateOnceAsClient,
			},
			MaxHeaderBytes: 1 << 20,
		}

		http2.ConfigureServer(service, &http2.Server{})
		http2.ConfigureServer(serviceH, &http2.Server{})

		commonHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			firewall.Mutex.RLock()
			domainData, domainFound := domains.DomainsData[r.Host]
			firewall.Mutex.RUnlock()

			if !domainFound {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "balooProxy: "+r.Host+" does not exist. If you are the owner please check your config.json if you believe this is a mistake")
				return
			}

			firewall.Mutex.Lock()                    // Lock to update domain data
			domainData = domains.DomainsData[r.Host] // Get the existing domain data
			domainData.TotalRequests++               // Increment the request count
			domains.DomainsData[r.Host] = domainData // Update the domain data in the map
			firewall.Mutex.Unlock()                  // Unlock after updating

			// Determine if it's an HTTPS request
			isHTTPS := r.TLS != nil ||
				strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")

			// Check for the "baloo_splash_seen" cookie to determine if splash should be skipped
			_, err := r.Cookie("baloo_splash_seen")
			splashSeen := err == nil // If cookie exists, splash has been seen

			// Determine if the request is for an HTML document
			// Heuristic: Check Accept header for "text/html" and if URL path does not strongly suggest an asset.
			isHTMLRequest := strings.Contains(r.Header.Get("Accept"), "text/html")

			// Refine by checking common asset extensions (regardless of Accept header for robustness)
			assetExtensions := []string{
				".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
				".webp", ".json", ".xml", ".txt", ".pdf", ".mp4", ".mp3", ".woff", ".woff2", ".ttf",
			}
			for _, ext := range assetExtensions {
				if strings.HasSuffix(r.URL.Path, ext) {
					isHTMLRequest = false // If it's an asset, it's not an HTML request for splash purposes
					break
				}
			}

			if isHTMLRequest {
				// Only apply splash logic if it's likely an HTML document request
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
				w.Header().Set("Pragma", "no-cache")

				if isHTTPS {
					if splashSeen {
						// If it's HTTPS and the splash has been seen, proceed to Middleware
						Middleware(w, r)
					} else {
						// HTTPS splash page: Shows a loading screen, then reloads the original URL
						// And sets a cookie so the splash is skipped next time.
						// Set the cookie for the session
						http.SetCookie(w, &http.Cookie{
							Name:     "baloo_splash_seen",
							Value:    "true",
							Path:     "/",                            // Available for all paths
							Expires:  time.Now().Add(24 * time.Hour), // Or use MaxAge for session-long
							HttpOnly: true,                           // Not accessible via client-side scripts
							Secure:   true,                           // Only sent over HTTPS
							SameSite: http.SameSiteLaxMode,           // Recommended for security
						})

						// The target URL is the original URL including scheme, host, path, and query parameters
						fullTargetURL := "https://" + r.Host + r.URL.RequestURI()

						// Pass the full URL to JavaScript for redirection
						httpsRedirPage := `<!DOCTYPE html><html lang="en"><head> <meta charset="UTF-8"> <title>LimitlessTXT Anti-DDoS</title> <script src="https://cdn.tailwindcss.com"></script></head><body class="bg-white text-gray-800 flex items-center justify-center h-screen"> <div class="text-center max-w-md mx-auto p-6 rounded-2xl shadow-lg border border-gray-200"> <h1 class="text-2xl font-semibold mb-2">Checking your browser before accessing</h1> <p class="text-sm mb-4">This process is automatic. Your browser will redirect once the check is complete.</p> <div class="text-left text-sm bg-gray-100 rounded-lg p-4 border border-gray-200 mb-6"> <p><strong>Challenge:</strong></p> <code id="challenge" class="break-words text-gray-600">Initializing challenge...</code> <p class="mt-2 text-xs text-gray-500" id="challengeStatus">Solving SHA-256 PoW challenge...</p> </div> <div class="w-full bg-gray-200 rounded-full h-3 mb-4"> <div id="progressBar" class="bg-blue-500 h-3 rounded-full transition-all duration-75 ease-in-out" style="width:0%"></div> </div> <p class="text-xs text-gray-500" id="statusText">Initializing...</p> </div> <script> async function sha256(message) { const msgBuffer = new TextEncoder().encode(message); const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer); const hashArray = Array.from(new Uint8Array(hashBuffer)); const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); return hashHex; } const challengeEl = document.getElementById("challenge"); const progressEl = document.getElementById("progressBar"); const statusEl = document.getElementById("statusText"); const initialChallengePrefix = "your_secret_server_prefix_"; const targetURL = "` + template.JSEscapeString(fullTargetURL) + `"; function randomStr(length) { const chars = 'abcdefghijklmnopqrstuvwxyz0123456789'; let result = ''; for (let i = 0; i < length; i++) { result += chars.charAt(Math.floor(Math.random() * chars.length)); } return result; } let step = 0; const totalSteps = 30; const interval = setInterval(async () => { const fakeToken = randomStr(11); const dummyHash = "c0ffee00deadbeefc0ffee00deadbeefc0ffee00deadbeefc0ffee00deadbeef"; challengeEl.textContent = 'sha256("' + initialChallengePrefix + '" + "' + fakeToken + '") = ' + dummyHash.substring(0, 16) + '...'; const percent = Math.floor((step / totalSteps) * 100); progressEl.style.width = percent + "%"; statusEl.textContent = "Solving challenge... " + percent + "%"; step++; if (step > totalSteps) { clearInterval(interval); progressEl.style.width = "100%"; statusEl.textContent = "Challenge passed! Redirecting..."; setTimeout(() => { window.location.href = targetURL; }, 500); } }, 30); </script></body></html>`
						fmt.Fprint(w, httpsRedirPage)
					}
				} else {
					// HTTP splash page: Redirects to HTTPS
					httpRedirPage := `<!DOCTYPE html><html><head><title>Redirecting to HTTPS</title><script>setTimeout(function(){window.location.href="https://` + r.Host + r.URL.Path + r.URL.RawQuery + `"},1e3)</script></head><body><h1>Redirecting to HTTPS</h1><p>Please wait while we securely redirect you...</p></body></html>`
					fmt.Fprint(w, httpRedirPage)
				}
			} else {
				// If it's not an HTML request (e.g., for JS, CSS, images), always proxy directly
				Middleware(w, r)
			}
		})
		service.Handler = commonHandler
		service.SetKeepAlivesEnabled(true)
		serviceH.Handler = commonHandler

		go func() {
			defer pnc.PanicHndl()
			if err := serviceH.ListenAndServeTLS("", ""); err != nil {
				panic(err)
			}
		}()

		if err := service.ListenAndServe(); err != nil {
			panic(err)
		}
	}
}

func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {

	buffer := bufferPool.Get().(*bytes.Buffer)
	buffer.Reset()
	defer bufferPool.Put(buffer)

	//Use Proxy Read Timeout
	transport := getTripperForDomain(req.Host)

	//Use inbuild RoundTrip
	resp, err := transport.RoundTrip(req)

	//Connection to backend failed. Display error message
	if err != nil {
		errStrs := strings.Split(err.Error(), " ")
		errMsg := ""
		for _, str := range errStrs {
			if !strings.Contains(str, ".") && !strings.Contains(str, "/") && !(strings.Contains(str, "[") && strings.Contains(str, "]")) {
				errMsg += str + " "
			}
		}

		buffer.WriteString(`<!DOCTYPE html><html><head><title>Error: `)
		buffer.WriteString(errMsg) // Page Title
		buffer.WriteString(`</title><style>body{font-family:'Helvetica Neue',sans-serif;color:#333;margin:0;padding:0}.container{display:flex;align-items:center;justify-content:center;height:100vh;background:#fafafa}.error-box{width:600px;padding:20px;background:#fff;border-radius:5px;box-shadow:0 2px 4px rgba(0,0,0,.1)}.error-box h1{font-size:36px;margin-bottom:20px}.error-box p{font-size:16px;line-height:1.5;margin-bottom:20px}.error-box p.description{font-style:italic;color:#666}.error-box a{display:inline-block;padding:10px 20px;background:#00b8d4;color:#fff;border-radius:5px;text-decoration:none;font-size:16px}</style><div class=container><div class=error-box><h1>Error: `)
		buffer.WriteString(errMsg) // Page Body
		buffer.WriteString(`</h1><p>Sorry, there was an error connecting to the backend. That's all we know.</p><a onclick="location.reload()">Reload page</a></div></div></body></html>`)

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(buffer.Bytes())),
		}, nil
	}

	//Connection was successfull, got bad response tho
	if resp.StatusCode > 499 && resp.StatusCode < 600 {

		limitReader := io.LimitReader(resp.Body, 1024*1024) // 1 MB for instance
		errBody, errErr := io.ReadAll(limitReader)

		// Close the original body
		resp.Body.Close()

		errMsg := ""
		if errErr == nil && len(errBody) > 0 {
			errMsg = string(errBody)
			if int64(len(errBody)) == 1024*1024 {
				errMsg += `<p>( Error message truncated. )</p>`
			}
		}

		if errErr == nil && len(errBody) != 0 {

			buffer.WriteString(`<!DOCTYPE html><html><head><title>Error: `)
			buffer.WriteString(resp.Status)
			buffer.WriteString(`</title><style>body{font-family:'Helvetica Neue',sans-serif;color:#333;margin:0;padding:0}.container{display:flex;align-items:center;justify-content:center;height:100vh;background:#fafafa}.error-box{width:600px;padding:20px;background:#fff;border-radius:5px;box-shadow:0 2px 4px rgba(0,0,0,.1)}.error-box h1{font-size:36px;margin-bottom:20px}.error-box p{font-size:16px;line-height:1.5;margin-bottom:20px}.error-box p.description{font-style:italic;color:#666}.error-box a{display:inline-block;padding:10px 20px;background:#00b8d4;color:#fff;border-radius:5px;text-decoration:none;font-size:16px}</style><div class=container><div class=error-box><h1>Error:`)
			buffer.WriteString(`</h1><p>Sorry, the backend returned this error.</p><iframe width="100%" height="25%" style="border:1px ridge lightgrey; border-radius: 5px;"srcdoc="`)
			buffer.WriteString(errMsg)
			buffer.WriteString(`"></iframe><a onclick="location.reload()">Reload page</a></div></div></body></html>`)

		} else {

			buffer.WriteString(`<!DOCTYPE html><html><head><title>Error: `)
			buffer.WriteString(resp.Status)
			buffer.WriteString(`</title><style>body{font-family:'Helvetica Neue',sans-serif;color:#333;margin:0;padding:0}.container{display:flex;align-items:center;justify-content:center;height:100vh;background:#fafafa}.error-box{width:600px;padding:20px;background:#fff;border-radius:5px;box-shadow:0 2px 4px rgba(0,0,0,.1)}.error-box h1{font-size:36px;margin-bottom:20px}.error-box p{font-size:16px;line-height:1.5;margin-bottom:20px}.error-box p.description{font-style:italic;color:#666}.error-box a{display:inline-block;padding:10px 20px;background:#00b8d4;color:#fff;border-radius:5px;text-decoration:none;font-size:16px}</style><div class=container><div class=error-box><h1>`)
			buffer.WriteString(resp.Status)
			buffer.WriteString(`</h1><p>Sorry, the backend returned an error. That's all we know.</p><a onclick="location.reload()">Reload page</a></div></div></body></html>`)
		}

		resp.Body.Close()

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(buffer.Bytes())),
		}, nil
	}

	return resp, nil
}

var defaultTransport = &http.Transport{
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext(ctx, network, addr)
	},
	TLSHandshakeTimeout: 10 * time.Second,
	TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	IdleConnTimeout:     90 * time.Second,
	MaxIdleConns:        10,
	MaxConnsPerHost:     10,
}

func getTripperForDomain(domain string) *http.Transport {

	transport, ok := transportMap.Load(domain)
	if !ok {
		transport, _ = transportMap.LoadOrStore(domain, defaultTransport)
	}
	return transport.(*http.Transport)
}

type RoundTripper struct {
}
