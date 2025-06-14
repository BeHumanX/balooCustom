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

		service.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			firewall.Mutex.RLock()
			domainData, domainFound := domains.DomainsData[r.Host]
			firewall.Mutex.RUnlock()

			if !domainFound {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "balooProxy: "+r.Host+" does not exist. If you are the owner please check your config.json if you believe this is a mistake")
				return
			}

			firewall.Mutex.Lock()
			domainData = domains.DomainsData[r.Host]
			domainData.TotalRequests++
			domains.DomainsData[r.Host] = domainData
			firewall.Mutex.Unlock()

			w.Header().Set("Content-Type", "text/html")
			redirectURL := "https://" + r.Host + r.URL.Path
			if r.URL.RawQuery != "" {
				redirectURL += "?" + r.URL.RawQuery
			}
			fmt.Fprintf(w, `
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>L-firewall TXT Anti-DDoS</title>
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body class="bg-white text-gray-800 flex items-center justify-center h-screen">
    <div class="text-center max-w-md mx-auto p-6 rounded-2xl shadow-lg border border-gray-200">
      <h1 class="text-2xl font-semibold mb-2">Checking your browser before accessing</h1>
      <p class="text-sm mb-4">This process is automatic. Your browser will redirect once the check is complete.</p>
      <div class="text-left text-sm bg-gray-100 rounded-lg p-4 border border-gray-200 mb-6">
        <p>
          <strong>Challenge:</strong>
        </p>
        <code id="challenge" class="break-words text-gray-600">Initializing challenge...</code>
        <p class="mt-2 text-xs text-gray-500" id="challengeStatus">Solving SHA-256 PoW challenge...</p>
      </div>
      <div class="w-full bg-gray-200 rounded-full h-3 mb-4">
        <div id="progressBar" class="bg-blue-500 h-3 rounded-full transition-all duration-75 ease-in-out" style="width:0%%"></div>
      </div>
      <p class="text-xs text-gray-500" id="statusText">Initializing...</p>
    </div>
    <script>
      function randomStr(length) {
        const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
          result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
      }
      const challengeEl = document.getElementById("challenge");
      const progressEl = document.getElementById("progressBar");
      const statusEl = document.getElementById("statusText");
      const initialChallengePrefix = "your_secret_server_prefix_";
      const targetURL = "%s";
      let step = 0;
      const totalSteps = 30;
      const interval = setInterval(() => {
        const fakeToken = randomStr(11);
        const dummyHash = "c0ffee00deadbeefc0ffee00deadbeefc0ffee00deadbeefc0ffee00deadbeef";
        challengeEl.textContent = 'sha256("' + initialChallengePrefix + '" + "' + fakeToken + '") = ' + dummyHash.substring(0, 16) + '...';
        const percent = Math.floor((step / totalSteps) * 100);
        progressEl.style.width = percent + "%%";
        statusEl.textContent = "Solving challenge... " + percent + "%%";
        step++;
        if (step > totalSteps) { 
		clearInterval(interval);
          progressEl.style.width = "100%%";
          statusEl.textContent = "Challenge passed! Redirecting...";
          setTimeout(() => {
            window.location.href = targetURL;
          }, 500);
        }
      }, 30);
    </script>
  </body>
</html>
`, redirectURL)
		})

		service.SetKeepAlivesEnabled(true)
		serviceH.Handler = http.HandlerFunc(Middleware)

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
