package badger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type Config struct {
	APIBaseUrl                  string   `json:"apiBaseUrl"`
	UserSessionCookieName       string   `json:"userSessionCookieName"`
	ResourceSessionRequestParam string   `json:"resourceSessionRequestParam"`
	TrustedProxies              []string `json:"trustedProxies,omitempty"`
	TrustForwardedHeaders       bool     `json:"trustForwardedHeaders,omitempty"`
}

type Badger struct {
	next                        http.Handler
	name                        string
	apiBaseUrl                  string
	userSessionCookieName       string
	resourceSessionRequestParam string
	trustedProxies              []string
	trustForwardedHeaders       bool
	trustedProxyNets            []*net.IPNet
}

type VerifyBody struct {
	Sessions           map[string]string `json:"sessions"`
	OriginalRequestURL string            `json:"originalRequestURL"`
	RequestScheme      *string           `json:"scheme"`
	RequestHost        *string           `json:"host"`
	RequestPath        *string           `json:"path"`
	RequestMethod      *string           `json:"method"`
	TLS                bool              `json:"tls"`
	RequestIP          *string           `json:"requestIp,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
	Query              map[string]string `json:"query,omitempty"`
}

type VerifyResponse struct {
	Data struct {
		Valid           bool              `json:"valid"`
		RedirectURL     *string           `json:"redirectUrl"`
		Username        *string           `json:"username,omitempty"`
		Email           *string           `json:"email,omitempty"`
		Name            *string           `json:"name,omitempty"`
		ResponseHeaders map[string]string `json:"responseHeaders,omitempty"`
	} `json:"data"`
}

type ExchangeSessionBody struct {
	RequestToken *string `json:"requestToken"`
	RequestHost  *string `json:"host"`
	RequestIP    *string `json:"requestIp,omitempty"`
}

type ExchangeSessionResponse struct {
	Data struct {
		Valid           bool              `json:"valid"`
		Cookie          *string           `json:"cookie"`
		ResponseHeaders map[string]string `json:"responseHeaders,omitempty"`
	} `json:"data"`
}

func CreateConfig() *Config {
	return &Config{}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Parse trusted proxy networks
	var trustedNets []*net.IPNet
	for _, proxy := range config.TrustedProxies {
		// Check if it's a CIDR notation
		if strings.Contains(proxy, "/") {
			_, ipNet, err := net.ParseCIDR(proxy)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR in trustedProxies: %s", proxy)
			}
			trustedNets = append(trustedNets, ipNet)
		} else {
			// Single IP address - convert to /32 or /128 CIDR
			ip := net.ParseIP(proxy)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP in trustedProxies: %s", proxy)
			}
			
			var mask net.IPMask
			if ip.To4() != nil {
				mask = net.CIDRMask(32, 32)
			} else {
				mask = net.CIDRMask(128, 128)
			}
			trustedNets = append(trustedNets, &net.IPNet{IP: ip, Mask: mask})
		}
	}

	return &Badger{
		next:                        next,
		name:                        name,
		apiBaseUrl:                  config.APIBaseUrl,
		userSessionCookieName:       config.UserSessionCookieName,
		resourceSessionRequestParam: config.ResourceSessionRequestParam,
		trustedProxies:              config.TrustedProxies,
		trustForwardedHeaders:       config.TrustForwardedHeaders,
		trustedProxyNets:            trustedNets,
	}, nil
}

func (p *Badger) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Get the real client IP
	clientIP := p.getRealIP(req)
	
	cookies := p.extractCookies(req)

	queryValues := req.URL.Query()

	if sessionRequestValue := queryValues.Get(p.resourceSessionRequestParam); sessionRequestValue != "" {
		body := ExchangeSessionBody{
			RequestToken: &sessionRequestValue,
			RequestHost:  &req.Host,
			RequestIP:    &clientIP,
		}

		jsonData, err := json.Marshal(body)
		if err != nil {
			http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		verifyURL := fmt.Sprintf("%s/badger/exchange-session", p.apiBaseUrl)
		resp, err := http.Post(verifyURL, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		var result ExchangeSessionResponse
		err = json.NewDecoder(resp.Body).Decode(&result)
		if err != nil {
			http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if result.Data.Cookie != nil && *result.Data.Cookie != "" {
			rw.Header().Add("Set-Cookie", *result.Data.Cookie)

			queryValues.Del(p.resourceSessionRequestParam)
			cleanedQuery := queryValues.Encode()
			originalRequestURL := fmt.Sprintf("%s://%s%s", p.getScheme(req), req.Host, req.URL.Path)
			if cleanedQuery != "" {
				originalRequestURL = fmt.Sprintf("%s?%s", originalRequestURL, cleanedQuery)
			}

			if result.Data.ResponseHeaders != nil {
				for key, value := range result.Data.ResponseHeaders {
					rw.Header().Add(key, value)
				}
			}

			fmt.Println("Got exchange token, redirecting to", originalRequestURL)
			http.Redirect(rw, req, originalRequestURL, http.StatusFound)
			return
		}
	}

	cleanedQuery := queryValues.Encode()
	originalRequestURL := fmt.Sprintf("%s://%s%s", p.getScheme(req), req.Host, req.URL.Path)
	if cleanedQuery != "" {
		originalRequestURL = fmt.Sprintf("%s?%s", originalRequestURL, cleanedQuery)
	}

	verifyURL := fmt.Sprintf("%s/badger/verify-session", p.apiBaseUrl)

	headers := make(map[string]string)
	for name, values := range req.Header {
		if len(values) > 0 {
			headers[name] = values[0] // Send only the first value for simplicity
		}
	}

	queryParams := make(map[string]string)
	for key, values := range queryValues {
		if len(values) > 0 {
			queryParams[key] = values[0]
		}
	}

	cookieData := VerifyBody{
		Sessions:           cookies,
		OriginalRequestURL: originalRequestURL,
		RequestScheme:      &req.URL.Scheme,
		RequestHost:        &req.Host,
		RequestPath:        &req.URL.Path,
		RequestMethod:      &req.Method,
		TLS:                req.TLS != nil,
		RequestIP:          &clientIP,
		Headers:            headers,
		Query:              queryParams,
	}

	jsonData, err := json.Marshal(cookieData)
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError) // TODO: redirect to error page
		return
	}

	resp, err := http.Post(verifyURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	for _, setCookie := range resp.Header["Set-Cookie"] {
		rw.Header().Add("Set-Cookie", setCookie)
	}

	if resp.StatusCode != http.StatusOK {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var result VerifyResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	req.Header.Del("Remote-User")
	req.Header.Del("Remote-Email")
	req.Header.Del("Remote-Name")

	if result.Data.ResponseHeaders != nil {
		for key, value := range result.Data.ResponseHeaders {
			rw.Header().Add(key, value)
		}
	}

	if result.Data.RedirectURL != nil && *result.Data.RedirectURL != "" {
		fmt.Println("Badger: Redirecting to", *result.Data.RedirectURL)
		http.Redirect(rw, req, *result.Data.RedirectURL, http.StatusFound)
		return
	}

	if result.Data.Valid {

		if result.Data.Username != nil {
			req.Header.Add("Remote-User", *result.Data.Username)
		}

		if result.Data.Email != nil {
			req.Header.Add("Remote-Email", *result.Data.Email)
		}

		if result.Data.Name != nil {
			req.Header.Add("Remote-Name", *result.Data.Name)
		}

		fmt.Println("Badger: Valid session")
		p.next.ServeHTTP(rw, req)
		return
	}

	http.Error(rw, "Unauthorized", http.StatusUnauthorized)
}

// getRealIP extracts the real client IP address from the request
func (p *Badger) getRealIP(req *http.Request) string {
	// Start with RemoteAddr as fallback
	remoteIP, _, _ := net.SplitHostPort(req.RemoteAddr)
	
	// If we don't trust forwarded headers, return RemoteAddr
	if !p.trustForwardedHeaders {
		return remoteIP
	}
	
	// Check if the request comes from a trusted proxy
	if !p.isFromTrustedProxy(remoteIP) {
		// If not from trusted proxy, don't trust forwarded headers
		return remoteIP
	}
	
	// Try to get IP from forwarded headers (in order of preference)
	// 1. X-Forwarded-For (most common, can contain multiple IPs)
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs separated by commas
		// The first one should be the original client
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			// Trim whitespace and return the first IP
			clientIP := strings.TrimSpace(ips[0])
			if net.ParseIP(clientIP) != nil {
				return clientIP
			}
		}
	}
	
	// 2. X-Real-IP (single IP, used by some proxies like nginx)
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		clientIP := strings.TrimSpace(xri)
		if net.ParseIP(clientIP) != nil {
			return clientIP
		}
	}
	
	// 3. CF-Connecting-IP (Cloudflare specific)
	if cfIP := req.Header.Get("CF-Connecting-IP"); cfIP != "" {
		clientIP := strings.TrimSpace(cfIP)
		if net.ParseIP(clientIP) != nil {
			return clientIP
		}
	}
	
	// 4. True-Client-IP (Cloudflare Enterprise)
	if tcIP := req.Header.Get("True-Client-IP"); tcIP != "" {
		clientIP := strings.TrimSpace(tcIP)
		if net.ParseIP(clientIP) != nil {
			return clientIP
		}
	}
	
	// Fall back to RemoteAddr if no valid forwarded IP found
	return remoteIP
}

// isFromTrustedProxy checks if the IP is from a trusted proxy
func (p *Badger) isFromTrustedProxy(ip string) bool {
	// If no trusted proxies configured, trust all (backward compatibility)
	// might want to change this default behavior to be more secure
	if len(p.trustedProxyNets) == 0 {
		// Default: trust common private networks if none specified
		return p.isPrivateIP(ip)
	}
	
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	
	// Check if IP is in any trusted network
	for _, trustedNet := range p.trustedProxyNets {
		if trustedNet.Contains(parsedIP) {
			return true
		}
	}
	
	return false
}

// isPrivateIP checks if an IP is in private IP ranges (RFC 1918)
func (p *Badger) isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	
	// Define private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128", // IPv6 loopback
		"fc00::/7", // IPv6 private
	}
	
	for _, cidr := range privateRanges {
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet != nil && ipNet.Contains(parsedIP) {
			return true
		}
	}
	
	return false
}

func (p *Badger) extractCookies(req *http.Request) map[string]string {
	cookies := make(map[string]string)
	isSecureRequest := req.TLS != nil

	for _, cookie := range req.Cookies() {
		if strings.HasPrefix(cookie.Name, p.userSessionCookieName) {
			if cookie.Secure && !isSecureRequest {
				continue
			}
			cookies[cookie.Name] = cookie.Value
		}
	}

	return cookies
}

func (p *Badger) getScheme(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	return "http"
}