package badger

import (
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestGetRealIP(t *testing.T) {
	tests := []struct {
		name                  string
		remoteAddr           string
		headers              map[string]string
		trustForwardedHeaders bool
		trustedProxies       []string
		expectedIP           string
	}{
		{
			name:                  "No forwarded headers, trust disabled",
			remoteAddr:           "192.168.1.100:12345",
			headers:              map[string]string{},
			trustForwardedHeaders: false,
			trustedProxies:       []string{},
			expectedIP:           "192.168.1.100",
		},
		{
			name:       "X-Forwarded-For with trusted proxy",
			remoteAddr: "10.0.0.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1, 10.0.0.1",
			},
			trustForwardedHeaders: true,
			trustedProxies:       []string{"10.0.0.0/8"},
			expectedIP:           "203.0.113.1",
		},
		{
			name:       "X-Forwarded-For with untrusted proxy",
			remoteAddr: "203.0.113.100:12345",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.1",
			},
			trustForwardedHeaders: true,
			trustedProxies:       []string{"10.0.0.0/8"},
			expectedIP:           "203.0.113.100", // Should not trust the header
		},
		{
			name:       "X-Real-IP with trusted proxy",
			remoteAddr: "172.16.0.1:12345",
			headers: map[string]string{
				"X-Real-IP": "203.0.113.2",
			},
			trustForwardedHeaders: true,
			trustedProxies:       []string{"172.16.0.0/12"},
			expectedIP:           "203.0.113.2",
		},
		{
			name:       "CF-Connecting-IP with Cloudflare IP",
			remoteAddr: "173.245.48.1:12345",
			headers: map[string]string{
				"CF-Connecting-IP": "203.0.113.3",
			},
			trustForwardedHeaders: true,
			trustedProxies:       []string{"173.245.48.0/20"},
			expectedIP:           "203.0.113.3",
		},
		{
			name:       "Multiple headers, X-Forwarded-For takes precedence",
			remoteAddr: "10.0.0.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.4",
				"X-Real-IP":       "203.0.113.5",
				"CF-Connecting-IP": "203.0.113.6",
			},
			trustForwardedHeaders: true,
			trustedProxies:       []string{"10.0.0.0/8"},
			expectedIP:           "203.0.113.4",
		},
		{
			name:       "Invalid IP in X-Forwarded-For, fallback to X-Real-IP",
			remoteAddr: "10.0.0.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "not-an-ip",
				"X-Real-IP":       "203.0.113.7",
			},
			trustForwardedHeaders: true,
			trustedProxies:       []string{"10.0.0.0/8"},
			expectedIP:           "203.0.113.7",
		},
		{
			name:       "Single trusted proxy IP (not CIDR)",
			remoteAddr: "192.168.1.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.8",
			},
			trustForwardedHeaders: true,
			trustedProxies:       []string{"192.168.1.1"},
			expectedIP:           "203.0.113.8",
		},
		{
			name:       "IPv6 support",
			remoteAddr: "[::1]:12345",
			headers: map[string]string{
				"X-Forwarded-For": "2001:db8::1",
			},
			trustForwardedHeaders: true,
			trustedProxies:       []string{"::1/128"},
			expectedIP:           "2001:db8::1",
		},
		{
			name:       "Default to private networks when no trusted proxies configured",
			remoteAddr: "192.168.1.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.9",
			},
			trustForwardedHeaders: true,
			trustedProxies:       []string{}, // Empty = trust private networks
			expectedIP:           "203.0.113.9",
		},
		{
			name:       "Multiple IPs in X-Forwarded-For, take first",
			remoteAddr: "10.0.0.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.10, 192.168.1.1, 10.0.0.1",
			},
			trustForwardedHeaders: true,
			trustedProxies:       []string{"10.0.0.0/8"},
			expectedIP:           "203.0.113.10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a Badger instance with test configuration
			b := &Badger{
				trustForwardedHeaders: tt.trustForwardedHeaders,
				trustedProxies:       tt.trustedProxies,
			}

			// Initialize trusted proxy networks
			b.trustedProxyNets = make([]*net.IPNet, 0)
			for _, proxy := range tt.trustedProxies {
				if strings.Contains(proxy, "/") {
					_, ipNet, _ := net.ParseCIDR(proxy)
					if ipNet != nil {
						b.trustedProxyNets = append(b.trustedProxyNets, ipNet)
					}
				} else {
					ip := net.ParseIP(proxy)
					if ip != nil {
						var mask net.IPMask
						if ip.To4() != nil {
							mask = net.CIDRMask(32, 32)
						} else {
							mask = net.CIDRMask(128, 128)
						}
						b.trustedProxyNets = append(b.trustedProxyNets, &net.IPNet{IP: ip, Mask: mask})
					}
				}
			}

			// Create a test request
			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     make(http.Header),
			}

			// Add test headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Test getRealIP
			result := b.getRealIP(req)

			if result != tt.expectedIP {
				t.Errorf("getRealIP() = %v, want %v", result, tt.expectedIP)
			}
		})
	}
}

func TestIsFromTrustedProxy(t *testing.T) {
	tests := []struct {
		name           string
		ip             string
		trustedProxies []string
		expected       bool
	}{
		{
			name:           "IP in trusted CIDR range",
			ip:             "10.0.0.5",
			trustedProxies: []string{"10.0.0.0/8"},
			expected:       true,
		},
		{
			name:           "IP not in trusted CIDR range",
			ip:             "192.168.1.1",
			trustedProxies: []string{"10.0.0.0/8"},
			expected:       false,
		},
		{
			name:           "Exact IP match",
			ip:             "192.168.1.1",
			trustedProxies: []string{"192.168.1.1"},
			expected:       true,
		},
		{
			name:           "No exact IP match",
			ip:             "192.168.1.2",
			trustedProxies: []string{"192.168.1.1"},
			expected:       false,
		},
		{
			name:           "Multiple ranges, IP in one",
			ip:             "172.16.0.1",
			trustedProxies: []string{"10.0.0.0/8", "172.16.0.0/12"},
			expected:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Badger{
				trustedProxies: tt.trustedProxies,
			}

			// Initialize trusted proxy networks
			b.trustedProxyNets = make([]*net.IPNet, 0)
			for _, proxy := range tt.trustedProxies {
				if strings.Contains(proxy, "/") {
					_, ipNet, _ := net.ParseCIDR(proxy)
					if ipNet != nil {
						b.trustedProxyNets = append(b.trustedProxyNets, ipNet)
					}
				} else {
					ip := net.ParseIP(proxy)
					if ip != nil {
						var mask net.IPMask
						if ip.To4() != nil {
							mask = net.CIDRMask(32, 32)
						} else {
							mask = net.CIDRMask(128, 128)
						}
						b.trustedProxyNets = append(b.trustedProxyNets, &net.IPNet{IP: ip, Mask: mask})
					}
				}
			}

			result := b.isFromTrustedProxy(tt.ip)

			if result != tt.expected {
				t.Errorf("isFromTrustedProxy(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "10.x.x.x private range",
			ip:       "10.0.0.1",
			expected: true,
		},
		{
			name:     "172.16.x.x private range",
			ip:       "172.16.0.1",
			expected: true,
		},
		{
			name:     "192.168.x.x private range",
			ip:       "192.168.1.1",
			expected: true,
		},
		{
			name:     "Localhost",
			ip:       "127.0.0.1",
			expected: true,
		},
		{
			name:     "Public IP",
			ip:       "8.8.8.8",
			expected: false,
		},
		{
			name:     "IPv6 loopback",
			ip:       "::1",
			expected: true,
		},
		{
			name:     "IPv6 private",
			ip:       "fc00::1",
			expected: true,
		},
		{
			name:     "IPv6 public",
			ip:       "2001:4860:4860::8888",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Badger{}
			result := b.isPrivateIP(tt.ip)

			if result != tt.expected {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}