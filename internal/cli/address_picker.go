package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// interactiveEndpointCandidate is one selectable public base URL for the
// setup QR (item 17): tailscale first, then real network addresses, docker
// bridges last.
type interactiveEndpointCandidate struct {
	url   string
	label string
}

// gatherEndpointCandidates collects selectable base URLs for the server.
// Order: tailscale MagicDNS name, tailscale IP, ordinary interface
// addresses, hostname; docker bridges go to the bottom.
func gatherEndpointCandidates(port int) []interactiveEndpointCandidate {
	portSuffix := fmt.Sprintf(":%d", port)
	out := make([]interactiveEndpointCandidate, 0, 8)
	seen := map[string]bool{}
	add := func(label, host string) {
		if host == "" || seen[host] {
			return
		}
		seen[host] = true
		out = append(out, interactiveEndpointCandidate{url: "http://" + host + portSuffix, label: label})
	}

	if magic, tsIP := tailscaleEndpoint(); magic != "" || tsIP != "" {
		add("tailscale MagicDNS name", magic)
		add("tailscale IP", tsIP)
	}

	var ordinary []interactiveEndpointCandidate
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}
				ip := ipNet.IP.To4()
				if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
					continue
				}
				host := ip.String()
				// Docker bridges (172.16/12) stay out of the menu: they are
				// never a public address for the phone (item 17).
				if ip.IsPrivate() && inCIDR(ip, "172.16.0.0/12") {
					continue
				}
				ordinary = append(ordinary, interactiveEndpointCandidate{url: "http://" + host + portSuffix, label: iface.Name})
			}
		}
	}
	out = append(out, ordinary...)
	if hostname, err := os.Hostname(); err == nil && strings.TrimSpace(hostname) != "" {
		add("hostname (resolves if you configured DNS/hosts)", strings.ToLower(strings.TrimSpace(hostname)))
	}
	// Final dedupe by URL (first wins): the tailscale CLI IP and the
	// tailscale0 interface address are the same endpoint.
	deduped := out[:0:0]
	seenURL := map[string]bool{}
	for _, c := range out {
		if seenURL[c.url] {
			continue
		}
		seenURL[c.url] = true
		deduped = append(deduped, c)
	}
	return deduped
}

func inCIDR(ip net.IP, cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.Contains(ip)
}

// tailscaleEndpoint returns the MagicDNS name and the first tailscale IP of
// this node when the tailscale CLI is available and the daemon answers.
func tailscaleEndpoint() (magicDNS, tsIP string) {
	out, err := exec.Command("tailscale", "status", "--json").Output()
	if err != nil {
		return "", ""
	}
	var status struct {
		Self struct {
			DNSName      string   `json:"DNSName"`
			TailscaleIPs []string `json:"TailscaleIPs"`
		} `json:"Self"`
	}
	if err := json.Unmarshal(out, &status); err != nil {
		return "", ""
	}
	magicDNS = strings.TrimSuffix(strings.TrimSpace(status.Self.DNSName), ".")
	if len(status.Self.TailscaleIPs) > 0 {
		tsIP = strings.TrimSpace(status.Self.TailscaleIPs[0])
	}
	return magicDNS, tsIP
}

// chooseEndpoint runs an interactive arrow-key menu over the candidates and
// falls back to free-text entry ("enter your own address"). Requires a
// terminal on both ends.
func chooseEndpoint(stdin io.Reader, stdout io.Writer, port int) (string, error) {
	candidates := gatherEndpointCandidates(port)
	options := make([]string, 0, len(candidates)+1)
	for _, c := range candidates {
		options = append(options, fmt.Sprintf("%s  (%s)", c.url, c.label))
	}
	options = append(options, "Enter your own address…")

	isTTY := false
	if file, ok := stdin.(*os.File); ok {
		isTTY = term.IsTerminal(int(file.Fd()))
	}
	if !isTTY {
		return "", fmt.Errorf("no terminal for the address menu; pass --public-url explicitly")
	}

	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	restored := false
	restore := func() {
		if !restored {
			restored = true
			_ = term.Restore(int(os.Stdin.Fd()), state)
		}
	}
	defer restore()

	selected := 0
	hintLine := "   ↑/↓ or 1-9, Enter to confirm, q to cancel"
	drawLine := func(i int, isSelected bool) {
		// The cursor lives at the end of the hint line: option i is
		// len(options)-i rows above it. Redraw only that row, then jump back.
		up := len(options) - i
		marker := "   "
		if isSelected {
			marker = "-> "
		}
		fmt.Fprintf(stdout, "\x1b[%dA\r\x1b[K%s%s\x1b[m", up, marker, options[i])
		fmt.Fprintf(stdout, "\x1b[%dB\r\x1b[K%s", up, hintLine)
	}
	fmt.Fprintf(stdout, "Choose the public address for the setup QR:\r\n")
	// Terminal is in raw mode: LF alone does not return the carriage, so
	// every line ends with an explicit CRLF (otherwise the list renders as
	// a staircase).
	for i, option := range options {
		marker := "   "
		if i == selected {
			marker = "-> "
		}
		fmt.Fprintf(stdout, "%s%s\r\n", marker, option)
	}
	fmt.Fprintf(stdout, "%s", hintLine)

	buf := make([]byte, 3)
	prevSelected := 0
	for {
		n, err := stdin.Read(buf)
		if err != nil {
			return "", err
		}
		confirmed := false
		cancelled := false
		prevSelected = selected
		if n == 3 && buf[0] == '\x1b' && buf[1] == '[' {
			switch buf[2] {
			case 'A': // up
				selected = (selected - 1 + len(options)) % len(options)
			case 'B': // down
				selected = (selected + 1) % len(options)
			}
		} else if n >= 1 {
			switch {
			case buf[0] == '\r' || buf[0] == '\n':
				confirmed = true
			case buf[0] == 'q':
				cancelled = true
			case buf[0] >= '1' && buf[0] <= '9':
				idx := int(buf[0] - '1')
				if idx < len(options) {
					selected = idx
					confirmed = true
				}
			}
		}
		if cancelled {
			return "", fmt.Errorf("cancelled")
		}
		if selected != prevSelected {
			// Point redraw: touch only the two lines that changed.
			drawLine(prevSelected, false)
			drawLine(selected, true)
		}
		if confirmed {
			if selected == len(candidates) {
				restore()
				fmt.Fprintf(stdout, "\r\n")
				fmt.Fprintf(stdout, "Public address (e.g. http://myhost.tailnet.ts.net:8777): ")
				line, readErr := bufio.NewReader(os.Stdin).ReadString('\n')
				if readErr != nil && line == "" {
					return "", readErr
				}
				text := strings.TrimSpace(line)
				if text == "" {
					return "", fmt.Errorf("empty address")
				}
				return normalizePublicURL(text, port), nil
			}
			fmt.Fprintf(stdout, "\r\n")
			return candidates[selected].url, nil
		}
	}
}

// normalizePublicURL accepts bare host[:port], http(s) URLs and MagicDNS
// names; missing scheme becomes http://, missing port gets the default.
func normalizePublicURL(text string, port int) string {
	text = strings.TrimSpace(text)
	text = strings.TrimSuffix(text, "/")
	if !strings.Contains(text, "://") {
		text = "http://" + text
	}
	u, err := url.Parse(text)
	if err != nil {
		return text
	}
	if u.Port() == "" {
		defaultPort := port
		if u.Scheme == "https" {
			defaultPort = 443
		}
		u.Host = net.JoinHostPort(u.Hostname(), strconv.Itoa(defaultPort))
	}
	return u.String()
}
