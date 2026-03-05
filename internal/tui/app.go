// Package tui provides a Bubbletea operator console for the CertStrike C2.
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// View represents the current TUI view.
type View int

const (
	ViewSessions  View = iota
	ViewCommands
	ViewListeners
	ViewImplants
)

// Session mirrors the C2 session data for the TUI.
type Session struct {
	ID         string
	Hostname   string
	Username   string
	OS         string
	Arch       string
	PID        int
	RemoteAddr string
	FirstSeen  time.Time
	LastCheckin time.Time
}

// CommandEntry represents a command sent to a session.
type CommandEntry struct {
	ID      string
	Command string
	Args    string
	Queued  time.Time
	Output  string
	Done    bool
}

// ListenerInfo describes a running C2 listener.
type ListenerInfo struct {
	BindAddress string
	Port        int
	Protocol    string
	Running     bool
	Sessions    int
}

// ImplantConfig describes a configured implant.
type ImplantConfig struct {
	ID       string
	Type     string
	C2URL    string
	Interval int
	Jitter   int
}

// Model is the Bubbletea model for the operator console.
type Model struct {
	view           View
	sessions       []Session
	selectedIdx    int
	selectedSession string
	commands       []CommandEntry
	listeners      []ListenerInfo
	implants       []ImplantConfig
	cmdInput       textinput.Model
	inputActive    bool
	width          int
	height         int
	statusMsg      string
	lastRefresh    time.Time
}

// NewModel creates a new TUI model with demo data.
func NewModel() Model {
	ti := textinput.New()
	ti.Placeholder = "Enter command..."
	ti.CharLimit = 256
	ti.Width = 60

	return Model{
		view:        ViewSessions,
		sessions:    []Session{},
		listeners: []ListenerInfo{
			{BindAddress: "0.0.0.0", Port: 8443, Protocol: "https", Running: true, Sessions: 0},
		},
		implants: []ImplantConfig{
			{ID: "smartpotato-001", Type: "SmartPotato", C2URL: "https://c2.example.com:8443", Interval: 5, Jitter: 20},
		},
		cmdInput:    ti,
		lastRefresh: time.Now(),
		statusMsg:   "Ready",
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, tickCmd())
}

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		m.lastRefresh = time.Now()
		return m, tickCmd()

	case tea.KeyMsg:
		if m.inputActive {
			switch msg.String() {
			case "enter":
				cmd := m.cmdInput.Value()
				if cmd != "" && m.selectedSession != "" {
					m.commands = append(m.commands, CommandEntry{
						ID:      fmt.Sprintf("cmd-%d", len(m.commands)+1),
						Command: cmd,
						Queued:  time.Now(),
					})
					m.statusMsg = fmt.Sprintf("Queued: %s → %s", cmd, m.selectedSession[:8])
				}
				m.cmdInput.Reset()
				return m, nil
			case "esc":
				m.inputActive = false
				m.cmdInput.Blur()
				return m, nil
			default:
				var cmd tea.Cmd
				m.cmdInput, cmd = m.cmdInput.Update(msg)
				return m, cmd
			}
		}

		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "1":
			m.view = ViewSessions
			m.statusMsg = "Sessions"
		case "2":
			m.view = ViewCommands
			m.statusMsg = "Commands"
		case "3":
			m.view = ViewListeners
			m.statusMsg = "Listeners"
		case "4":
			m.view = ViewImplants
			m.statusMsg = "Implants"
		case "j", "down":
			m.moveSelection(1)
		case "k", "up":
			m.moveSelection(-1)
		case "enter":
			if m.view == ViewSessions && len(m.sessions) > 0 {
				m.selectedSession = m.sessions[m.selectedIdx].ID
				m.view = ViewCommands
				m.statusMsg = fmt.Sprintf("Session: %s", m.selectedSession[:8])
			}
		case "i":
			if m.view == ViewCommands {
				m.inputActive = true
				m.cmdInput.Focus()
				cmds = append(cmds, textinput.Blink)
			}
		case "tab":
			m.view = (m.view + 1) % 4
		}
	}

	return m, tea.Batch(cmds...)
}

func (m *Model) moveSelection(delta int) {
	max := 0
	switch m.view {
	case ViewSessions:
		max = len(m.sessions)
	case ViewCommands:
		max = len(m.commands)
	case ViewListeners:
		max = len(m.listeners)
	case ViewImplants:
		max = len(m.implants)
	}
	if max == 0 {
		return
	}
	m.selectedIdx += delta
	if m.selectedIdx < 0 {
		m.selectedIdx = 0
	}
	if m.selectedIdx >= max {
		m.selectedIdx = max - 1
	}
}

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FF6600")).
			Background(lipgloss.Color("#1a1a2e")).
			Padding(0, 1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FF88"))

	selectedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#000000")).
			Background(lipgloss.Color("#FF6600"))

	normalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CCCCCC"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666666"))

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF6600")).
			Bold(true)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#FF6600")).
			Padding(0, 1)
)

func (m Model) View() string {
	var b strings.Builder

	// Header
	banner := titleStyle.Render(" CERTSTRIKE C2 CONSOLE ")
	tabs := m.renderTabs()
	b.WriteString(banner + "  " + tabs + "\n\n")

	// Main content
	switch m.view {
	case ViewSessions:
		b.WriteString(m.renderSessions())
	case ViewCommands:
		b.WriteString(m.renderCommands())
	case ViewListeners:
		b.WriteString(m.renderListeners())
	case ViewImplants:
		b.WriteString(m.renderImplants())
	}

	// Status bar
	b.WriteString("\n")
	status := fmt.Sprintf(" %s | %s | q:quit tab:switch 1-4:views",
		statusStyle.Render(m.statusMsg),
		dimStyle.Render(m.lastRefresh.Format("15:04:05")))
	b.WriteString(status)

	return b.String()
}

func (m Model) renderTabs() string {
	tabs := []string{"[1]Sessions", "[2]Commands", "[3]Listeners", "[4]Implants"}
	var parts []string
	for i, t := range tabs {
		if View(i) == m.view {
			parts = append(parts, headerStyle.Render(t))
		} else {
			parts = append(parts, dimStyle.Render(t))
		}
	}
	return strings.Join(parts, " | ")
}

func (m Model) renderSessions() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render("Active Sessions") + "\n\n")

	if len(m.sessions) == 0 {
		b.WriteString(dimStyle.Render("  No active sessions. Waiting for implant check-ins...\n"))
		b.WriteString(dimStyle.Render("  Start a listener: certstrike c2 --port 8443 --protocol https\n"))
		return b.String()
	}

	// Table header
	hdr := fmt.Sprintf("  %-10s %-15s %-12s %-10s %-18s %-20s",
		"ID", "HOSTNAME", "USER", "OS", "IP", "LAST SEEN")
	b.WriteString(headerStyle.Render(hdr) + "\n")
	b.WriteString(dimStyle.Render(strings.Repeat("─", 90)) + "\n")

	for i, s := range m.sessions {
		id := s.ID
		if len(id) > 8 {
			id = id[:8]
		}
		ago := time.Since(s.LastCheckin).Round(time.Second)
		line := fmt.Sprintf("  %-10s %-15s %-12s %-10s %-18s %s ago",
			id, s.Hostname, s.Username, s.OS, s.RemoteAddr, ago)
		if i == m.selectedIdx {
			b.WriteString(selectedStyle.Render(line) + "\n")
		} else {
			b.WriteString(normalStyle.Render(line) + "\n")
		}
	}

	b.WriteString("\n" + dimStyle.Render("  j/k:navigate  enter:select  "))
	return b.String()
}

func (m Model) renderCommands() string {
	var b strings.Builder

	if m.selectedSession != "" {
		sid := m.selectedSession
		if len(sid) > 8 {
			sid = sid[:8]
		}
		b.WriteString(headerStyle.Render(fmt.Sprintf("Commands → Session %s", sid)) + "\n\n")
	} else {
		b.WriteString(headerStyle.Render("Commands (no session selected)") + "\n\n")
	}

	if len(m.commands) == 0 {
		b.WriteString(dimStyle.Render("  No commands yet. Press 'i' to enter a command.\n"))
	} else {
		for i, c := range m.commands {
			status := "⏳"
			if c.Done {
				status = "✓"
			}
			line := fmt.Sprintf("  %s %-10s %s", status, c.ID, c.Command)
			if i == m.selectedIdx {
				b.WriteString(selectedStyle.Render(line) + "\n")
			} else {
				b.WriteString(normalStyle.Render(line) + "\n")
			}
			if c.Output != "" {
				b.WriteString(dimStyle.Render("    → "+c.Output) + "\n")
			}
		}
	}

	if m.inputActive {
		b.WriteString("\n  " + m.cmdInput.View())
	} else {
		b.WriteString("\n" + dimStyle.Render("  i:input command  esc:back"))
	}

	return b.String()
}

func (m Model) renderListeners() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render("Active Listeners") + "\n\n")

	if len(m.listeners) == 0 {
		b.WriteString(dimStyle.Render("  No active listeners.\n"))
		return b.String()
	}

	hdr := fmt.Sprintf("  %-18s %-8s %-10s %-10s",
		"BIND", "PORT", "PROTOCOL", "SESSIONS")
	b.WriteString(headerStyle.Render(hdr) + "\n")
	b.WriteString(dimStyle.Render(strings.Repeat("─", 50)) + "\n")

	for i, l := range m.listeners {
		status := "●"
		if !l.Running {
			status = "○"
		}
		line := fmt.Sprintf("  %s %-15s %-8d %-10s %-10d",
			status, l.BindAddress, l.Port, l.Protocol, l.Sessions)
		if i == m.selectedIdx {
			b.WriteString(selectedStyle.Render(line) + "\n")
		} else {
			b.WriteString(normalStyle.Render(line) + "\n")
		}
	}

	return b.String()
}

func (m Model) renderImplants() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render("Implant Configurations") + "\n\n")

	if len(m.implants) == 0 {
		b.WriteString(dimStyle.Render("  No implant configurations.\n"))
		return b.String()
	}

	hdr := fmt.Sprintf("  %-18s %-15s %-35s %-8s %-8s",
		"ID", "TYPE", "C2 URL", "INTERVAL", "JITTER")
	b.WriteString(headerStyle.Render(hdr) + "\n")
	b.WriteString(dimStyle.Render(strings.Repeat("─", 90)) + "\n")

	for i, imp := range m.implants {
		line := fmt.Sprintf("  %-18s %-15s %-35s %-8ds %-8d%%",
			imp.ID, imp.Type, imp.C2URL, imp.Interval, imp.Jitter)
		if i == m.selectedIdx {
			b.WriteString(selectedStyle.Render(line) + "\n")
		} else {
			b.WriteString(normalStyle.Render(line) + "\n")
		}
	}

	return b.String()
}
