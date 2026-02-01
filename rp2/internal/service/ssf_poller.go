package service

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/lab-matsuura/oidc-ssf/pkg/ssf"
	"github.com/lab-matsuura/oidc-ssf/rp2/internal/config"
)

// SSFPoller handles RFC 8936 Poll-based SET delivery
type SSFPoller struct {
	cfg            *config.Config
	client         *SSFClient
	sessionService *SessionService
	userService    *UserService
	receiver       *ssf.Receiver

	// Pending acknowledgements for the next poll request
	pendingAcks   []string
	pendingAcksMu sync.Mutex

	// Control channels
	stopCh chan struct{}
	doneCh chan struct{}
}

// NewSSFPoller creates a new SSF poller
func NewSSFPoller(
	cfg *config.Config,
	client *SSFClient,
	sessionService *SessionService,
	userService *UserService,
) *SSFPoller {
	poller := &SSFPoller{
		cfg:            cfg,
		client:         client,
		sessionService: sessionService,
		userService:    userService,
		receiver:       ssf.NewReceiver(&ssf.ReceiverConfig{}),
		pendingAcks:    make([]string, 0),
		stopCh:         make(chan struct{}),
		doneCh:         make(chan struct{}),
	}

	// Register event handlers
	poller.registerEventHandlers()

	return poller
}

// registerEventHandlers sets up handlers for different SSF event types
func (p *SSFPoller) registerEventHandlers() {
	p.receiver.RegisterEventHandler(ssf.EventTypeSessionRevoked, p.handleSessionRevoked)
	p.receiver.RegisterEventHandler(ssf.EventTypeCredentialChange, p.handleCredentialChange)
	p.receiver.RegisterEventHandler(ssf.EventTypeTokenClaimsChange, p.handleTokenClaimsChange)
	p.receiver.RegisterEventHandler(ssf.EventTypeAccountDisabled, p.handleAccountDisabled)
	p.receiver.RegisterDefaultHandler(p.handleDefaultEvent)
}

// Start begins the polling loop
func (p *SSFPoller) Start(ctx context.Context) {
	isLongPolling := p.cfg.SSFPollMode == "long"
	if isLongPolling {
		log.Printf("SSF Poller: Starting in long polling mode (continuous)")
	} else {
		log.Printf("SSF Poller: Starting with interval %v", p.cfg.SSFPollInterval)
	}

	go func() {
		defer close(p.doneCh)

		// Initial poll after a short delay to allow stream creation
		time.Sleep(2 * time.Second)

		if isLongPolling {
			// Long polling: poll continuously (server holds connection)
			for {
				select {
				case <-p.stopCh:
					log.Printf("SSF Poller: Stopping")
					return
				case <-ctx.Done():
					log.Printf("SSF Poller: Context cancelled")
					return
				default:
					p.poll(ctx)
				}
			}
		} else {
			// Short polling: use ticker interval
			ticker := time.NewTicker(p.cfg.SSFPollInterval)
			defer ticker.Stop()

			p.poll(ctx)

			for {
				select {
				case <-ticker.C:
					p.poll(ctx)
				case <-p.stopCh:
					log.Printf("SSF Poller: Stopping")
					return
				case <-ctx.Done():
					log.Printf("SSF Poller: Context cancelled")
					return
				}
			}
		}
	}()
}

// Stop gracefully stops the polling loop
func (p *SSFPoller) Stop() {
	close(p.stopCh)
	<-p.doneCh
}

// poll performs a single poll request
func (p *SSFPoller) poll(ctx context.Context) {
	// Get stream ID (creates stream if needed)
	streamID, err := p.client.EnsureStream(ctx)
	if err != nil {
		log.Printf("SSF Poller: Failed to ensure stream: %v", err)
		return
	}

	// Get pending acks
	p.pendingAcksMu.Lock()
	acks := p.pendingAcks
	p.pendingAcks = make([]string, 0)
	p.pendingAcksMu.Unlock()

	// Perform poll request (RFC 8936)
	resp, err := p.client.Poll(ctx, streamID, acks)
	if err != nil {
		log.Printf("SSF Poller: Poll failed: %v", err)
		// Put acks back for retry
		if len(acks) > 0 {
			p.pendingAcksMu.Lock()
			p.pendingAcks = append(acks, p.pendingAcks...)
			p.pendingAcksMu.Unlock()
		}
		return
	}

	// Process received SETs
	if len(resp.Sets) > 0 {
		log.Printf("SSF Poller: Received %d SET(s)", len(resp.Sets))
	}

	for jti, setToken := range resp.Sets {
		if err := p.processSET(setToken); err != nil {
			log.Printf("SSF Poller: Failed to process SET %s: %v", jti, err)
			// Still acknowledge to prevent redelivery of malformed SETs
		}

		// Queue for acknowledgement in next poll (RFC 8936)
		p.pendingAcksMu.Lock()
		p.pendingAcks = append(p.pendingAcks, jti)
		p.pendingAcksMu.Unlock()
	}

	if resp.MoreAvailable {
		// More SETs available - poll again immediately
		log.Printf("SSF Poller: More SETs available, polling again")
		go p.poll(ctx)
	}
}

// processSET processes a single SET token
func (p *SSFPoller) processSET(setToken string) error {
	// Use the receiver to validate and process the SET
	received, err := p.receiver.ReceiveSET(setToken)
	if err != nil {
		return err
	}

	log.Printf("SSF Poller: Processed SET (JTI: %s) with events: %v", received.SET.JTI, received.SET.Events)
	return nil
}

// Event handlers

func (p *SSFPoller) handleSessionRevoked(eventType string, event any, set *ssf.SET) error {
	log.Printf("SSF Poller: SESSION REVOKED - JTI: %s", set.JTI)

	userSub := set.SubjectIdentifier()
	if userSub == "" {
		log.Printf("SSF Poller: SESSION REVOKED - No user identifier found")
		return nil
	}

	count, err := p.sessionService.RevokeSessionsByUserSub(context.Background(), userSub)
	if err != nil {
		log.Printf("SSF Poller: Error revoking sessions for user %s: %v", userSub, err)
		return err
	}
	log.Printf("SSF Poller: Revoked %d sessions for user: %s", count, userSub)

	return nil
}

func (p *SSFPoller) handleCredentialChange(eventType string, event any, set *ssf.SET) error {
	log.Printf("SSF Poller: CREDENTIAL CHANGE - JTI: %s", set.JTI)

	userSub := set.SubjectIdentifier()
	if userSub == "" {
		log.Printf("SSF Poller: CREDENTIAL CHANGE - No user identifier found")
		return nil
	}

	count, err := p.sessionService.RevokeSessionsByUserSub(context.Background(), userSub)
	if err != nil {
		log.Printf("SSF Poller: Error revoking sessions for user %s: %v", userSub, err)
		return err
	}
	log.Printf("SSF Poller: Revoked %d sessions for user %s due to credential change", count, userSub)

	return nil
}

func (p *SSFPoller) handleTokenClaimsChange(eventType string, event any, set *ssf.SET) error {
	log.Printf("SSF Poller: TOKEN CLAIMS CHANGE - JTI: %s", set.JTI)

	eventMap, ok := event.(map[string]any)
	if !ok {
		return nil
	}

	userSub := set.SubjectIdentifier()
	if userSub == "" {
		log.Printf("SSF Poller: TOKEN CLAIMS CHANGE - No user identifier found")
		return nil
	}

	// Extract new role from claims and update user
	if claims, ok := eventMap["claims"].(map[string]any); ok {
		if newRole, ok := claims["role"].(string); ok {
			err := p.userService.UpdateUserRole(context.Background(), userSub, newRole)
			if err != nil {
				log.Printf("SSF Poller: Error updating role for user %s: %v", userSub, err)
				return err
			}
			log.Printf("SSF Poller: Updated role to '%s' for user: %s", newRole, userSub)
		}
	}

	return nil
}

func (p *SSFPoller) handleAccountDisabled(eventType string, event any, set *ssf.SET) error {
	log.Printf("SSF Poller: ACCOUNT DISABLED - JTI: %s", set.JTI)

	userSub := set.SubjectIdentifier()
	if userSub == "" {
		log.Printf("SSF Poller: ACCOUNT DISABLED - No user identifier found")
		return nil
	}

	count, err := p.sessionService.RevokeSessionsByUserSub(context.Background(), userSub)
	if err != nil {
		log.Printf("SSF Poller: Error revoking sessions for disabled user %s: %v", userSub, err)
		return err
	}
	log.Printf("SSF Poller: Revoked %d sessions for disabled user: %s", count, userSub)

	return nil
}

func (p *SSFPoller) handleDefaultEvent(eventType string, event any, set *ssf.SET) error {
	log.Printf("SSF Poller: RECEIVED EVENT - Type: %s, JTI: %s", eventType, set.JTI)
	return nil
}
