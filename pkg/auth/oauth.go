package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

// OAuthOpts holds the configuration for the OAuth2 provider.
type OAuthOpts struct {
	ClientID     string
	ClientSecret string
	// RedirectURL is the callback URL registered with the OAuth2 provider.
	RedirectURL string
	// AuthURL is the provider's authorization endpoint.
	AuthURL string
	// TokenURL is the provider's token endpoint.
	TokenURL string
	// UserInfoURL is the provider's userinfo endpoint (optional).
	// When set, Keel fetches the authenticated user's username from this URL.
	UserInfoURL string
	// Scopes is the list of OAuth2 scopes to request.
	// Defaults to ["openid", "profile", "email"] when empty.
	Scopes []string

	// Secret used to sign the internal Keel JWT issued after successful OAuth login.
	Secret []byte
}

// OAuthProvider handles the OAuth2 Authorization Code flow.
type OAuthProvider struct {
	opts   *OAuthOpts
	config *oauth2.Config
	secret []byte
}

// NewOAuthProvider creates a new OAuthProvider from the given opts.
// Returns nil when the required fields (ClientID, ClientSecret, AuthURL, TokenURL) are not set.
func NewOAuthProvider(opts *OAuthOpts) *OAuthProvider {
	if opts.ClientID == "" || opts.ClientSecret == "" || opts.AuthURL == "" || opts.TokenURL == "" {
		return nil
	}

	if len(opts.Secret) == 0 {
		opts.Secret = []byte(randStringRunes(23))
	}

	scopes := opts.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	cfg := &oauth2.Config{
		ClientID:     opts.ClientID,
		ClientSecret: opts.ClientSecret,
		RedirectURL:  opts.RedirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  opts.AuthURL,
			TokenURL: opts.TokenURL,
		},
		Scopes: scopes,
	}

	return &OAuthProvider{
		opts:   opts,
		config: cfg,
		secret: opts.Secret,
	}
}

// Enabled reports whether OAuth2 authentication is configured.
func (p *OAuthProvider) Enabled() bool {
	return p != nil &&
		p.opts.ClientID != "" &&
		p.opts.ClientSecret != "" &&
		p.opts.AuthURL != "" &&
		p.opts.TokenURL != ""
}

// GetAuthURL returns the provider's authorization URL with the given state parameter.
func (p *OAuthProvider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

// GenerateState produces a cryptographically random, URL-safe state string for
// CSRF protection in the OAuth2 flow.
func GenerateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// userInfoResponse is a minimal subset of the standard OIDC UserInfo response.
type userInfoResponse struct {
	Sub               string `json:"sub"`
	Name              string `json:"name"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
}

// ExchangeCode exchanges the authorization code for a Keel JWT.
// It fetches user info from the configured UserInfoURL (when set) to populate
// the username in the issued token.
func (p *OAuthProvider) ExchangeCode(ctx context.Context, code string) (*AuthResponse, error) {
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	username := "oauth-user"

	if p.opts.UserInfoURL != "" {
		client := p.config.Client(ctx, token)
		resp, err := fetchUserInfo(client, p.opts.UserInfoURL)
		if err != nil {
			log.WithError(err).Warn("oauth: failed to fetch user info, using default username")
		} else if resp != nil {
			switch {
			case resp.PreferredUsername != "":
				username = resp.PreferredUsername
			case resp.Name != "":
				username = resp.Name
			case resp.Email != "":
				username = resp.Email
			case resp.Sub != "":
				username = resp.Sub
			}
		}
	}

	da := &DefaultAuthenticator{secret: p.secret}
	return da.GenerateToken(User{Username: username})
}

func fetchUserInfo(client *http.Client, url string) (*userInfoResponse, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading userinfo response: %w", err)
	}

	var ui userInfoResponse
	if err := json.Unmarshal(body, &ui); err != nil {
		return nil, fmt.Errorf("parsing userinfo response: %w", err)
	}
	return &ui, nil
}
