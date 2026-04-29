package http

import (
	"encoding/json"
	"fmt"
	"net/http"

	request "github.com/golang-jwt/jwt/v4/request"
	"github.com/keel-hq/keel/pkg/auth"
	log "github.com/sirupsen/logrus"
)

// AuthConfig is returned by /v1/auth/config so the frontend knows which auth
// methods are available.
type AuthConfig struct {
	BasicAuthEnabled bool `json:"basic_auth_enabled"`
	OAuthEnabled     bool `json:"oauth_enabled"`
}

func (s *TriggerServer) authConfigHandler(resp http.ResponseWriter, req *http.Request) {
	cfg := AuthConfig{
		BasicAuthEnabled: s.authenticator.Enabled(),
		OAuthEnabled:     s.oauthProvider.Enabled(),
	}
	response(&cfg, http.StatusOK, nil, resp, req)
}

// oauthInitiateHandler starts the OAuth2 Authorization Code flow by redirecting
// the browser to the configured provider's authorization URL.
func (s *TriggerServer) oauthInitiateHandler(resp http.ResponseWriter, req *http.Request) {
	state, err := auth.GenerateState()
	if err != nil {
		log.WithError(err).Error("oauth: failed to generate state")
		http.Error(resp, "internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(resp, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(resp, req, s.oauthProvider.GetAuthURL(state), http.StatusFound)
}

// oauthCallbackHandler handles the redirect from the OAuth2 provider, exchanges
// the authorization code for a Keel JWT, then redirects the browser to the
// frontend with the token as a query parameter.
func (s *TriggerServer) oauthCallbackHandler(resp http.ResponseWriter, req *http.Request) {
	stateCookie, err := req.Cookie("oauth_state")
	if err != nil {
		http.Error(resp, "missing state cookie", http.StatusBadRequest)
		return
	}

	if req.URL.Query().Get("state") != stateCookie.Value {
		http.Error(resp, "invalid state", http.StatusBadRequest)
		return
	}

	// Clear the state cookie immediately.
	http.SetCookie(resp, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	code := req.URL.Query().Get("code")
	if code == "" {
		http.Error(resp, "missing code", http.StatusBadRequest)
		return
	}

	authResp, err := s.oauthProvider.ExchangeCode(req.Context(), code)
	if err != nil {
		log.WithError(err).Error("oauth: code exchange failed")
		http.Error(resp, "authentication failed", http.StatusUnauthorized)
		return
	}

	// Redirect the browser to the login page carrying the issued token so the
	// frontend can store it and proceed to the dashboard.
	http.Redirect(resp, req, "/user/login?token="+authResp.Token, http.StatusFound)
}

func authHeadersMiddleware(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	rw.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	rw.Header().Set("Access-Control-Allow-Headers",
		"Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	rw.Header().Set("Access-Control-Expose-Headers", "Authorization")
	rw.Header().Set("Access-Control-Request-Headers", "Authorization")

	next(rw, r)
}

func (s *TriggerServer) requireAdminAuthorization(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {

		// rw.Header().Set("Access-Control-Expose-Headers", "Authorization")
		// rw.Header().Set("Access-Control-Request-Headers", "Authorization")
		//
		if r.Method == "OPTIONS" {
			rw.WriteHeader(200)
			return
		}

		username, password, ok := r.BasicAuth()
		if ok {
			resp, err := s.authenticator.Authenticate(&auth.AuthRequest{
				Username: username,
				Password: password,
				AuthType: auth.AuthTypeBasic,
			})

			if err != nil {
				log.WithFields(log.Fields{
					"error": err,
					"user":  username,
					"pas":   password,
				}).Error("failed uath")
				// rw.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			r = auth.SetAuthenticationDetails(r, &resp.User)

			next(rw, r)
			return
		}

		// authenticating via token

		resp, err := s.authenticator.Authenticate(&auth.AuthRequest{
			Token:    extractToken(r),
			AuthType: auth.AuthTypeToken,
		})

		if err != nil {
			// rw.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

			log.Warnf("authentication by token failed, token: %s, err: %s", extractToken(r), err)
			http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		r = auth.SetAuthenticationDetails(r, &resp.User)

		next(rw, r)
	}
}

func extractToken(req *http.Request) string {
	ex := request.AuthorizationHeaderExtractor
	token, err := ex.ExtractToken(req)
	if err != nil {
		return ""
	}

	return token
}

func (s *TriggerServer) logoutHandler(resp http.ResponseWriter, req *http.Request) {

	resp.WriteHeader(200)
	resp.Write([]byte(`{}`))
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *TriggerServer) loginHandler(resp http.ResponseWriter, req *http.Request) {

	var lr loginRequest
	dec := json.NewDecoder(req.Body)
	defer req.Body.Close()

	err := dec.Decode(&lr)
	if err != nil {
		resp.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(resp, "%s", err)
		return
	}

	authResp, err := s.authenticator.Authenticate(&auth.AuthRequest{
		Username: lr.Username,
		Password: lr.Password,
		AuthType: auth.AuthTypeBasic,
	})

	if err != nil {
		log.Warnf("auth failed for user '%s', error: %s", lr.Username, err)
		http.Error(resp, "username or password incorrect", 401)
		return
	}

	log.Infof("auth successful for user %s", lr.Username)

	resp.Header().Add("Access-Control-Expose-Headers", "Authorization")
	resp.Header().Add("Authorization", fmt.Sprintf("Bearer %s", authResp.Token))

	response(authResp, 200, nil, resp, req)
}

func (s *TriggerServer) refreshHandler(resp http.ResponseWriter, req *http.Request) {
	user := auth.GetAccountFromCtx(req.Context())

	authResp, err := s.authenticator.GenerateToken(*user)
	if err != nil {
		response(nil, http.StatusOK, err, resp, req)
		return
	}

	// adding token to header
	resp.Header().Add("Access-Control-Expose-Headers", "Authorization")
	resp.Header().Add("Authorization", fmt.Sprintf("Bearer %s", authResp.Token))

	response(authResp, http.StatusOK, err, resp, req)
}

