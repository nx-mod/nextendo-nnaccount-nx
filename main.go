// nextendo-nnaccount-nx — the Nintendo Account side of a local Nextendo stack.
//
// A real Switch's account service (nnAccount) talks to two hosts:
//
//	accounts.nintendo.com      /connect/1.0.0/api/token    tokens (refresh grant, as captured from a console)
//	                           /connect/1.0.0/authorize    id_token for a game or service
//	                           /1.0.0/certificates         the keys its tokens are signed with (their "jku")
//	api.accounts.nintendo.com  /2.0.0/users/me             the account profile
//
// Production Nextendo answers these from a private service (nx-account); without it the local stack relayed
// /connect to production and had no users/me at all. This serves them locally for the accounts held by
// nextendo-account, whose /internal/identity supplies the profile. Plain HTTP: tls-front terminates TLS.
//
// Tokens are RS256 JWTs signed with a key kept in NNACCOUNT_DATA. Nintendo Account ids a console already
// holds (from a link made against production) are mapped to local accounts in links.json, with
// NNACCOUNT_DEFAULT_PID as the fallback.
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"image"
	"image/color"
	"image/draw"
	_ "image/jpeg"
	"image/png"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	issuer       = "https://accounts.nintendo.com"
	jku          = "https://accounts.nintendo.com/1.0.0/certificates"
	keyID        = "nextendo-nnaccount-1"
	accessTTL    = 900 * time.Second
	idTokenTTL   = 900 * time.Second
	refreshTTL   = 365 * 24 * time.Hour
	systemClient = "6ffd70c434d303c8" // nnAccount's own client id (the console's "aud")
)

// The scope list production returned with every access token.
var accessScopes = []string{"openid", "offline", "napps", "urn:oauth:init-sso", "user", "user.birthday", "user.email",
	"user.links", "user.links[].id", "user.terms", "user.screenName", "user.loginId"}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

type service struct {
	key         *rsa.PrivateKey
	accountURL  string
	internalKey string
	defaultPID  uint64
	localOpen   bool // NNACCOUNT_LOCAL_OPEN=1: an unknown Nintendo Account gets an account of its own
	dataDir     string

	mu     sync.Mutex
	links  map[string]uint64 // Nintendo Account id -> Nextendo PID
	emails map[string]string // Nintendo Account id -> the e-mail it signed in with (users/me)
}

// ---------------------------------------------------------------- keys and tokens

func loadOrCreateKey(dir string) (*rsa.PrivateKey, error) {
	path := filepath.Join(dir, "nnaccount_signing_key.pem")
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("%s: not PEM", path)
		}
		return x509.ParsePKCS1PrivateKey(blk.Bytes)
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	log.Printf("[nnaccount] new signing key written to %s", path)
	return k, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64json(v any) string {
	b, _ := json.Marshal(v)
	return b64(b)
}

func newJTI() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (s *service) sign(claims map[string]any) string {
	head := b64json(map[string]any{"alg": "RS256", "jku": jku, "kid": keyID, "typ": "JWT"})
	body := b64json(claims)
	sum := sha256.Sum256([]byte(head + "." + body))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		log.Printf("[nnaccount] sign: %v", err)
	}
	return head + "." + body + "." + b64(sig)
}

// jwtClaims reads a JWT's claims without verifying it: tokens a console already holds were signed by
// production, whose key this service does not have.
func jwtClaims(tok string) map[string]any {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

func claimString(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

// ---------------------------------------------------------------- accounts

type identity struct {
	PID            uint64 `json:"pid"`
	NaID           string `json:"naID"`
	BaasUserID     string `json:"baasUserID"`
	Nickname       string `json:"nickname"`
	Mii            string `json:"mii"`
	Avatar         string `json:"avatar"`
	ImageUpdatedAt int64  `json:"imageUpdatedAt"`
}

func (s *service) identity(pid uint64) (*identity, error) {
	req, _ := http.NewRequest("GET", s.accountURL+"/internal/identity?pid="+strconv.FormatUint(pid, 10), nil)
	req.Header.Set("X-Internal-Key", s.internalKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("identity pid %d: %d %s", pid, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var id identity
	if err := json.NewDecoder(resp.Body).Decode(&id); err != nil {
		return nil, err
	}
	return &id, nil
}

func (s *service) linksPath() string { return filepath.Join(s.dataDir, "links.json") }

func (s *service) emailsPath() string { return filepath.Join(s.dataDir, "emails.json") }

func (s *service) loadLinks() {
	s.links = map[string]uint64{}
	if b, err := os.ReadFile(s.linksPath()); err == nil {
		json.Unmarshal(b, &s.links)
	}
	s.emails = map[string]string{}
	if b, err := os.ReadFile(s.emailsPath()); err == nil {
		json.Unmarshal(b, &s.emails)
	}
}

func (s *service) saveLinksLocked() {
	b, _ := json.MarshalIndent(s.links, "", "  ")
	os.WriteFile(s.linksPath(), b, 0o600)
	b, _ = json.MarshalIndent(s.emails, "", "  ")
	os.WriteFile(s.emailsPath(), b, 0o600)
}

// pidFor maps a Nintendo Account id to a Nextendo PID: a known link; else the default account; else, with
// NNACCOUNT_LOCAL_OPEN=1, an account of its own from nextendo-account's local open mode (/api/nsa creates
// one for an id nobody owns). A console linked elsewhere (production Nextendo) keeps working on the LAN stack
// instead of asking to sign in again. The mapping is recorded in links.json, so it stays stable.
func (s *service) pidFor(naID string) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if pid, ok := s.links[naID]; ok {
		return pid, true
	}
	if naID == "" {
		return 0, false
	}
	pid := s.defaultPID
	if pid == 0 && s.localOpen {
		pid = s.openAccountFor(naID)
	}
	if pid == 0 {
		return 0, false
	}
	s.links[naID] = pid
	s.saveLinksLocked()
	log.Printf("[nnaccount] Nintendo Account %s linked to PID %d (links.json)", naID, pid)
	return pid, true
}

// openAccountFor asks nextendo-account's /api/nsa (local open mode) for the account of this id, creating it.
func (s *service) openAccountFor(naID string) uint64 {
	n, err := strconv.ParseUint(naID, 16, 64)
	if err != nil || n == 0 {
		return 0
	}
	resp, err := http.Get(s.accountURL + "/api/nsa?id=" + strconv.FormatUint(n, 10))
	if err != nil {
		log.Printf("[nnaccount] /api/nsa: %v", err)
		return 0
	}
	defer resp.Body.Close()
	var out struct {
		PID uint64 `json:"pid"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&out) != nil {
		return 0
	}
	return out.PID
}

// ---------------------------------------------------------------- handlers

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, code, desc string) {
	writeJSON(w, http.StatusBadRequest, map[string]any{"error": code, "error_description": desc})
}

// readForm parses the body once and logs the request in full: the formats of the calls not yet captured
// from a console (authorize) are learnt from these lines.
func readForm(r *http.Request) url.Values {
	body, _ := io.ReadAll(r.Body)
	vals, _ := url.ParseQuery(string(body))
	for k, v := range r.URL.Query() {
		if _, ok := vals[k]; !ok {
			vals[k] = v
		}
	}
	log.Printf("[nnaccount] %s %s%s ua=%q body=%s", r.Method, r.Host, r.URL.RequestURI(), r.UserAgent(), redact(string(body)))
	return vals
}

// redact shortens tokens in logged bodies (their claims are what matter, not their signatures).
func redact(body string) string {
	vals, err := url.ParseQuery(body)
	if err != nil {
		return body
	}
	parts := []string{}
	for k, v := range vals {
		s := strings.Join(v, ",")
		if k == "nx_password" {
			s = "***"
		} else if strings.Count(s, ".") == 2 && len(s) > 80 {
			s = fmt.Sprintf("jwt%v", jwtClaims(s))
		}
		parts = append(parts, k+"="+s)
	}
	return strings.Join(parts, "&")
}

func (s *service) accessToken(naID, clientID string) string {
	now := time.Now().Unix()
	return s.sign(map[string]any{
		"ac:grt": 4, "ac:scp": []int{0, 1, 4, 5, 8, 9, 10, 11, 12, 13, 23, 28},
		"aud": clientID, "exp": now + int64(accessTTL.Seconds()), "iat": now,
		"iss": issuer, "jti": newJTI(), "sub": naID, "typ": "token",
	})
}

// idToken is the account's OpenID token. nintendo.ai carries the Nextendo account's BaaS user id: BaaS
// federation (linking or importing this Nintendo Account on a console) puts the console on that user.
func (s *service) idToken(naID, clientID, nonce string) string {
	now := time.Now().Unix()
	claims := map[string]any{
		"aud": clientID, "exp": now + int64(idTokenTTL.Seconds()), "iat": now, "iss": issuer,
		"jti": newJTI(), "sub": naID, "typ": "id_token",
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if pid, ok := s.pidFor(naID); ok {
		if id, err := s.identity(pid); err == nil && id.BaasUserID != "" {
			claims["nintendo"] = map[string]any{"ai": id.BaasUserID}
		}
	}
	return s.sign(claims)
}

func (s *service) refreshToken(naID, clientID string) string {
	now := time.Now().Unix()
	return s.sign(map[string]any{
		"aud": clientID, "exp": now + int64(refreshTTL.Seconds()), "iat": now,
		"iss": issuer, "jti": newJTI(), "sub": naID,
	})
}

// POST /connect/1.0.0/api/token
func (s *service) token(w http.ResponseWriter, r *http.Request) {
	f := readForm(r)
	clientID := f.Get("client_id")
	if clientID == "" {
		clientID = systemClient
	}
	switch f.Get("grant_type") {
	case "refresh_token":
		c := jwtClaims(f.Get("refresh_token"))
		naID := claimString(c, "sub")
		if _, ok := s.pidFor(naID); !ok {
			log.Printf("[nnaccount] token: Nintendo Account %q has no Nextendo account", naID)
			oauthError(w, "invalid_grant", "unknown account")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": s.accessToken(naID, clientID), "expires_in": int(accessTTL.Seconds()),
			"scope": accessScopes, "token_type": "Bearer",
		})
	case "authorization_code":
		naID, ok := takeCode(f.Get("code"))
		if !ok {
			oauthError(w, "invalid_grant", "unknown or expired code")
			return
		}
		s.tokenSet(w, naID, clientID)
	case "urn:ietf:params:oauth:grant-type:jwt-bearer-session-token":
		naID := claimString(jwtClaims(f.Get("session_token")), "sub")
		if _, ok := s.pidFor(naID); !ok {
			oauthError(w, "invalid_grant", "unknown account")
			return
		}
		s.tokenSet(w, naID, clientID)
	default:
		log.Printf("[nnaccount] token: grant_type %q not implemented", f.Get("grant_type"))
		oauthError(w, "unsupported_grant_type", f.Get("grant_type"))
	}
}

// POST /connect/1.0.0/authorize — an id_token for a game or service. The console's request format has
// not been captured yet (readForm logs it); this answers with the standard OAuth shape for id_token.
func (s *service) authorize(w http.ResponseWriter, r *http.Request) {
	f := readForm(r)
	if r.Method == http.MethodGet || f.Get("nx_login") != "" {
		s.linkPage(w, r, f)
		return
	}
	naID := ""
	if at := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); at != "" {
		naID = claimString(jwtClaims(at), "sub")
	}
	for _, k := range []string{"access_token", "session_token", "refresh_token", "id_token_hint"} {
		if naID == "" {
			naID = claimString(jwtClaims(f.Get(k)), "sub")
		}
	}
	if _, ok := s.pidFor(naID); !ok {
		log.Printf("[nnaccount] authorize: no account for Nintendo Account %q", naID)
		oauthError(w, "access_denied", "unknown account")
		return
	}
	clientID := f.Get("client_id")
	if clientID == "" {
		clientID = systemClient
	}
	// A silent OAuth request (nnAccount, prompt=none, e.g. NxELicense's response_type "code id_token" to
	// nintendo://e-license.nx.sys) wants the standard redirect: the grant in the redirect URI's fragment
	// (query for a plain code), not JSON. Answering JSON left the page the console was opening blank.
	if redirect := f.Get("redirect_uri"); redirect != "" && f.Get("response_type") != "" {
		rt := f.Get("response_type")
		v := url.Values{}
		if strings.Contains(rt, "code") {
			v.Set("code", s.newCode(naID))
		}
		if strings.Contains(rt, "id_token") {
			v.Set("id_token", s.idToken(naID, clientID, strings.TrimSpace(f.Get("nonce"))))
		}
		if st := strings.TrimSpace(f.Get("state")); st != "" {
			v.Set("state", st)
		}
		sep := "#"
		if rt == "code" && f.Get("response_mode") != "fragment" {
			sep = "?"
		}
		log.Printf("[nnaccount] authorize: %s for client %s -> redirect to %s", rt, clientID, redirect)
		http.Redirect(w, r, redirect+sep+v.Encode(), http.StatusFound)
		return
	}
	resp := map[string]any{"id_token": s.idToken(naID, clientID, f.Get("nonce")), "expires_in": int(idTokenTTL.Seconds()), "token_type": "Bearer"}
	if st := f.Get("state"); st != "" {
		resp["state"] = st
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------- linking from the console

// The console links a Nintendo Account by opening /connect/1.0.0/authorize in its browser applet and
// waiting for a redirect to its nintendo:// callback. The page signs in with a Nextendo e-mail and
// password (nextendo-account's /internal/login; with NEXTENDO_LOCAL_OPEN=1 a new e-mail creates the
// account), then redirects with a one-time code the console exchanges at /api/session_token or /api/token.

type grant struct {
	naID    string
	expires time.Time
}

var (
	codesMu sync.Mutex
	codes   = map[string]grant{}
)

func (s *service) newCode(naID string) string {
	b := make([]byte, 24)
	rand.Read(b)
	c := b64(b)
	codesMu.Lock()
	codes[c] = grant{naID, time.Now().Add(10 * time.Minute)}
	codesMu.Unlock()
	return c
}

// takeCode redeems a code once.
func takeCode(c string) (string, bool) {
	codesMu.Lock()
	defer codesMu.Unlock()
	g, ok := codes[c]
	delete(codes, c)
	if !ok || time.Now().After(g.expires) {
		return "", false
	}
	return g.naID, true
}

// login checks Nextendo credentials and records the account's Nintendo Account id as linked to it.
func (s *service) login(email, password string) (string, uint64, error) {
	body, _ := json.Marshal(map[string]string{"login": email, "password": password})
	req, _ := http.NewRequest("POST", s.accountURL+"/internal/login", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Key", s.internalKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	var id identity
	if err := json.NewDecoder(resp.Body).Decode(&id); err != nil {
		return "", 0, err
	}
	naID := id.NaID
	if naID == "" {
		naID = fmt.Sprintf("%016x", id.PID)
	}
	s.mu.Lock()
	s.links[naID] = id.PID
	s.emails[naID] = email
	s.saveLinksLocked()
	s.mu.Unlock()
	return naID, id.PID, nil
}

var linkPageTmpl = template.Must(template.New("link").Parse(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Nextendo</title>
<style>
body{margin:0;background:#1b1b1f;color:#eee;font-family:sans-serif}
.box{max-width:560px;margin:60px auto;padding:32px;background:#26262c;border-radius:12px}
h1{margin:0 0 8px;font-size:30px;color:#e60012}
p{color:#aaa;font-size:18px}
input{display:block;width:100%;box-sizing:border-box;margin:10px 0;padding:16px;font-size:22px;border:0;border-radius:8px}
button{width:100%;padding:18px;font-size:24px;background:#e60012;color:#fff;border:0;border-radius:8px}
.err{color:#ff6b6b}
</style></head><body><div class="box">
<h1>Nextendo</h1>
<p>Sign in with your Nextendo e-mail and password. A new e-mail creates the account.</p>
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<form method="post" action="/connect/1.0.0/authorize">
{{range $k, $v := .Params}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
<input type="hidden" name="nx_login" value="1">
<input type="email" name="nx_email" placeholder="E-mail" value="{{.Email}}">
<input type="password" name="nx_password" placeholder="Password">
<button type="submit">Sign in</button>
</form></div></body></html>`))

func (s *service) linkPage(w http.ResponseWriter, r *http.Request, f url.Values) {
	params := map[string]string{}
	for k, v := range f {
		if !strings.HasPrefix(k, "nx_") && len(v) > 0 {
			params[k] = v[0]
		}
	}
	show := func(msg, email string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		linkPageTmpl.Execute(w, map[string]any{"Params": params, "Error": msg, "Email": email})
	}
	if f.Get("nx_login") == "" {
		show("", "")
		return
	}
	email := strings.TrimSpace(f.Get("nx_email"))
	naID, pid, err := s.login(email, f.Get("nx_password"))
	if err != nil {
		log.Printf("[nnaccount] link: sign-in for %q refused: %v", email, err)
		show("Wrong e-mail or password.", email)
		return
	}
	log.Printf("[nnaccount] link: %s signed in, PID %d, Nintendo Account %s", email, pid, naID)

	// Answer in the shape the request asked for: a code (and session_token_code) and the state, in the query for
	// response_type=code, otherwise in the fragment, as OAuth does.
	redirect := f.Get("redirect_uri")
	code := s.newCode(naID)
	v := url.Values{}
	rt := f.Get("response_type")
	if strings.Contains(rt, "session_token_code") {
		v.Set("session_token_code", code)
	} else {
		v.Set("code", code)
	}
	if strings.Contains(rt, "id_token") {
		v.Set("id_token", s.idToken(naID, f.Get("client_id"), f.Get("nonce")))
	}
	if st := f.Get("state"); st != "" {
		v.Set("state", st)
	}
	sep := "#"
	if f.Get("response_mode") == "query" || (rt == "code" && f.Get("response_mode") != "fragment") {
		sep = "?"
	}
	loc := redirect + sep + v.Encode()
	log.Printf("[nnaccount] link: redirect to %s (response_type %q)", redirect, rt)
	http.Redirect(w, r, loc, http.StatusFound)
}

// POST /connect/1.0.0/api/session_token — a session_token_code from the link page, exchanged for a session token.
func (s *service) sessionToken(w http.ResponseWriter, r *http.Request) {
	f := readForm(r)
	naID, ok := takeCode(f.Get("session_token_code"))
	if !ok {
		oauthError(w, "invalid_grant", "unknown or expired code")
		return
	}
	clientID := f.Get("client_id")
	if clientID == "" {
		clientID = systemClient
	}
	writeJSON(w, http.StatusOK, map[string]any{"session_token": s.refreshToken(naID, clientID), "code": f.Get("session_token_code")})
}

// tokenSet is what a completed link returns: access, refresh and id tokens for the account.
func (s *service) tokenSet(w http.ResponseWriter, naID, clientID string) {
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": s.accessToken(naID, clientID), "refresh_token": s.refreshToken(naID, clientID),
		"id_token":      s.idToken(naID, clientID, ""),
		"session_token": s.refreshToken(naID, clientID),
		"expires_in":    int(accessTTL.Seconds()), "scope": accessScopes, "token_type": "Bearer",
	})
}

// GET /1.0.0/certificates — the JWK set for this service's tokens.
func (s *service) certificates(w http.ResponseWriter, r *http.Request) {
	pub := s.key.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "alg": "RS256", "use": "sig", "kid": keyID,
		"n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// GET /2.0.0/users/me — the account profile, in the shape of Nintendo's API, from the Nextendo account.
func (s *service) usersMe(w http.ResponseWriter, r *http.Request) {
	log.Printf("[nnaccount] %s %s%s ua=%q", r.Method, r.Host, r.URL.RequestURI(), r.UserAgent())
	at := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	naID := claimString(jwtClaims(at), "sub")
	pid, ok := s.pidFor(naID)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"errorCode": "invalid_token", "detail": "unknown account"})
		return
	}
	id, err := s.identity(pid)
	if err != nil {
		log.Printf("[nnaccount] users/me: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"errorCode": "internal_server_error"})
		return
	}
	s.mu.Lock()
	email := s.emails[naID]
	s.mu.Unlock()
	if email == "" {
		email = naID + "@nextendo.local"
	}
	// Every field production sends, in its types: nnAccount rejects a profile that lacks one (the link then ends
	// in a server error), and fetches iconUri right after.
	const created = int64(1716149960)
	updated := created
	if id.ImageUpdatedAt > updated {
		updated = id.ImageUpdatedAt
	}
	perm := func(permitted bool) map[string]any {
		return map[string]any{"editable": map[string]any{"admin": false, "self": true}, "permitted": permitted,
			"updatedAt": created, "userConfirmed": true}
	}
	optIn := map[string]any{"optedIn": false, "updatedAt": created}
	writeJSON(w, http.StatusOK, map[string]any{
		"agreedTerms": map[string]any{
			"EULA":          map[string]any{"agreedAt": created, "country": "US", "version": 2},
			"privacyPolicy": map[string]any{"agreedAt": created, "country": "US", "version": 2},
		},
		"analyticsOptedIn": false, "analyticsOptedInUpdatedAt": created,
		"analyticsPermissions": map[string]any{"dataCollection": perm(false), "internalAnalysis": perm(true),
			"targetMarketing": perm(false)},
		"birthday": "1990-01-01", "clientFriendsOptedIn": true, "clientFriendsOptedInUpdatedAt": created,
		"country": "US", "createdAt": created,
		"eachEmailOptedIn": map[string]any{"deals": optIn, "survey": optIn},
		"email":            email, "emailOptedIn": false, "emailOptedInUpdatedAt": created, "emailVerified": true,
		"gender": "unknown", "iconUri": "https://cdn.accounts.nintendo.com/icons/v1/" + naID + ".png",
		"id": naID, "isChild": false, "language": "en-US", "links": map[string]any{}, "loginId": nil,
		"nickname": id.Nickname, "phoneNumberEnabled": false, "region": nil, "screenName": maskEmail(email),
		"termsAgreementRequired": false,
		"timezone": map[string]any{"id": "America/New_York", "name": "America/New_York", "utcOffset": "-04:00",
			"utcOffsetSeconds": -14400},
		"updatedAt": updated,
	})
}

// maskEmail is Nintendo's screenName: "nextendo@example.com" -> "ne•••@e••••".
func maskEmail(email string) string {
	user, domain, _ := strings.Cut(email, "@")
	head := func(s string, n int) string {
		r := []rune(s)
		if len(r) > n {
			r = r[:n]
		}
		return string(r)
	}
	return head(user, 2) + "•••@" + head(domain, 1) + "••••"
}

// GET /icons/v1/<Nintendo Account id>.png (cdn.accounts.nintendo.com) — the profile's iconUri: the Nextendo
// account's avatar as a PNG, or a plain Nextendo-red square when it has none.
func (s *service) icon(w http.ResponseWriter, r *http.Request) {
	naID := strings.TrimSuffix(filepath.Base(r.URL.Path), ".png")
	var img image.Image
	if pid, ok := s.pidFor(naID); ok {
		if id, err := s.identity(pid); err == nil && id.Avatar != "" {
			if raw, err := base64.StdEncoding.DecodeString(id.Avatar); err == nil {
				img, _, _ = image.Decode(bytes.NewReader(raw))
			}
		}
	}
	if img == nil {
		m := image.NewRGBA(image.Rect(0, 0, 256, 256))
		draw.Draw(m, m.Bounds(), &image.Uniform{color.RGBA{230, 0, 18, 255}}, image.Point{}, draw.Src)
		img = m
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-cache")
	png.Encode(w, img)
}

func main() {
	s := &service{
		accountURL:  envOr("NNACCOUNT_ACCOUNT_URL", "http://127.0.0.1:8080"),
		internalKey: os.Getenv("NEXTENDO_INTERNAL_KEY"),
		dataDir:     envOr("NNACCOUNT_DATA", "."),
		localOpen:   os.Getenv("NNACCOUNT_LOCAL_OPEN") == "1",
	}
	if v := os.Getenv("NNACCOUNT_DEFAULT_PID"); v != "" {
		s.defaultPID, _ = strconv.ParseUint(v, 10, 64)
	}
	os.MkdirAll(s.dataDir, 0o700)
	k, err := loadOrCreateKey(s.dataDir)
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}
	s.key = k
	s.loadLinks()

	mux := http.NewServeMux()
	mux.HandleFunc("/connect/1.0.0/api/token", s.token)
	mux.HandleFunc("/connect/1.0.0/authorize", s.authorize)
	mux.HandleFunc("/connect/1.0.0/api/session_token", s.sessionToken)
	mux.HandleFunc("/1.0.0/certificates", s.certificates)
	mux.HandleFunc("/2.0.0/users/me", s.usersMe)
	mux.HandleFunc("/icons/v1/", s.icon)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		log.Printf("[nnaccount] NOT HANDLED %s %s%s body=%s", r.Method, r.Host, r.URL.RequestURI(), redact(string(body)))
		writeJSON(w, http.StatusNotFound, map[string]any{"errorCode": "not_found"})
	})

	addr := envOr("NNACCOUNT_LISTEN", "127.0.0.1:8470")
	log.Printf("[nnaccount] listening on %s (account=%s, default PID %d, %d links)", addr, s.accountURL, s.defaultPID, len(s.links))
	log.Fatal(http.ListenAndServe(addr, mux))
}
