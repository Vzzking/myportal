package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const passwordChars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"

const (
	sessionCookieName = "resume_session"
	adminCookieName   = "resume_admin"
	sessionDuration   = 24 * time.Hour
	dataFile          = "data/requests.json"
)

type Request struct {
	Email          string     `json:"email"`
	VerifyToken    string     `json:"verify_token"`
	DownloadToken  string     `json:"download_token"`
	Password       string     `json:"password"`
	CreatedAt      time.Time  `json:"created_at"`
	VerifiedAt     *time.Time `json:"verified_at,omitempty"`
	DownloadedAt   *time.Time `json:"downloaded_at,omitempty"`
}

type Session struct {
	Email         string
	DownloadToken string
	ExpiresAt     time.Time
}

var (
	templates *template.Template
	store     struct {
		mu           sync.RWMutex
		requests     []Request
		verifyMap    map[string]int // verify_token -> index
		downloadMap  map[string]int // download_token -> index
		sessions     map[string]*Session
	}
)

func init() {
	store.verifyMap = make(map[string]int)
	store.downloadMap = make(map[string]int)
	store.sessions = make(map[string]*Session)
	loadRequests()
}

func main() {
	var err error
	templates, err = template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatal("templates:", err)
	}

	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		for range ticker.C {
			cleanExpiredSessions()
		}
	}()

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/access", handleAccess)
	http.HandleFunc("/terms", handleTerms)
	http.HandleFunc("/verify-sent", handleVerifySent)
	http.HandleFunc("/verify", handleVerify)
	http.HandleFunc("/download", handleDownload)
	http.HandleFunc("/download/file", handleDownloadFile)
	http.HandleFunc("/admin", handleAdmin)
	http.HandleFunc("/admin/login", handleAdminLogin)
	http.HandleFunc("/admin/logout", handleAdminLogout)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// --- persistence ---

func loadRequests() {
	store.mu.Lock()
	defer store.mu.Unlock()
	f, err := os.Open(dataFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("load requests: %v", err)
		}
		return
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&store.requests); err != nil {
		log.Printf("decode requests: %v", err)
		return
	}
	for i := range store.requests {
		r := &store.requests[i]
		store.verifyMap[r.VerifyToken] = i
		store.downloadMap[r.DownloadToken] = i
	}
}

func saveRequests() {
	store.mu.Lock()
	data := make([]Request, len(store.requests))
	copy(data, store.requests)
	store.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(dataFile), 0700); err != nil {
		log.Printf("mkdir data: %v", err)
		return
	}
	f, err := os.Create(dataFile)
	if err != nil {
		log.Printf("save requests: %v", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		log.Printf("encode requests: %v", err)
	}
}

// --- handlers ---

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	render(w, "base.html", map[string]interface{}{
		"ContentTemplate": "index_content",
		"Title":           "Главная",
	})
}

func handleAccess(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		errMsg := ""
		if r.URL.Query().Get("error") == "invalid" {
			errMsg = "Ссылка для подтверждения недействительна или уже использована. Запросите доступ снова."
		}
		if r.URL.Query().Get("error") == "used" {
			errMsg = "Ссылка на скачивание уже была использована. Один запрос — одно скачивание."
		}
		render(w, "base.html", map[string]interface{}{
			"ContentTemplate": "access_content",
			"Title":           "Получить доступ",
			"Error":           errMsg,
		})
	case http.MethodPost:
		handleAccessPost(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func handleAccessPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	email := r.FormValue("email")
	termsAccepted := r.FormValue("terms") == "on"
	if email == "" {
		render(w, "base.html", map[string]interface{}{
			"ContentTemplate": "access_content",
			"Title":           "Получить доступ",
			"Error":           "Укажите адрес электронной почты.",
			"Email":           email,
			"Terms":           termsAccepted,
		})
		return
	}
	if !termsAccepted {
		render(w, "base.html", map[string]interface{}{
			"ContentTemplate": "access_content",
			"Title":           "Получить доступ",
			"Error":           "Необходимо принять условия использования (Terms of Use).",
			"Email":           email,
		})
		return
	}

	verifyToken := mustGenerateToken()
	downloadToken := mustGenerateToken()
	password := mustGeneratePassword()
	now := time.Now()
	req := Request{
		Email:         email,
		VerifyToken:   verifyToken,
		DownloadToken: downloadToken,
		Password:      password,
		CreatedAt:     now,
	}

	store.mu.Lock()
	store.requests = append(store.requests, req)
	idx := len(store.requests) - 1
	store.verifyMap[verifyToken] = idx
	store.downloadMap[downloadToken] = idx
	store.mu.Unlock()
	saveRequests()

	sendVerificationEmail(email, verifyToken, password)

	http.Redirect(w, r, "/verify-sent?email="+email, http.StatusSeeOther)
}

func handleVerifySent(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	render(w, "base.html", map[string]interface{}{
		"ContentTemplate": "verify_sent_content",
		"Title":           "Проверьте почту",
		"Email":           email,
	})
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Redirect(w, r, "/access", http.StatusSeeOther)
		return
	}
	store.mu.Lock()
	idx, ok := store.verifyMap[token]
	if !ok || idx >= len(store.requests) {
		store.mu.Unlock()
		http.Redirect(w, r, "/access?error=invalid", http.StatusSeeOther)
		return
	}
	req := &store.requests[idx]
	now := time.Now()
	req.VerifiedAt = &now
	delete(store.verifyMap, token)
	downloadToken := req.DownloadToken
	store.mu.Unlock()
	saveRequests()

	sessionID := mustGenerateToken()
	store.mu.Lock()
	store.sessions[sessionID] = &Session{
		Email:         req.Email,
		DownloadToken: downloadToken,
		ExpiresAt:     time.Now().Add(sessionDuration),
	}
	store.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   int(sessionDuration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/download", http.StatusSeeOther)
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/access", http.StatusSeeOther)
		return
	}
	store.mu.RLock()
	session := store.sessions[cookie.Value]
	store.mu.RUnlock()
	if session == nil || time.Now().After(session.ExpiresAt) {
		http.Redirect(w, r, "/access", http.StatusSeeOther)
		return
	}

	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	downloadURL := baseURL + "/download/file?token=" + session.DownloadToken

	render(w, "base.html", map[string]interface{}{
		"ContentTemplate": "download_content",
		"Title":           "Скачать резюме",
		"DownloadURL":     downloadURL,
	})
}

func handleDownloadFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Redirect(w, r, "/access?error=invalid", http.StatusSeeOther)
		return
	}

	store.mu.Lock()
	idx, ok := store.downloadMap[token]
	if !ok || idx >= len(store.requests) {
		store.mu.Unlock()
		http.Redirect(w, r, "/access?error=invalid", http.StatusSeeOther)
		return
	}
	req := &store.requests[idx]
	if req.DownloadedAt != nil {
		store.mu.Unlock()
		http.Redirect(w, r, "/access?error=used", http.StatusSeeOther)
		return
	}
	now := time.Now()
	req.DownloadedAt = &now
	delete(store.downloadMap, token)
	store.mu.Unlock()
	saveRequests()

	resumePath := os.Getenv("RESUME_PATH")
	if resumePath == "" {
		log.Printf("RESUME_PATH not set, cannot serve file")
		http.Error(w, "Файл резюме не настроен.", http.StatusInternalServerError)
		return
	}
	data, err := os.ReadFile(resumePath)
	if err != nil {
		log.Printf("read resume: %v", err)
		http.Error(w, "Файл недоступен.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "attachment; filename=resume.pdf")
	w.Write(data)
}

func handleTerms(w http.ResponseWriter, r *http.Request) {
	render(w, "base.html", map[string]interface{}{
		"ContentTemplate": "terms_content",
		"Title":           "Условия использования",
	})
}

// --- admin ---

func adminAuthenticated(r *http.Request) bool {
	c, err := r.Cookie(adminCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	secret := os.Getenv("ADMIN_SECRET")
	if secret == "" {
		return false
	}
	h := sha256.Sum256([]byte(secret))
	expected := hex.EncodeToString(h[:])
	return c.Value == expected
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin" {
		http.NotFound(w, r)
		return
	}
	if !adminAuthenticated(r) {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	store.mu.RLock()
	requests := make([]Request, len(store.requests))
	copy(requests, store.requests)
	store.mu.RUnlock()
	// newest first
	for i, j := 0, len(requests)-1; i < j; i, j = i+1, j-1 {
		requests[i], requests[j] = requests[j], requests[i]
	}

	render(w, "base.html", map[string]interface{}{
		"ContentTemplate": "admin_content",
		"Title":           "Заявки на резюме",
		"Requests":        requests,
	})
}

func handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if adminAuthenticated(r) {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		password := r.FormValue("password")
		secret := os.Getenv("ADMIN_SECRET")
		if secret != "" && password == secret {
			h := sha256.Sum256([]byte(secret))
			http.SetCookie(w, &http.Cookie{
				Name:     adminCookieName,
				Value:    hex.EncodeToString(h[:]),
				Path:     "/",
				MaxAge:   86400 * 7, // 7 days
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		render(w, "base.html", map[string]interface{}{
			"ContentTemplate": "admin_login_content",
			"Title":           "Вход",
			"Error":           "Неверный пароль",
		})
		return
	}
	render(w, "base.html", map[string]interface{}{
		"ContentTemplate": "admin_login_content",
		"Title":           "Вход",
	})
}

func handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   adminCookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// --- helpers ---

func render(w http.ResponseWriter, name string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template %s: %v", name, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func mustGenerateToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func mustGeneratePassword() string {
	const length = 12
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	out := make([]byte, length)
	for i := range out {
		out[i] = passwordChars[int(b[i])%len(passwordChars)]
	}
	return string(out)
}

func sendVerificationEmail(to, verifyToken, password string) {
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	verifyURL := baseURL + "/verify?token=" + verifyToken

	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")

	body := "Здравствуйте.\r\n\r\n" +
		"Код подтверждения (введите при необходимости): " + password + "\r\n" +
		"Он нужен только чтобы убедиться, что письмо получил человек с реальным адресом.\r\n\r\n" +
		"Перейдите по ссылке для перехода на страницу скачивания резюме (скачать можно будет только один раз):\r\n\r\n" +
		verifyURL + "\r\n\r\n" +
		"Ссылка действительна 24 часа.\r\n"

	if smtpHost == "" || smtpUser == "" {
		log.Printf("[EMAIL] To: %s | Code: %s | Verify: %s", to, password, verifyURL)
		return
	}

	addr := smtpHost
	if smtpPort != "" {
		addr = smtpHost + ":" + smtpPort
	}
	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
	msg := []byte("To: " + to + "\r\n" +
		"Subject: Доступ к резюме (одноразовая ссылка)\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		body)
	if err := smtp.SendMail(addr, auth, smtpUser, []string{to}, msg); err != nil {
		log.Printf("send mail: %v", err)
	}
}

func cleanExpiredSessions() {
	store.mu.Lock()
	defer store.mu.Unlock()
	now := time.Now()
	for id, s := range store.sessions {
		if now.After(s.ExpiresAt) {
			delete(store.sessions, id)
		}
	}
}
