package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// ─── Global State ─────────────────────────────────────────────────────────────

var (
	db         *sql.DB
	sessionsMu sync.RWMutex
	sessions   = make(map[string]SessionData, 256)

	// Response buffer pool — reuse allocations across requests
	bufPool = sync.Pool{
		New: func() any { return bytes.NewBuffer(make([]byte, 0, 512)) },
	}

	// Pre-encoded static HTML page bytes — served from memory, zero alloc per request
	htmlPageBytes []byte
)

type SessionData struct {
	Username  string
	ExpiresAt time.Time
}

// ─── MD5 Helper ───────────────────────────────────────────────────────────────

func md5Hash(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func hashit(salt, password string) string {
	step3 := strings.ToLower(md5Hash(salt)) + strings.ToLower(md5Hash(password))
	return strings.ToLower(md5Hash(step3))
}

// ─── Session Helpers ──────────────────────────────────────────────────────────

// secureToken generates a cryptographically random 32-byte hex token
func secureToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func createSession(username string) string {
	token := secureToken()
	sessionsMu.Lock()
	sessions[token] = SessionData{Username: username, ExpiresAt: time.Now().Add(24 * time.Hour)}
	sessionsMu.Unlock()
	return token
}

func getSession(r *http.Request) (SessionData, bool) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return SessionData{}, false
	}
	sessionsMu.RLock()
	s, ok := sessions[cookie.Value]
	sessionsMu.RUnlock()
	if !ok || time.Now().After(s.ExpiresAt) {
		return SessionData{}, false
	}
	return s, true
}

func deleteSession(r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return
	}
	sessionsMu.Lock()
	delete(sessions, cookie.Value)
	sessionsMu.Unlock()
}

// cleanExpiredSessions runs in background, purges stale sessions every 30 min
func cleanExpiredSessions() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		sessionsMu.Lock()
		for k, v := range sessions {
			if now.After(v.ExpiresAt) {
				delete(sessions, k)
			}
		}
		sessionsMu.Unlock()
	}
}

// ─── DB Init ──────────────────────────────────────────────────────────────────

func initDB() {
	host := getEnv("DB_HOST", "208.84.103.75")
	port := getEnv("DB_PORT", "3306")
	user := getEnv("DB_USER", "u1649_NtHPQzNRvz")
	pass := getEnv("DB_PASS", "qJHEEZZraPLuQGGOtHPSvWT=")
	name := getEnv("DB_NAME", "s1649_Dewata")

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?parseTime=true&collation=utf8mb4_unicode_ci&timeout=10s&readTimeout=15s&writeTimeout=15s&interpolateParams=true",
		user, pass, host, port, name,
	)
	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Printf("DB open error: %v", err)
		return
	}

	// Tune connection pool based on CPU count
	cpus := runtime.NumCPU()
	maxOpen := cpus * 8
	if maxOpen < 16 {
		maxOpen = 16
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(cpus * 2)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(2 * time.Minute)

	if err = db.Ping(); err != nil {
		log.Printf("DB ping error: %v", err)
	} else {
		log.Printf("Database connected! (pool: max=%d idle=%d)", maxOpen, cpus*2)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ─── JSON Response (zero-alloc buffer pool) ───────────────────────────────────

func jsonResp(w http.ResponseWriter, code int, data any) {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	if err := json.NewEncoder(buf).Encode(data); err != nil {
		bufPool.Put(buf)
		http.Error(w, `{"error":"encode error"}`, 500)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	w.Write(buf.Bytes())
	bufPool.Put(buf)
}

// ─── Security + Middleware ────────────────────────────────────────────────────

// securityHeaders adds hardened HTTP headers to every response
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-XSS-Protection", "1; mode=block")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}



// maxBodyBytes is the max request body we accept (4 KB is plenty for JSON API)
const maxBodyBytes = 4 * 1024

// decodeJSON decodes r.Body into v with a 4 KB cap — prevents large-body DoS
func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(&io.LimitedReader{R: r.Body, N: maxBodyBytes})
	return dec.Decode(v)
}

// ─── API Handlers ──────────────────────────────────────────────────────────────

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonResp(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}
	var pName, pPassword, passSalt string
	err := db.QueryRow("SELECT pName, pPassword, pass_salt FROM accounts WHERE pName=?", req.Username).
		Scan(&pName, &pPassword, &passSalt)
	if err == sql.ErrNoRows {
		jsonResp(w, 401, map[string]string{"error": "username tidak ditemukan"})
		return
	} else if err != nil {
		jsonResp(w, 500, map[string]string{"error": "db error"})
		return
	}
	hashed := hashit(passSalt, req.Password)
	if hashed != pPassword {
		jsonResp(w, 401, map[string]string{"error": "password salah"})
		return
	}
	jsonResp(w, 200, map[string]string{"status": "ok", "username": pName})
}

func handleVerifyAdminKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Username string `json:"username"`
		AdminKey string `json:"admin_key"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonResp(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}
	var name, key string
	err := db.QueryRow("SELECT Name, pAdminKey FROM admin WHERE Name=?", req.Username).Scan(&name, &key)
	if err == sql.ErrNoRows {
		jsonResp(w, 401, map[string]string{"error": "kamu bukan admin"})
		return
	} else if err != nil {
		jsonResp(w, 500, map[string]string{"error": "db error"})
		return
	}
	if key != req.AdminKey {
		jsonResp(w, 401, map[string]string{"error": "admin key salah"})
		return
	}
	token := createSession(req.Username)
	http.SetCookie(w, &http.Cookie{Name: "session_token", Value: token, Path: "/", HttpOnly: true, MaxAge: 86400})
	jsonResp(w, 200, map[string]string{"status": "ok", "username": name})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	deleteSession(r)
	http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "", Path: "/", MaxAge: -1})
	jsonResp(w, 200, map[string]string{"status": "ok"})
}

func handleCheckAuth(w http.ResponseWriter, r *http.Request) {
	s, ok := getSession(r)
	if !ok {
		jsonResp(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	jsonResp(w, 200, map[string]string{"status": "ok", "username": s.Username})
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, ok := getSession(r)
		if !ok {
			jsonResp(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func handleGetcordList(w http.ResponseWriter, r *http.Request) {
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}
	rows, err := db.Query("SELECT id, Name, X, Y, Z, A FROM getcord ORDER BY id")
	if err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Cord struct {
		ID   int     `json:"id"`
		Name string  `json:"name"`
		X    float64 `json:"x"`
		Y    float64 `json:"y"`
		Z    float64 `json:"z"`
		A    float64 `json:"a"`
	}
	var list []Cord
	for rows.Next() {
		var c Cord
		if err := rows.Scan(&c.ID, &c.Name, &c.X, &c.Y, &c.Z, &c.A); err == nil {
			list = append(list, c)
		}
	}
	if list == nil {
		list = []Cord{}
	}
	jsonResp(w, 200, list)
}

func handleDeleteGetcord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", 405)
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/getcord/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonResp(w, 400, map[string]string{"error": "invalid id"})
		return
	}
	_, err = db.Exec("DELETE FROM getcord WHERE id=?", id)
	if err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}
	jsonResp(w, 200, map[string]string{"status": "deleted"})
}

func handleCheckUser(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		jsonResp(w, 400, map[string]string{"error": "username required"})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}
	var name string
	err := db.QueryRow("SELECT pName FROM accounts WHERE pName=?", username).Scan(&name)
	if err == sql.ErrNoRows {
		jsonResp(w, 404, map[string]string{"error": "user tidak ditemukan"})
		return
	} else if err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}
	jsonResp(w, 200, map[string]string{"status": "found"})
}

// ─── Central Limit Map ────────────────────────────────────────────────────────
// Single source of truth — edit limit di sini saja
var columnLimits = map[string]int64{
	// Money
	"pCash":      500_000_000,
	"pBank":      500_000_000,
	"pUangMerah": 500_000_000,
	"pRouble":    1_000,
	// Items
	"pBatu":      1_000,
	"pBatuk":     1_000,
	"pFish":      1_000,
	"pPenyu":     1_000,
	"pDolphin":   1_000,
	"pHiu":       1_000,
	"pMegalodon": 1_000,
	"pCaught":    1_000,
	"pPadi":      1_000,
	"pAyam":      1_000,
	"pSemen":     1_000,
	"pEmas":      1_000,
	"pSusu":      1_000,
	"pMinyak":    1_000,
	"pAyamKemas": 1_000,
	"pAyamPotong":1_000,
	"pAyamHidup": 1_000,
	"pBulu":      1_000,
	// Account
	"pDrugs":     500,
	"pMicin":     500,
	"pSteroid":   500,
	"pComponent": 5_000,
	"pMetall":    5_000,
	"pFood":      200,
	"pDrink":     200,
}

func checkLimit(col string, val int64) error {
	limit, ok := columnLimits[col]
	if !ok {
		return nil // kolom tanpa limit khusus
	}
	if val < 0 {
		return fmt.Errorf("value tidak boleh negatif")
	}
	if val > limit {
		return fmt.Errorf("value melebihi batas maksimal %s untuk kolom %s",
			formatLimit(limit), col)
	}
	return nil
}

func formatLimit(n int64) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%g miliar", float64(n)/1_000_000_000)
	case n >= 1_000_000:
		return fmt.Sprintf("%g juta", float64(n)/1_000_000)
	default:
		return fmt.Sprintf("%d", n)
	}
}

func handleSetMoney(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Username string `json:"username"`
		Type     string `json:"type"`
		Value    int64  `json:"value"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonResp(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	allowedTypes := map[string]bool{"pRouble": true, "pCash": true, "pBank": true, "pUangMerah": true}
	if !allowedTypes[req.Type] {
		jsonResp(w, 400, map[string]string{"error": "type tidak valid"})
		return
	}
	if err := checkLimit(req.Type, req.Value); err != nil {
		jsonResp(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}
	var name string
	if err := db.QueryRow("SELECT pName FROM accounts WHERE pName=?", req.Username).Scan(&name); err == sql.ErrNoRows {
		jsonResp(w, 404, map[string]string{"error": "user tidak ditemukan"})
		return
	}
	query := fmt.Sprintf("UPDATE accounts SET %s=? WHERE pName=?", req.Type)
	if _, err := db.Exec(query, req.Value, req.Username); err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s, _ := getSession(r)
	logAction(s.Username, fmt.Sprintf("Set %s %s -> %d", req.Type, req.Username, req.Value))
	jsonResp(w, 200, map[string]string{"status": "updated"})
}

func handleSetItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Username string `json:"username"`
		Type     string `json:"type"`
		Value    int64  `json:"value"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonResp(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	itemTypes := map[string]bool{
		"pBatu": true, "pBatuk": true, "pFish": true, "pPenyu": true,
		"pDolphin": true, "pHiu": true, "pMegalodon": true, "pCaught": true,
		"pPadi": true, "pAyam": true, "pSemen": true, "pEmas": true,
		"pSusu": true, "pMinyak": true, "pAyamKemas": true, "pAyamPotong": true,
		"pAyamHidup": true, "pBulu": true,
	}
	if !itemTypes[req.Type] {
		jsonResp(w, 400, map[string]string{"error": "type tidak valid"})
		return
	}
	if err := checkLimit(req.Type, req.Value); err != nil {
		jsonResp(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}
	var name string
	if err := db.QueryRow("SELECT pName FROM accounts WHERE pName=?", req.Username).Scan(&name); err == sql.ErrNoRows {
		jsonResp(w, 404, map[string]string{"error": "user tidak ditemukan"})
		return
	}
	query := fmt.Sprintf("UPDATE accounts SET %s=? WHERE pName=?", req.Type)
	if _, err := db.Exec(query, req.Value, req.Username); err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s, _ := getSession(r)
	logAction(s.Username, fmt.Sprintf("Set item %s %s -> %d", req.Type, req.Username, req.Value))
	jsonResp(w, 200, map[string]string{"status": "updated"})
}

func handleSetAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Username string `json:"username"`
		Type     string `json:"type"`
		Value    int64  `json:"value"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonResp(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	accTypes := map[string]bool{
		"pDrugs": true, "pMicin": true, "pSteroid": true,
		"pComponent": true, "pMetall": true, "pFood": true, "pDrink": true,
	}
	if !accTypes[req.Type] {
		jsonResp(w, 400, map[string]string{"error": "type tidak valid"})
		return
	}
	if err := checkLimit(req.Type, req.Value); err != nil {
		jsonResp(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}
	var name string
	if err := db.QueryRow("SELECT pName FROM accounts WHERE pName=?", req.Username).Scan(&name); err == sql.ErrNoRows {
		jsonResp(w, 404, map[string]string{"error": "user tidak ditemukan"})
		return
	}
	query := fmt.Sprintf("UPDATE accounts SET %s=? WHERE pName=?", req.Type)
	if _, err := db.Exec(query, req.Value, req.Username); err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s, _ := getSession(r)
	logAction(s.Username, fmt.Sprintf("Set account %s %s -> %d", req.Type, req.Username, req.Value))
	jsonResp(w, 200, map[string]string{"status": "updated"})
}

func handleSetProperty(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Username string      `json:"username"`
		Type     string      `json:"type"`
		Value    interface{} `json:"value"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonResp(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	propTypes := map[string]bool{"pSkin": true, "pMaskID": true, "pCS": true, "pFreeRoulet": true}
	if !propTypes[req.Type] {
		jsonResp(w, 400, map[string]string{"error": "type tidak valid"})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}
	var name string
	if err := db.QueryRow("SELECT pName FROM accounts WHERE pName=?", req.Username).Scan(&name); err == sql.ErrNoRows {
		jsonResp(w, 404, map[string]string{"error": "user tidak ditemukan"})
		return
	}
	// Validate specific constraints
	switch req.Type {
	case "pMaskID":
		val := int64(req.Value.(float64))
		if val > 9999 {
			jsonResp(w, 400, map[string]string{"error": "mask ID max 4 digit"})
			return
		}
	case "pFreeRoulet":
		val := int64(req.Value.(float64))
		if val > 300 {
			jsonResp(w, 400, map[string]string{"error": "max gacha 300"})
			return
		}
	}
	query := fmt.Sprintf("UPDATE accounts SET %s=? WHERE pName=?", req.Type)
	if _, err := db.Exec(query, req.Value, req.Username); err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s, _ := getSession(r)
	logAction(s.Username, fmt.Sprintf("Set property %s %s -> %v", req.Type, req.Username, req.Value))
	jsonResp(w, 200, map[string]string{"status": "updated"})
}

func handleAdminLog(w http.ResponseWriter, r *http.Request) {
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}
	rows, err := db.Query("SELECT user_id, action, date FROM admin_log ORDER BY date DESC LIMIT 200")
	if err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	type LogEntry struct {
		UserID int    `json:"user_id"`
		Action string `json:"action"`
		Date   string `json:"date"`
	}
	list := make([]LogEntry, 0, 200)
	for rows.Next() {
		var e LogEntry
		var rawDate []byte
		if err := rows.Scan(&e.UserID, &e.Action, &rawDate); err == nil {
			e.Date = string(rawDate)
			list = append(list, e)
		}
	}
	jsonResp(w, 200, list)
}

// logActionCh is a buffered channel for async, non-blocking log writes
var logActionCh = make(chan logEntry, 512)

type logEntry struct {
	UserID int
	Action string
	Date   string
}

// startLogWorker drains logActionCh and batches INSERT to DB in background
func startLogWorker() {
	go func() {
		for e := range logActionCh {
			if db == nil {
				continue
			}
			db.Exec("INSERT INTO admin_log (user_id, action, date) VALUES (?, ?, ?)",
				e.UserID, e.Action, e.Date)
		}
	}()
}

// lookupAccountID returns pID for a given username — uses pID per actual schema
func lookupAccountID(username string) int {
	if db == nil {
		return 0
	}
	var id int
	db.QueryRow("SELECT pID FROM accounts WHERE pName=? LIMIT 1", username).Scan(&id)
	return id
}

// logAction is fully async — never blocks request handlers
func logAction(username, action string) {
	uid := lookupAccountID(username)
	select {
	case logActionCh <- logEntry{
		UserID: uid,
		Action: action,
		Date:   time.Now().Format("2006-01-02 15:04:05"),
	}:
	default:
		// channel full — drop silently rather than block
	}
}

// ─── Set Gun ──────────────────────────────────────────────────────────────────

// SAMP weapon IDs 23-31 mapping
var weaponNames = map[int]string{
	23: "Silenced Pistol",
	24: "Desert Eagle",
	25: "Shotgun",
	26: "Sawnoff Shotgun",
	27: "Combat Shotgun",
	28: "Micro SMG / Uzi",
	29: "MP5",
	30: "AK-47",
	31: "M4",
}

func handleSetGun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Username string `json:"username"`
		GunID    int    `json:"gun_id"`
		Ammo     int    `json:"ammo"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonResp(w, 400, map[string]string{"error": "invalid request"})
		return
	}

	// Validate gun id
	gunName, ok := weaponNames[req.GunID]
	if !ok {
		jsonResp(w, 400, map[string]string{"error": "gun ID tidak valid, hanya ID 23-31 yang diizinkan"})
		return
	}

	// Validate ammo
	if req.Ammo < 0 || req.Ammo > 1000 {
		jsonResp(w, 400, map[string]string{"error": "ammo harus antara 0-1000"})
		return
	}

	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}

	// Check user exists
	var pName string
	if err := db.QueryRow("SELECT pName FROM accounts WHERE pName=?", req.Username).Scan(&pName); err == sql.ErrNoRows {
		jsonResp(w, 404, map[string]string{"error": "user tidak ditemukan"})
		return
	} else if err != nil {
		jsonResp(w, 500, map[string]string{"error": "db error: " + err.Error()})
		return
	}

	// Read current pGun and pAmmo
	var pGunStr, pAmmoStr string
	if err := db.QueryRow("SELECT pGun, pAmmo FROM accounts WHERE pName=?", req.Username).Scan(&pGunStr, &pAmmoStr); err != nil {
		jsonResp(w, 500, map[string]string{"error": "gagal baca data senjata: " + err.Error()})
		return
	}

	// Parse comma-separated strings into slices of 13
	parseSlot := func(s string) []string {
		parts := strings.Split(s, ",")
		for len(parts) < 13 {
			parts = append(parts, "0")
		}
		return parts[:13]
	}
	guns := parseSlot(pGunStr)
	ammos := parseSlot(pAmmoStr)

	// Find slot: first check if gunID already exists in a slot (update that slot)
	// Otherwise find first empty slot (value == "0")
	slotIndex := -1
	for i, g := range guns {
		if strings.TrimSpace(g) == fmt.Sprintf("%d", req.GunID) {
			slotIndex = i
			break
		}
	}
	if slotIndex == -1 {
		// Find first empty slot
		for i, g := range guns {
			if strings.TrimSpace(g) == "0" {
				slotIndex = i
				break
			}
		}
	}
	if slotIndex == -1 {
		jsonResp(w, 400, map[string]string{"error": "semua slot senjata sudah penuh (13 slot)"})
		return
	}

	// Set the gun and ammo at the found slot
	guns[slotIndex] = fmt.Sprintf("%d", req.GunID)
	ammos[slotIndex] = fmt.Sprintf("%d", req.Ammo)

	newGun := strings.Join(guns, ",")
	newAmmo := strings.Join(ammos, ",")

	_, err := db.Exec("UPDATE accounts SET pGun=?, pAmmo=? WHERE pName=?", newGun, newAmmo, req.Username)
	if err != nil {
		jsonResp(w, 500, map[string]string{"error": "gagal update: " + err.Error()})
		return
	}

	s, _ := getSession(r)
	logAction(s.Username, fmt.Sprintf("Set gun %s (ID:%d) ammo:%d untuk %s di slot %d", gunName, req.GunID, req.Ammo, req.Username, slotIndex))

	jsonResp(w, 200, map[string]any{
		"status":    "updated",
		"slot":      slotIndex,
		"gun_name":  gunName,
		"pGun":      newGun,
		"pAmmo":     newAmmo,
	})
}

func handleGetGunSlots(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		jsonResp(w, 400, map[string]string{"error": "username required"})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}
	var pGun, pAmmo string
	err := db.QueryRow("SELECT pGun, pAmmo FROM accounts WHERE pName=?", username).Scan(&pGun, &pAmmo)
	if err == sql.ErrNoRows {
		jsonResp(w, 404, map[string]string{"error": "user tidak ditemukan"})
		return
	} else if err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}
	jsonResp(w, 200, map[string]string{"pGun": pGun, "pAmmo": pAmmo})
}

// ─── Set Vehicle ──────────────────────────────────────────────────────────────

var vehicleNames = map[int]string{
	400: "Landstalker", 401: "Bravura", 402: "Buffalo", 403: "Linerunner",
	404: "Pereniel", 405: "Sentinel", 406: "Dumper", 407: "Firetruck",
	408: "Trashmaster", 409: "Stretch", 410: "Manana", 411: "Infernus",
	412: "Voodoo", 413: "Pony", 414: "Mule", 415: "Cheetah",
	416: "Ambulance", 417: "Leviathan", 418: "Moonbeam", 419: "Esperanto",
	420: "Taxi", 421: "Washington", 422: "Bobcat", 423: "Mr Whoopee",
	424: "BF Injection", 425: "Hunter", 426: "Premier", 427: "Enforcer",
	428: "Securicar", 429: "Banshee", 430: "Predator", 431: "Bus",
	432: "Rhino", 433: "Barracks", 434: "Hotknife", 435: "Trailer",
	436: "Previon", 437: "Coach", 438: "Cabbie", 439: "Stallion",
	440: "Rumpo", 441: "RC Bandit", 442: "Romero", 443: "Packer",
	444: "Monster", 445: "Admiral", 446: "Squalo", 447: "Seasparrow",
	448: "Pizzaboy", 449: "Tram", 450: "Trailer 2", 451: "Turismo",
	452: "Speeder", 453: "Reefer", 454: "Tropic", 455: "Flatbed",
	456: "Yankee", 457: "Caddy", 458: "Solair", 459: "Berkley's RC Van",
	460: "Skimmer", 461: "PCJ-600", 462: "Faggio", 463: "Freeway",
	464: "RC Baron", 465: "RC Raider", 466: "Glendale", 467: "Oceanic",
	468: "Sanchez", 469: "Sparrow", 470: "Patriot", 471: "Quad",
	472: "Coastguard", 473: "Dinghy", 474: "Hermes", 475: "Sabre",
	476: "Rustler", 477: "ZR-350", 478: "Walton", 479: "Regina",
	480: "Comet", 481: "BMX", 482: "Burrito", 483: "Camper",
	484: "Marquis", 485: "Baggage", 486: "Dozer", 487: "Maverick",
	488: "News Chopper", 489: "Rancher", 490: "FBI Rancher", 491: "Virgo",
	492: "Greenwood", 493: "Jetmax", 494: "Hotring", 495: "Sandking",
	496: "Blista Compact", 497: "Police Maverick", 498: "Boxville",
	499: "Benson", 500: "Mesa", 501: "RC Goblin", 502: "Hotring Racer A",
	503: "Hotring Racer B", 504: "Bloodring Banger", 505: "Rancher",
	506: "Super GT", 507: "Elegant", 508: "Journey", 509: "Bike",
	510: "Mountain Bike", 511: "Beagle", 512: "Cropduster", 513: "Stuntplane",
	514: "Tanker", 515: "Roadtrain", 516: "Nebula", 517: "Majestic",
	518: "Buccaneer", 519: "Shamal", 520: "Hydra", 521: "FCR-900",
	522: "NRG-500", 523: "HPV1000", 524: "Cement Truck", 525: "Tow Truck",
	526: "Fortune", 527: "Cadrona", 528: "FBI Truck", 529: "Willard",
	530: "Forklift", 531: "Tractor", 532: "Combine", 533: "Feltzer",
	534: "Remington", 535: "Slamvan", 536: "Blade", 537: "Freight",
	538: "Streak", 539: "Vortex", 540: "Vincent", 541: "Bullet",
	542: "Clover", 543: "Sadler", 544: "Firetruck LA", 545: "Hustler",
	546: "Intruder", 547: "Primo", 548: "Cargobob", 549: "Tampa",
	550: "Sunrise", 551: "Merit", 552: "Utility", 553: "Nevada",
	554: "Yosemite", 555: "Windsor", 556: "Monster A", 557: "Monster B",
	558: "Uranus", 559: "Jester", 560: "Sultan", 561: "Stratum",
	562: "Elegy", 563: "Raindance", 564: "RC Tiger", 565: "Flash",
	566: "Tahoma", 567: "Savanna", 568: "Bandito", 569: "Freight Flat",
	570: "Streak Carriage", 571: "Kart", 572: "Mower", 573: "Dune",
	574: "Sweeper", 575: "Broadway", 576: "Tornado", 577: "AT-400",
	578: "DFT-30", 579: "Huntley", 580: "Stafford", 581: "BF-400",
	582: "Newsvan", 583: "Tug", 584: "Trailer 3", 585: "Emperor",
	586: "Wayfarer", 587: "Euros", 588: "Hotdog", 589: "Club",
	590: "Freight Box", 591: "Trailer 4", 592: "Andromada", 593: "Dodo",
	594: "RC Cam", 595: "Launch", 596: "Police Car LSPD",
	597: "Police Car SFPD", 598: "Police Car LVPD", 599: "Police Ranger",
	600: "Picador", 601: "S.W.A.T.", 602: "Alpha", 603: "Phoenix",
	604: "Glendale Shit", 605: "Sadler Shit", 606: "Baggage Trailer A",
	607: "Baggage Trailer B", 608: "Tug Stairs Trailer", 609: "Boxville",
	610: "Farm Plow", 611: "Utility Trailer",
}

func handleSetVeh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Username string `json:"username"`
		VehID    int    `json:"veh_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonResp(w, 400, map[string]string{"error": "invalid request"})
		return
	}

	vehName, ok := vehicleNames[req.VehID]
	if !ok {
		jsonResp(w, 400, map[string]string{"error": "vehicle ID tidak valid (400-611)"})
		return
	}

	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}

	var pName string
	if err := db.QueryRow("SELECT pName FROM accounts WHERE pName=?", req.Username).Scan(&pName); err == sql.ErrNoRows {
		jsonResp(w, 404, map[string]string{"error": "user tidak ditemukan"})
		return
	} else if err != nil {
		jsonResp(w, 500, map[string]string{"error": "db error: " + err.Error()})
		return
	}

	var cModelStr string
	if err := db.QueryRow("SELECT cModel FROM accounts WHERE pName=?", req.Username).Scan(&cModelStr); err != nil {
		jsonResp(w, 500, map[string]string{"error": "gagal baca data kendaraan: " + err.Error()})
		return
	}

	// Parse 5-slot comma-separated string
	parts := strings.Split(cModelStr, ",")
	for len(parts) < 5 {
		parts = append(parts, "0")
	}
	slots := parts[:5]

	// Check if vehicle already in a slot → update that slot
	slotIndex := -1
	for i, v := range slots {
		if strings.TrimSpace(v) == fmt.Sprintf("%d", req.VehID) {
			slotIndex = i
			break
		}
	}
	// Otherwise find first empty slot
	if slotIndex == -1 {
		for i, v := range slots {
			if strings.TrimSpace(v) == "0" {
				slotIndex = i
				break
			}
		}
	}
	if slotIndex == -1 {
		jsonResp(w, 400, map[string]string{"error": "semua slot kendaraan sudah penuh (5 slot)"})
		return
	}

	slots[slotIndex] = fmt.Sprintf("%d", req.VehID)
	newCModel := strings.Join(slots, ",")

	if _, err := db.Exec("UPDATE accounts SET cModel=? WHERE pName=?", newCModel, req.Username); err != nil {
		jsonResp(w, 500, map[string]string{"error": "gagal update: " + err.Error()})
		return
	}

	s, _ := getSession(r)
	logAction(s.Username, fmt.Sprintf("Set kendaraan %s (ID:%d) untuk %s di slot %d", vehName, req.VehID, req.Username, slotIndex))

	jsonResp(w, 200, map[string]any{
		"status":   "updated",
		"slot":     slotIndex,
		"veh_name": vehName,
		"cModel":   newCModel,
	})
}

func handleGetVehSlots(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		jsonResp(w, 400, map[string]string{"error": "username required"})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}
	var cModel string
	err := db.QueryRow("SELECT cModel FROM accounts WHERE pName=?", username).Scan(&cModel)
	if err == sql.ErrNoRows {
		jsonResp(w, 404, map[string]string{"error": "user tidak ditemukan"})
		return
	} else if err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}
	jsonResp(w, 200, map[string]string{"cModel": cModel})
}



// ─── Set VIP ──────────────────────────────────────────────────────────────────

func handleSetVip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Username string `json:"username"`
		VipType  int    `json:"vip_type"`
		Days     int    `json:"days"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonResp(w, 400, map[string]string{"error": "invalid request"})
		return
	}

	// Validate vip type
	vipNames := map[int]string{0: "Non-VIP", 1: "VIP Low", 2: "VIP Medium", 3: "VIP High"}
	vipName, ok := vipNames[req.VipType]
	if !ok {
		jsonResp(w, 400, map[string]string{"error": "tipe VIP tidak valid (0-3)"})
		return
	}

	// Validate days — only required when activating VIP (type > 0)
	if req.VipType > 0 {
		if req.Days <= 0 {
			jsonResp(w, 400, map[string]string{"error": "hari harus lebih dari 0 saat mengaktifkan VIP"})
			return
		}
		if req.Days > 3650 {
			jsonResp(w, 400, map[string]string{"error": "maksimal 3650 hari (10 tahun)"})
			return
		}
	}

	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}

	// Check user exists
	var pName string
	if err := db.QueryRow("SELECT pName FROM accounts WHERE pName=?", req.Username).Scan(&pName); err == sql.ErrNoRows {
		jsonResp(w, 404, map[string]string{"error": "user tidak ditemukan"})
		return
	} else if err != nil {
		jsonResp(w, 500, map[string]string{"error": "db error: " + err.Error()})
		return
	}

	// pVipTime stores remaining days as integer
	var vipTime int
	if req.VipType == 0 {
		vipTime = 0 // nonaktifkan, reset waktu
	} else {
		// Read current pVipTime and add on top if already active
		var curTime int
		db.QueryRow("SELECT pVipTime FROM accounts WHERE pName=?", req.Username).Scan(&curTime)
		if curTime > 0 {
			vipTime = curTime + req.Days // tambah ke sisa waktu yang ada
		} else {
			vipTime = req.Days
		}
	}

	_, err := db.Exec("UPDATE accounts SET pVip=?, pVipTime=? WHERE pName=?", req.VipType, vipTime, req.Username)
	if err != nil {
		jsonResp(w, 500, map[string]string{"error": "gagal update: " + err.Error()})
		return
	}

	s, _ := getSession(r)
	if req.VipType == 0 {
		logAction(s.Username, fmt.Sprintf("Nonaktifkan VIP untuk %s", req.Username))
	} else {
		logAction(s.Username, fmt.Sprintf("Set %s +%d hari (total %d hari) untuk %s", vipName, req.Days, vipTime, req.Username))
	}

	jsonResp(w, 200, map[string]any{
		"status":   "updated",
		"vip_name": vipName,
		"vip_type": req.VipType,
		"vip_time": vipTime,
	})
}

func handleGetVip(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		jsonResp(w, 400, map[string]string{"error": "username required"})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}
	var pVip, pVipTime int
	err := db.QueryRow("SELECT pVip, pVipTime FROM accounts WHERE pName=?", username).Scan(&pVip, &pVipTime)
	if err == sql.ErrNoRows {
		jsonResp(w, 404, map[string]string{"error": "user tidak ditemukan"})
		return
	} else if err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}
	jsonResp(w, 200, map[string]any{"pVip": pVip, "pVipTime": pVipTime})
}

// ─── Inventory ────────────────────────────────────────────────────────────────

func handleGetInventory(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		jsonResp(w, 400, map[string]string{"error": "username required"})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}

	type InventoryData struct {
		// Identity
		PName    string `json:"pName"`
		PLevel   int    `json:"pLevel"`
		PExp     int    `json:"pExp"`
		PJob     int    `json:"pJob"`
		PMember  int    `json:"pMember"`
		PRank    int    `json:"pRank"`
		PVip     int    `json:"pVip"`
		PVipTime int    `json:"pVipTime"`
		// Money
		PCash      int64 `json:"pCash"`
		PBank      int64 `json:"pBank"`
		PUangMerah int64 `json:"pUangMerah"`
		PRouble    int   `json:"pRouble"`
		PGopay     int   `json:"pGopay"`
		// Items
		PBatu      int `json:"pBatu"`
		PBatuk     int `json:"pBatuk"`
		PFish      int `json:"pFish"`
		PPenyu     int `json:"pPenyu"`
		PDolphin   int `json:"pDolphin"`
		PHiu       int `json:"pHiu"`
		PMegalodon int `json:"pMegalodon"`
		PCaught    int `json:"pCaught"`
		PPadi      int `json:"pPadi"`
		PAyam      int `json:"pAyam"`
		PSemen     int `json:"pSemen"`
		PEmas      int `json:"pEmas"`
		PSusu      int `json:"pSusu"`
		PMinyak    int `json:"pMinyak"`
		PAyamKemas  int `json:"pAyamKemas"`
		PAyamPotong int `json:"pAyamPotong"`
		PAyamHidup  int `json:"pAyamHidup"`
		PBulu      int `json:"pBulu"`
		// Account items
		PDrugs     int `json:"pDrugs"`
		PMicin     int `json:"pMicin"`
		PSteroid   int `json:"pSteroid"`
		PComponent int `json:"pComponent"`
		PMetall    int `json:"pMetall"`
		PFood      int `json:"pFood"`
		PDrink     int `json:"pDrink"`
		// Weapons & vehicles (raw strings)
		PGun   string `json:"pGun"`
		PAmmo  string `json:"pAmmo"`
		CModel string `json:"cModel"`
		// Status
		PHP     float64 `json:"pHP"`
		PArmour float64 `json:"pArmour"`
		PSkin   int     `json:"pSkin"`
		PCS     int     `json:"pCS"`
		PWanted int     `json:"pWanted"`
		PPrison int     `json:"pPrison"`
	}

	var d InventoryData
	err := db.QueryRow(`SELECT
		pName,pLevel,pExp,pJob,pMember,pRank,pVip,pVipTime,
		pCash,pBank,pUangMerah,pRouble,pGopay,
		pBatu,pBatuk,pFish,pPenyu,pDolphin,pHiu,pMegalodon,pCaught,
		pPadi,pAyam,pSemen,pEmas,pSusu,pMinyak,pAyamKemas,pAyamPotong,pAyamHidup,pBulu,
		pDrugs,pMicin,pSteroid,pComponent,pMetall,pFood,pDrink,
		pGun,pAmmo,cModel,
		pHP,pArmour,pSkin,pCS,pWanted,pPrison
		FROM accounts WHERE pName=?`, username).Scan(
		&d.PName, &d.PLevel, &d.PExp, &d.PJob, &d.PMember, &d.PRank, &d.PVip, &d.PVipTime,
		&d.PCash, &d.PBank, &d.PUangMerah, &d.PRouble, &d.PGopay,
		&d.PBatu, &d.PBatuk, &d.PFish, &d.PPenyu, &d.PDolphin, &d.PHiu, &d.PMegalodon, &d.PCaught,
		&d.PPadi, &d.PAyam, &d.PSemen, &d.PEmas, &d.PSusu, &d.PMinyak, &d.PAyamKemas, &d.PAyamPotong, &d.PAyamHidup, &d.PBulu,
		&d.PDrugs, &d.PMicin, &d.PSteroid, &d.PComponent, &d.PMetall, &d.PFood, &d.PDrink,
		&d.PGun, &d.PAmmo, &d.CModel,
		&d.PHP, &d.PArmour, &d.PSkin, &d.PCS, &d.PWanted, &d.PPrison,
	)
	if err == sql.ErrNoRows {
		jsonResp(w, 404, map[string]string{"error": "user tidak ditemukan"})
		return
	} else if err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}
	jsonResp(w, 200, d)
}

// ─── Set Admin ────────────────────────────────────────────────────────────────

var adminLevels = map[int]string{
	1:  "Admin Trial",
	2:  "Admin",
	3:  "Admin",
	4:  "Admin",
	5:  "Admin",
	6:  "Admin",
	7:  "Admin",
	8:  "High Admin",
	9:  "Handle Admin",
	10: "Co-Owner",
	15: "Owner",
	20: "Developer",
}

func handleSetAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Username string `json:"username"`
		Level    int    `json:"level"`
		AName    string `json:"aname"`
		Key      string `json:"key"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonResp(w, 400, map[string]string{"error": "invalid request"})
		return
	}

	levelName, ok := adminLevels[req.Level]
	if !ok {
		jsonResp(w, 400, map[string]string{"error": "level admin tidak valid"})
		return
	}
	if strings.TrimSpace(req.Username) == "" {
		jsonResp(w, 400, map[string]string{"error": "username wajib diisi"})
		return
	}
	if strings.TrimSpace(req.AName) == "" {
		jsonResp(w, 400, map[string]string{"error": "admin name wajib diisi"})
		return
	}
	if strings.TrimSpace(req.Key) == "" {
		jsonResp(w, 400, map[string]string{"error": "admin key wajib diisi"})
		return
	}
	if len(req.AName) > 32 {
		jsonResp(w, 400, map[string]string{"error": "admin name maksimal 32 karakter"})
		return
	}
	if len(req.Key) > 32 {
		jsonResp(w, 400, map[string]string{"error": "admin key maksimal 32 karakter"})
		return
	}

	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}

	// Check if player exists in accounts
	var pName string
	if err := db.QueryRow("SELECT pName FROM accounts WHERE pName=?", req.Username).Scan(&pName); err == sql.ErrNoRows {
		jsonResp(w, 404, map[string]string{"error": "player tidak ditemukan di tabel accounts"})
		return
	} else if err != nil {
		jsonResp(w, 500, map[string]string{"error": "db error: " + err.Error()})
		return
	}

	// Check if already exists in admin table
	var existName string
	exists := db.QueryRow("SELECT Name FROM admin WHERE Name=?", req.Username).Scan(&existName) == nil

	var dbErr error
	if exists {
		// UPDATE existing record
		_, dbErr = db.Exec(
			"UPDATE admin SET pAdmin=?, pAname=?, pAdminKey=? WHERE Name=?",
			req.Level, req.AName, req.Key, req.Username,
		)
	} else {
		// INSERT new admin record
		_, dbErr = db.Exec(
			"INSERT INTO admin (Name, pAdmin, pAname, pAdminKey, pAdmRep, pAdmRepDay, pAdmKick, pAdmBan, pAdmWarn, pAdmPrison, pAdmMute, pDataNaz) VALUES (?,?,?,?,0,0,0,0,0,0,0,'')",
			req.Username, req.Level, req.AName, req.Key,
		)
	}
	if dbErr != nil {
		jsonResp(w, 500, map[string]string{"error": "gagal simpan: " + dbErr.Error()})
		return
	}

	s, _ := getSession(r)
	action := "Set admin"
	if exists {
		action = "Update admin"
	}
	logAction(s.Username, fmt.Sprintf("%s %s → Level %d (%s) / AName:%s", action, req.Username, req.Level, levelName, req.AName))

	jsonResp(w, 200, map[string]any{
		"status":     "ok",
		"action":     action,
		"level_name": levelName,
		"is_new":     !exists,
	})
}

func handleGetAdminInfo(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		jsonResp(w, 400, map[string]string{"error": "username required"})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}
	type AdminInfo struct {
		Name       string `json:"Name"`
		PAdmin     int    `json:"pAdmin"`
		PAname     string `json:"pAname"`
		PAdminKey  string `json:"pAdminKey"`
		PAdmRep    int    `json:"pAdmRep"`
		PAdmKick   int    `json:"pAdmKick"`
		PAdmBan    int    `json:"pAdmBan"`
		PAdmWarn   int    `json:"pAdmWarn"`
		PAdmPrison int    `json:"pAdmPrison"`
		PAdmMute   int    `json:"pAdmMute"`
		InviteDate string `json:"invite_date"`
	}
	var a AdminInfo
	var rawDate []byte
	err := db.QueryRow("SELECT Name,pAdmin,pAname,pAdminKey,pAdmRep,pAdmKick,pAdmBan,pAdmWarn,pAdmPrison,pAdmMute,invite_date FROM admin WHERE Name=?", username).
		Scan(&a.Name, &a.PAdmin, &a.PAname, &a.PAdminKey, &a.PAdmRep, &a.PAdmKick, &a.PAdmBan, &a.PAdmWarn, &a.PAdmPrison, &a.PAdmMute, &rawDate)
	if err == sql.ErrNoRows {
		jsonResp(w, 404, map[string]string{"error": "tidak ditemukan di tabel admin"})
		return
	} else if err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}
	a.InviteDate = string(rawDate)
	jsonResp(w, 200, a)
}

func handleRemoveAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonResp(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}
	res, err := db.Exec("DELETE FROM admin WHERE Name=?", req.Username)
	if err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		jsonResp(w, 404, map[string]string{"error": "admin tidak ditemukan"})
		return
	}
	s, _ := getSession(r)
	logAction(s.Username, fmt.Sprintf("Remove admin %s dari tabel admin", req.Username))
	jsonResp(w, 200, map[string]string{"status": "removed"})
}

func handleGetAdminList(w http.ResponseWriter, r *http.Request) {
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}
	rows, err := db.Query("SELECT Name, pAdmin, pAname, pAdmRep, pAdmKick, pAdmBan, invite_date FROM admin ORDER BY pAdmin DESC")
	if err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	type AdminRow struct {
		Name       string `json:"Name"`
		PAdmin     int    `json:"pAdmin"`
		PAname     string `json:"pAname"`
		PAdmRep    int    `json:"pAdmRep"`
		PAdmKick   int    `json:"pAdmKick"`
		PAdmBan    int    `json:"pAdmBan"`
		InviteDate string `json:"invite_date"`
	}
	var list []AdminRow
	for rows.Next() {
		var a AdminRow
		var rawDate []byte
		if err := rows.Scan(&a.Name, &a.PAdmin, &a.PAname, &a.PAdmRep, &a.PAdmKick, &a.PAdmBan, &rawDate); err == nil {
			a.InviteDate = string(rawDate)
			list = append(list, a)
		}
	}
	if list == nil {
		list = []AdminRow{}
	}
	jsonResp(w, 200, list)
}

// ─── Punishment: Off Jail ─────────────────────────────────────────────────────

func handleOffJail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Username string `json:"username"`
		Minutes  int    `json:"minutes"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonResp(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	if strings.TrimSpace(req.Username) == "" {
		jsonResp(w, 400, map[string]string{"error": "username wajib diisi"})
		return
	}
	if req.Minutes < 10 || req.Minutes > 300 {
		jsonResp(w, 400, map[string]string{"error": "durasi harus antara 10 dan 300 menit"})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}

	// Check player exists + get current pPrison
	var pID int
	var pPrison int
	err := db.QueryRow("SELECT pID, pPrison FROM accounts WHERE pName=? LIMIT 1", req.Username).Scan(&pID, &pPrison)
	if err == sql.ErrNoRows {
		jsonResp(w, 404, map[string]string{"error": "pemain tidak ditemukan"})
		return
	} else if err != nil {
		jsonResp(w, 500, map[string]string{"error": "db error: " + err.Error()})
		return
	}

	// Check if player is admin
	var adminName string
	isAdmin := db.QueryRow("SELECT Name FROM admin WHERE Name=? LIMIT 1", req.Username).Scan(&adminName) == nil
	if isAdmin {
		jsonResp(w, 400, map[string]string{"error": "pemain ini adalah admin, tidak bisa dipenjara"})
		return
	}

	// Check if already in jail
	if pPrison > 0 {
		remaining := pPrison / 60
		jsonResp(w, 400, map[string]string{"error": fmt.Sprintf("pemain sudah di penjara (%d menit tersisa)", remaining)})
		return
	}

	// Set pPrison in seconds, pMestoPrison = 0
	seconds := req.Minutes * 60
	_, err = db.Exec("UPDATE accounts SET pPrison=?, pMestoPrison=0 WHERE pName=?", seconds, req.Username)
	if err != nil {
		jsonResp(w, 500, map[string]string{"error": "gagal update: " + err.Error()})
		return
	}

	// Increment pAdmPrison on admin who did the action
	s, _ := getSession(r)
	db.Exec("UPDATE admin SET pAdmPrison=pAdmPrison+1 WHERE Name=?", s.Username)
	logAction(s.Username, fmt.Sprintf("OffJail %s selama %d menit (%d detik)", req.Username, req.Minutes, seconds))

	jsonResp(w, 200, map[string]any{
		"status":   "ok",
		"username": req.Username,
		"minutes":  req.Minutes,
		"seconds":  seconds,
	})
}

func handleFreeJail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonResp(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	if strings.TrimSpace(req.Username) == "" {
		jsonResp(w, 400, map[string]string{"error": "username wajib diisi"})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}

	var pPrison int
	err := db.QueryRow("SELECT pPrison FROM accounts WHERE pName=? LIMIT 1", req.Username).Scan(&pPrison)
	if err == sql.ErrNoRows {
		jsonResp(w, 404, map[string]string{"error": "pemain tidak ditemukan"})
		return
	} else if err != nil {
		jsonResp(w, 500, map[string]string{"error": "db error: " + err.Error()})
		return
	}
	if pPrison == 0 {
		jsonResp(w, 400, map[string]string{"error": "pemain tidak sedang di penjara"})
		return
	}

	_, err = db.Exec("UPDATE accounts SET pPrison=0, pMestoPrison=0 WHERE pName=?", req.Username)
	if err != nil {
		jsonResp(w, 500, map[string]string{"error": "gagal update: " + err.Error()})
		return
	}

	s, _ := getSession(r)
	logAction(s.Username, fmt.Sprintf("FreeJail %s (sisa %d detik dibebaskan)", req.Username, pPrison))

	jsonResp(w, 200, map[string]any{
		"status":            "ok",
		"username":          req.Username,
		"freed_seconds":     pPrison,
		"freed_minutes":     pPrison / 60,
	})
}

func handleGetPrisonStatus(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		jsonResp(w, 400, map[string]string{"error": "username required"})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}
	var pPrison, pWanted int
	err := db.QueryRow("SELECT pPrison, pWanted FROM accounts WHERE pName=? LIMIT 1", username).Scan(&pPrison, &pWanted)
	if err == sql.ErrNoRows {
		jsonResp(w, 404, map[string]string{"error": "pemain tidak ditemukan"})
		return
	} else if err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}
	jsonResp(w, 200, map[string]any{
		"username": username,
		"pPrison":  pPrison,
		"minutes":  pPrison / 60,
		"pWanted":  pWanted,
		"in_jail":  pPrison > 0,
	})
}

// ─── Punishment: Off Ban ──────────────────────────────────────────────────────

func handleOffBan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Username string `json:"username"`
		Days     int    `json:"days"`
		Reason   string `json:"reason"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonResp(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	if strings.TrimSpace(req.Username) == "" {
		jsonResp(w, 400, map[string]string{"error": "username wajib diisi"})
		return
	}
	if req.Days < 1 || req.Days > 30 {
		jsonResp(w, 400, map[string]string{"error": "durasi ban harus antara 1 dan 30 hari"})
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "Melanggar peraturan"
	}
	if len(reason) > 32 {
		reason = reason[:32] // kolom reason varchar(32)
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}

	// Cek player exist di accounts
	var pID int
	err := db.QueryRow("SELECT pID FROM accounts WHERE pName=? LIMIT 1", req.Username).Scan(&pID)
	if err == sql.ErrNoRows {
		jsonResp(w, 404, map[string]string{"error": "pemain tidak ditemukan"})
		return
	} else if err != nil {
		jsonResp(w, 500, map[string]string{"error": "db error: " + err.Error()})
		return
	}

	// Cek apakah player adalah admin
	var adminName string
	if db.QueryRow("SELECT Name FROM admin WHERE Name=? LIMIT 1", req.Username).Scan(&adminName) == nil {
		jsonResp(w, 400, map[string]string{"error": "pemain ini adalah admin, tidak bisa di-ban"})
		return
	}

	// Cek apakah sudah di-ban aktif — lockstate=1 (INT)
	var existID int
	alreadyBanned := db.QueryRow(
		"SELECT id FROM banlog WHERE nameplayer=? AND lockstate=1 LIMIT 1", req.Username,
	).Scan(&existID) == nil
	if alreadyBanned {
		jsonResp(w, 400, map[string]string{"error": "pemain sudah dalam status banned"})
		return
	}

	now := time.Now().Unix()
	unbanDate := now + int64(86400*req.Days) // gettime() + (86400 * days)

	s, _ := getSession(r)
	adminWho := s.Username
	if len(adminWho) > 32 {
		adminWho = adminWho[:32] // nameadmin varchar(32)
	}

	// INSERT sesuai schema: nameplayer, nameadmin, reason, date, unbandate, lockstate
	_, err = db.Exec(
		`INSERT INTO banlog (nameplayer, nameadmin, reason, date, unbandate, lockstate)
		 VALUES (?, ?, ?, ?, ?, 1)`,
		req.Username, adminWho, reason, now, unbanDate,
	)
	if err != nil {
		jsonResp(w, 500, map[string]string{"error": "gagal insert banlog: " + err.Error()})
		return
	}

	// Increment pAdmBan di tabel admin
	db.Exec("UPDATE admin SET pAdmBan=pAdmBan+1 WHERE Name=?", s.Username)

	logAction(s.Username, fmt.Sprintf("OffBan %s selama %d hari | alasan: %s", req.Username, req.Days, reason))

	expireStr := time.Unix(unbanDate, 0).Format("2006-01-02 15:04:05")
	jsonResp(w, 200, map[string]any{
		"status":      "banned",
		"username":    req.Username,
		"days":        req.Days,
		"reason":      reason,
		"banned_by":   s.Username,
		"expire_date": expireStr,
		"expire_unix": unbanDate,
	})
}

func handleUnban(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonResp(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	if strings.TrimSpace(req.Username) == "" {
		jsonResp(w, 400, map[string]string{"error": "username wajib diisi"})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}

	// Cek ada ban aktif (lockstate=1 INT)
	var banID int
	err := db.QueryRow(
		"SELECT id FROM banlog WHERE nameplayer=? AND lockstate=1 LIMIT 1", req.Username,
	).Scan(&banID)
	if err == sql.ErrNoRows {
		jsonResp(w, 404, map[string]string{"error": "pemain tidak dalam status banned"})
		return
	} else if err != nil {
		jsonResp(w, 500, map[string]string{"error": "db error: " + err.Error()})
		return
	}

	// Set lockstate=0 (unban)
	_, err = db.Exec("UPDATE banlog SET lockstate=0 WHERE nameplayer=? AND lockstate=1", req.Username)
	if err != nil {
		jsonResp(w, 500, map[string]string{"error": "gagal unban: " + err.Error()})
		return
	}

	s, _ := getSession(r)
	logAction(s.Username, fmt.Sprintf("Unban %s", req.Username))

	jsonResp(w, 200, map[string]any{
		"status":   "unbanned",
		"username": req.Username,
	})
}

func handleGetBanStatus(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		jsonResp(w, 400, map[string]string{"error": "username required"})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}

	type BanInfo struct {
		IsBanned   bool   `json:"is_banned"`
		Reason     string `json:"reason"`
		BannedBy   string `json:"banned_by"`
		DateUnix   int64  `json:"date_unix"`
		UnbanUnix  int64  `json:"unban_unix"`
		BanDate    string `json:"ban_date"`
		ExpireDate string `json:"expire_date"`
		DaysLeft   int    `json:"days_left"`
	}

	var info BanInfo
	// Query kolom sesuai schema: nameadmin, reason, date, unbandate
	err := db.QueryRow(
		`SELECT nameadmin, reason, date, unbandate
		 FROM banlog WHERE nameplayer=? AND lockstate=1
		 ORDER BY id DESC LIMIT 1`, username,
	).Scan(&info.BannedBy, &info.Reason, &info.DateUnix, &info.UnbanUnix)

	if err == sql.ErrNoRows {
		// Tidak banned — cek apakah player ada
		var pID int
		if db.QueryRow("SELECT pID FROM accounts WHERE pName=? LIMIT 1", username).Scan(&pID) == sql.ErrNoRows {
			jsonResp(w, 404, map[string]string{"error": "pemain tidak ditemukan"})
			return
		}
		jsonResp(w, 200, BanInfo{IsBanned: false})
		return
	} else if err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}

	info.IsBanned = true
	info.BanDate    = time.Unix(info.DateUnix, 0).Format("2006-01-02 15:04:05")
	info.ExpireDate = time.Unix(info.UnbanUnix, 0).Format("2006-01-02 15:04:05")
	secsLeft := info.UnbanUnix - time.Now().Unix()
	if secsLeft > 0 {
		info.DaysLeft = int(secsLeft/86400) + 1
	}
	jsonResp(w, 200, info)
}

// ─── Property: Add Bisnis & Add House ────────────────────────────────────────

var bizzInteriorTypes = map[int]string{
	1: "Beer Shop", 2: "Fast Food", 3: "Market", 4: "Clothes",
	5: "Equipment", 7: "Hotel", 8: "Clothes", 9: "Equipment",
	10: "Hotel", 11: "Clothes", 12: "Equipment", 13: "Hotel",
}

func handleAddBizz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		BMessage    string  `json:"bMessage"`
		BuyPrice    int64   `json:"bBuyPrice"`
		Interior    int     `json:"bInterior"`
		EntranceX   float64 `json:"bEntranceX"`
		EntranceY   float64 `json:"bEntranceY"`
		EntranceZ   float64 `json:"bEntranceZ"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonResp(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	if strings.TrimSpace(req.BMessage) == "" {
		jsonResp(w, 400, map[string]string{"error": "nama bisnis wajib diisi"})
		return
	}
	if req.BuyPrice < 5_000_000 || req.BuyPrice > 100_000_000 {
		jsonResp(w, 400, map[string]string{"error": "harga beli harus antara 5 juta dan 100 juta"})
		return
	}
	if _, ok := bizzInteriorTypes[req.Interior]; !ok {
		jsonResp(w, 400, map[string]string{"error": "tipe interior tidak valid"})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}

	// Auto-increment bID
	var maxID int
	db.QueryRow("SELECT COALESCE(MAX(bID),0) FROM bizz").Scan(&maxID)
	newID := maxID + 1

	_, err := db.Exec(`INSERT INTO bizz
		(bID, bOwned, bOwner, bMessage, bEntranceX, bEntranceY, bEntranceZ,
		 bExitX, bExitY, bExitZ, bBuyPrice, bEntranceCost, bMoney, bRaschet,
		 bLocked, bInterior, bProducts, bPrice, bBarX, bBarY, bBarZ,
		 bMafia, b, bVirtualWorld, bOplata, bSlet, bArenda,
		 bUpdMusic, bUpdHeal, bUpdSub, bSotrud, bSklad, bPhone, bProcent, bSong)
		VALUES (?,0,'The State',?,?,?,?,0.0,0.0,0.0,?,0,0,0,0,?,0,?,0.0,0.0,0.0,0,0,0,0,0,0,0,0,0,0,0,0,0,'0')`,
		newID, req.BMessage,
		req.EntranceX, req.EntranceY, req.EntranceZ,
		req.BuyPrice, req.Interior, req.BuyPrice,
	)
	if err != nil {
		jsonResp(w, 500, map[string]string{"error": "gagal insert: " + err.Error()})
		return
	}

	s, _ := getSession(r)
	typeName := bizzInteriorTypes[req.Interior]
	logAction(s.Username, fmt.Sprintf("Add bisnis bID=%d '%s' tipe=%s harga=%d", newID, req.BMessage, typeName, req.BuyPrice))

	jsonResp(w, 200, map[string]any{
		"status": "created",
		"bID":    newID,
		"bMessage": req.BMessage,
		"type_name": typeName,
	})
}

func handleAddHouse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		EntranceX float64 `json:"hEntrancex"`
		EntranceY float64 `json:"hEntrancey"`
		EntranceZ float64 `json:"hEntrancez"`
		CarX      float64 `json:"hCarx"`
		CarY      float64 `json:"hCary"`
		CarZ      float64 `json:"hCarz"`
		CarC      float64 `json:"hCarc"`
		HValue    int64   `json:"hValue"`
		HInt      int     `json:"hInt"`
		HKlass    int     `json:"hKlass"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonResp(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	if req.HValue < 5_000_000 || req.HValue > 100_000_000 {
		jsonResp(w, 400, map[string]string{"error": "harga rumah harus antara 5 juta dan 100 juta"})
		return
	}
	if req.HInt < 0 || req.HInt > 2 {
		jsonResp(w, 400, map[string]string{"error": "tipe interior tidak valid (0-2)"})
		return
	}
	if req.HKlass < 0 || req.HKlass > 3 {
		jsonResp(w, 400, map[string]string{"error": "tipe house tidak valid (0-3)"})
		return
	}
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}

	var maxID int
	db.QueryRow("SELECT COALESCE(MAX(hID),0) FROM house").Scan(&maxID)
	newID := maxID + 1

	_, err := db.Exec(`INSERT INTO house
		(hID, hEntrancex, hEntrancey, hEntrancez,
		 hCarx, hCary, hCarz, hCarc,
		 hOwner, hValue, hHel, hInt, hLock, hOwned, hKlass,
		 hUpdAD, hUpdHel, hUpdSub, hUpdWkaf,
		 hHealpickX, hHealpickY, hHealpickZ,
		 hWkafX, hWkafY, hWkafZ, hWkafX1, hWkafY1, hWkafZ1,
		 hWkafDrugs, hWkafMoney, hWkafPatr, hWkafMetall,
		 hWkafSDPistol, hWkafDeagle, hWkafShotGun, hWkafMP5, hWkafAK47, hWkafM4,
		 hSlet, hTakings, hOplata, hLodgers, hUpdStore, hUpdStorePos,
		 hWeaponID, hAmmo, hDrugs)
		VALUES (?,?,?,?,?,?,?,?,'The State',?,100,?,0,0,?,0,0,0,0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0,0,0,0,0,0,0,0,0,0,0,0,0,'null,null,null',0,'0.0,0.0,0.0','0,0,0','0,0,0',0)`,
		newID,
		req.EntranceX, req.EntranceY, req.EntranceZ,
		req.CarX, req.CarY, req.CarZ, req.CarC,
		req.HValue, req.HInt, req.HKlass,
	)
	if err != nil {
		jsonResp(w, 500, map[string]string{"error": "gagal insert: " + err.Error()})
		return
	}

	hIntNames := map[int]string{0: "Miskin", 1: "Medium", 2: "High"}
	hKlassNames := map[int]string{0: "Miskin", 1: "Medium", 2: "High", 3: "VIP"}
	s, _ := getSession(r)
	logAction(s.Username, fmt.Sprintf("Add house hID=%d int=%s klass=%s harga=%d",
		newID, hIntNames[req.HInt], hKlassNames[req.HKlass], req.HValue))

	jsonResp(w, 200, map[string]any{
		"status":      "created",
		"hID":         newID,
		"int_name":    hIntNames[req.HInt],
		"klass_name":  hKlassNames[req.HKlass],
	})
}

func handleGetPropertyStats(w http.ResponseWriter, r *http.Request) {
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}
	var totalBizz, ownedBizz, totalHouse, ownedHouse int
	db.QueryRow("SELECT COUNT(*), SUM(CASE WHEN bOwned=1 THEN 1 ELSE 0 END) FROM bizz").Scan(&totalBizz, &ownedBizz)
	db.QueryRow("SELECT COUNT(*), SUM(CASE WHEN hOwned=1 THEN 1 ELSE 0 END) FROM house").Scan(&totalHouse, &ownedHouse)
	jsonResp(w, 200, map[string]any{
		"total_bizz":  totalBizz,
		"owned_bizz":  ownedBizz,
		"total_house": totalHouse,
		"owned_house": ownedHouse,
	})
}

// ─── HTML Page ────────────────────────────────────────────────────────────────

const htmlPage = `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Dewata Nation RP — Admin Panel</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@400;500;600;700&family=Exo+2:wght@300;400;500;600;700&display=swap" rel="stylesheet"/>
<style>
/* ══════════════════════════════════════
   DEWATA NATION RP — CYBERPUNK VIOLET
   Premium Dark Theme v2.0
══════════════════════════════════════ */
@import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=Exo+2:wght@300;400;500;600;700&family=Orbitron:wght@400;700;900&display=swap');

:root{
  /* Core palette */
  --bg:         #07080f;
  --surface:    #0d0e1a;
  --surface2:   #111228;
  --surface3:   #161830;
  --surface4:   #1c1f3a;

  /* Borders */
  --border:     #1e2048;
  --border2:    #2a2d5a;

  /* Accent — Purple/Violet neon */
  --accent:     #a855f7;
  --accent2:    #7c3aed;
  --accent3:    #c084fc;
  --accentglow: rgba(168,85,247,0.22);
  --accentglow2:rgba(168,85,247,0.08);

  /* Secondary accent — hot pink neon */
  --pink:       #ec4899;
  --pinkglow:   rgba(236,72,153,0.2);

  /* Status */
  --red:        #f43f5e;
  --green:      #10b981;
  --blue:       #3b82f6;
  --yellow:     #f59e0b;

  /* Text */
  --text:       #e2e8f8;
  --text2:      #a0aec8;
  --textmuted:  #4a5580;

  /* Layout */
  --sidebar:    268px;
  --topbar:     64px;
  --radius:     14px;
  --radius-sm:  9px;
  --radius-lg:  20px;
}

/* ── Reset ── */
*{box-sizing:border-box;margin:0;padding:0}
html{font-size:16px;-webkit-text-size-adjust:100%}
body{
  background:var(--bg);
  color:var(--text);
  font-family:'Exo 2',sans-serif;
  min-height:100vh;
  overflow-x:hidden;
  -webkit-font-smoothing:antialiased;
}

/* ── Cyberpunk background grid ── */
body::before{
  content:'';
  position:fixed;
  inset:0;
  background-image:
    linear-gradient(rgba(168,85,247,0.03) 1px,transparent 1px),
    linear-gradient(90deg,rgba(168,85,247,0.03) 1px,transparent 1px);
  background-size:40px 40px;
  pointer-events:none;
  z-index:0;
}
body::after{
  content:'';
  position:fixed;
  top:-30vh;left:-20vw;
  width:70vw;height:70vh;
  background:radial-gradient(ellipse,rgba(124,58,237,0.12),transparent 65%);
  pointer-events:none;
  z-index:0;
}
#loading-screen,#auth-wrapper,#app{position:relative;z-index:1}

/* ── Loading ── */
#loading-screen{
  position:fixed;inset:0;
  background:var(--bg);
  z-index:9999;
  display:flex;flex-direction:column;align-items:center;justify-content:center;gap:24px;padding:24px;
  transition:opacity 0.5s ease;
}
#loading-screen.hidden{
  opacity:0;
  pointer-events:none;
  visibility:hidden;
}
.loading-logo{
  width:clamp(80px,20vw,110px);height:clamp(80px,20vw,110px);
  border-radius:20px;object-fit:cover;
  box-shadow:0 0 0 1px var(--border2),0 0 40px var(--accentglow),0 0 80px rgba(168,85,247,0.1);
}
.loading-title{
  font-family:'Orbitron',sans-serif;
  font-size:clamp(14px,3vw,18px);
  font-weight:700;
  letter-spacing:4px;
  color:var(--accent);
  text-transform:uppercase;
  text-shadow:0 0 20px var(--accentglow);
}
.loading-bar-wrap{
  width:min(300px,85vw);height:3px;
  background:var(--surface3);
  border-radius:99px;overflow:hidden;
  box-shadow:0 0 8px rgba(0,0,0,0.5);
}
.loading-bar{
  height:100%;width:0%;
  background:linear-gradient(90deg,var(--accent2),var(--accent),var(--accent3));
  border-radius:99px;
  transition:width 0.35s cubic-bezier(0.4,0,0.2,1);
  box-shadow:0 0 12px var(--accentglow);
}
.loading-text{font-family:'Rajdhani',sans-serif;font-size:11px;letter-spacing:3px;color:var(--textmuted);text-transform:uppercase}

/* ── Auth ── */
#auth-wrapper{
  position:fixed;inset:0;
  display:flex;align-items:center;justify-content:center;
  background:var(--bg);
  z-index:100;padding:16px;overflow-y:auto;
}
#auth-wrapper.hidden{display:none}
.auth-box{
  background:var(--surface);
  border:1px solid var(--border2);
  border-radius:var(--radius-lg);
  padding:clamp(24px,5vw,40px);
  width:100%;max-width:430px;
  position:relative;overflow:hidden;margin:auto;
  box-shadow:0 0 0 1px rgba(168,85,247,0.1),0 32px 80px rgba(0,0,0,0.6),0 0 60px rgba(124,58,237,0.08);
}
.auth-box::before{
  content:'';position:absolute;
  top:-80px;right:-80px;
  width:220px;height:220px;
  background:radial-gradient(circle,rgba(168,85,247,0.18),transparent 65%);
  pointer-events:none;
}
.auth-box::after{
  content:'';position:absolute;
  bottom:-60px;left:-60px;
  width:160px;height:160px;
  background:radial-gradient(circle,rgba(236,72,153,0.12),transparent 65%);
  pointer-events:none;
}
.auth-banner-wrap{
  width:100%;border-radius:12px;margin-bottom:22px;
  overflow:hidden;background:var(--surface2);
  aspect-ratio:16/5;display:flex;align-items:center;justify-content:center;
  border:1px solid var(--border);
}
.auth-banner{width:100%;height:100%;object-fit:cover;display:block}
.auth-banner-fallback{font-family:'Orbitron',sans-serif;font-size:16px;font-weight:700;color:var(--accent);letter-spacing:3px;text-align:center;padding:16px;text-shadow:0 0 20px var(--accentglow)}
.auth-title{
  font-family:'Orbitron',sans-serif;
  font-size:clamp(16px,4vw,22px);font-weight:700;
  letter-spacing:2px;color:var(--accent);margin-bottom:6px;
  text-shadow:0 0 20px var(--accentglow);
}
.auth-sub{font-size:13px;color:var(--textmuted);margin-bottom:24px;letter-spacing:0.3px}

/* ── Form elements ── */
.form-group{margin-bottom:16px}
.form-group label{
  display:block;font-size:10px;letter-spacing:1.5px;
  text-transform:uppercase;color:var(--textmuted);
  margin-bottom:8px;font-weight:600;
}
.form-group input,.form-group select{
  width:100%;
  background:var(--surface2);
  border:1px solid var(--border2);
  border-radius:var(--radius-sm);
  padding:12px 16px;
  color:var(--text);
  font-family:'Exo 2',sans-serif;font-size:14px;
  outline:none;
  transition:border-color 0.2s,box-shadow 0.2s;
  -webkit-appearance:none;appearance:none;
}
.form-group input:focus,.form-group select:focus{
  border-color:var(--accent);
  box-shadow:0 0 0 3px rgba(168,85,247,0.12),inset 0 0 12px rgba(168,85,247,0.04);
}
.form-group input::placeholder{color:var(--textmuted)}
.form-group select{
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath fill='%234a5580' d='M6 8L0 0h12z'/%3E%3C/svg%3E");
  background-repeat:no-repeat;background-position:right 14px center;padding-right:36px;
}

/* ── Buttons ── */
.btn{
  width:100%;padding:13px;border:none;
  border-radius:var(--radius-sm);
  font-family:'Rajdhani',sans-serif;font-size:15px;font-weight:700;
  letter-spacing:2px;cursor:pointer;
  transition:all 0.22s cubic-bezier(0.4,0,0.2,1);
  text-transform:uppercase;touch-action:manipulation;
  position:relative;overflow:hidden;
}
.btn::after{
  content:'';position:absolute;inset:0;
  background:linear-gradient(135deg,rgba(255,255,255,0.07),transparent);
  pointer-events:none;
}
.btn-primary{
  background:linear-gradient(135deg,var(--accent2),var(--accent),var(--accent3));
  color:#fff;
  box-shadow:0 4px 20px rgba(168,85,247,0.35);
}
.btn-primary:hover{
  transform:translateY(-2px);
  box-shadow:0 8px 32px rgba(168,85,247,0.5),0 0 0 1px rgba(168,85,247,0.3);
}
.btn-primary:active{transform:translateY(0);box-shadow:0 2px 10px rgba(168,85,247,0.3)}
.btn-danger{background:linear-gradient(135deg,#e11d48,var(--red));color:#fff;padding:9px 16px;width:auto;font-size:13px;border-radius:var(--radius-sm);letter-spacing:1px;box-shadow:0 4px 16px rgba(244,63,94,0.3)}
.btn-danger:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(244,63,94,0.45)}
.btn-sm{padding:9px 16px;width:auto;font-size:13px;border-radius:var(--radius-sm);letter-spacing:1px}
.btn-copy{
  background:var(--surface3);
  color:var(--accent3);
  border:1px solid var(--border2);
}
.btn-copy:hover{
  background:var(--accentglow2);
  border-color:rgba(168,85,247,0.4);
  color:var(--accent);
}
.auth-error{
  background:rgba(244,63,94,0.08);border:1px solid rgba(244,63,94,0.4);
  border-radius:var(--radius-sm);padding:10px 14px;font-size:13px;color:var(--red);
  margin-bottom:14px;display:none;
}
.auth-error.show{display:block}

/* ── App Layout ── */
#app{display:none;min-height:100vh}
#app.visible{display:flex}

/* ── Sidebar ── */
#sidebar{
  width:var(--sidebar);
  background:linear-gradient(180deg,var(--surface) 0%,#0a0b18 100%);
  border-right:1px solid var(--border);
  display:flex;flex-direction:column;
  transition:transform 0.3s cubic-bezier(0.4,0,0.2,1);
  position:fixed;top:0;bottom:0;left:0;
  z-index:50;overflow:hidden;will-change:transform;
}
#sidebar::before{
  content:'';position:absolute;
  top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,var(--accent),transparent);
  opacity:0.5;
}
#sidebar.collapsed{transform:translateX(calc(-1 * var(--sidebar)))}

.sidebar-header{
  padding:18px 16px;
  border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:12px;flex-shrink:0;
  background:rgba(168,85,247,0.03);
}
.sidebar-logo-wrap{
  width:40px;height:40px;border-radius:10px;overflow:hidden;flex-shrink:0;
  background:var(--surface3);display:flex;align-items:center;justify-content:center;
  border:1px solid var(--border2);
  box-shadow:0 0 12px rgba(168,85,247,0.15);
}
.sidebar-logo{width:100%;height:100%;object-fit:cover;display:block}
.sidebar-logo-fallback{font-size:20px;line-height:1}
.sidebar-title{
  font-family:'Orbitron',sans-serif;
  font-size:13px;font-weight:700;
  color:var(--accent);letter-spacing:1px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
  text-shadow:0 0 12px var(--accentglow);
}

.sidebar-nav{flex:1;overflow-y:auto;overflow-x:hidden;padding:10px 8px}
.nav-section-label{
  font-size:9px;letter-spacing:2px;text-transform:uppercase;
  color:var(--textmuted);padding:12px 14px 6px;font-weight:700;
}
.nav-item{
  display:flex;align-items:center;gap:12px;
  padding:11px 14px;border-radius:12px;cursor:pointer;
  transition:all 0.2s cubic-bezier(0.4,0,0.2,1);
  color:var(--text2);margin-bottom:3px;
  font-weight:500;font-size:14px;
  white-space:nowrap;user-select:none;
  border:1px solid transparent;
  -webkit-tap-highlight-color:transparent;
}
.nav-item:hover{
  background:var(--surface3);
  color:var(--text);
  border-color:var(--border);
}
.nav-item:active{transform:scale(0.98)}
.nav-item.active{
  background:linear-gradient(135deg,rgba(168,85,247,0.15),rgba(124,58,237,0.08));
  color:var(--accent3);
  border-color:rgba(168,85,247,0.25);
  box-shadow:inset 0 0 20px rgba(168,85,247,0.05),0 0 0 1px rgba(168,85,247,0.1);
}
.nav-item.active .nav-icon{
  filter:drop-shadow(0 0 6px var(--accentglow));
}
.nav-icon{font-size:17px;flex-shrink:0;width:22px;text-align:center;transition:filter 0.2s}

.sidebar-footer{padding:12px;border-top:1px solid var(--border);flex-shrink:0;background:rgba(0,0,0,0.2)}
.sidebar-user{display:flex;align-items:center;gap:10px;margin-bottom:10px;min-width:0;padding:8px;border-radius:10px;background:var(--surface3);border:1px solid var(--border)}
.user-avatar{
  width:36px;height:36px;
  background:linear-gradient(135deg,var(--accent2),var(--accent));
  border-radius:50%;display:flex;align-items:center;justify-content:center;
  font-family:'Orbitron',sans-serif;font-weight:700;color:#fff;
  flex-shrink:0;font-size:14px;
  box-shadow:0 0 12px var(--accentglow);
}
.user-info{flex:1;min-width:0;overflow:hidden}
.user-name{font-weight:600;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.user-role{font-size:9px;color:var(--accent3);letter-spacing:1.5px;text-transform:uppercase;margin-top:1px}

/* ── Main ── */
#main{flex:1;margin-left:var(--sidebar);transition:margin-left 0.3s cubic-bezier(0.4,0,0.2,1);display:flex;flex-direction:column;min-height:100vh;min-width:0}
#main.expanded{margin-left:0}

/* ── Topbar ── */
#topbar{
  background:rgba(13,14,26,0.85);
  backdrop-filter:blur(20px);
  -webkit-backdrop-filter:blur(20px);
  border-bottom:1px solid var(--border);
  padding:0 20px;height:var(--topbar);
  display:flex;align-items:center;gap:12px;
  position:sticky;top:0;z-index:40;flex-shrink:0;
}
#topbar::after{
  content:'';position:absolute;
  bottom:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,rgba(168,85,247,0.3),transparent);
}
#menu-toggle{
  background:var(--surface3);
  border:1px solid var(--border2);
  border-radius:var(--radius-sm);
  padding:8px 11px;cursor:pointer;
  color:var(--text2);font-size:17px;
  transition:all 0.2s;flex-shrink:0;
  -webkit-tap-highlight-color:transparent;touch-action:manipulation;
}
#menu-toggle:hover{
  background:var(--accentglow2);
  border-color:rgba(168,85,247,0.4);
  color:var(--accent);
}
.topbar-title{
  font-family:'Orbitron',sans-serif;
  font-size:clamp(13px,2.5vw,17px);font-weight:700;
  color:var(--text);letter-spacing:1px;
  flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
}
.topbar-status{
  display:flex;align-items:center;gap:8px;
  font-size:11px;color:var(--textmuted);
  flex-shrink:0;max-width:140px;overflow:hidden;
}
.topbar-status span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.status-dot{width:7px;height:7px;border-radius:50%;background:var(--green);flex-shrink:0}

/* ── Page Content ── */
#content{flex:1;padding:clamp(14px,3vw,28px);overflow-x:hidden}
.page{display:none}
.page.active{display:block}

/* ── Page header ── */
.page-title{
  font-family:'Orbitron',sans-serif;
  font-size:clamp(18px,4vw,24px);font-weight:700;
  color:var(--text);letter-spacing:2px;margin-bottom:6px;
}
.page-sub{color:var(--textmuted);font-size:13px;margin-bottom:22px;line-height:1.6}

/* ── Cards ── */
.card{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--radius);
  padding:clamp(16px,3vw,24px);
  margin-bottom:18px;
  position:relative;overflow:hidden;
  transition:border-color 0.2s;
}
.card::before{
  content:'';position:absolute;
  top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,rgba(168,85,247,0.2),transparent);
  pointer-events:none;
}
.card:hover{border-color:var(--border2)}
.card-title{
  font-family:'Rajdhani',sans-serif;
  font-size:16px;font-weight:700;
  color:var(--accent3);letter-spacing:1px;
  margin-bottom:18px;
  display:flex;align-items:center;gap:10px;
  padding-bottom:12px;
  border-bottom:1px solid var(--border);
}

/* ── Dashboard Banner ── */
.dash-banner-wrap{
  width:100%;border-radius:var(--radius);overflow:hidden;
  margin-bottom:22px;background:var(--surface2);
  aspect-ratio:16/5;min-height:100px;max-height:220px;
  display:flex;align-items:center;justify-content:center;
  box-shadow:0 8px 40px rgba(0,0,0,0.5),0 0 0 1px var(--border);
}
.dash-banner{width:100%;height:100%;object-fit:cover;display:block}
.dash-banner-fallback{font-family:'Orbitron',sans-serif;font-size:clamp(14px,3vw,20px);font-weight:700;color:var(--accent);letter-spacing:3px;text-align:center;padding:20px;text-shadow:0 0 20px var(--accentglow)}

/* Info grid (dashboard) */
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;margin-bottom:18px}
.info-card{
  background:var(--surface2);border:1px solid var(--border);
  border-radius:12px;padding:18px;
  transition:border-color 0.2s,box-shadow 0.2s;
}
.info-card:hover{border-color:var(--border2);box-shadow:0 4px 20px rgba(0,0,0,0.3)}
.info-label{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--textmuted);margin-bottom:8px;font-weight:700}
.info-value{font-family:'Rajdhani',sans-serif;font-size:clamp(15px,3vw,21px);font-weight:700;color:var(--text);margin-bottom:12px;word-break:break-all;line-height:1.3}
.info-copy-btn{
  display:inline-flex;align-items:center;gap:6px;
  background:var(--surface3);border:1px solid var(--border2);
  color:var(--accent3);padding:7px 14px;border-radius:8px;
  font-size:12px;font-family:'Rajdhani',sans-serif;letter-spacing:1px;
  cursor:pointer;transition:all 0.2s;font-weight:600;touch-action:manipulation;
}
.info-copy-btn:hover{background:var(--accentglow2);border-color:rgba(168,85,247,0.4);color:var(--accent)}

/* ── Table ── */
.table-wrap{
  overflow-x:auto;border-radius:12px;
  border:1px solid var(--border);
  -webkit-overflow-scrolling:touch;
}
table{width:100%;border-collapse:collapse;font-size:13px;min-width:520px}
thead th{
  background:var(--surface2);
  padding:12px 14px;text-align:left;
  font-family:'Rajdhani',sans-serif;font-size:10px;
  letter-spacing:2px;text-transform:uppercase;
  color:var(--textmuted);border-bottom:1px solid var(--border);white-space:nowrap;
}
tbody td{
  padding:12px 14px;
  border-bottom:1px solid rgba(30,32,72,0.5);
  vertical-align:middle;
}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:rgba(168,85,247,0.03)}
.cord-text{font-family:monospace;font-size:11px;color:var(--accent3)}
.badge{display:inline-block;padding:3px 10px;border-radius:99px;font-size:11px;font-weight:700;font-family:'Rajdhani',sans-serif;letter-spacing:1px}
.badge-green{background:rgba(16,185,129,0.12);color:var(--green);border:1px solid rgba(16,185,129,0.25)}
.badge-blue{background:rgba(59,130,246,0.12);color:var(--blue);border:1px solid rgba(59,130,246,0.25)}
.badge-purple{background:rgba(168,85,247,0.12);color:var(--accent3);border:1px solid rgba(168,85,247,0.25)}

/* ── Set Form ── */
.set-card{
  background:var(--surface2);border:1px solid var(--border);
  border-radius:12px;padding:18px;
  transition:border-color 0.2s;
}
.set-card:hover{border-color:var(--border2)}
.set-title{
  font-family:'Rajdhani',sans-serif;font-size:14px;font-weight:700;
  color:var(--accent3);letter-spacing:1px;
  margin-bottom:14px;padding-bottom:10px;
  border-bottom:1px solid var(--border);
}
.input-row{display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:10px;margin-bottom:14px;align-items:flex-end}
.input-row .form-group{margin-bottom:0}
.prop-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}

.success-msg{
  background:rgba(16,185,129,0.08);
  border:1px solid rgba(16,185,129,0.3);
  border-radius:var(--radius-sm);padding:10px 14px;
  font-size:13px;color:var(--green);margin-top:10px;display:none;
}
.success-msg.show{display:block}
.error-msg{
  background:rgba(244,63,94,0.08);
  border:1px solid rgba(244,63,94,0.3);
  border-radius:var(--radius-sm);padding:10px 14px;
  font-size:13px;color:var(--red);margin-top:10px;display:none;
}
.error-msg.show{display:block}

/* ── Log ── */
.log-item{
  display:flex;align-items:flex-start;gap:12px;
  padding:13px 0;border-bottom:1px solid rgba(30,32,72,0.5);flex-wrap:wrap;
}
.log-item:last-child{border-bottom:none}
.log-user{font-family:'Rajdhani',sans-serif;font-size:13px;font-weight:700;color:var(--accent3);min-width:110px;flex-shrink:0}
.log-action{font-size:13px;flex:1;color:var(--text2);min-width:120px;word-break:break-word}
.log-date{font-size:11px;color:var(--textmuted);white-space:nowrap;flex-shrink:0}

/* ── Toast ── */
#toast{
  position:fixed;bottom:20px;right:16px;left:16px;
  max-width:340px;margin:0 auto;
  background:var(--surface3);border:1px solid var(--border2);
  border-radius:12px;padding:13px 18px;
  font-size:13px;font-weight:600;
  box-shadow:0 16px 48px rgba(0,0,0,0.6),0 0 0 1px rgba(168,85,247,0.1);
  z-index:9999;transform:translateY(100px);opacity:0;transition:all 0.3s cubic-bezier(0.4,0,0.2,1);
}
#toast.show{transform:translateY(0);opacity:1}
#toast.success{border-color:rgba(16,185,129,0.5);color:var(--green);background:rgba(16,185,129,0.08)}
#toast.error{border-color:rgba(244,63,94,0.5);color:var(--red);background:rgba(244,63,94,0.08)}

/* ── Overlay ── */
#sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:49;backdrop-filter:blur(4px)}
#sidebar-overlay.show{display:block}

/* ── Animations ── */
@keyframes fadeIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.page.active{animation:fadeIn 0.3s cubic-bezier(0.4,0,0.2,1)}
@keyframes pulse{
  0%,100%{box-shadow:0 0 4px var(--green),0 0 8px rgba(16,185,129,0.3)}
  50%{box-shadow:0 0 8px var(--green),0 0 16px rgba(16,185,129,0.5)}
}
.status-dot{animation:pulse 2.5s ease-in-out infinite}
@keyframes exportpulse{0%{width:15%}50%{width:85%}100%{width:15%}}
@keyframes accentpulse{0%,100%{opacity:0.6}50%{opacity:1}}

/* ── Glow dividers ── */
.glow-line{height:1px;background:linear-gradient(90deg,transparent,rgba(168,85,247,0.5),transparent);margin:16px 0}

/* ── Scrollbar ── */
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:99px}
::-webkit-scrollbar-thumb:hover{background:var(--accent2)}

/* ══════════════════════════════════════
   RESPONSIVE BREAKPOINTS
══════════════════════════════════════ */

/* Tablet & below: sidebar becomes drawer */
@media(max-width:900px){
  #sidebar{transform:translateX(calc(-1 * var(--sidebar)))}
  #sidebar.collapsed{transform:translateX(calc(-1 * var(--sidebar)))}
  #sidebar.open{transform:translateX(0)}
  #main{margin-left:0 !important}
}

/* Mobile landscape / small tablet */
@media(max-width:640px){
  :root{--topbar:56px}
  #content{padding:12px}
  .card{padding:14px;border-radius:12px;margin-bottom:12px}
  .page-title{font-size:18px;letter-spacing:1px}
  .input-row{grid-template-columns:1fr 1fr;gap:8px}
  .input-row .btn-sm{grid-column:1/-1;width:100%}
  .info-grid{grid-template-columns:1fr}
  .dash-banner-wrap{aspect-ratio:16/6;min-height:80px}
  table{min-width:460px}
  .topbar-status{display:none}
}

/* Mobile portrait */
@media(max-width:420px){
  .auth-box{padding:20px 16px;border-radius:16px}
  .auth-banner-wrap{aspect-ratio:16/6}
  .input-row{grid-template-columns:1fr}
  .input-row .btn-sm{width:100%}
  .log-item{flex-direction:column;gap:4px}
  .log-date{align-self:flex-end}
  #toast{left:10px;right:10px;bottom:12px}
}

/* Desktop large */
@media(min-width:1400px){
  :root{--sidebar:280px}
}
</style>
</head>
<body>

<!-- Loading -->
<div id="loading-screen">
  <div id="loading-img-wrap" style="width:clamp(80px,20vw,120px);height:clamp(80px,20vw,120px);border-radius:16px;overflow:hidden;box-shadow:0 0 40px var(--accentglow);background:var(--surface2);display:flex;align-items:center;justify-content:center">
    <img id="loading-logo" src="/icon/iconme.png" alt="Logo" style="width:100%;height:100%;object-fit:cover;display:block" onerror="this.style.display='none';document.getElementById('loading-logo-fb').style.display='block'"/>
    <span id="loading-logo-fb" style="display:none;font-size:36px">&#9889;</span>
  </div>
  <div style="text-align:center">
    <div style="font-family:'Rajdhani',sans-serif;font-size:clamp(18px,5vw,22px);font-weight:700;color:var(--accent);letter-spacing:3px;margin-bottom:4px">DEWATA NATION RP</div>
    <div style="font-size:11px;letter-spacing:4px;color:var(--textmuted);margin-bottom:20px">ADMIN CONTROL PANEL</div>
    <div class="loading-bar-wrap"><div class="loading-bar" id="loading-bar"></div></div>
  </div>
  <div class="loading-text" id="loading-text">Initializing...</div>
</div>

<!-- Auth: Login -->
<div id="auth-wrapper">
  <div id="login-box" class="auth-box">
    <div class="auth-banner-wrap">
      <img class="auth-banner" src="/icon/iconme.png" alt="Dewata Nation RP" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'"/>
      <div class="auth-banner-fallback" style="display:none;width:100%;align-items:center;justify-content:center">&#9889; DEWATA NATION RP</div>
    </div>
    <div class="auth-title">&#9889; DEWATA NATION RP</div>
    <div class="auth-sub">Admin Control Panel — Masuk untuk melanjutkan</div>
    <div class="auth-error" id="login-error"></div>
    <div class="form-group">
      <label>Username</label>
      <input type="text" id="login-user" placeholder="Masukkan username..." autocomplete="username"/>
    </div>
    <div class="form-group">
      <label>Password</label>
      <input type="password" id="login-pass" placeholder="Masukkan password..." autocomplete="current-password"/>
    </div>
    <button class="btn btn-primary" onclick="doLogin()">MASUK</button>
  </div>
  <div id="adminkey-box" class="auth-box" style="display:none">
    <div class="auth-banner-wrap">
      <img class="auth-banner" src="/icon/iconme.png" alt="Dewata Nation RP" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'"/>
      <div class="auth-banner-fallback" style="display:none;width:100%;align-items:center;justify-content:center">&#128273; VERIFIKASI ADMIN</div>
    </div>
    <div class="auth-title">&#128273; VERIFIKASI ADMIN</div>
    <div class="auth-sub">Masukkan Admin Key untuk akses panel</div>
    <div class="auth-error" id="key-error"></div>
    <div class="form-group">
      <label>Admin Key</label>
      <input type="password" id="admin-key" placeholder="Masukkan admin key..." autocomplete="off"/>
    </div>
    <button class="btn btn-primary" onclick="doVerifyKey()">VERIFIKASI</button>
  </div>
</div>

<!-- App -->
<div id="app">
  <!-- Sidebar Overlay (mobile) -->
  <div id="sidebar-overlay" onclick="toggleSidebar()"></div>

  <!-- Sidebar -->
  <nav id="sidebar">
    <div class="sidebar-header">
      <div class="sidebar-logo-wrap">
        <img class="sidebar-logo" src="/icon/iconme.png" alt="Logo" onerror="this.style.display='none';this.nextElementSibling.style.display='block'"/>
        <span class="sidebar-logo-fallback" style="display:none">&#9889;</span>
      </div>
      <div class="sidebar-title">DEWATA NRP</div>
    </div>
    <div class="sidebar-nav">
      <div class="nav-item active" onclick="showPage('dashboard')">
        <span class="nav-icon">🏠</span>
        <span>Dashboard</span>
      </div>
      <div class="nav-item" onclick="showPage('getcord')">
        <span class="nav-icon">📍</span>
        <span>Getcord List</span>
      </div>
      <div class="nav-item" onclick="showPage('set')">
        <span class="nav-icon">⚙️</span>
        <span>Set Menu</span>
      </div>
      <div class="nav-item" onclick="showPage('adminlog')">
        <span class="nav-icon">📋</span>
        <span>Admin Log</span>
      </div>
      <div class="nav-item" onclick="showPage('inventory')">
        <span class="nav-icon">🎒</span>
        <span>Inventori Player</span>
      </div>
      <div class="nav-item" onclick="showPage('setadmin')">
        <span class="nav-icon">🛡️</span>
        <span>Set Admin</span>
      </div>
      <div class="nav-item" onclick="showPage('property')">
        <span class="nav-icon">🏠</span>
        <span>Add Property</span>
      </div>
      <div class="nav-item" onclick="showPage('punishment')">
        <span class="nav-icon">⛓️</span>
        <span>Punishment</span>
      </div>
      <div class="nav-item" onclick="showPage('backup')">
        <span class="nav-icon">💾</span>
        <span>Backup Database</span>
      </div>
    </div>
    <div class="sidebar-footer">
      <div class="sidebar-user">
        <div class="user-avatar" id="user-avatar">?</div>
        <div class="user-info">
          <div class="user-name" id="sidebar-username">-</div>
          <div class="user-role">ADMINISTRATOR</div>
        </div>
      </div>
      <button class="btn btn-danger" style="width:100%" onclick="doLogout()">🚪 LOGOUT</button>
    </div>
  </nav>

  <!-- Main -->
  <div id="main" class="expanded">
    <div id="topbar">
      <button id="menu-toggle" onclick="toggleSidebar()">☰</button>
      <div class="topbar-title" id="page-title">Dashboard</div>
      <div class="topbar-status">
        <div class="status-dot"></div>
        <span id="admin-name-top">-</span>
      </div>
    </div>

    <div id="content">

      <!-- Dashboard Page -->
      <div class="page active" id="page-dashboard">
        <div class="dash-banner-wrap">
          <img class="dash-banner" src="/icon/iconme.png" alt="Dewata Nation RP" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'"/>
          <div class="dash-banner-fallback" style="display:none;width:100%;align-items:center;justify-content:center">&#9889; DEWATA NATION ROLEPLAY</div>
        </div>
        <div class="page-title">Dashboard</div>
        <div class="page-sub">Selamat datang di Dewata Nation Roleplay Admin Panel. Gunakan menu sidebar untuk navigasi fitur.</div>
        <div class="info-grid">
          <div class="info-card">
            <div class="info-label">🌐 Server IP & Port</div>
            <div class="info-value">208.84.103.75:7103</div>
            <button class="info-copy-btn" onclick="copyText('208.84.103.75:7103',this)">📋 Copy IP</button>
          </div>
          <div class="info-card">
            <div class="info-label">💬 WhatsApp Group</div>
            <div class="info-value" style="font-size:13px">Dewata Nation RP Community</div>
            <button class="info-copy-btn" onclick="copyText('https://chat.whatsapp.com/GQ1V4a5ieKbHiXZLxqQx99',this)">📋 Copy Link WA</button>
          </div>
        </div>
        <div class="card">
          <div class="card-title">ℹ️ Informasi Panel</div>
          <p style="font-size:14px;color:var(--textmuted);line-height:1.8">
            Panel admin ini digunakan untuk mengelola server <strong style="color:var(--accent)">Dewata Nation Roleplay SAMP</strong>. 
            Anda dapat mengelola koordinat getcord, mengatur item dan uang pemain, serta memantau aktivitas admin melalui log.
            Semua tindakan tercatat otomatis di Admin Log untuk keamanan server.
          </p>
        </div>
      </div>

      <!-- Getcord Page -->
      <div class="page" id="page-getcord">
        <div class="page-title">📍 Getcord List</div>
        <div class="page-sub">Daftar koordinat yang tersimpan di database server.</div>
        <div class="card">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
            <div class="card-title" style="margin:0">Koordinat List</div>
            <button class="btn btn-copy btn-sm" onclick="loadGetcord()">🔄 Refresh</button>
          </div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>ID</th><th>Name</th><th>X</th><th>Y</th><th>Z</th><th>A</th><th>Copy</th><th>Hapus</th></tr></thead>
              <tbody id="getcord-tbody"><tr><td colspan="8" style="text-align:center;color:var(--textmuted);padding:28px">Memuat data...</td></tr></tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Set Menu Page -->
      <div class="page" id="page-set">
        <div class="page-title">⚙️ Set Menu</div>
        <div class="page-sub">Kelola data pemain: uang, item, akun, dan properti.</div>

        <!-- Set Money -->
        <div class="card">
          <div class="card-title">💰 Set Uang Pemain</div>
          <div class="input-row">
            <div class="form-group"><label>Username</label><input type="text" id="money-user" placeholder="Username..."/></div>
            <div class="form-group"><label>Value</label><input type="number" id="money-val" placeholder="0" min="0" max="500000000"/></div>
            <div class="form-group"><label>Type</label>
              <select id="money-type" onchange="updateMoneyMax()">
                <option value="pCash" data-max="500000000">pCash — Uang Cash (max 500jt)</option>
                <option value="pBank" data-max="500000000">pBank — Uang Bank (max 500jt)</option>
                <option value="pUangMerah" data-max="500000000">pUangMerah — Uang Merah (max 500jt)</option>
                <option value="pRouble" data-max="1000">pRouble — Donate Coin (max 1.000)</option>
              </select>
            </div>
            <button class="btn btn-primary btn-sm" onclick="setMoney()" style="flex-shrink:0;margin-bottom:0">SET</button>
          </div>
          <div id="money-limit-info" style="font-size:12px;color:var(--textmuted);margin-bottom:4px">Limit: <strong style="color:var(--accent)">500.000.000</strong></div>
          <div class="error-msg" id="money-err"></div>
          <div class="success-msg" id="money-ok"></div>
        </div>

        <!-- Set Item -->
        <div class="card">
          <div class="card-title">🎒 Set Item Pemain</div>
          <div class="input-row">
            <div class="form-group"><label>Username</label><input type="text" id="item-user" placeholder="Username..."/></div>
            <div class="form-group"><label>Value (max 1.000)</label><input type="number" id="item-val" placeholder="0" min="0" max="1000"/></div>
            <div class="form-group"><label>Type</label>
              <select id="item-type">
                <option value="pBatu">pBatu — Batu Bersih</option>
                <option value="pBatuk">pBatuk — Batu Kotor</option>
                <option value="pFish">pFish — Ikan</option>
                <option value="pPenyu">pPenyu — Penyu</option>
                <option value="pDolphin">pDolphin — Dolpin</option>
                <option value="pHiu">pHiu — Hiu</option>
                <option value="pMegalodon">pMegalodon — Megalodon</option>
                <option value="pCaught">pCaught — Umpan Mancing</option>
                <option value="pPadi">pPadi — Padi</option>
                <option value="pAyam">pAyam — Ayam</option>
                <option value="pSemen">pSemen — Semen</option>
                <option value="pEmas">pEmas — Emas</option>
                <option value="pSusu">pSusu — Susu Sapi</option>
                <option value="pMinyak">pMinyak — Minyak</option>
                <option value="pAyamKemas">pAyamKemas — Ayam Kemas</option>
                <option value="pAyamPotong">pAyamPotong — Ayam Potong</option>
                <option value="pAyamHidup">pAyamHidup — Ayam Hidup</option>
                <option value="pBulu">pBulu — Bulu Ayam</option>
              </select>
            </div>
            <button class="btn btn-primary btn-sm" onclick="setItem()" style="flex-shrink:0;margin-bottom:0">SET</button>
          </div>
          <div style="font-size:12px;color:var(--textmuted);margin-bottom:4px">Limit semua item: <strong style="color:var(--accent)">1.000</strong></div>
          <div class="error-msg" id="item-err"></div>
          <div class="success-msg" id="item-ok"></div>
        </div>

        <!-- Set Account -->
        <div class="card">
          <div class="card-title">🗃️ Set Akun Pemain</div>
          <div class="input-row">
            <div class="form-group"><label>Username</label><input type="text" id="acc-user" placeholder="Username..."/></div>
            <div class="form-group"><label>Value</label><input type="number" id="acc-val" placeholder="0" min="0" max="5000"/></div>
            <div class="form-group"><label>Type</label>
              <select id="acc-type" onchange="updateAccMax()">
                <option value="pDrugs"     data-max="500" >pDrugs — Drugs (max 500)</option>
                <option value="pMicin"     data-max="500" >pMicin — Marijuana (max 500)</option>
                <option value="pSteroid"   data-max="500" >pSteroid — Steroid (max 500)</option>
                <option value="pComponent" data-max="5000">pComponent — Component (max 5.000)</option>
                <option value="pMetall"    data-max="5000">pMetall — Besi (max 5.000)</option>
                <option value="pFood"      data-max="200" >pFood — Makanan (max 200)</option>
                <option value="pDrink"     data-max="200" >pDrink — Minuman (max 200)</option>
              </select>
            </div>
            <button class="btn btn-primary btn-sm" onclick="setAccount()" style="flex-shrink:0;margin-bottom:0">SET</button>
          </div>
          <div id="acc-limit-info" style="font-size:12px;color:var(--textmuted);margin-bottom:4px">Limit: <strong style="color:var(--accent)" id="acc-limit-val">500</strong></div>
          <div class="error-msg" id="acc-err"></div>
          <div class="success-msg" id="acc-ok"></div>
        </div>

        <!-- Set Property -->
        <div class="card">
          <div class="card-title">🔧 Set Properti Pemain</div>
          <div class="prop-grid" id="prop-grid">
            <!-- pSkin -->
            <div class="set-card">
              <div class="set-title">🎭 Set Skin</div>
              <div class="form-group"><label>Username</label><input type="text" id="prop-skin-user" placeholder="Username..."/></div>
              <div class="form-group"><label>Skin ID</label><input type="number" id="prop-skin-val" placeholder="0"/></div>
              <button class="btn btn-primary" onclick="setProp('pSkin','prop-skin-user','prop-skin-val','prop-skin-msg','prop-skin-err')">SET SKIN</button>
              <div class="error-msg" id="prop-skin-err"></div>
              <div class="success-msg" id="prop-skin-msg"></div>
            </div>
            <!-- pMaskID -->
            <div class="set-card">
              <div class="set-title">🎭 Set Mask ID (max 4 digit)</div>
              <div class="form-group"><label>Username</label><input type="text" id="prop-mask-user" placeholder="Username..."/></div>
              <div class="form-group"><label>Mask ID (max 9999)</label><input type="number" id="prop-mask-val" placeholder="0" max="9999"/></div>
              <button class="btn btn-primary" onclick="setProp('pMaskID','prop-mask-user','prop-mask-val','prop-mask-msg','prop-mask-err')">SET MASK</button>
              <div class="error-msg" id="prop-mask-err"></div>
              <div class="success-msg" id="prop-mask-msg"></div>
            </div>
            <!-- pCS -->
            <div class="set-card">
              <div class="set-title">✨ Set CS (Custom Skin)</div>
              <div class="form-group"><label>Username</label><input type="text" id="prop-cs-user" placeholder="Username..."/></div>
              <div class="form-group"><label>Status CS</label>
                <select id="prop-cs-val">
                  <option value="1">Aktifkan CS</option>
                  <option value="0">Non-aktifkan CS</option>
                </select>
              </div>
              <button class="btn btn-primary" onclick="setProp('pCS','prop-cs-user','prop-cs-val','prop-cs-msg','prop-cs-err')">SET CS</button>
              <div class="error-msg" id="prop-cs-err"></div>
              <div class="success-msg" id="prop-cs-msg"></div>
            </div>
            <!-- pFreeRoulet -->
            <div class="set-card">
              <div class="set-title">🎰 Set Gacha (Free Roulet)</div>
              <div class="form-group"><label>Username</label><input type="text" id="prop-gacha-user" placeholder="Username..."/></div>
              <div class="form-group"><label>Jumlah Gacha (max 300)</label><input type="number" id="prop-gacha-val" placeholder="0" max="300"/></div>
              <button class="btn btn-primary" onclick="setProp('pFreeRoulet','prop-gacha-user','prop-gacha-val','prop-gacha-msg','prop-gacha-err')">SET GACHA</button>
              <div class="error-msg" id="prop-gacha-err"></div>
              <div class="success-msg" id="prop-gacha-msg"></div>
            </div>
          </div>
        </div>
        
        <!-- Set VIP -->
        <div class="card">
          <div class="card-title">&#11088; Set VIP Pemain</div>

          <!-- Current VIP info panel -->
          <div id="vip-info-wrap" style="display:none;background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:16px;margin-bottom:16px">
            <div style="font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--textmuted);margin-bottom:10px;font-weight:600">Info VIP Saat Ini</div>
            <div style="display:flex;flex-wrap:wrap;gap:12px" id="vip-info-content"></div>
          </div>

          <div class="input-row">
            <div class="form-group">
              <label>Username</label>
              <input type="text" id="vip-user" placeholder="Username..." oninput="clearVipInfo()"/>
            </div>
            <div class="form-group">
              <label>Tipe VIP</label>
              <select id="vip-type" onchange="onVipTypeChange()">
                <option value="0">0 — Nonaktifkan VIP</option>
                <option value="1">1 — VIP Low</option>
                <option value="2">2 — VIP Medium</option>
                <option value="3">3 — VIP High</option>
              </select>
            </div>
            <div class="form-group" id="vip-days-wrap">
              <label>Durasi (hari)</label>
              <input type="number" id="vip-days" placeholder="30" min="1" max="3650"/>
            </div>
            <button class="btn btn-primary btn-sm" onclick="setVip()" style="flex-shrink:0;margin-bottom:0">SET</button>
          </div>

          <!-- Quick presets -->
          <div id="vip-presets" style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px">
            <span style="font-size:11px;color:var(--textmuted);align-self:center;letter-spacing:1px;text-transform:uppercase;font-weight:600">Quick:</span>
            <button class="btn btn-copy btn-sm" onclick="setVipDays(7)">7 Hari</button>
            <button class="btn btn-copy btn-sm" onclick="setVipDays(30)">30 Hari</button>
            <button class="btn btn-copy btn-sm" onclick="setVipDays(90)">90 Hari</button>
            <button class="btn btn-copy btn-sm" onclick="setVipDays(180)">180 Hari</button>
            <button class="btn btn-copy btn-sm" onclick="setVipDays(365)">1 Tahun</button>
          </div>

          <div style="display:flex;gap:8px;margin-bottom:4px">
            <button class="btn btn-copy btn-sm" onclick="checkVipStatus()">&#128270; Cek Status VIP</button>
          </div>

          <div class="error-msg" id="vip-err"></div>
          <div class="success-msg" id="vip-ok"></div>
        </div>

        <!-- Set Gun -->
        <div class="card">
          <div class="card-title">&#128299; Set Senjata Pemain</div>
          <div class="gun-preview-wrap" id="gun-preview-wrap" style="display:none;background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:14px;margin-bottom:14px">
            <div style="font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--textmuted);margin-bottom:8px;font-weight:600">Preview Slot Senjata</div>
            <div id="gun-slot-preview" style="display:flex;flex-wrap:wrap;gap:6px"></div>
          </div>
          <div class="input-row">
            <div class="form-group">
              <label>Username</label>
              <input type="text" id="gun-user" placeholder="Username..." oninput="clearGunPreview()"/>
            </div>
            <div class="form-group">
              <label>ID Senjata (23-31)</label>
              <select id="gun-id" onchange="updateGunLabel()">
                <option value="23">23 — Silenced Pistol</option>
                <option value="24">24 — Desert Eagle</option>
                <option value="25">25 — Shotgun</option>
                <option value="26">26 — Sawnoff Shotgun</option>
                <option value="27">27 — Combat Shotgun</option>
                <option value="28">28 — Micro SMG / Uzi</option>
                <option value="29">29 — MP5</option>
                <option value="30">30 — AK-47</option>
                <option value="31">31 — M4</option>
              </select>
            </div>
            <div class="form-group">
              <label>Ammo (max 1000)</label>
              <input type="number" id="gun-ammo" placeholder="0" min="0" max="1000"/>
            </div>
            <button class="btn btn-primary btn-sm" onclick="setGun()" style="flex-shrink:0;margin-bottom:0">SET</button>
          </div>
          <div style="display:flex;gap:8px;margin-top:4px;margin-bottom:4px">
            <button class="btn btn-copy btn-sm" onclick="previewGunSlots()">&#128270; Lihat Slot</button>
          </div>
          <div class="error-msg" id="gun-err"></div>
          <div class="success-msg" id="gun-ok"></div>
        </div>

        <!-- Set Vehicle -->
        <div class="card">
          <div class="card-title">&#128663; Set Kendaraan Pemain</div>
          <div id="veh-preview-wrap" style="display:none;background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:14px;margin-bottom:14px">
            <div style="font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--textmuted);margin-bottom:8px;font-weight:600">Preview Slot Kendaraan</div>
            <div id="veh-slot-preview" style="display:flex;flex-wrap:wrap;gap:6px"></div>
          </div>
          <div class="input-row">
            <div class="form-group">
              <label>Username</label>
              <input type="text" id="veh-user" placeholder="Username..." oninput="clearVehPreview()"/>
            </div>
            <div class="form-group" style="flex:2">
              <label>Kendaraan</label>
              <select id="veh-id" style="width:100%">
                <option value="400">400 — Landstalker</option>
                <option value="401">401 — Bravura</option>
                <option value="402">402 — Buffalo</option>
                <option value="403">403 — Linerunner</option>
                <option value="404">404 — Pereniel</option>
                <option value="405">405 — Sentinel</option>
                <option value="406">406 — Dumper</option>
                <option value="407">407 — Firetruck</option>
                <option value="408">408 — Trashmaster</option>
                <option value="409">409 — Stretch</option>
                <option value="410">410 — Manana</option>
                <option value="411">411 — Infernus</option>
                <option value="412">412 — Voodoo</option>
                <option value="413">413 — Pony</option>
                <option value="414">414 — Mule</option>
                <option value="415">415 — Cheetah</option>
                <option value="416">416 — Ambulance</option>
                <option value="417">417 — Leviathan</option>
                <option value="418">418 — Moonbeam</option>
                <option value="419">419 — Esperanto</option>
                <option value="420">420 — Taxi</option>
                <option value="421">421 — Washington</option>
                <option value="422">422 — Bobcat</option>
                <option value="423">423 — Mr Whoopee</option>
                <option value="424">424 — BF Injection</option>
                <option value="425">425 — Hunter</option>
                <option value="426">426 — Premier</option>
                <option value="427">427 — Enforcer</option>
                <option value="428">428 — Securicar</option>
                <option value="429">429 — Banshee</option>
                <option value="430">430 — Predator</option>
                <option value="431">431 — Bus</option>
                <option value="432">432 — Rhino</option>
                <option value="433">433 — Barracks</option>
                <option value="434">434 — Hotknife</option>
                <option value="436">436 — Previon</option>
                <option value="437">437 — Coach</option>
                <option value="438">438 — Cabbie</option>
                <option value="439">439 — Stallion</option>
                <option value="440">440 — Rumpo</option>
                <option value="442">442 — Romero</option>
                <option value="443">443 — Packer</option>
                <option value="444">444 — Monster</option>
                <option value="445">445 — Admiral</option>
                <option value="446">446 — Squalo</option>
                <option value="447">447 — Seasparrow</option>
                <option value="448">448 — Pizzaboy</option>
                <option value="451">451 — Turismo</option>
                <option value="452">452 — Speeder</option>
                <option value="453">453 — Reefer</option>
                <option value="454">454 — Tropic</option>
                <option value="455">455 — Flatbed</option>
                <option value="456">456 — Yankee</option>
                <option value="457">457 — Caddy</option>
                <option value="458">458 — Solair</option>
                <option value="460">460 — Skimmer</option>
                <option value="461">461 — PCJ-600</option>
                <option value="462">462 — Faggio</option>
                <option value="463">463 — Freeway</option>
                <option value="466">466 — Glendale</option>
                <option value="467">467 — Oceanic</option>
                <option value="468">468 — Sanchez</option>
                <option value="469">469 — Sparrow</option>
                <option value="470">470 — Patriot</option>
                <option value="471">471 — Quad</option>
                <option value="474">474 — Hermes</option>
                <option value="475">475 — Sabre</option>
                <option value="476">476 — Rustler</option>
                <option value="477">477 — ZR-350</option>
                <option value="478">478 — Walton</option>
                <option value="479">479 — Regina</option>
                <option value="480">480 — Comet</option>
                <option value="481">481 — BMX</option>
                <option value="482">482 — Burrito</option>
                <option value="483">483 — Camper</option>
                <option value="484">484 — Marquis</option>
                <option value="487">487 — Maverick</option>
                <option value="489">489 — Rancher</option>
                <option value="490">490 — FBI Rancher</option>
                <option value="491">491 — Virgo</option>
                <option value="492">492 — Greenwood</option>
                <option value="493">493 — Jetmax</option>
                <option value="494">494 — Hotring</option>
                <option value="495">495 — Sandking</option>
                <option value="496">496 — Blista Compact</option>
                <option value="498">498 — Boxville</option>
                <option value="499">499 — Benson</option>
                <option value="500">500 — Mesa</option>
                <option value="502">502 — Hotring Racer A</option>
                <option value="503">503 — Hotring Racer B</option>
                <option value="506">506 — Super GT</option>
                <option value="507">507 — Elegant</option>
                <option value="508">508 — Journey</option>
                <option value="510">510 — Mountain Bike</option>
                <option value="511">511 — Beagle</option>
                <option value="512">512 — Cropduster</option>
                <option value="513">513 — Stuntplane</option>
                <option value="516">516 — Nebula</option>
                <option value="517">517 — Majestic</option>
                <option value="518">518 — Buccaneer</option>
                <option value="519">519 — Shamal</option>
                <option value="520">520 — Hydra</option>
                <option value="521">521 — FCR-900</option>
                <option value="522">522 — NRG-500</option>
                <option value="523">523 — HPV1000</option>
                <option value="526">526 — Fortune</option>
                <option value="527">527 — Cadrona</option>
                <option value="529">529 — Willard</option>
                <option value="533">533 — Feltzer</option>
                <option value="534">534 — Remington</option>
                <option value="535">535 — Slamvan</option>
                <option value="536">536 — Blade</option>
                <option value="540">540 — Vincent</option>
                <option value="541">541 — Bullet</option>
                <option value="542">542 — Clover</option>
                <option value="543">543 — Sadler</option>
                <option value="545">545 — Hustler</option>
                <option value="546">546 — Intruder</option>
                <option value="547">547 — Primo</option>
                <option value="549">549 — Tampa</option>
                <option value="550">550 — Sunrise</option>
                <option value="551">551 — Merit</option>
                <option value="555">555 — Windsor</option>
                <option value="558">558 — Uranus</option>
                <option value="559">559 — Jester</option>
                <option value="560">560 — Sultan</option>
                <option value="561">561 — Stratum</option>
                <option value="562">562 — Elegy</option>
                <option value="565">565 — Flash</option>
                <option value="566">566 — Tahoma</option>
                <option value="567">567 — Savanna</option>
                <option value="568">568 — Bandito</option>
                <option value="571">571 — Kart</option>
                <option value="575">575 — Broadway</option>
                <option value="576">576 — Tornado</option>
                <option value="579">579 — Huntley</option>
                <option value="580">580 — Stafford</option>
                <option value="581">581 — BF-400</option>
                <option value="585">585 — Emperor</option>
                <option value="586">586 — Wayfarer</option>
                <option value="587">587 — Euros</option>
                <option value="589">589 — Club</option>
                <option value="596">596 — Police Car LSPD</option>
                <option value="597">597 — Police Car SFPD</option>
                <option value="598">598 — Police Car LVPD</option>
                <option value="599">599 — Police Ranger</option>
                <option value="600">600 — Picador</option>
                <option value="601">601 — S.W.A.T.</option>
                <option value="602">602 — Alpha</option>
                <option value="603">603 — Phoenix</option>
              </select>
            </div>
            <button class="btn btn-primary btn-sm" onclick="setVeh()" style="flex-shrink:0;margin-bottom:0">SET</button>
          </div>
          <div style="display:flex;gap:8px;margin-top:4px;margin-bottom:4px">
            <button class="btn btn-copy btn-sm" onclick="previewVehSlots()">&#128270; Lihat Slot</button>
          </div>
          <div class="error-msg" id="veh-err"></div>
          <div class="success-msg" id="veh-ok"></div>
        </div>
      </div>
      <div class="page" id="page-adminlog">
        <div class="page-title">📋 Admin Log</div>
        <div class="page-sub">Riwayat kegiatan admin di server Dewata Nation RP.</div>
        <div class="card">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
            <div class="card-title" style="margin:0">Log Aktivitas</div>
            <button class="btn btn-copy btn-sm" onclick="loadAdminLog()">🔄 Refresh</button>
          </div>
          <div id="log-list"><div style="text-align:center;color:var(--textmuted);padding:28px">Memuat log...</div></div>
        </div>
      </div>

    </div><!-- /content -->
  </div><!-- /main -->
</div><!-- /app -->

<!-- Inventory Page -->
<template id="tpl-inventory">
  <div class="page" id="page-inventory">
    <div class="page-title">&#127890; Inventori Player</div>
    <div class="page-sub">Lihat semua data inventori lengkap milik player.</div>

    <!-- Search bar -->
    <div class="card" style="margin-bottom:16px">
      <div style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">
        <div class="form-group" style="flex:1;min-width:200px;margin-bottom:0">
          <label>Username Player</label>
          <input type="text" id="inv-search" placeholder="Masukkan username..." onkeydown="if(event.key==='Enter')loadInventory()"/>
        </div>
        <button class="btn btn-primary btn-sm" style="height:44px;padding:0 24px" onclick="loadInventory()">&#128269; CARI</button>
      </div>
    </div>

    <!-- Results -->
    <div id="inv-result" style="display:none">

      <!-- Profile header -->
      <div class="card" id="inv-profile-card" style="margin-bottom:16px;background:linear-gradient(135deg,var(--surface),var(--surface2))">
        <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
          <div id="inv-avatar" style="width:60px;height:60px;border-radius:16px;background:var(--accentglow);border:2px solid var(--accent);display:flex;align-items:center;justify-content:center;font-family:Rajdhani,sans-serif;font-size:28px;font-weight:700;color:var(--accent);flex-shrink:0"></div>
          <div style="flex:1;min-width:0">
            <div id="inv-name" style="font-family:Rajdhani,sans-serif;font-size:24px;font-weight:700;color:var(--text);letter-spacing:1px"></div>
            <div id="inv-badges" style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px"></div>
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:10px" id="inv-stats"></div>
        </div>
      </div>

      <!-- Money -->
      <div class="card" style="margin-bottom:14px">
        <div class="card-title">&#128176; Uang &amp; Wallet</div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px" id="inv-money"></div>
      </div>

      <!-- Weapons -->
      <div class="card" style="margin-bottom:14px">
        <div class="card-title">&#128299; Senjata</div>
        <div style="display:flex;flex-wrap:wrap;gap:8px" id="inv-weapons"></div>
      </div>

      <!-- Vehicles -->
      <div class="card" style="margin-bottom:14px">
        <div class="card-title">&#128663; Kendaraan</div>
        <div style="display:flex;flex-wrap:wrap;gap:8px" id="inv-vehicles"></div>
      </div>

      <!-- Items -->
      <div class="card" style="margin-bottom:14px">
        <div class="card-title">&#127873; Item</div>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px" id="inv-items"></div>
      </div>

      <!-- Account items -->
      <div class="card" style="margin-bottom:14px">
        <div class="card-title">&#128203; Akun Item</div>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px" id="inv-account"></div>
      </div>

    </div><!-- /inv-result -->

    <div id="inv-empty" style="display:none;text-align:center;padding:40px;color:var(--textmuted)">
      <div style="font-size:48px;margin-bottom:12px">&#128269;</div>
      <div style="font-family:Rajdhani,sans-serif;font-size:18px">Player tidak ditemukan</div>
    </div>
    <div id="inv-loading" style="display:none;text-align:center;padding:40px;color:var(--textmuted)">
      <div style="font-size:32px;margin-bottom:12px">&#8987;</div>
      <div>Memuat data inventori...</div>
    </div>
    <div id="inv-err-msg" style="display:none" class="error-msg show"></div>
  </div>
</template>

<!-- Set Admin Page -->
<template id="tpl-setadmin">
  <div class="page" id="page-setadmin">
    <div class="page-title">&#128737; Set Admin</div>
    <div class="page-sub">Kelola data admin server Dewata Nation RP.</div>

    <!-- Form card -->
    <div class="card" style="margin-bottom:16px">
      <div class="card-title">&#128737; Set / Update Admin</div>

      <!-- Admin info preview -->
      <div id="sa-info-wrap" style="display:none;background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:14px;margin-bottom:16px">
        <div style="font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--textmuted);margin-bottom:10px;font-weight:600">Info Admin Saat Ini</div>
        <div id="sa-info-content" style="display:flex;flex-wrap:wrap;gap:10px"></div>
      </div>

      <div class="input-row">
        <div class="form-group">
          <label>Username (Name)</label>
          <input type="text" id="sa-user" placeholder="Username player..." oninput="clearSaInfo()"/>
        </div>
        <div class="form-group">
          <label>Level Admin (pAdmin)</label>
          <select id="sa-level">
            <option value="1" >1  — Admin Trial</option>
            <option value="2" >2  — Admin</option>
            <option value="3" >3  — Admin</option>
            <option value="4" >4  — Admin</option>
            <option value="5" >5  — Admin</option>
            <option value="6" >6  — Admin</option>
            <option value="7" >7  — Admin</option>
            <option value="8" >8  — High Admin</option>
            <option value="9" >9  — Handle Admin</option>
            <option value="10">10 — Co-Owner</option>
            <option value="15">15 — Owner</option>
            <option value="20">20 — Developer</option>
          </select>
        </div>
        <div class="form-group">
          <label>Admin Name (pAname)</label>
          <input type="text" id="sa-aname" placeholder="Nama admin..." maxlength="32"/>
        </div>
        <div class="form-group">
          <label>Admin Key (pAdminKey)</label>
          <input type="text" id="sa-key" placeholder="Kunci admin..." maxlength="32"/>
        </div>
      </div>

      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:4px">
        <button class="btn btn-primary btn-sm" onclick="setAdmin()">&#128737; SET ADMIN</button>
        <button class="btn btn-copy btn-sm" onclick="checkAdminInfo()">&#128269; Cek Info Admin</button>
        <button class="btn btn-sm" onclick="removeAdmin()" style="background:rgba(232,48,48,0.12);color:var(--red);border:1px solid rgba(232,48,48,0.3)">&#128465; Hapus Admin</button>
      </div>
      <div class="error-msg" id="sa-err"></div>
      <div class="success-msg" id="sa-ok"></div>
    </div>

    <!-- Admin list card -->
    <div class="card">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px">
        <div class="card-title" style="margin:0">&#128101; Daftar Admin</div>
        <button class="btn btn-copy btn-sm" onclick="loadAdminList()">&#128260; Refresh</button>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>Level</th>
              <th>Jabatan</th>
              <th>Admin Name</th>
              <th>Rep</th>
              <th>Kick</th>
              <th>Ban</th>
              <th>Join</th>
              <th>Aksi</th>
            </tr>
          </thead>
          <tbody id="sa-list-tbody">
            <tr><td colspan="9" style="text-align:center;color:var(--textmuted);padding:28px">Klik Refresh untuk memuat...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<!-- Property Page -->
<template id="tpl-property">
  <div class="page" id="page-property">
    <div class="page-title">&#127968; Add Property</div>
    <div class="page-sub">Tambahkan bisnis atau rumah baru ke dalam server.</div>

    <!-- Stats row -->
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:20px" id="prop-stats">
      <div class="info-card" style="text-align:center">
        <div class="info-label">Total Bisnis</div>
        <div style="font-family:Orbitron,sans-serif;font-size:28px;font-weight:700;color:var(--accent)" id="stat-bizz-total">—</div>
        <div style="font-size:11px;color:var(--textmuted);margin-top:4px" id="stat-bizz-owned">— dimiliki</div>
      </div>
      <div class="info-card" style="text-align:center">
        <div class="info-label">Total Rumah</div>
        <div style="font-family:Orbitron,sans-serif;font-size:28px;font-weight:700;color:var(--accent3)" id="stat-house-total">—</div>
        <div style="font-size:11px;color:var(--textmuted);margin-top:4px" id="stat-house-owned">— dimiliki</div>
      </div>
    </div>

    <!-- Tab switcher -->
    <div style="display:flex;gap:8px;margin-bottom:20px">
      <button class="btn btn-primary btn-sm" id="tab-bizz-btn" onclick="switchPropTab('bizz')">&#127981; Add Bisnis</button>
      <button class="btn btn-copy btn-sm"    id="tab-house-btn" onclick="switchPropTab('house')">&#127968; Add Rumah</button>
    </div>

    <!-- ═══ ADD BISNIS ═══ -->
    <div id="prop-tab-bizz">
      <div class="card">
        <div class="card-title">&#127981; Add Bisnis Baru</div>

        <div class="input-row" style="grid-template-columns:1fr 1fr">
          <div class="form-group">
            <label>Nama Bisnis (bMessage)</label>
            <input type="text" id="bizz-name" placeholder="contoh: Toko ABC..." maxlength="64"/>
          </div>
          <div class="form-group">
            <label>Harga Beli (bBuyPrice) — 5jt s/d 100jt</label>
            <input type="number" id="bizz-price" placeholder="5000000" min="5000000" max="100000000"/>
          </div>
        </div>

        <div class="form-group">
          <label>Tipe Interior (bInterior)</label>
          <select id="bizz-interior">
            <option value="1">1 — Beer Shop</option>
            <option value="2">2 — Fast Food</option>
            <option value="3">3 — Market</option>
            <option value="4">4 — Clothes</option>
            <option value="5">5 — Equipment</option>
            <option value="7">7 — Hotel</option>
            <option value="8">8 — Clothes</option>
            <option value="9">9 — Equipment</option>
            <option value="10">10 — Hotel</option>
            <option value="11">11 — Clothes</option>
            <option value="12">12 — Equipment</option>
            <option value="13">13 — Hotel</option>
          </select>
        </div>

        <div style="margin-bottom:14px">
          <div style="font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--textmuted);margin-bottom:10px;font-weight:700">Koordinat Entrance</div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px">
            <div class="form-group" style="margin-bottom:0">
              <label>X (bEntranceX)</label>
              <input type="number" id="bizz-x" placeholder="0.0" step="0.001"/>
            </div>
            <div class="form-group" style="margin-bottom:0">
              <label>Y (bEntranceY)</label>
              <input type="number" id="bizz-y" placeholder="0.0" step="0.001"/>
            </div>
            <div class="form-group" style="margin-bottom:0">
              <label>Z (bEntranceZ)</label>
              <input type="number" id="bizz-z" placeholder="0.0" step="0.001"/>
            </div>
          </div>
        </div>

        <div style="background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;margin-bottom:14px;font-size:12px;color:var(--textmuted);line-height:1.7">
          ℹ️ Field lainnya akan diset ke default:
          <span style="color:var(--text2)">bOwned=0, bOwner='The State', bLocked=0, bMoney=0, bMafia=0, bSong='0', dll</span>
        </div>

        <button class="btn btn-primary" style="max-width:220px" onclick="addBizz()">&#43; ADD BISNIS</button>
        <div class="error-msg"   id="bizz-err"></div>
        <div class="success-msg" id="bizz-ok"></div>
      </div>
    </div>

    <!-- ═══ ADD HOUSE ═══ -->
    <div id="prop-tab-house" style="display:none">
      <div class="card">
        <div class="card-title">&#127968; Add Rumah Baru</div>

        <div class="input-row" style="grid-template-columns:1fr 1fr">
          <div class="form-group">
            <label>Harga Rumah (hValue) — 5jt s/d 100jt</label>
            <input type="number" id="house-value" placeholder="5000000" min="5000000" max="100000000"/>
          </div>
          <div class="form-group">
            <label>Tipe Interior (hInt)</label>
            <select id="house-int">
              <option value="0">0 — Miskin</option>
              <option value="1">1 — Medium</option>
              <option value="2">2 — High</option>
            </select>
          </div>
        </div>

        <div class="form-group">
          <label>Tipe Kelas Rumah (hKlass)</label>
          <select id="house-klass">
            <option value="0">0 — Miskin</option>
            <option value="1">1 — Medium</option>
            <option value="2">2 — High</option>
            <option value="3">3 — VIP</option>
          </select>
        </div>

        <div style="margin-bottom:14px">
          <div style="font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--textmuted);margin-bottom:10px;font-weight:700">Koordinat Entrance Rumah</div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px">
            <div class="form-group" style="margin-bottom:0">
              <label>X (hEntrancex)</label>
              <input type="number" id="house-ex" placeholder="0.0" step="0.001"/>
            </div>
            <div class="form-group" style="margin-bottom:0">
              <label>Y (hEntrancey)</label>
              <input type="number" id="house-ey" placeholder="0.0" step="0.001"/>
            </div>
            <div class="form-group" style="margin-bottom:0">
              <label>Z (hEntrancez)</label>
              <input type="number" id="house-ez" placeholder="0.0" step="0.001"/>
            </div>
          </div>
        </div>

        <div style="margin-bottom:14px">
          <div style="font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--textmuted);margin-bottom:10px;font-weight:700">Koordinat Spawn Kendaraan</div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:10px">
            <div class="form-group" style="margin-bottom:0">
              <label>X (hCarx)</label>
              <input type="number" id="house-cx" placeholder="0.0" step="0.001"/>
            </div>
            <div class="form-group" style="margin-bottom:0">
              <label>Y (hCary)</label>
              <input type="number" id="house-cy" placeholder="0.0" step="0.001"/>
            </div>
            <div class="form-group" style="margin-bottom:0">
              <label>Z (hCarz)</label>
              <input type="number" id="house-cz" placeholder="0.0" step="0.001"/>
            </div>
            <div class="form-group" style="margin-bottom:0">
              <label>Angle (hCarc)</label>
              <input type="number" id="house-cc" placeholder="0.0" step="0.001"/>
            </div>
          </div>
        </div>

        <div style="background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;margin-bottom:14px;font-size:12px;color:var(--textmuted);line-height:1.7">
          ℹ️ Field lainnya akan diset ke default:
          <span style="color:var(--text2)">hOwned=0, hOwner='The State', hLock=0, hHel=100, hSlet=0, hLodgers='null,null,null', dll</span>
        </div>

        <button class="btn btn-primary" style="max-width:220px" onclick="addHouse()">&#43; ADD RUMAH</button>
        <div class="error-msg"   id="house-err"></div>
        <div class="success-msg" id="house-ok"></div>
      </div>
    </div>

  </div>
</template>

<!-- Punishment Page -->
<template id="tpl-punishment">
  <div class="page" id="page-punishment">
    <div class="page-title">&#9939; Punishment</div>
    <div class="page-sub">Kelola hukuman pemain — pilih metode di bawah.</div>

    <!-- Tab switcher -->
    <div style="display:flex;gap:8px;margin-bottom:22px">
      <button id="pun-tab-jail-btn" class="btn btn-primary btn-sm" onclick="switchPunTab('jail')" style="min-width:140px">
        &#9939; Jail / Penjara
      </button>
      <button id="pun-tab-ban-btn" class="btn btn-copy btn-sm" onclick="switchPunTab('ban')" style="min-width:140px">
        &#128683; Ban Akun
      </button>
    </div>

    <!-- ═══ TAB JAIL ═══ -->
    <div id="pun-tab-jail">

      <!-- Cek status jail -->
      <div class="card" style="margin-bottom:16px">
        <div class="card-title">&#128269; Cek Status Penjara</div>
        <div style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">
          <div class="form-group" style="flex:1;min-width:200px;margin-bottom:0">
            <label>Username Player</label>
            <input type="text" id="pun-user" placeholder="Masukkan username..." oninput="clearPunInfo()" onkeydown="if(event.key==='Enter')checkPunStatus()"/>
          </div>
          <button class="btn btn-copy btn-sm" style="height:44px;padding:0 20px" onclick="checkPunStatus()">&#128269; CEK STATUS</button>
        </div>
        <div id="pun-status-panel" style="display:none;margin-top:16px;background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:14px">
          <div style="font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--textmuted);margin-bottom:12px;font-weight:700">Status Penjara Saat Ini</div>
          <div style="display:flex;flex-wrap:wrap;gap:10px" id="pun-status-content"></div>
        </div>
      </div>

      <!-- Off Jail -->
      <div class="card" style="margin-bottom:16px">
        <div class="card-title">&#9939; Set Penjara (Off Jail)</div>
        <div style="background:rgba(168,85,247,0.06);border:1px solid rgba(168,85,247,0.2);border-radius:10px;padding:12px 14px;margin-bottom:16px;font-size:12px;color:var(--text2);line-height:1.8">
          &#9432;&nbsp; Sesuai command <code style="color:var(--accent3);background:var(--surface3);padding:2px 6px;border-radius:4px">/offjail</code> — hanya untuk <strong>pemain offline</strong>.
          Durasi: <strong style="color:var(--accent3)">10–300 menit</strong>. Pemain yang sudah di penjara atau admin tidak bisa di-jail.
        </div>
        <div style="margin-bottom:14px">
          <div style="font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--textmuted);margin-bottom:8px;font-weight:700">Preset Durasi</div>
          <div style="display:flex;flex-wrap:wrap;gap:6px">
            <button class="btn btn-copy btn-sm" onclick="setPunMins(10)">10 Menit</button>
            <button class="btn btn-copy btn-sm" onclick="setPunMins(30)">30 Menit</button>
            <button class="btn btn-copy btn-sm" onclick="setPunMins(60)">1 Jam</button>
            <button class="btn btn-copy btn-sm" onclick="setPunMins(120)">2 Jam</button>
            <button class="btn btn-copy btn-sm" onclick="setPunMins(180)">3 Jam</button>
            <button class="btn btn-copy btn-sm" onclick="setPunMins(300)">5 Jam (MAX)</button>
          </div>
        </div>
        <div class="input-row" style="grid-template-columns:1fr 1fr auto">
          <div class="form-group" style="margin-bottom:0">
            <label>Username Player</label>
            <input type="text" id="jail-user" placeholder="Username pemain..."/>
          </div>
          <div class="form-group" style="margin-bottom:0">
            <label>Durasi (menit) — min 10, max 300</label>
            <input type="number" id="jail-mins" placeholder="60" min="10" max="300"/>
          </div>
          <button class="btn btn-primary btn-sm" style="height:44px;padding:0 20px;background:linear-gradient(135deg,#7c3aed,#a855f7)" onclick="doOffJail()">&#9939; JAIL</button>
        </div>
        <div class="error-msg"   id="jail-err"></div>
        <div class="success-msg" id="jail-ok"></div>
      </div>

      <!-- Free Jail -->
      <div class="card">
        <div class="card-title">&#128275; Bebaskan dari Penjara</div>
        <div style="background:rgba(16,185,129,0.06);border:1px solid rgba(16,185,129,0.2);border-radius:10px;padding:12px 14px;margin-bottom:16px;font-size:12px;color:var(--text2)">
          &#9432;&nbsp; Set <code style="color:var(--green);background:var(--surface3);padding:2px 6px;border-radius:4px">pPrison=0</code> dan <code style="color:var(--green);background:var(--surface3);padding:2px 6px;border-radius:4px">pMestoPrison=0</code> untuk membebaskan pemain dari penjara.
        </div>
        <div style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">
          <div class="form-group" style="flex:1;min-width:200px;margin-bottom:0">
            <label>Username Player</label>
            <input type="text" id="free-user" placeholder="Username pemain..."/>
          </div>
          <button class="btn btn-sm" style="height:44px;padding:0 20px;background:linear-gradient(135deg,#059669,var(--green));color:#fff;border:none" onclick="doFreeJail()">&#128275; BEBASKAN</button>
        </div>
        <div class="error-msg"   id="free-err"></div>
        <div class="success-msg" id="free-ok"></div>
      </div>

    </div>

    <!-- ═══ TAB BAN ═══ -->
    <div id="pun-tab-ban" style="display:none">

      <!-- Cek status ban -->
      <div class="card" style="margin-bottom:16px">
        <div class="card-title">&#128269; Cek Status Ban</div>
        <div style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">
          <div class="form-group" style="flex:1;min-width:200px;margin-bottom:0">
            <label>Username Player</label>
            <input type="text" id="ban-search" placeholder="Masukkan username..." oninput="clearBanInfo()" onkeydown="if(event.key==='Enter')checkBanStatus()"/>
          </div>
          <button class="btn btn-copy btn-sm" style="height:44px;padding:0 20px" onclick="checkBanStatus()">&#128269; CEK BAN</button>
        </div>
        <div id="ban-status-panel" style="display:none;margin-top:16px;background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:14px">
          <div style="font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--textmuted);margin-bottom:12px;font-weight:700">Status Ban Saat Ini</div>
          <div id="ban-status-content" style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:12px"></div>
          <div id="ban-detail-wrap" style="display:none;background:var(--surface3);border:1px solid var(--border);border-radius:10px;padding:12px;font-size:13px;line-height:1.9">
            <div id="ban-detail-content"></div>
          </div>
        </div>
      </div>

      <!-- Off Ban -->
      <div class="card" style="margin-bottom:16px">
        <div class="card-title">&#128683; Set Ban (Off Ban)</div>
        <div style="background:rgba(244,63,94,0.06);border:1px solid rgba(244,63,94,0.2);border-radius:10px;padding:12px 14px;margin-bottom:16px;font-size:12px;color:var(--text2);line-height:1.8">
          &#9432;&nbsp; Sesuai command <code style="color:#f43f5e;background:var(--surface3);padding:2px 6px;border-radius:4px">/offban</code> — hanya untuk <strong>pemain offline</strong>.
          Durasi: <strong style="color:#f43f5e">1–30 hari</strong>. Admin tidak bisa di-ban. Pemain yang sudah di-ban tidak bisa di-ban lagi.
        </div>
        <div style="margin-bottom:14px">
          <div style="font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--textmuted);margin-bottom:8px;font-weight:700">Preset Durasi Ban</div>
          <div style="display:flex;flex-wrap:wrap;gap:6px">
            <button class="btn btn-copy btn-sm" onclick="setBanDays(1)">1 Hari</button>
            <button class="btn btn-copy btn-sm" onclick="setBanDays(3)">3 Hari</button>
            <button class="btn btn-copy btn-sm" onclick="setBanDays(7)">7 Hari</button>
            <button class="btn btn-copy btn-sm" onclick="setBanDays(14)">14 Hari</button>
            <button class="btn btn-copy btn-sm" onclick="setBanDays(30)" style="border-color:rgba(244,63,94,0.4);color:#f43f5e">30 Hari (MAX)</button>
          </div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
          <div class="form-group" style="margin-bottom:0">
            <label>Username Player</label>
            <input type="text" id="ban-user" placeholder="Username pemain..."/>
          </div>
          <div class="form-group" style="margin-bottom:0">
            <label>Durasi (hari) — min 1, max 30</label>
            <input type="number" id="ban-days" placeholder="7" min="1" max="30"/>
          </div>
        </div>
        <div class="form-group">
          <label>Alasan Ban (opsional, max 32 karakter)</label>
          <input type="text" id="ban-reason" placeholder="contoh: Cheating, bug abuse, dll..." maxlength="32"/>
        </div>
        <button class="btn btn-sm" style="background:linear-gradient(135deg,#be123c,var(--red));color:#fff;border:none;padding:10px 24px;max-width:200px" onclick="doOffBan()">&#128683; BAN PEMAIN</button>
        <div class="error-msg"   id="ban-err"></div>
        <div class="success-msg" id="ban-ok"></div>
      </div>

      <!-- Unban -->
      <div class="card">
        <div class="card-title">&#9989; Unban Pemain</div>
        <div style="background:rgba(16,185,129,0.06);border:1px solid rgba(16,185,129,0.2);border-radius:10px;padding:12px 14px;margin-bottom:16px;font-size:12px;color:var(--text2)">
          &#9432;&nbsp; Set <code style="color:var(--green);background:var(--surface3);padding:2px 6px;border-radius:4px">lockstate=0</code> pada record ban aktif di tabel <code style="color:var(--green);background:var(--surface3);padding:2px 6px;border-radius:4px">banlog</code>.
        </div>
        <div style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">
          <div class="form-group" style="flex:1;min-width:200px;margin-bottom:0">
            <label>Username Player</label>
            <input type="text" id="unban-user" placeholder="Username pemain..."/>
          </div>
          <button class="btn btn-sm" style="height:44px;padding:0 20px;background:linear-gradient(135deg,#059669,var(--green));color:#fff;border:none" onclick="doUnban()">&#9989; UNBAN</button>
        </div>
        <div class="error-msg"   id="unban-err"></div>
        <div class="success-msg" id="unban-ok"></div>
      </div>

    </div>

  </div>
</template>

<!-- Backup Page (inside content, added via JS showPage) -->
<template id="tpl-backup">
  <div class="page" id="page-backup">
    <div class="page-title">💾 Backup Database</div>
    <div class="page-sub">Export seluruh struktur dan data database server Dewata Nation RP.</div>
    <div class="card">
      <div class="card-title">&#128190; Export Database</div>
      <div style="background:var(--surface2);border:1px solid var(--border);border-radius:14px;padding:28px;text-align:center;margin-bottom:20px">
        <div style="font-size:48px;margin-bottom:16px">&#128190;</div>
        <div style="font-family:'Rajdhani',sans-serif;font-size:22px;font-weight:700;color:var(--text);margin-bottom:8px">Full Database Export</div>
        <div style="font-size:13px;color:var(--textmuted);margin-bottom:24px;max-width:480px;margin-left:auto;margin-right:auto;line-height:1.7">
          Export seluruh struktur tabel (CREATE TABLE) beserta data (INSERT INTO) dari database <strong style="color:var(--accent)">s1649_Dewata</strong> ke file <code style="background:var(--surface3);padding:2px 8px;border-radius:4px;font-size:12px">.sql</code> yang bisa di-import kembali.
        </div>
        <button id="export-btn" class="btn btn-primary" style="max-width:320px;margin:0 auto;display:flex;align-items:center;justify-content:center;gap:10px;font-size:17px" onclick="doExport()">
          <span>&#128190;</span>
          <span>EXPORT DATABASE SEKARANG</span>
        </button>
        <div id="export-progress" style="display:none;margin-top:20px">
          <div style="font-size:13px;color:var(--textmuted);margin-bottom:10px">Sedang mengekspor database, harap tunggu...</div>
          <div style="width:100%;max-width:320px;margin:0 auto;height:4px;background:var(--surface3);border-radius:99px;overflow:hidden">
            <div id="export-bar" style="height:100%;width:0%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:99px;animation:exportpulse 1.5s ease-in-out infinite"></div>
          </div>
        </div>
      </div>
      <div class="card" style="margin-bottom:0;background:var(--surface2)">
        <div class="card-title" style="font-size:14px;margin-bottom:12px">&#128274; Informasi Backup</div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;font-size:13px;color:var(--textmuted)">
          <div style="display:flex;align-items:flex-start;gap:10px"><span style="color:var(--accent);flex-shrink:0">&#10003;</span><span>Termasuk semua tabel dan struktur</span></div>
          <div style="display:flex;align-items:flex-start;gap:10px"><span style="color:var(--accent);flex-shrink:0">&#10003;</span><span>Termasuk seluruh data setiap tabel</span></div>
          <div style="display:flex;align-items:flex-start;gap:10px"><span style="color:var(--accent);flex-shrink:0">&#10003;</span><span>Format .sql siap di-import</span></div>
          <div style="display:flex;align-items:flex-start;gap:10px"><span style="color:var(--accent);flex-shrink:0">&#10003;</span><span>Tercatat di Admin Log</span></div>
          <div style="display:flex;align-items:flex-start;gap:10px"><span style="color:var(--accent);flex-shrink:0">&#10003;</span><span>Nama file otomatis dengan timestamp</span></div>
          <div style="display:flex;align-items:flex-start;gap:10px"><span style="color:var(--accent);flex-shrink:0">&#10003;</span><span>Aman: hanya admin yang bisa akses</span></div>
        </div>
      </div>
    </div>
  </div>
</template>

<!-- Toast -->
<div id="toast"></div>

<script>
// ─── State ─────────────────────────────────────────────────────────────────────
var currentUser = '';
var tempLoginUser = '';
var sidebarOpen = false;

function isDrawerMode() { return window.innerWidth <= 900; }

window.addEventListener('resize', function() {
  // On resize: if switching to desktop, remove drawer classes; apply push logic
  if (!isDrawerMode()) {
    document.getElementById('sidebar-overlay').classList.remove('show');
    document.getElementById('sidebar').classList.remove('open');
    if (sidebarOpen) {
      document.getElementById('sidebar').classList.remove('collapsed');
      document.getElementById('main').classList.remove('expanded');
    } else {
      document.getElementById('sidebar').classList.add('collapsed');
      document.getElementById('main').classList.add('expanded');
    }
  } else {
    // Mobile: main always full width
    document.getElementById('main').classList.add('expanded');
    document.getElementById('main').classList.remove('expanded'); // reset to let CSS handle
    document.getElementById('main').style.marginLeft = '';
  }
});

// ─── Loading ───────────────────────────────────────────────────────────────────
function startLoading() {
  var bar  = document.getElementById('loading-bar');
  var text = document.getElementById('loading-text');
  var steps = [
    [15,  'Initializing...'],
    [35,  'Connecting to database...'],
    [55,  'Loading modules...'],
    [75,  'Verifying session...'],
    [90,  'Almost ready...'],
    [100, 'Ready!']
  ];
  var i = 0;
  function nextStep() {
    if (i >= steps.length) return;
    var s = steps[i++];
    bar.style.width = s[0] + '%';
    if (text) text.textContent = s[1];
    if (s[0] < 100) {
      setTimeout(nextStep, 260);
    } else {
      setTimeout(function() {
        var ls = document.getElementById('loading-screen');
        ls.classList.add('hidden');
        // Setelah transisi selesai, force display:none agar benar-benar tidak blocking
        setTimeout(function() { ls.style.display = 'none'; }, 550);
        checkAuth();
      }, 350);
    }
  }
  nextStep();
}

// ─── Auth ──────────────────────────────────────────────────────────────────────
async function checkAuth() {
  try {
    var r = await fetch('/api/check-auth');
    if (r.ok) {
      var d = await r.json();
      enterApp(d.username);
    } else {
      showAuth();
    }
  } catch(e) { showAuth(); }
}

function showAuth() {
  document.getElementById('auth-wrapper').classList.remove('hidden');
  document.getElementById('login-box').style.display = '';
  document.getElementById('adminkey-box').style.display = 'none';
}

async function doLogin() {
  var user = document.getElementById('login-user').value.trim();
  var pass = document.getElementById('login-pass').value;
  var errEl = document.getElementById('login-error');
  errEl.classList.remove('show');
  if (!user || !pass) { showErr(errEl, 'Username dan password wajib diisi'); return; }
  try {
    var r = await fetch('/api/login', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,password:pass})});
    var d = await r.json();
    if (!r.ok) { showErr(errEl, d.error || 'Login gagal'); return; }
    tempLoginUser = d.username;
    document.getElementById('login-box').style.display = 'none';
    document.getElementById('adminkey-box').style.display = '';
    document.getElementById('admin-key').focus();
  } catch(e) { showErr(errEl, 'Koneksi error'); }
}

async function doVerifyKey() {
  var key = document.getElementById('admin-key').value.trim();
  var errEl = document.getElementById('key-error');
  errEl.classList.remove('show');
  if (!key) { showErr(errEl, 'Admin key wajib diisi'); return; }
  try {
    var r = await fetch('/api/verify-admin-key', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:tempLoginUser,admin_key:key})});
    var d = await r.json();
    if (!r.ok) { showErr(errEl, d.error || 'Verifikasi gagal'); return; }
    enterApp(d.username);
  } catch(e) { showErr(errEl, 'Koneksi error'); }
}

async function doLogout() {
  await fetch('/api/logout', {method:'POST'});
  currentUser = '';
  document.getElementById('app').style.display = 'none';
  document.getElementById('app').classList.remove('visible');
  showAuth();
}

function enterApp(username) {
  currentUser = username;
  document.getElementById('auth-wrapper').classList.add('hidden');
  var app = document.getElementById('app');
  app.style.display = 'flex';
  app.classList.add('visible');
  document.getElementById('sidebar-username').textContent = username;
  document.getElementById('admin-name-top').textContent = username;
  document.getElementById('user-avatar').textContent = username.charAt(0).toUpperCase();
  // Open sidebar on desktop by default, closed on mobile
  if (!isDrawerMode()) {
    sidebarOpen = true;
    document.getElementById('sidebar').classList.remove('collapsed');
    document.getElementById('main').classList.remove('expanded');
  } else {
    sidebarOpen = false;
    document.getElementById('main').classList.add('expanded');
  }
  showPage('dashboard');
}

// ─── Sidebar ───────────────────────────────────────────────────────────────────
function toggleSidebar() {
  var sb = document.getElementById('sidebar');
  var ov = document.getElementById('sidebar-overlay');
  var main = document.getElementById('main');
  sidebarOpen = !sidebarOpen;
  if (isDrawerMode()) {
    // Drawer mode: slide over content
    sb.classList.toggle('open', sidebarOpen);
    ov.classList.toggle('show', sidebarOpen);
  } else {
    // Push mode: sidebar pushes main content
    sb.classList.toggle('collapsed', !sidebarOpen);
    main.classList.toggle('expanded', !sidebarOpen);
  }
}

// ─── Pages ─────────────────────────────────────────────────────────────────────
var pageTitles = {dashboard:'Dashboard',getcord:'Getcord List',set:'Set Menu',adminlog:'Admin Log',inventory:'Inventori Player',setadmin:'Set Admin',property:'Add Property',punishment:'Punishment',backup:'Backup Database'};

function showPage(name) {
  if (['backup','inventory','setadmin','property','punishment'].indexOf(name) !== -1 && !document.getElementById('page-'+name)) {
    var tpl = document.getElementById('tpl-'+name);
    var node = tpl.content.cloneNode(true);
    document.getElementById('content').appendChild(node);
  }
  document.querySelectorAll('.page').forEach(function(p) { p.classList.remove('active'); });
  document.querySelectorAll('.nav-item').forEach(function(n) { n.classList.remove('active'); });
  document.getElementById('page-'+name).classList.add('active');
  document.getElementById('page-title').textContent = pageTitles[name] || name;
  var navItems = document.querySelectorAll('.nav-item');
  var idx = {dashboard:0,getcord:1,set:2,adminlog:3,inventory:4,setadmin:5,property:6,punishment:7,backup:8};
  if (navItems[idx[name]]) navItems[idx[name]].classList.add('active');
  if (isDrawerMode() && sidebarOpen) {
    sidebarOpen = false;
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('sidebar-overlay').classList.remove('show');
  }
  if (name==='getcord') loadGetcord();
  if (name==='adminlog') loadAdminLog();
  if (name==='property') loadPropStats();
}

// ─── Getcord ───────────────────────────────────────────────────────────────────
async function loadGetcord() {
  const tbody = document.getElementById('getcord-tbody');
  tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--textmuted);padding:28px">Memuat...</td></tr>';
  try {
    const r = await fetch('/api/getcord');
    const d = await r.json();
    if (!r.ok || !Array.isArray(d) || d.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--textmuted);padding:28px">Tidak ada data</td></tr>';
      return;
    }
    tbody.innerHTML = d.map(function(c) {
      var cord = c.x.toFixed(4)+', '+c.y.toFixed(4)+', '+c.z.toFixed(4)+', '+c.a.toFixed(4);
      return '<tr>'+
        '<td><span class="badge badge-blue">'+c.id+'</span></td>'+
        '<td><strong>'+escHtml(c.name)+'</strong></td>'+
        '<td class="cord-text">'+c.x.toFixed(4)+'</td>'+
        '<td class="cord-text">'+c.y.toFixed(4)+'</td>'+
        '<td class="cord-text">'+c.z.toFixed(4)+'</td>'+
        '<td class="cord-text">'+c.a.toFixed(4)+'</td>'+
        '<td><button class="btn btn-copy btn-sm" onclick="copyText(\''+cord+'\',this)">Copy</button></td>'+
        '<td><button class="btn btn-danger" onclick="deleteGetcord('+c.id+',this)">Hapus</button></td>'+
      '</tr>';
    }).join('');
  } catch { tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--red);padding:28px">Error memuat data</td></tr>'; }
}

async function deleteGetcord(id, btn) {
  if (!confirm('Hapus koordinat ID '+id+'?')) return;
  try {
    const r = await fetch('/api/getcord/'+id, {method:'DELETE'});
    if (r.ok) { showToast('Koordinat dihapus!','success'); loadGetcord(); }
    else { const d=await r.json(); showToast(d.error||'Gagal','error'); }
  } catch { showToast('Koneksi error','error'); }
}

// ─── Set Money ────────────────────────────────────────────────────────────────
// ─── Limit helpers (mirror of Go columnLimits) ────────────────────────────────
var colLimits = {
  pCash:500000000, pBank:500000000, pUangMerah:500000000, pRouble:1000,
  pBatu:1000, pBatuk:1000, pFish:1000, pPenyu:1000, pDolphin:1000,
  pHiu:1000, pMegalodon:1000, pCaught:1000, pPadi:1000, pAyam:1000,
  pSemen:1000, pEmas:1000, pSusu:1000, pMinyak:1000, pAyamKemas:1000,
  pAyamPotong:1000, pAyamHidup:1000, pBulu:1000,
  pDrugs:500, pMicin:500, pSteroid:500,
  pComponent:5000, pMetall:5000, pFood:200, pDrink:200
};

function fmtLimit(n) {
  if (n >= 1000000000) return (n/1000000000).toFixed(0)+' miliar';
  if (n >= 1000000)    return (n/1000000).toFixed(0)+' juta';
  if (n >= 1000)       return n.toLocaleString('id-ID');
  return String(n);
}

function updateMoneyMax() {
  var sel = document.getElementById('money-type');
  var opt = sel.options[sel.selectedIndex];
  var max = parseInt(opt.getAttribute('data-max')) || 500000000;
  document.getElementById('money-val').max = max;
  document.getElementById('money-limit-info').innerHTML =
    'Limit: <strong style="color:var(--accent)">'+fmtLimit(max)+'</strong>';
}

function updateAccMax() {
  var sel = document.getElementById('acc-type');
  var opt = sel.options[sel.selectedIndex];
  var max = parseInt(opt.getAttribute('data-max')) || 500;
  document.getElementById('acc-val').max = max;
  document.getElementById('acc-limit-val').textContent = fmtLimit(max);
}

async function setMoney() {
  var user = document.getElementById('money-user').value.trim();
  var val = parseInt(document.getElementById('money-val').value);
  var type = document.getElementById('money-type').value;
  var limit = colLimits[type] || 500000000;
  resetMsg('money-err','money-ok');
  if (!user) { showMsg('money-err','Username wajib diisi'); return; }
  if (isNaN(val) || val < 0) { showMsg('money-err','Value tidak valid'); return; }
  if (val > limit) { showMsg('money-err','Value melebihi batas '+fmtLimit(limit)+' untuk '+type); return; }
  try {
    var r = await fetch('/api/set/money',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,type:type,value:val})});
    var d = await r.json();
    if (!r.ok) { showMsg('money-err', d.error||'Gagal'); return; }
    showMsg('money-ok','Berhasil set '+type+' untuk '+user+' = '+val.toLocaleString('id-ID'));
    showToast('Berhasil!','success');
  } catch(e) { showMsg('money-err','Koneksi error'); }
}

// ─── Set Item ─────────────────────────────────────────────────────────────────
async function setItem() {
  var user = document.getElementById('item-user').value.trim();
  var val = parseInt(document.getElementById('item-val').value);
  var type = document.getElementById('item-type').value;
  var limit = colLimits[type] || 1000;
  resetMsg('item-err','item-ok');
  if (!user) { showMsg('item-err','Username wajib diisi'); return; }
  if (isNaN(val) || val < 0) { showMsg('item-err','Value tidak valid'); return; }
  if (val > limit) { showMsg('item-err','Value melebihi batas '+fmtLimit(limit)+' untuk '+type); return; }
  try {
    var r = await fetch('/api/set/item',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,type:type,value:val})});
    var d = await r.json();
    if (!r.ok) { showMsg('item-err', d.error||'Gagal'); return; }
    showMsg('item-ok','Berhasil set '+type+' untuk '+user+' = '+val.toLocaleString('id-ID'));
    showToast('Berhasil!','success');
  } catch(e) { showMsg('item-err','Koneksi error'); }
}

// ─── Set Account ──────────────────────────────────────────────────────────────
async function setAccount() {
  var user = document.getElementById('acc-user').value.trim();
  var val = parseInt(document.getElementById('acc-val').value);
  var type = document.getElementById('acc-type').value;
  var limit = colLimits[type] || 500;
  resetMsg('acc-err','acc-ok');
  if (!user) { showMsg('acc-err','Username wajib diisi'); return; }
  if (isNaN(val) || val < 0) { showMsg('acc-err','Value tidak valid'); return; }
  if (val > limit) { showMsg('acc-err','Value melebihi batas '+fmtLimit(limit)+' untuk '+type); return; }
  try {
    var r = await fetch('/api/set/account',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,type:type,value:val})});
    var d = await r.json();
    if (!r.ok) { showMsg('acc-err', d.error||'Gagal'); return; }
    showMsg('acc-ok','Berhasil set '+type+' untuk '+user+' = '+val.toLocaleString('id-ID'));
    showToast('Berhasil!','success');
  } catch(e) { showMsg('acc-err','Koneksi error'); }
}

async function setProp(type, userEl, valEl, okEl, errEl) {
  const user = document.getElementById(userEl).value.trim();
  let val = document.getElementById(valEl).value;
  document.getElementById(okEl).classList.remove('show');
  document.getElementById(errEl).classList.remove('show');
  if (!user) { document.getElementById(errEl).textContent='Username wajib diisi'; document.getElementById(errEl).classList.add('show'); return; }
  // parse value
  if (type==='pCS') val = parseInt(val);
  else if (type==='pSkin'||type==='pMaskID'||type==='pFreeRoulet') val = parseInt(val);
  try {
    const r = await fetch('/api/set/property',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,type,value:val})});
    const d = await r.json();
    if (!r.ok) { document.getElementById(errEl).textContent=d.error||'Gagal'; document.getElementById(errEl).classList.add('show'); return; }
    document.getElementById(okEl).textContent='Berhasil set '+type+' untuk '+user;
    document.getElementById(okEl).classList.add('show');
    showToast('Berhasil!','success');
  } catch { document.getElementById(errEl).textContent='Koneksi error'; document.getElementById(errEl).classList.add('show'); }
}

// ─── Set VIP ──────────────────────────────────────────────────────────────────
var vipLabels = {0:'Non-VIP', 1:'VIP Low', 2:'VIP Medium', 3:'VIP High'};
var vipColors = {0:'var(--textmuted)', 1:'#c084fc', 2:'#a855f7', 3:'#a855f7'};
var vipBadgeBg = {
  0:'rgba(100,120,140,0.15)',
  1:'rgba(79,195,247,0.12)',
  2:'rgba(41,182,246,0.15)',
  3:'rgba(168,85,247,0.18)'
};

function clearVipInfo() {
  document.getElementById('vip-info-wrap').style.display = 'none';
  resetMsg('vip-err','vip-ok');
}

function onVipTypeChange() {
  var type = parseInt(document.getElementById('vip-type').value);
  var daysWrap = document.getElementById('vip-days-wrap');
  var presets = document.getElementById('vip-presets');
  if (type === 0) {
    daysWrap.style.display = 'none';
    presets.style.display = 'none';
  } else {
    daysWrap.style.display = '';
    presets.style.display = 'flex';
  }
}

function setVipDays(n) {
  document.getElementById('vip-days').value = n;
}

async function checkVipStatus() {
  var user = document.getElementById('vip-user').value.trim();
  resetMsg('vip-err','vip-ok');
  if (!user) { showMsg('vip-err','Username wajib diisi'); return; }
  try {
    var r2 = await fetch('/api/get-vip?username='+encodeURIComponent(user));
    var d2 = await r2.json();
    if (!r2.ok) { showMsg('vip-err', d2.error || 'User tidak ditemukan'); return; }
    var vtype = d2.pVip;
    var vtime = d2.pVipTime;
    var label = vipLabels[vtype] || 'Unknown';
    var col = vipColors[vtype] || 'var(--textmuted)';
    var bg = vipBadgeBg[vtype] || 'var(--surface3)';
    var wrap = document.getElementById('vip-info-wrap');
    var content = document.getElementById('vip-info-content');
    content.innerHTML =
      '<div style="background:'+bg+';border:1px solid '+col+';border-radius:10px;padding:12px 18px;min-width:120px;text-align:center">'+
        '<div style="font-size:11px;color:var(--textmuted);margin-bottom:4px;text-transform:uppercase;letter-spacing:1px">Status</div>'+
        '<div style="font-family:Rajdhani,sans-serif;font-size:20px;font-weight:700;color:'+col+'">'+escHtml(label)+'</div>'+
      '</div>'+
      '<div style="background:var(--surface3);border:1px solid var(--border);border-radius:10px;padding:12px 18px;min-width:120px;text-align:center">'+
        '<div style="font-size:11px;color:var(--textmuted);margin-bottom:4px;text-transform:uppercase;letter-spacing:1px">Sisa Waktu</div>'+
        '<div style="font-family:Rajdhani,sans-serif;font-size:20px;font-weight:700;color:var(--text)">'+vtime+' <span style="font-size:13px;font-weight:400;color:var(--textmuted)">hari</span></div>'+
      '</div>'+
      '<div style="background:var(--surface3);border:1px solid var(--border);border-radius:10px;padding:12px 18px;min-width:120px;text-align:center">'+
        '<div style="font-size:11px;color:var(--textmuted);margin-bottom:4px;text-transform:uppercase;letter-spacing:1px">ID Tipe</div>'+
        '<div style="font-family:Rajdhani,sans-serif;font-size:20px;font-weight:700;color:var(--text)">'+vtype+'</div>'+
      '</div>';
    wrap.style.display = 'block';
  } catch(e) { showMsg('vip-err','Koneksi error'); }
}

async function setVip() {
  var user = document.getElementById('vip-user').value.trim();
  var vtype = parseInt(document.getElementById('vip-type').value);
  var days = vtype === 0 ? 0 : parseInt(document.getElementById('vip-days').value);
  resetMsg('vip-err','vip-ok');
  if (!user) { showMsg('vip-err','Username wajib diisi'); return; }
  if (vtype > 0) {
    if (isNaN(days) || days <= 0) { showMsg('vip-err','Masukkan jumlah hari yang valid'); return; }
    if (days > 3650) { showMsg('vip-err','Maksimal 3650 hari (10 tahun)'); return; }
  }
  try {
    var r = await fetch('/api/set/vip', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:user, vip_type:vtype, days:days})
    });
    var d = await r.json();
    if (!r.ok) { showMsg('vip-err', d.error || 'Gagal set VIP'); return; }
    var msg = vtype === 0
      ? 'VIP '+user+' berhasil dinonaktifkan'
      : 'Berhasil set '+d.vip_name+' untuk '+user+' — Total: '+d.vip_time+' hari';
    showMsg('vip-ok', msg);
    showToast('VIP berhasil diset!','success');
    if (document.getElementById('vip-info-wrap').style.display !== 'none') checkVipStatus();
  } catch(e) { showMsg('vip-err','Koneksi error'); }
}

// ─── Set Gun ──────────────────────────────────────────────────────────────────
var gunNames = {
  23:'Silenced Pistol', 24:'Desert Eagle', 25:'Shotgun',
  26:'Sawnoff Shotgun', 27:'Combat Shotgun', 28:'Micro SMG / Uzi',
  29:'MP5', 30:'AK-47', 31:'M4'
};

function clearGunPreview() {
  document.getElementById('gun-preview-wrap').style.display = 'none';
  resetMsg('gun-err','gun-ok');
}

function updateGunLabel() {
  // Nothing special needed, select already shows name
}

async function previewGunSlots() {
  var user = document.getElementById('gun-user').value.trim();
  resetMsg('gun-err','gun-ok');
  if (!user) { showMsg('gun-err', 'Username wajib diisi untuk melihat slot'); return; }
  try {
    var r = await fetch('/api/get-gun-slots?username='+encodeURIComponent(user));
    var d = await r.json();
    if (!r.ok) { showMsg('gun-err', d.error || 'Gagal memuat slot'); return; }
    var wrap = document.getElementById('gun-preview-wrap');
    var preview = document.getElementById('gun-slot-preview');
    var guns = d.pGun.split(',');
    var ammos = d.pAmmo.split(',');
    var html = '';
    for (var i = 0; i < 13; i++) {
      var gid = parseInt(guns[i]) || 0;
      var am = parseInt(ammos[i]) || 0;
      if (gid === 0) {
        html += '<div style="background:var(--surface3);border:1px solid var(--border);border-radius:8px;padding:6px 10px;font-size:11px;color:var(--textmuted);min-width:80px;text-align:center">'+
          '<div style="font-weight:700;margin-bottom:2px">Slot '+(i+1)+'</div>'+
          '<div>Kosong</div></div>';
      } else {
        var name = gunNames[gid] || ('ID '+gid);
        html += '<div style="background:rgba(168,85,247,0.08);border:1px solid rgba(168,85,247,0.3);border-radius:8px;padding:6px 10px;font-size:11px;color:var(--accent);min-width:80px;text-align:center">'+
          '<div style="font-weight:700;margin-bottom:2px">Slot '+(i+1)+'</div>'+
          '<div style="color:var(--text);font-size:12px;font-weight:600">'+escHtml(name)+'</div>'+
          '<div style="color:var(--textmuted)">'+am+' peluru</div></div>';
      }
    }
    preview.innerHTML = html;
    wrap.style.display = 'block';
  } catch(e) { showMsg('gun-err', 'Koneksi error'); }
}

async function setGun() {
  var user = document.getElementById('gun-user').value.trim();
  var gunId = parseInt(document.getElementById('gun-id').value);
  var ammo = parseInt(document.getElementById('gun-ammo').value);
  resetMsg('gun-err','gun-ok');
  if (!user) { showMsg('gun-err', 'Username wajib diisi'); return; }
  if (isNaN(ammo) || ammo < 0) { showMsg('gun-err', 'Ammo tidak valid'); return; }
  if (ammo > 1000) { showMsg('gun-err', 'Ammo maksimal 1000'); return; }
  try {
    var r = await fetch('/api/set/gun', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:user, gun_id:gunId, ammo:ammo})
    });
    var d = await r.json();
    if (!r.ok) { showMsg('gun-err', d.error || 'Gagal set senjata'); return; }
    var msg = 'Berhasil set '+d.gun_name+' (ID:'+gunId+') ammo:'+ammo+' untuk '+user+' di Slot '+(d.slot+1);
    showMsg('gun-ok', msg);
    showToast('Senjata berhasil diset!', 'success');
    // Auto-refresh preview if visible
    if (document.getElementById('gun-preview-wrap').style.display !== 'none') {
      previewGunSlots();
    }
  } catch(e) { showMsg('gun-err', 'Koneksi error'); }
}

// ─── Set Vehicle ──────────────────────────────────────────────────────────────
var vehIcons = {
  // bikes
  481:'&#128690;', 509:'&#128690;', 510:'&#128690;', 462:'&#128690;', 463:'&#128690;',
  468:'&#128690;', 471:'&#128690;', 521:'&#128690;', 522:'&#128690;', 523:'&#128690;',
  581:'&#128690;', 586:'&#128690;',
  // air
  417:'&#9992;', 425:'&#9992;', 447:'&#9992;', 460:'&#9992;', 469:'&#9992;',
  476:'&#9992;', 487:'&#9992;', 488:'&#9992;', 497:'&#9992;', 511:'&#9992;',
  512:'&#9992;', 513:'&#9992;', 519:'&#9992;', 520:'&#9992;', 548:'&#9992;',
  563:'&#9992;',
  // boats
  430:'&#9875;', 446:'&#9875;', 452:'&#9875;', 453:'&#9875;', 454:'&#9875;',
  473:'&#9875;', 484:'&#9875;', 493:'&#9875;', 595:'&#9875;',
  // trucks/big
  403:'&#128666;', 407:'&#128666;', 408:'&#128666;', 414:'&#128666;',
  431:'&#128666;', 433:'&#128666;', 437:'&#128666;', 443:'&#128666;',
  455:'&#128666;', 456:'&#128666;',
};

function getVehIcon(id) {
  return vehIcons[id] || '&#128663;';
}

function clearVehPreview() {
  document.getElementById('veh-preview-wrap').style.display = 'none';
  resetMsg('veh-err','veh-ok');
}

async function previewVehSlots() {
  var user = document.getElementById('veh-user').value.trim();
  resetMsg('veh-err','veh-ok');
  if (!user) { showMsg('veh-err','Username wajib diisi untuk melihat slot'); return; }
  try {
    var r = await fetch('/api/get-veh-slots?username='+encodeURIComponent(user));
    var d = await r.json();
    if (!r.ok) { showMsg('veh-err', d.error || 'Gagal memuat slot'); return; }
    var wrap = document.getElementById('veh-preview-wrap');
    var preview = document.getElementById('veh-slot-preview');
    var models = d.cModel.split(',');
    while (models.length < 5) models.push('0');
    var html = '';
    for (var i = 0; i < 5; i++) {
      var vid = parseInt(models[i]) || 0;
      if (vid === 0) {
        html += '<div style="background:var(--surface3);border:1px solid var(--border);border-radius:10px;padding:10px 14px;font-size:11px;color:var(--textmuted);min-width:100px;text-align:center">'+
          '<div style="font-size:22px;margin-bottom:4px">&#9744;</div>'+
          '<div style="font-weight:700;margin-bottom:2px">Slot '+(i+1)+'</div>'+
          '<div>Kosong</div></div>';
      } else {
        var sel = document.getElementById('veh-id');
        var vname = 'ID '+vid;
        for (var j = 0; j < sel.options.length; j++) {
          if (parseInt(sel.options[j].value) === vid) {
            vname = sel.options[j].text.split(' — ')[1] || vname;
            break;
          }
        }
        html += '<div style="background:rgba(168,85,247,0.08);border:1px solid rgba(168,85,247,0.3);border-radius:10px;padding:10px 14px;font-size:11px;color:var(--accent);min-width:100px;text-align:center">'+
          '<div style="font-size:22px;margin-bottom:4px">'+getVehIcon(vid)+'</div>'+
          '<div style="font-weight:700;margin-bottom:2px">Slot '+(i+1)+'</div>'+
          '<div style="color:var(--text);font-size:12px;font-weight:600">'+escHtml(vname)+'</div>'+
          '<div style="color:var(--textmuted)">ID: '+vid+'</div></div>';
      }
    }
    preview.innerHTML = html;
    wrap.style.display = 'block';
  } catch(e) { showMsg('veh-err','Koneksi error'); }
}

async function setVeh() {
  var user = document.getElementById('veh-user').value.trim();
  var vehId = parseInt(document.getElementById('veh-id').value);
  var sel = document.getElementById('veh-id');
  var vehName = sel.options[sel.selectedIndex].text.split(' — ')[1] || ('ID '+vehId);
  resetMsg('veh-err','veh-ok');
  if (!user) { showMsg('veh-err','Username wajib diisi'); return; }
  try {
    var r = await fetch('/api/set/veh', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({username:user, veh_id:vehId})
    });
    var d = await r.json();
    if (!r.ok) { showMsg('veh-err', d.error || 'Gagal set kendaraan'); return; }
    showMsg('veh-ok', 'Berhasil set '+d.veh_name+' (ID:'+vehId+') untuk '+user+' di Slot '+(d.slot+1));
    showToast('Kendaraan berhasil diset!','success');
    if (document.getElementById('veh-preview-wrap').style.display !== 'none') {
      previewVehSlots();
    }
  } catch(e) { showMsg('veh-err','Koneksi error'); }
}

// ─── Admin Log ────────────────────────────────────────────────────────────────
async function loadAdminLog() {
  var el = document.getElementById('log-list');
  el.innerHTML = '<div style="text-align:center;color:var(--textmuted);padding:28px">Memuat log...</div>';
  try {
    var r = await fetch('/api/admin-log');
    var d = await r.json();
    if (!r.ok || !Array.isArray(d) || d.length === 0) {
      el.innerHTML = '<div style="text-align:center;color:var(--textmuted);padding:28px">Belum ada log</div>';
      return;
    }
    el.innerHTML = d.map(function(l) {
      var uid = l.user_id || 0;
      var dateStr = l.date ? l.date.replace('T',' ').substring(0,19) : '-';
      return '<div class="log-item">'+
        '<div class="log-user"><span class="badge badge-blue" style="font-size:11px;letter-spacing:0.5px">ID&nbsp;'+uid+'</span></div>'+
        '<div class="log-action">'+escHtml(l.action)+'</div>'+
        '<div class="log-date">&#128336;&nbsp;'+escHtml(dateStr)+'</div>'+
      '</div>';
    }).join('');
  } catch(e) {
    el.innerHTML = '<div style="text-align:center;color:var(--red);padding:28px">Error memuat log</div>';
  }
}

// ─── Inventory ────────────────────────────────────────────────────────────────

var invWeaponNames = {
  23:'Silenced Pistol',24:'Desert Eagle',25:'Shotgun',26:'Sawnoff Shotgun',
  27:'Combat Shotgun',28:'Micro SMG',29:'MP5',30:'AK-47',31:'M4'
};

var invVipLabel = {0:'Non-VIP',1:'VIP Low',2:'VIP Medium',3:'VIP High'};
var invVipColor = {0:'var(--textmuted)',1:'#c084fc',2:'#a855f7',3:'#a855f7'};

function invMoneyCard(label, val, color) {
  color = color || 'var(--accent)';
  return '<div style="background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:12px 14px">'+
    '<div style="font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--textmuted);margin-bottom:4px;font-weight:600">'+label+'</div>'+
    '<div style="font-family:Rajdhani,sans-serif;font-size:18px;font-weight:700;color:'+color+'">'+
      Number(val).toLocaleString('id-ID')+'</div>'+
  '</div>';
}

function invItemCard(label, val, icon, warn) {
  icon = icon || '&#127873;';
  var color = val > 0 ? 'var(--text)' : 'var(--textmuted)';
  var bg = val > 0 ? 'var(--surface2)' : 'var(--surface)';
  var border = val > 0 ? 'var(--border)' : 'rgba(30,45,69,0.4)';
  return '<div style="background:'+bg+';border:1px solid '+border+';border-radius:10px;padding:10px 12px;display:flex;align-items:center;gap:10px">'+
    '<span style="font-size:20px;flex-shrink:0">'+icon+'</span>'+
    '<div style="min-width:0">'+
      '<div style="font-size:10px;color:var(--textmuted);letter-spacing:0.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+label+'</div>'+
      '<div style="font-family:Rajdhani,sans-serif;font-size:16px;font-weight:700;color:'+color+'">'+Number(val).toLocaleString('id-ID')+'</div>'+
    '</div>'+
  '</div>';
}

function invStatBox(label, val, color) {
  color = color || 'var(--text)';
  return '<div style="background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:10px 14px;text-align:center;min-width:80px">'+
    '<div style="font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--textmuted);margin-bottom:4px">'+label+'</div>'+
    '<div style="font-family:Rajdhani,sans-serif;font-size:17px;font-weight:700;color:'+color+'">'+val+'</div>'+
  '</div>';
}

async function loadInventory() {
  var user = document.getElementById('inv-search').value.trim();
  if (!user) { showToast('Masukkan username player','error'); return; }

  var result  = document.getElementById('inv-result');
  var empty   = document.getElementById('inv-empty');
  var loading = document.getElementById('inv-loading');
  var errMsg  = document.getElementById('inv-err-msg');
  result.style.display='none'; empty.style.display='none';
  errMsg.style.display='none'; loading.style.display='block';

  try {
    var r = await fetch('/api/inventory?username='+encodeURIComponent(user));
    var d = await r.json();
    loading.style.display = 'none';
    if (!r.ok) {
      if (r.status === 404) { empty.style.display='block'; return; }
      errMsg.textContent = d.error || 'Gagal memuat data';
      errMsg.style.display = 'block'; return;
    }

    // ── Profile header ──
    document.getElementById('inv-avatar').textContent = d.pName.charAt(0).toUpperCase();
    document.getElementById('inv-name').textContent = d.pName;

    // Badges
    var badges = '';
    var vCol = invVipColor[d.pVip] || 'var(--textmuted)';
    if (d.pVip > 0) badges += '<span style="background:rgba(168,85,247,0.12);border:1px solid '+vCol+';border-radius:99px;padding:3px 10px;font-size:11px;font-family:Rajdhani,sans-serif;font-weight:700;color:'+vCol+'">'+escHtml(invVipLabel[d.pVip])+'</span>';
    if (d.pWanted > 0) badges += '<span style="background:rgba(232,48,48,0.12);border:1px solid var(--red);border-radius:99px;padding:3px 10px;font-size:11px;font-family:Rajdhani,sans-serif;font-weight:700;color:var(--red)">WANTED '+d.pWanted+'</span>';
    if (d.pPrison > 0) badges += '<span style="background:rgba(106,128,153,0.15);border:1px solid var(--textmuted);border-radius:99px;padding:3px 10px;font-size:11px;font-family:Rajdhani,sans-serif;font-weight:700;color:var(--textmuted)">PENJARA</span>';
    if (d.pCS > 0)     badges += '<span style="background:rgba(32,192,96,0.1);border:1px solid var(--green);border-radius:99px;padding:3px 10px;font-size:11px;font-family:Rajdhani,sans-serif;font-weight:700;color:var(--green)">Custom Skin</span>';
    document.getElementById('inv-badges').innerHTML = badges;

    // Stats bar
    var hpColor = d.pHP >= 70 ? 'var(--green)' : d.pHP >= 30 ? 'var(--accent)' : 'var(--red)';
    document.getElementById('inv-stats').innerHTML =
      invStatBox('Level', d.pLevel, 'var(--accent)') +
      invStatBox('EXP', Number(d.pExp).toLocaleString('id-ID')) +
      invStatBox('HP', Math.round(d.pHP)+'%', hpColor) +
      invStatBox('Armour', Math.round(d.pArmour)+'%', 'var(--blue)') +
      invStatBox('Skin ID', d.pSkin) +
      (d.pVip > 0 ? invStatBox('VIP Hari', d.pVipTime, vCol) : '');

    // ── Money ──
    document.getElementById('inv-money').innerHTML =
      invMoneyCard('pCash (Uang Cash)', d.pCash, '#20c060') +
      invMoneyCard('pBank (Uang Bank)', d.pBank, '#2088e8') +
      invMoneyCard('pUangMerah', d.pUangMerah, '#e83030') +
      invMoneyCard('pRouble (Coin)', d.pRouble, '#a855f7') +
      invMoneyCard('pGopay', d.pGopay, '#c084fc');

    // ── Weapons ──
    var guns  = d.pGun.split(',');
    var ammos = d.pAmmo.split(',');
    var wHtml = '';
    var hasWeapon = false;
    for (var i = 0; i < 13; i++) {
      var gid = parseInt(guns[i]) || 0;
      var am  = parseInt(ammos[i]) || 0;
      if (gid === 0) continue;
      hasWeapon = true;
      var wname = invWeaponNames[gid] || ('ID '+gid);
      wHtml += '<div style="background:rgba(168,85,247,0.08);border:1px solid rgba(168,85,247,0.25);border-radius:10px;padding:10px 14px;min-width:130px">'+
        '<div style="font-size:11px;color:var(--textmuted);margin-bottom:4px">Slot '+(i+1)+' &bull; ID '+gid+'</div>'+
        '<div style="font-family:Rajdhani,sans-serif;font-size:15px;font-weight:700;color:var(--accent)">&#128299; '+escHtml(wname)+'</div>'+
        '<div style="font-size:12px;color:var(--textmuted);margin-top:2px">Ammo: <strong style="color:var(--text)">'+am+'</strong></div>'+
      '</div>';
    }
    document.getElementById('inv-weapons').innerHTML = hasWeapon ? wHtml :
      '<div style="color:var(--textmuted);font-size:13px;padding:8px">Tidak ada senjata</div>';

    // ── Vehicles ──
    var vehSel = document.getElementById('veh-id');
    var models = d.cModel.split(',');
    var vHtml = ''; var hasVeh = false;
    for (var i = 0; i < 5; i++) {
      var vid = parseInt(models[i]) || 0;
      if (vid === 0) continue;
      hasVeh = true;
      var vname = 'ID '+vid;
      if (vehSel) {
        for (var j = 0; j < vehSel.options.length; j++) {
          if (parseInt(vehSel.options[j].value) === vid) {
            vname = vehSel.options[j].text.split(' — ')[1] || vname; break;
          }
        }
      }
      vHtml += '<div style="background:rgba(168,85,247,0.08);border:1px solid rgba(168,85,247,0.25);border-radius:10px;padding:10px 14px;min-width:130px">'+
        '<div style="font-size:11px;color:var(--textmuted);margin-bottom:4px">Slot '+(i+1)+'</div>'+
        '<div style="font-family:Rajdhani,sans-serif;font-size:15px;font-weight:700;color:var(--accent)">&#128663; '+escHtml(vname)+'</div>'+
        '<div style="font-size:12px;color:var(--textmuted);margin-top:2px">ID: '+vid+'</div>'+
      '</div>';
    }
    document.getElementById('inv-vehicles').innerHTML = hasVeh ? vHtml :
      '<div style="color:var(--textmuted);font-size:13px;padding:8px">Tidak ada kendaraan</div>';

    // ── Items ──
    var items = [
      {k:'pBatu',l:'Batu Bersih',i:'&#128296;'},   {k:'pBatuk',l:'Batu Kotor',i:'&#128296;'},
      {k:'pFish',l:'Ikan',i:'&#127920;'},            {k:'pPenyu',l:'Penyu',i:'&#128034;'},
      {k:'pDolphin',l:'Dolpin',i:'&#128011;'},       {k:'pHiu',l:'Hiu',i:'&#129416;'},
      {k:'pMegalodon',l:'Megalodon',i:'&#129416;'},  {k:'pCaught',l:'Umpan Mancing',i:'&#127908;'},
      {k:'pPadi',l:'Padi',i:'&#127807;'},            {k:'pAyam',l:'Ayam',i:'&#128020;'},
      {k:'pSemen',l:'Semen',i:'&#129521;'},          {k:'pEmas',l:'Emas',i:'&#129756;'},
      {k:'pSusu',l:'Susu Sapi',i:'&#127843;'},       {k:'pMinyak',l:'Minyak',i:'&#129695;'},
      {k:'pAyamKemas',l:'Ayam Kemas',i:'&#128020;'},{k:'pAyamPotong',l:'Ayam Potong',i:'&#128020;'},
      {k:'pAyamHidup',l:'Ayam Hidup',i:'&#128020;'},{k:'pBulu',l:'Bulu Ayam',i:'&#129413;'},
    ];
    var iHtml = '';
    items.forEach(function(it) { iHtml += invItemCard(it.l, d[it.k], it.i); });
    document.getElementById('inv-items').innerHTML = iHtml;

    // ── Account items ──
    var accItems = [
      {k:'pDrugs',l:'Drugs',i:'&#128138;'},       {k:'pMicin',l:'Marijuana',i:'&#127807;'},
      {k:'pSteroid',l:'Steroid',i:'&#128138;'},   {k:'pComponent',l:'Component',i:'&#9881;'},
      {k:'pMetall',l:'Besi/Metal',i:'&#129520;'}, {k:'pFood',l:'Makanan',i:'&#127860;'},
      {k:'pDrink',l:'Minuman',i:'&#127865;'},
    ];
    var aHtml = '';
    accItems.forEach(function(it) { aHtml += invItemCard(it.l, d[it.k], it.i); });
    document.getElementById('inv-account').innerHTML = aHtml;

    result.style.display = 'block';

  } catch(e) {
    loading.style.display = 'none';
    errMsg.textContent = 'Koneksi error: '+e.message;
    errMsg.style.display = 'block';
  }
}

// ─── Punishment ───────────────────────────────────────────────────────────────

function switchPunTab(tab) {
  var jailEl   = document.getElementById('pun-tab-jail');
  var banEl    = document.getElementById('pun-tab-ban');
  var jailBtn  = document.getElementById('pun-tab-jail-btn');
  var banBtn   = document.getElementById('pun-tab-ban-btn');
  if (!jailEl || !banEl) return;
  if (tab === 'jail') {
    jailEl.style.display  = 'block';
    banEl.style.display   = 'none';
    jailBtn.className = 'btn btn-primary btn-sm';
    banBtn.className  = 'btn btn-copy btn-sm';
  } else {
    jailEl.style.display  = 'none';
    banEl.style.display   = 'block';
    jailBtn.className = 'btn btn-copy btn-sm';
    banBtn.className  = 'btn btn-primary btn-sm';
  }
}

function clearPunInfo() {
  document.getElementById('pun-status-panel').style.display = 'none';
}

function setPunMins(n) {
  document.getElementById('jail-mins').value = n;
  // Also sync username from cek field if filled
  var user = document.getElementById('pun-user').value.trim();
  if (user) document.getElementById('jail-user').value = user;
}

function punStatBox(label, val, color) {
  color = color || 'var(--text)';
  return '<div style="background:var(--surface3);border:1px solid var(--border);border-radius:10px;padding:10px 16px;min-width:100px;text-align:center">'+
    '<div style="font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--textmuted);margin-bottom:4px">'+label+'</div>'+
    '<div style="font-family:Rajdhani,sans-serif;font-size:16px;font-weight:700;color:'+color+'">'+val+'</div>'+
  '</div>';
}

async function checkPunStatus() {
  var user = document.getElementById('pun-user').value.trim();
  if (!user) { showToast('Masukkan username player', 'error'); return; }

  try {
    var r = await fetch('/api/punishment/status?username='+encodeURIComponent(user));
    var d = await r.json();
    if (!r.ok) {
      showToast(d.error || 'Tidak ditemukan', 'error');
      document.getElementById('pun-status-panel').style.display = 'none';
      return;
    }

    var jailColor   = d.in_jail ? 'var(--red)' : 'var(--green)';
    var jailLabel   = d.in_jail ? 'DI PENJARA' : 'BEBAS';
    var minutesStr  = d.in_jail ? d.minutes + ' menit tersisa' : '0 menit';
    var wantedColor = d.pWanted > 0 ? 'var(--yellow)' : 'var(--textmuted)';

    document.getElementById('pun-status-content').innerHTML =
      punStatBox('Status', jailLabel, jailColor) +
      punStatBox('Sisa Waktu', minutesStr, jailColor) +
      punStatBox('pPrison (detik)', d.pPrison, d.in_jail ? 'var(--red)' : 'var(--textmuted)') +
      punStatBox('Wanted', d.pWanted > 0 ? 'Bintang '+d.pWanted : 'Aman', wantedColor);

    document.getElementById('pun-status-panel').style.display = 'block';

    // Auto-fill jail form username
    document.getElementById('jail-user').value = user;
    document.getElementById('free-user').value = user;

  } catch(e) { showToast('Koneksi error', 'error'); }
}

async function doOffJail() {
  var user = document.getElementById('jail-user').value.trim();
  var mins = parseInt(document.getElementById('jail-mins').value);
  resetMsg('jail-err', 'jail-ok');

  if (!user) { showMsg('jail-err', 'Username wajib diisi'); return; }
  if (isNaN(mins) || mins < 10 || mins > 300) {
    showMsg('jail-err', 'Durasi harus antara 10 - 300 menit'); return;
  }

  try {
    var r = await fetch('/api/punishment/jail', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: user, minutes: mins})
    });
    var d = await r.json();
    if (!r.ok) { showMsg('jail-err', d.error || 'Gagal set penjara'); return; }

    var hrs  = Math.floor(mins / 60);
    var rem  = mins % 60;
    var durStr = hrs > 0 ? hrs+'j '+rem+'m' : mins+' menit';
    showMsg('jail-ok', user + ' berhasil dipenjara selama ' + durStr + ' (' + d.seconds + ' detik)');
    showToast('&#9939; ' + user + ' dipenjara ' + durStr, 'success');
    document.getElementById('jail-mins').value = '';

    // Refresh status if panel visible
    if (document.getElementById('pun-status-panel').style.display !== 'none') {
      document.getElementById('pun-user').value = user;
      checkPunStatus();
    }
  } catch(e) { showMsg('jail-err', 'Koneksi error'); }
}

async function doFreeJail() {
  var user = document.getElementById('free-user').value.trim();
  resetMsg('free-err', 'free-ok');
  if (!user) { showMsg('free-err', 'Username wajib diisi'); return; }

  try {
    var r = await fetch('/api/punishment/free', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: user})
    });
    var d = await r.json();
    if (!r.ok) { showMsg('free-err', d.error || 'Gagal bebaskan pemain'); return; }

    showMsg('free-ok', user + ' berhasil dibebaskan! (sisa ' + d.freed_minutes + ' menit dihapus)');
    showToast('&#128275; ' + user + ' dibebaskan dari penjara!', 'success');

    // Refresh status panel
    if (document.getElementById('pun-status-panel').style.display !== 'none') {
      document.getElementById('pun-user').value = user;
      checkPunStatus();
    }
  } catch(e) { showMsg('free-err', 'Koneksi error'); }
}

// ─── Ban JS ────────────────────────────────────────────────────────────────────

function clearBanInfo() {
  document.getElementById('ban-status-panel').style.display = 'none';
}

function setBanDays(n) {
  document.getElementById('ban-days').value = n;
  var user = document.getElementById('ban-search').value.trim();
  if (user) document.getElementById('ban-user').value = user;
}

function banStatBox(label, val, color) {
  color = color || 'var(--text)';
  return '<div style="background:var(--surface3);border:1px solid var(--border);border-radius:10px;padding:10px 16px;min-width:100px;text-align:center">'+
    '<div style="font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--textmuted);margin-bottom:4px">'+label+'</div>'+
    '<div style="font-family:Rajdhani,sans-serif;font-size:15px;font-weight:700;color:'+color+'">'+val+'</div>'+
  '</div>';
}

async function checkBanStatus() {
  var user = document.getElementById('ban-search').value.trim();
  if (!user) { showToast('Masukkan username player', 'error'); return; }
  try {
    var r = await fetch('/api/punishment/ban-status?username='+encodeURIComponent(user));
    var d = await r.json();
    if (r.status === 404) { showToast(d.error || 'Pemain tidak ditemukan', 'error'); return; }
    if (!r.ok) { showToast(d.error || 'Error', 'error'); return; }

    var panel   = document.getElementById('ban-status-panel');
    var content = document.getElementById('ban-status-content');
    var detail  = document.getElementById('ban-detail-wrap');
    var detailC = document.getElementById('ban-detail-content');

    if (!d.is_banned) {
      content.innerHTML = banStatBox('Status', 'BEBAS', 'var(--green)') +
                          banStatBox('Riwayat Ban', 'Tidak Ada', 'var(--textmuted)');
      detail.style.display = 'none';
    } else {
      var daysLeft = d.days_left || 0;
      content.innerHTML =
        banStatBox('Status', 'BANNED', 'var(--red)') +
        banStatBox('Sisa', daysLeft + ' hari', 'var(--red)') +
        banStatBox('Di-ban oleh', escHtml(d.banned_by || '-'), 'var(--accent3)');

      detailC.innerHTML =
        '<div>&#128683; <strong style="color:var(--red)">AKUN DIBLOKIR</strong></div>'+
        '<div style="color:var(--textmuted)">Alasan: <span style="color:var(--text)">'+escHtml(d.reason || '-')+'</span></div>'+
        '<div style="color:var(--textmuted)">Tanggal ban: <span style="color:var(--text)">'+escHtml(d.ban_date || '-')+'</span></div>'+
        '<div style="color:var(--textmuted)">Expire: <span style="color:var(--yellow)">'+escHtml(d.expire_date || '-')+'</span></div>';
      detail.style.display = 'block';
    }

    panel.style.display = 'block';
    // Auto-fill form
    document.getElementById('ban-user').value   = user;
    document.getElementById('unban-user').value = user;
  } catch(e) { showToast('Koneksi error', 'error'); }
}

async function doOffBan() {
  var user   = document.getElementById('ban-user').value.trim();
  var days   = parseInt(document.getElementById('ban-days').value);
  var reason = document.getElementById('ban-reason').value.trim();
  resetMsg('ban-err', 'ban-ok');

  if (!user)                              { showMsg('ban-err','Username wajib diisi'); return; }
  if (isNaN(days) || days < 1 || days > 30) { showMsg('ban-err','Durasi ban harus antara 1 - 30 hari'); return; }

  try {
    var r = await fetch('/api/punishment/ban', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: user, days: days, reason: reason})
    });
    var d = await r.json();
    if (!r.ok) { showMsg('ban-err', d.error || 'Gagal ban pemain'); return; }

    showMsg('ban-ok',
      user + ' berhasil di-ban selama ' + days + ' hari' +
      (reason ? ' | Alasan: ' + escHtml(reason) : '') +
      ' | Expire: ' + escHtml(d.expire_date)
    );
    showToast('&#128683; ' + user + ' di-ban ' + days + ' hari', 'success');
    document.getElementById('ban-days').value   = '';
    document.getElementById('ban-reason').value = '';

    // Refresh ban status panel if open
    if (document.getElementById('ban-status-panel').style.display !== 'none') {
      document.getElementById('ban-search').value = user;
      checkBanStatus();
    }
  } catch(e) { showMsg('ban-err', 'Koneksi error'); }
}

async function doUnban() {
  var user = document.getElementById('unban-user').value.trim();
  resetMsg('unban-err', 'unban-ok');
  if (!user) { showMsg('unban-err', 'Username wajib diisi'); return; }

  try {
    var r = await fetch('/api/punishment/unban', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: user})
    });
    var d = await r.json();
    if (!r.ok) { showMsg('unban-err', d.error || 'Gagal unban'); return; }

    showMsg('unban-ok', user + ' berhasil di-unban!');
    showToast('&#9989; ' + user + ' berhasil di-unban!', 'success');

    // Refresh ban status panel
    if (document.getElementById('ban-status-panel').style.display !== 'none') {
      document.getElementById('ban-search').value = user;
      checkBanStatus();
    }
  } catch(e) { showMsg('unban-err', 'Koneksi error'); }
}

// ─── Set Admin ────────────────────────────────────────────────────────────────
var adminLevelNames = {
  1:'Admin Trial', 2:'Admin', 3:'Admin', 4:'Admin', 5:'Admin',
  6:'Admin', 7:'Admin', 8:'High Admin', 9:'Handle Admin',
  10:'Co-Owner', 15:'Owner', 20:'Developer'
};
var adminLevelColors = {
  1:'var(--textmuted)', 2:'var(--text)', 3:'var(--text)', 4:'var(--text)',
  5:'var(--text)', 6:'var(--text)', 7:'var(--text)', 8:'#c084fc',
  9:'#a855f7', 10:'var(--accent)', 15:'#f0a030', 20:'var(--red)'
};

function clearSaInfo() {
  document.getElementById('sa-info-wrap').style.display = 'none';
  resetMsg('sa-err','sa-ok');
}

async function checkAdminInfo() {
  var user = document.getElementById('sa-user').value.trim();
  resetMsg('sa-err','sa-ok');
  if (!user) { showMsg('sa-err','Username wajib diisi'); return; }
  try {
    var r = await fetch('/api/get-admin-info?username='+encodeURIComponent(user));
    var d = await r.json();
    if (!r.ok) { showMsg('sa-err', d.error || 'Tidak ditemukan di tabel admin'); return; }

    // Auto-fill form fields
    document.getElementById('sa-aname').value = d.pAname;
    document.getElementById('sa-key').value   = d.pAdminKey;
    var sel = document.getElementById('sa-level');
    for (var i = 0; i < sel.options.length; i++) {
      if (parseInt(sel.options[i].value) === d.pAdmin) { sel.selectedIndex = i; break; }
    }

    var lvlName  = adminLevelNames[d.pAdmin] || ('Level '+d.pAdmin);
    var lvlColor = adminLevelColors[d.pAdmin] || 'var(--text)';
    var dateStr  = d.invite_date ? d.invite_date.replace('T',' ').substring(0,16) : '-';

    var content = document.getElementById('sa-info-content');
    content.innerHTML =
      saInfoBox('Level', d.pAdmin+' — '+lvlName, lvlColor) +
      saInfoBox('Admin Name', escHtml(d.pAname), 'var(--accent)') +
      saInfoBox('Admin Key', escHtml(d.pAdminKey), 'var(--text)') +
      saInfoBox('Rep', d.pAdmRep, 'var(--green)') +
      saInfoBox('Kick', d.pAdmKick, 'var(--red)') +
      saInfoBox('Ban', d.pAdmBan, 'var(--red)') +
      saInfoBox('Warn', d.pAdmWarn, '#f0a030') +
      saInfoBox('Mute', d.pAdmMute, 'var(--textmuted)') +
      saInfoBox('Join', dateStr, 'var(--textmuted)');

    document.getElementById('sa-info-wrap').style.display = 'block';
  } catch(e) { showMsg('sa-err','Koneksi error'); }
}

function saInfoBox(label, val, color) {
  return '<div style="background:var(--surface3);border:1px solid var(--border);border-radius:10px;padding:10px 14px;min-width:90px;text-align:center">'+
    '<div style="font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--textmuted);margin-bottom:4px">'+label+'</div>'+
    '<div style="font-family:Rajdhani,sans-serif;font-size:14px;font-weight:700;color:'+color+'">'+val+'</div>'+
  '</div>';
}

async function setAdmin() {
  var user  = document.getElementById('sa-user').value.trim();
  var level = parseInt(document.getElementById('sa-level').value);
  var aname = document.getElementById('sa-aname').value.trim();
  var key   = document.getElementById('sa-key').value.trim();
  resetMsg('sa-err','sa-ok');
  if (!user)  { showMsg('sa-err','Username wajib diisi'); return; }
  if (!aname) { showMsg('sa-err','Admin name wajib diisi'); return; }
  if (!key)   { showMsg('sa-err','Admin key wajib diisi'); return; }
  try {
    var r = await fetch('/api/set/admin', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({username:user, level:level, aname:aname, key:key})
    });
    var d = await r.json();
    if (!r.ok) { showMsg('sa-err', d.error || 'Gagal'); return; }
    var isNew = d.is_new;
    var msg = (isNew ? 'Admin baru ditambahkan: ' : 'Admin diupdate: ') +
      user + ' → Level ' + level + ' (' + d.level_name + ')';
    showMsg('sa-ok', msg);
    showToast(isNew ? 'Admin berhasil ditambahkan!' : 'Admin berhasil diupdate!', 'success');
    // Refresh list if visible
    if (document.getElementById('sa-list-tbody') &&
        document.getElementById('sa-list-tbody').children.length > 0 &&
        document.getElementById('sa-list-tbody').children[0].children.length > 1) {
      loadAdminList();
    }
    if (document.getElementById('sa-info-wrap').style.display !== 'none') checkAdminInfo();
  } catch(e) { showMsg('sa-err','Koneksi error'); }
}

async function removeAdmin() {
  var user = document.getElementById('sa-user').value.trim();
  resetMsg('sa-err','sa-ok');
  if (!user) { showMsg('sa-err','Username wajib diisi'); return; }
  if (!confirm('Yakin hapus admin '+user+' dari tabel admin?')) return;
  try {
    var r = await fetch('/api/remove-admin', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({username:user})
    });
    var d = await r.json();
    if (!r.ok) { showMsg('sa-err', d.error || 'Gagal hapus'); return; }
    showMsg('sa-ok', 'Admin '+user+' berhasil dihapus');
    showToast('Admin dihapus!', 'success');
    document.getElementById('sa-info-wrap').style.display = 'none';
    loadAdminList();
  } catch(e) { showMsg('sa-err','Koneksi error'); }
}

async function loadAdminList() {
  var tbody = document.getElementById('sa-list-tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--textmuted);padding:20px">Memuat...</td></tr>';
  try {
    var r = await fetch('/api/admin-list');
    var d = await r.json();
    if (!r.ok || !Array.isArray(d) || d.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--textmuted);padding:20px">Belum ada admin</td></tr>';
      return;
    }
    tbody.innerHTML = d.map(function(a) {
      var lvlName  = adminLevelNames[a.pAdmin] || ('Lv'+a.pAdmin);
      var lvlColor = adminLevelColors[a.pAdmin] || 'var(--text)';
      var dateStr  = a.invite_date ? a.invite_date.replace('T',' ').substring(0,10) : '-';
      return '<tr>'+
        '<td style="font-weight:600;color:var(--text)">'+escHtml(a.Name)+'</td>'+
        '<td><span class="badge" style="background:rgba(168,85,247,0.1);color:'+lvlColor+';border:1px solid '+lvlColor+';border-radius:6px;padding:2px 8px;font-size:11px;font-family:Rajdhani,sans-serif;font-weight:700">'+a.pAdmin+'</span></td>'+
        '<td style="color:'+lvlColor+';font-size:12px;font-weight:600">'+escHtml(lvlName)+'</td>'+
        '<td style="color:var(--accent);font-size:13px">'+escHtml(a.pAname)+'</td>'+
        '<td style="color:var(--green)">'+a.pAdmRep+'</td>'+
        '<td style="color:var(--red)">'+a.pAdmKick+'</td>'+
        '<td style="color:var(--red)">'+a.pAdmBan+'</td>'+
        '<td style="color:var(--textmuted);font-size:12px">'+dateStr+'</td>'+
        '<td><button class="btn btn-copy btn-sm" style="font-size:11px" onclick="quickEditAdmin(\''+escHtml(a.Name)+'\')">Edit</button></td>'+
      '</tr>';
    }).join('');
  } catch(e) {
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--red);padding:20px">Error memuat daftar admin</td></tr>';
  }
}

function quickEditAdmin(name) {
  document.getElementById('sa-user').value = name;
  checkAdminInfo();
  window.scrollTo({top:0, behavior:'smooth'});
}

// ─── Add Property ─────────────────────────────────────────────────────────────

function switchPropTab(tab) {
  var bizzTab  = document.getElementById('prop-tab-bizz');
  var houseTab = document.getElementById('prop-tab-house');
  var bizzBtn  = document.getElementById('tab-bizz-btn');
  var houseBtn = document.getElementById('tab-house-btn');
  if (!bizzTab || !houseTab) return;
  if (tab === 'bizz') {
    bizzTab.style.display  = 'block';
    houseTab.style.display = 'none';
    bizzBtn.className  = 'btn btn-primary btn-sm';
    houseBtn.className = 'btn btn-copy btn-sm';
  } else {
    bizzTab.style.display  = 'none';
    houseTab.style.display = 'block';
    bizzBtn.className  = 'btn btn-copy btn-sm';
    houseBtn.className = 'btn btn-primary btn-sm';
  }
}

async function loadPropStats() {
  try {
    var r = await fetch('/api/property/stats');
    if (!r.ok) return;
    var d = await r.json();
    var el = function(id) { return document.getElementById(id); };
    if (el('stat-bizz-total'))  el('stat-bizz-total').textContent  = d.total_bizz || 0;
    if (el('stat-bizz-owned'))  el('stat-bizz-owned').textContent  = (d.owned_bizz || 0) + ' dimiliki';
    if (el('stat-house-total')) el('stat-house-total').textContent = d.total_house || 0;
    if (el('stat-house-owned')) el('stat-house-owned').textContent = (d.owned_house || 0) + ' dimiliki';
  } catch(e) {}
}

async function addBizz() {
  var name     = document.getElementById('bizz-name').value.trim();
  var price    = parseInt(document.getElementById('bizz-price').value);
  var interior = parseInt(document.getElementById('bizz-interior').value);
  var x        = parseFloat(document.getElementById('bizz-x').value);
  var y        = parseFloat(document.getElementById('bizz-y').value);
  var z        = parseFloat(document.getElementById('bizz-z').value);

  resetMsg('bizz-err', 'bizz-ok');
  if (!name)                              { showMsg('bizz-err','Nama bisnis wajib diisi'); return; }
  if (isNaN(price) || price < 5000000 || price > 100000000)
                                          { showMsg('bizz-err','Harga harus antara 5 juta - 100 juta'); return; }
  if (isNaN(x) || isNaN(y) || isNaN(z)) { showMsg('bizz-err','Koordinat X, Y, Z wajib diisi'); return; }

  try {
    var r = await fetch('/api/property/add-bizz', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        bMessage: name, bBuyPrice: price, bInterior: interior,
        bEntranceX: x, bEntranceY: y, bEntranceZ: z
      })
    });
    var d = await r.json();
    if (!r.ok) { showMsg('bizz-err', d.error || 'Gagal tambah bisnis'); return; }
    showMsg('bizz-ok', 'Bisnis berhasil ditambahkan! ID: ' + d.bID + ' | ' + escHtml(d.bMessage) + ' (' + escHtml(d.type_name) + ')');
    showToast('Bisnis #' + d.bID + ' berhasil dibuat!', 'success');
    // Reset form
    document.getElementById('bizz-name').value  = '';
    document.getElementById('bizz-price').value = '';
    document.getElementById('bizz-x').value = '';
    document.getElementById('bizz-y').value = '';
    document.getElementById('bizz-z').value = '';
    loadPropStats();
  } catch(e) { showMsg('bizz-err', 'Koneksi error'); }
}

async function addHouse() {
  var value = parseInt(document.getElementById('house-value').value);
  var hInt  = parseInt(document.getElementById('house-int').value);
  var klass = parseInt(document.getElementById('house-klass').value);
  var ex = parseFloat(document.getElementById('house-ex').value);
  var ey = parseFloat(document.getElementById('house-ey').value);
  var ez = parseFloat(document.getElementById('house-ez').value);
  var cx = parseFloat(document.getElementById('house-cx').value);
  var cy = parseFloat(document.getElementById('house-cy').value);
  var cz = parseFloat(document.getElementById('house-cz').value);
  var cc = parseFloat(document.getElementById('house-cc').value);

  resetMsg('house-err', 'house-ok');
  if (isNaN(value) || value < 5000000 || value > 100000000)
                                              { showMsg('house-err','Harga harus antara 5 juta - 100 juta'); return; }
  if (isNaN(ex) || isNaN(ey) || isNaN(ez))  { showMsg('house-err','Koordinat entrance X, Y, Z wajib diisi'); return; }
  if (isNaN(cx) || isNaN(cy) || isNaN(cz) || isNaN(cc))
                                              { showMsg('house-err','Koordinat spawn kendaraan wajib diisi'); return; }

  try {
    var r = await fetch('/api/property/add-house', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        hEntrancex: ex, hEntrancey: ey, hEntrancez: ez,
        hCarx: cx, hCary: cy, hCarz: cz, hCarc: cc,
        hValue: value, hInt: hInt, hKlass: klass
      })
    });
    var d = await r.json();
    if (!r.ok) { showMsg('house-err', d.error || 'Gagal tambah rumah'); return; }
    showMsg('house-ok', 'Rumah berhasil ditambahkan! ID: ' + d.hID + ' | Interior: ' + escHtml(d.int_name) + ' | Kelas: ' + escHtml(d.klass_name));
    showToast('Rumah #' + d.hID + ' berhasil dibuat!', 'success');
    // Reset form
    ['house-value','house-ex','house-ey','house-ez','house-cx','house-cy','house-cz','house-cc'].forEach(function(id) {
      document.getElementById(id).value = '';
    });
    loadPropStats();
  } catch(e) { showMsg('house-err', 'Koneksi error'); }
}

// ─── Backup Export ────────────────────────────────────────────────────────────
function doExport() {
  var btn = document.getElementById('export-btn');
  var prog = document.getElementById('export-progress');
  if (!btn || !prog) return;
  btn.disabled = true;
  btn.style.opacity = '0.6';
  btn.style.cursor = 'not-allowed';
  prog.style.display = 'block';
  showToast('Sedang mengekspor database...', 'success');

  // Use fetch + blob download to handle the file
  fetch('/api/backup/export')
    .then(function(r) {
      if (!r.ok) {
        return r.json().then(function(d) { throw new Error(d.error || 'Export gagal'); });
      }
      var disposition = r.headers.get('Content-Disposition') || '';
      var filenameMatch = disposition.match(/filename="(.+?)"/);
      var filename = filenameMatch ? filenameMatch[1] : 'dewata_backup.sql';
      return r.blob().then(function(blob) { return {blob: blob, filename: filename}; });
    })
    .then(function(result) {
      var url = URL.createObjectURL(result.blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = result.filename;
      document.body.appendChild(a);
      a.click();
      setTimeout(function() { URL.revokeObjectURL(url); document.body.removeChild(a); }, 1000);
      showToast('Export berhasil! File sedang diunduh.', 'success');
    })
    .catch(function(err) {
      showToast('Error: ' + err.message, 'error');
    })
    .finally(function() {
      btn.disabled = false;
      btn.style.opacity = '';
      btn.style.cursor = '';
      prog.style.display = 'none';
    });
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn ? btn.textContent : '';
    if (btn) btn.textContent = '✅ Copied!';
    showToast('Tersalin ke clipboard!','success');
    if (btn) setTimeout(() => btn.textContent = orig, 1500);
  }).catch(() => showToast('Gagal copy','error'));
}

function showToast(msg, type='success') {
  const t = document.getElementById('toast');
  t.textContent = (type==='success'?'✅ ':'❌ ') + msg;
  t.className = 'show ' + type;
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.className='', 2800);
}

function showErr(el, msg) { el.textContent=msg; el.classList.add('show'); }
function showMsg(id, msg) { document.getElementById(id).textContent=msg; document.getElementById(id).classList.add('show'); }
function resetMsg(...ids) { ids.forEach(id => document.getElementById(id).classList.remove('show')); }
function escHtml(s) { return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

// Enter key support
document.addEventListener('keydown', e => {
  if (e.key==='Enter') {
    const active = document.activeElement;
    if (active && active.closest('#login-box')) doLogin();
    else if (active && active.closest('#adminkey-box')) doVerifyKey();
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
startLoading();
</script>
</body>
</html>`

// ─── Backup / Export ──────────────────────────────────────────────────────────

func handleBackupExport(w http.ResponseWriter, r *http.Request) {
	if db == nil {
		jsonResp(w, 500, map[string]string{"error": "database not connected"})
		return
	}

	dbName := getEnv("DB_NAME", "s1649_Dewata")
	var buf strings.Builder

	buf.WriteString("-- ============================================================\n")
	buf.WriteString("-- Dewata Nation RP — Full Database Backup\n")
	buf.WriteString(fmt.Sprintf("-- Database : %s\n", dbName))
	buf.WriteString(fmt.Sprintf("-- Generated: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	buf.WriteString("-- ============================================================\n\n")
	buf.WriteString("SET FOREIGN_KEY_CHECKS=0;\n")
	buf.WriteString("SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\n")
	buf.WriteString("SET NAMES utf8mb4;\n\n")

	// Get all tables
	tableRows, err := db.Query("SHOW FULL TABLES")
	if err != nil {
		jsonResp(w, 500, map[string]string{"error": "failed to list tables: " + err.Error()})
		return
	}
	defer tableRows.Close()

	var tables []struct{ name, ttype string }
	for tableRows.Next() {
		var t, tt string
		if err := tableRows.Scan(&t, &tt); err == nil {
			tables = append(tables, struct{ name, ttype string }{t, tt})
		}
	}
	tableRows.Close()

	for _, tbl := range tables {
		buf.WriteString(fmt.Sprintf("-- ------------------------------------------------------------\n"))
		buf.WriteString(fmt.Sprintf("-- Table: %s\n", tbl.name))
		buf.WriteString(fmt.Sprintf("-- ------------------------------------------------------------\n\n"))

		// DROP + CREATE structure
		var createName, createSQL string
		if tbl.ttype == "VIEW" {
			row := db.QueryRow(fmt.Sprintf("SHOW CREATE VIEW `%s`", tbl.name))
			var viewName, viewSQL, cs, cc string
			if err := row.Scan(&viewName, &viewSQL, &cs, &cc); err == nil {
				buf.WriteString(fmt.Sprintf("DROP VIEW IF EXISTS `%s`;\n", tbl.name))
				buf.WriteString(viewSQL + ";\n\n")
			}
			continue
		}

		row := db.QueryRow(fmt.Sprintf("SHOW CREATE TABLE `%s`", tbl.name))
		if err := row.Scan(&createName, &createSQL); err != nil {
			buf.WriteString(fmt.Sprintf("-- ERROR getting structure for %s: %v\n\n", tbl.name, err))
			continue
		}
		buf.WriteString(fmt.Sprintf("DROP TABLE IF EXISTS `%s`;\n", tbl.name))
		buf.WriteString(createSQL + ";\n\n")

		// Get row count
		var rowCount int
		db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM `%s`", tbl.name)).Scan(&rowCount)
		if rowCount == 0 {
			continue
		}

		// Get columns
		colRows, err := db.Query(fmt.Sprintf("SHOW COLUMNS FROM `%s`", tbl.name))
		if err != nil {
			continue
		}
		var colNames []string
		for colRows.Next() {
			var field, ftype, null, key, def, extra sql.NullString
			if err := colRows.Scan(&field, &ftype, &null, &key, &def, &extra); err == nil {
				colNames = append(colNames, field.String)
			}
		}
		colRows.Close()

		// Stream rows in batches of 500
		dataRows, err := db.Query(fmt.Sprintf("SELECT * FROM `%s`", tbl.name))
		if err != nil {
			buf.WriteString(fmt.Sprintf("-- ERROR reading data for %s\n\n", tbl.name))
			continue
		}

		cols, _ := dataRows.Columns()
		vals := make([]interface{}, len(cols))
		valPtrs := make([]interface{}, len(cols))
		for i := range vals {
			valPtrs[i] = &vals[i]
		}

		buf.WriteString(fmt.Sprintf("-- Data for table `%s` (%d rows)\n", tbl.name, rowCount))

		batchCount := 0
		batchSize := 500
		first := true

		for dataRows.Next() {
			if err := dataRows.Scan(valPtrs...); err != nil {
				continue
			}

			if first || batchCount%batchSize == 0 {
				if !first {
					buf.WriteString(";\n")
				}
				// Build INSERT header
				colList := "`" + strings.Join(colNames, "`,`") + "`"
				buf.WriteString(fmt.Sprintf("INSERT INTO `%s` (%s) VALUES\n", tbl.name, colList))
				first = false
			} else {
				buf.WriteString(",\n")
			}

			// Build row values
			buf.WriteString("(")
			for i, val := range vals {
				if i > 0 {
					buf.WriteString(",")
				}
				if val == nil {
					buf.WriteString("NULL")
				} else {
					switch v := val.(type) {
					case []byte:
						buf.WriteString("'")
						buf.WriteString(strings.ReplaceAll(string(v), "'", "\\'"))
						buf.WriteString("'")
					case string:
						buf.WriteString("'")
						buf.WriteString(strings.ReplaceAll(v, "'", "\\'"))
						buf.WriteString("'")
					case int64:
						buf.WriteString(fmt.Sprintf("%d", v))
					case float64:
						buf.WriteString(fmt.Sprintf("%g", v))
					case bool:
						if v {
							buf.WriteString("1")
						} else {
							buf.WriteString("0")
						}
					case time.Time:
						buf.WriteString("'")
						buf.WriteString(v.Format("2006-01-02 15:04:05"))
						buf.WriteString("'")
					default:
						buf.WriteString(fmt.Sprintf("'%v'", v))
					}
				}
			}
			buf.WriteString(")")
			batchCount++
		}
		dataRows.Close()

		if !first {
			buf.WriteString(";\n")
		}
		buf.WriteString("\n")
	}

	buf.WriteString("SET FOREIGN_KEY_CHECKS=1;\n")
	buf.WriteString(fmt.Sprintf("-- ============================================================\n"))
	buf.WriteString(fmt.Sprintf("-- Backup complete: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	buf.WriteString(fmt.Sprintf("-- ============================================================\n"))

	filename := fmt.Sprintf("dewata_backup_%s.sql", time.Now().Format("20060102_150405"))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(200)
	w.Write([]byte(buf.String()))

	// Log the action
	if cookie, err := r.Cookie("session_token"); err == nil {
		sessionsMu.RLock()
		s, ok := sessions[cookie.Value]
		sessionsMu.RUnlock()
		if ok {
			logAction(s.Username, "Export backup database full")
		}
	}
}

// ─── Main ──────────────────────────────────────────────────────────────────────

func main() {
	// Use all available CPU cores
	runtime.GOMAXPROCS(runtime.NumCPU())

	initDB()

	// Pre-encode HTML page once into memory — served from []byte, zero alloc per req
	htmlPageBytes = []byte(htmlPage)

	// Start background workers
	go cleanExpiredSessions()
	startLogWorker()

	mux := http.NewServeMux()

	// ── Static files with caching headers ──────────────────────────────────────
	iconFS := http.FileServer(http.Dir("icon"))
	mux.Handle("/icon/", http.StripPrefix("/icon/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		iconFS.ServeHTTP(w, r)
	})))

	// ── HTML page — served from pre-encoded bytes ───────────────────────────────
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		w.Write(htmlPageBytes)
	})

	// ── Auth endpoints ──────────────────────────────────────────────────────────
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/verify-admin-key", handleVerifyAdminKey)
	mux.HandleFunc("/api/logout", handleLogout)
	mux.HandleFunc("/api/check-auth", handleCheckAuth)

	// ── Protected endpoints ─────────────────────────────────────────────────────
	protected := func(h http.HandlerFunc) http.HandlerFunc { return authMiddleware(h) }

	mux.HandleFunc("/api/getcord",        protected(handleGetcordList))
	mux.HandleFunc("/api/getcord/",       protected(handleDeleteGetcord))
	mux.HandleFunc("/api/check-user",     protected(handleCheckUser))
	mux.HandleFunc("/api/set/money",      protected(handleSetMoney))
	mux.HandleFunc("/api/set/item",       protected(handleSetItem))
	mux.HandleFunc("/api/set/account",    protected(handleSetAccount))
	mux.HandleFunc("/api/set/property",   protected(handleSetProperty))
	mux.HandleFunc("/api/set/vip",        protected(handleSetVip))
	mux.HandleFunc("/api/get-vip",        protected(handleGetVip))
	mux.HandleFunc("/api/inventory",      protected(handleGetInventory))
	mux.HandleFunc("/api/set/admin",      protected(handleSetAdmin))
	mux.HandleFunc("/api/get-admin-info", protected(handleGetAdminInfo))
	mux.HandleFunc("/api/remove-admin",   protected(handleRemoveAdmin))
	mux.HandleFunc("/api/admin-list",     protected(handleGetAdminList))
	mux.HandleFunc("/api/set/gun",        protected(handleSetGun))
	mux.HandleFunc("/api/get-gun-slots",  protected(handleGetGunSlots))
	mux.HandleFunc("/api/set/veh",        protected(handleSetVeh))
	mux.HandleFunc("/api/get-veh-slots",  protected(handleGetVehSlots))
	mux.HandleFunc("/api/admin-log",      protected(handleAdminLog))
	mux.HandleFunc("/api/backup/export",     protected(handleBackupExport))
	mux.HandleFunc("/api/property/add-bizz", protected(handleAddBizz))
	mux.HandleFunc("/api/property/add-house",protected(handleAddHouse))
	mux.HandleFunc("/api/property/stats",    protected(handleGetPropertyStats))
	mux.HandleFunc("/api/punishment/jail",      protected(handleOffJail))
	mux.HandleFunc("/api/punishment/free",      protected(handleFreeJail))
	mux.HandleFunc("/api/punishment/status",    protected(handleGetPrisonStatus))
	mux.HandleFunc("/api/punishment/ban",       protected(handleOffBan))
	mux.HandleFunc("/api/punishment/unban",     protected(handleUnban))
	mux.HandleFunc("/api/punishment/ban-status",protected(handleGetBanStatus))

	// ── Tuned HTTP server ───────────────────────────────────────────────────────
	port := getEnv("PORT", "8080")
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: securityHeaders(mux),

		// Timeouts — prevent slow-client attacks
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,

		// Larger max header — reasonable for admin panel
		MaxHeaderBytes: 1 << 18, // 256 KB
	}

	log.Printf("🚀 Dewata Nation RP Admin Panel | addr=:%s | cpus=%d", port, runtime.NumCPU())
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
