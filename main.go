package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// ─── Global State ─────────────────────────────────────────────────────────────

var (
	db          *sql.DB
	sessionsMu  sync.RWMutex
	sessions    = make(map[string]SessionData)
)

type SessionData struct {
	Username  string
	ExpiresAt time.Time
}

// ─── MD5 Helper ───────────────────────────────────────────────────────────────

func md5Hash(s string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(s)))
}

func hashit(salt, password string) string {
	step3 := strings.ToLower(md5Hash(salt)) + strings.ToLower(md5Hash(password))
	step4 := strings.ToLower(md5Hash(step3))
	return step4
}

// ─── Session Helpers ──────────────────────────────────────────────────────────

func createSession(username string) string {
	token := md5Hash(username + time.Now().String() + "dewata_secret_2026")
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

// ─── DB Init ──────────────────────────────────────────────────────────────────

func initDB() {
	host := getEnv("DB_HOST", "localhost")
	port := getEnv("DB_PORT", "3306")
	user := getEnv("DB_USER", "root")
	pass := getEnv("DB_PASS", "")
	name := getEnv("DB_NAME", "samp")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true", user, pass, host, port, name)
	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Printf("DB open error: %v", err)
		return
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	if err = db.Ping(); err != nil {
		log.Printf("DB ping error: %v", err)
	} else {
		log.Println("Database connected!")
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ─── JSON Response ─────────────────────────────────────────────────────────────

func jsonResp(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResp(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	allowedTypes := map[string]bool{"pRouble": true, "pCash": true, "pBank": true, "pUangMerah": true}
	if !allowedTypes[req.Type] {
		jsonResp(w, 400, map[string]string{"error": "type tidak valid"})
		return
	}
	if req.Value > 500000000 {
		jsonResp(w, 400, map[string]string{"error": "value melebihi 500 juta"})
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
		Value    int    `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	if req.Value > 500 {
		jsonResp(w, 400, map[string]string{"error": "value melebihi 500"})
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
		Value    int    `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	if req.Value > 700 {
		jsonResp(w, 400, map[string]string{"error": "value melebihi 700"})
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	rows, err := db.Query("SELECT user_id, action, date FROM admin_log ORDER BY id DESC LIMIT 200")
	if err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	type LogEntry struct {
		UserID string `json:"user_id"`
		Action string `json:"action"`
		Date   string `json:"date"`
	}
	var list []LogEntry
	for rows.Next() {
		var e LogEntry
		if err := rows.Scan(&e.UserID, &e.Action, &e.Date); err == nil {
			list = append(list, e)
		}
	}
	if list == nil {
		list = []LogEntry{}
	}
	jsonResp(w, 200, list)
}

func logAction(username, action string) {
	if db == nil {
		return
	}
	db.Exec("INSERT INTO admin_log (user_id, action, date) VALUES (?, ?, ?)",
		username, action, time.Now().Format("2006-01-02 15:04:05"))
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
<link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=Exo+2:wght@300;400;500;600;700&display=swap" rel="stylesheet"/>
<style>
:root{
  --bg:#0a0c10;
  --surface:#0e1219;
  --surface2:#141923;
  --surface3:#1a2233;
  --border:#1e2d45;
  --accent:#e8a020;
  --accent2:#f0c040;
  --accentglow:rgba(232,160,32,0.25);
  --red:#e83030;
  --green:#20c060;
  --blue:#2088e8;
  --text:#d0dcea;
  --textmuted:#6a8099;
  --sidebar:260px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Exo 2',sans-serif;min-height:100vh;overflow-x:hidden}
/* Loading Screen */
#loading-screen{position:fixed;inset:0;background:var(--bg);z-index:9999;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:24px;transition:opacity 0.5s}
#loading-screen.hidden{opacity:0;pointer-events:none}
.loading-logo{width:120px;height:120px;border-radius:16px;object-fit:cover;box-shadow:0 0 40px var(--accentglow)}
.loading-bar-wrap{width:280px;height:4px;background:var(--surface3);border-radius:99px;overflow:hidden}
.loading-bar{height:100%;width:0%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:99px;transition:width 0.3s}
.loading-text{font-family:'Rajdhani',sans-serif;font-size:13px;letter-spacing:3px;color:var(--textmuted);text-transform:uppercase}

/* Auth Screens */
#auth-wrapper{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:var(--bg);z-index:100}
#auth-wrapper.hidden{display:none}
.auth-box{background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:40px;width:100%;max-width:420px;position:relative;overflow:hidden}
.auth-box::before{content:'';position:absolute;top:-60px;right:-60px;width:180px;height:180px;background:radial-gradient(circle,var(--accentglow),transparent 70%);pointer-events:none}
.auth-banner{width:100%;border-radius:12px;margin-bottom:24px;object-fit:cover;height:120px}
.auth-title{font-family:'Rajdhani',sans-serif;font-size:26px;font-weight:700;letter-spacing:2px;color:var(--accent);margin-bottom:6px}
.auth-sub{font-size:13px;color:var(--textmuted);margin-bottom:28px}
.form-group{margin-bottom:18px}
.form-group label{display:block;font-size:12px;letter-spacing:1px;text-transform:uppercase;color:var(--textmuted);margin-bottom:8px}
.form-group input,.form-group select{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:12px 16px;color:var(--text);font-family:'Exo 2',sans-serif;font-size:14px;outline:none;transition:border-color 0.2s}
.form-group input:focus,.form-group select:focus{border-color:var(--accent)}
.btn{width:100%;padding:13px;border:none;border-radius:10px;font-family:'Rajdhani',sans-serif;font-size:16px;font-weight:700;letter-spacing:2px;cursor:pointer;transition:all 0.2s;text-transform:uppercase}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#0a0c10}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 24px var(--accentglow)}
.btn-danger{background:var(--red);color:#fff;padding:8px 16px;width:auto;font-size:13px;border-radius:8px;letter-spacing:1px}
.btn-sm{padding:8px 16px;width:auto;font-size:13px;border-radius:8px;letter-spacing:1px}
.btn-copy{background:var(--surface3);color:var(--accent);border:1px solid var(--border)}
.btn-copy:hover{background:var(--accentglow)}
.auth-error{background:rgba(232,48,48,0.1);border:1px solid var(--red);border-radius:8px;padding:10px 14px;font-size:13px;color:var(--red);margin-bottom:16px;display:none}
.auth-error.show{display:block}

/* App Layout */
#app{display:none;min-height:100vh}
#app.visible{display:flex}

/* Sidebar */
#sidebar{width:var(--sidebar);background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;transition:transform 0.3s,width 0.3s;position:fixed;top:0;bottom:0;left:0;z-index:50;overflow:hidden}
#sidebar.collapsed{transform:translateX(calc(-1 * var(--sidebar)))}
.sidebar-header{padding:20px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px}
.sidebar-logo{width:40px;height:40px;border-radius:10px;object-fit:cover;flex-shrink:0}
.sidebar-title{font-family:'Rajdhani',sans-serif;font-size:18px;font-weight:700;color:var(--accent);letter-spacing:1px;white-space:nowrap}
.sidebar-nav{flex:1;overflow-y:auto;padding:12px 8px}
.nav-item{display:flex;align-items:center;gap:12px;padding:12px 14px;border-radius:12px;cursor:pointer;transition:all 0.2s;color:var(--textmuted);margin-bottom:4px;font-weight:500;white-space:nowrap}
.nav-item:hover{background:var(--surface3);color:var(--text)}
.nav-item.active{background:linear-gradient(135deg,rgba(232,160,32,0.15),rgba(240,192,64,0.08));color:var(--accent);border:1px solid rgba(232,160,32,0.2)}
.nav-icon{font-size:18px;flex-shrink:0;width:22px;text-align:center}
.sidebar-footer{padding:16px;border-top:1px solid var(--border)}
.sidebar-user{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.user-avatar{width:36px;height:36px;background:var(--accentglow);border:1px solid var(--accent);border-radius:50%;display:flex;align-items:center;justify-content:center;font-family:'Rajdhani',sans-serif;font-weight:700;color:var(--accent);flex-shrink:0}
.user-info{flex:1;overflow:hidden}
.user-name{font-weight:600;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.user-role{font-size:11px;color:var(--accent);letter-spacing:1px}

/* Main Content */
#main{flex:1;margin-left:var(--sidebar);transition:margin-left 0.3s;display:flex;flex-direction:column;min-height:100vh}
#main.expanded{margin-left:0}

/* Topbar */
#topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;height:64px;display:flex;align-items:center;gap:16px;position:sticky;top:0;z-index:40}
#menu-toggle{background:none;border:1px solid var(--border);border-radius:10px;padding:8px 12px;cursor:pointer;color:var(--text);font-size:18px;transition:all 0.2s}
#menu-toggle:hover{background:var(--surface3);border-color:var(--accent);color:var(--accent)}
.topbar-title{font-family:'Rajdhani',sans-serif;font-size:20px;font-weight:700;color:var(--accent);letter-spacing:1px;flex:1}
.topbar-status{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--textmuted)}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green)}

/* Page Content */
#content{flex:1;padding:28px;overflow-x:hidden}
.page{display:none}
.page.active{display:block}

/* Cards */
.card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px;margin-bottom:20px}
.card-title{font-family:'Rajdhani',sans-serif;font-size:18px;font-weight:700;color:var(--accent);letter-spacing:1px;margin-bottom:16px;display:flex;align-items:center;gap:10px}
.page-title{font-family:'Rajdhani',sans-serif;font-size:28px;font-weight:700;color:var(--text);letter-spacing:2px;margin-bottom:6px}
.page-sub{color:var(--textmuted);font-size:14px;margin-bottom:24px}

/* Dashboard */
.dash-banner{width:100%;border-radius:16px;height:180px;object-fit:cover;margin-bottom:24px;box-shadow:0 8px 32px rgba(0,0,0,0.4)}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
.info-card{background:var(--surface2);border:1px solid var(--border);border-radius:14px;padding:20px}
.info-label{font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--textmuted);margin-bottom:8px}
.info-value{font-family:'Rajdhani',sans-serif;font-size:22px;font-weight:700;color:var(--text);margin-bottom:12px;word-break:break-all}
.info-copy-btn{display:inline-flex;align-items:center;gap:6px;background:var(--surface3);border:1px solid var(--border);color:var(--accent);padding:6px 14px;border-radius:8px;font-size:12px;font-family:'Rajdhani',sans-serif;letter-spacing:1px;cursor:pointer;transition:all 0.2s;font-weight:600}
.info-copy-btn:hover{background:var(--accentglow);border-color:var(--accent)}

/* Table */
.table-wrap{overflow-x:auto;border-radius:12px;border:1px solid var(--border)}
table{width:100%;border-collapse:collapse;font-size:13px}
thead th{background:var(--surface2);padding:12px 16px;text-align:left;font-family:'Rajdhani',sans-serif;font-size:12px;letter-spacing:2px;text-transform:uppercase;color:var(--textmuted);border-bottom:1px solid var(--border)}
tbody td{padding:12px 16px;border-bottom:1px solid rgba(30,45,69,0.5);vertical-align:middle}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--surface2)}
.cord-text{font-family:monospace;font-size:12px;color:var(--accent2)}
.badge{display:inline-block;padding:3px 10px;border-radius:99px;font-size:11px;font-weight:600;font-family:'Rajdhani',sans-serif;letter-spacing:1px}
.badge-green{background:rgba(32,192,96,0.15);color:var(--green);border:1px solid rgba(32,192,96,0.3)}
.badge-blue{background:rgba(32,136,232,0.15);color:var(--blue);border:1px solid rgba(32,136,232,0.3)}

/* Set Form */
.set-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}
.set-card{background:var(--surface2);border:1px solid var(--border);border-radius:14px;padding:20px}
.set-title{font-family:'Rajdhani',sans-serif;font-size:15px;font-weight:700;color:var(--accent);letter-spacing:1px;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.input-row{display:flex;gap:10px;margin-bottom:12px;align-items:flex-end}
.input-row .form-group{flex:1;margin-bottom:0}
.success-msg{background:rgba(32,192,96,0.1);border:1px solid var(--green);border-radius:8px;padding:10px 14px;font-size:13px;color:var(--green);margin-top:10px;display:none}
.success-msg.show{display:block}
.error-msg{background:rgba(232,48,48,0.1);border:1px solid var(--red);border-radius:8px;padding:10px 14px;font-size:13px;color:var(--red);margin-top:10px;display:none}
.error-msg.show{display:block}

/* Log */
.log-item{display:flex;align-items:flex-start;gap:12px;padding:12px 0;border-bottom:1px solid rgba(30,45,69,0.5)}
.log-item:last-child{border-bottom:none}
.log-user{font-family:'Rajdhani',sans-serif;font-size:13px;font-weight:700;color:var(--accent);min-width:120px;flex-shrink:0}
.log-action{font-size:13px;flex:1;color:var(--text)}
.log-date{font-size:11px;color:var(--textmuted);flex-shrink:0;white-space:nowrap}

/* Toast */
#toast{position:fixed;bottom:28px;right:28px;background:var(--surface3);border:1px solid var(--border);border-radius:12px;padding:14px 20px;font-size:13px;font-weight:600;box-shadow:0 8px 32px rgba(0,0,0,0.4);z-index:9999;transform:translateY(80px);opacity:0;transition:all 0.3s;max-width:320px}
#toast.show{transform:translateY(0);opacity:1}
#toast.success{border-color:var(--green);color:var(--green)}
#toast.error{border-color:var(--red);color:var(--red)}

/* Overlay */
#sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:49}
#sidebar-overlay.show{display:block}

/* Responsive */
@media(max-width:768px){
  #main{margin-left:0}
  #main.expanded{margin-left:0}
  #sidebar{transform:translateX(calc(-1 * var(--sidebar)))}
  #sidebar.open{transform:translateX(0)}
  .info-grid{grid-template-columns:1fr}
  .set-grid{grid-template-columns:1fr}
  #content{padding:16px}
}

/* Animations */
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.page.active{animation:fadeIn 0.3s ease}
@keyframes pulse{0%,100%{box-shadow:0 0 6px var(--green)}50%{box-shadow:0 0 12px var(--green)}}
.status-dot{animation:pulse 2s infinite}

/* Scrollbar */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--surface)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:99px}
::-webkit-scrollbar-thumb:hover{background:var(--accent)}
</style>
</head>
<body>

<!-- Loading -->
<div id="loading-screen">
  <img class="loading-logo" src="https://logo-dewata-nationrp.edgeone.app/IMG-20260131-WA0425.jpg" alt="Logo" onerror="this.style.display='none'"/>
  <div>
    <div style="font-family:'Rajdhani',sans-serif;font-size:22px;font-weight:700;color:var(--accent);letter-spacing:3px;text-align:center;margin-bottom:4px">DEWATA NATION RP</div>
    <div style="font-size:11px;letter-spacing:4px;color:var(--textmuted);text-align:center;margin-bottom:20px">ADMIN CONTROL PANEL</div>
    <div class="loading-bar-wrap"><div class="loading-bar" id="loading-bar"></div></div>
  </div>
  <div class="loading-text" id="loading-text">Initializing...</div>
</div>

<!-- Auth: Login -->
<div id="auth-wrapper">
  <div id="login-box" class="auth-box">
    <img class="auth-banner" src="https://logo-dewata-nationrp.edgeone.app/IMG-20260131-WA0425.jpg" alt="Banner" onerror="this.style.display='none'"/>
    <div class="auth-title">⚡ DEWATA NATION RP</div>
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
    <div class="auth-title">🔑 VERIFIKASI ADMIN</div>
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
      <img class="sidebar-logo" src="https://logo-dewata-nationrp.edgeone.app/IMG-20260131-WA0425.jpg" alt="Logo" onerror="this.style.display='none'"/>
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
        <img class="dash-banner" src="https://logo-dewata-nationrp.edgeone.app/IMG-20260131-WA0425.jpg" alt="Banner" onerror="this.style.height='0';this.style.margin='0'"/>
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
            <div class="form-group"><label>Value</label><input type="number" id="money-val" placeholder="0" max="500000000"/></div>
            <div class="form-group"><label>Type</label>
              <select id="money-type">
                <option value="pRouble">pRouble (Donate Coin)</option>
                <option value="pCash">pCash (Uang Cash)</option>
                <option value="pBank">pBank (Uang Bank)</option>
                <option value="pUangMerah">pUangMerah (Uang Merah)</option>
              </select>
            </div>
            <button class="btn btn-primary btn-sm" onclick="setMoney()" style="flex-shrink:0;margin-bottom:0">SET</button>
          </div>
          <div class="error-msg" id="money-err"></div>
          <div class="success-msg" id="money-ok"></div>
        </div>

        <!-- Set Item -->
        <div class="card">
          <div class="card-title">🎒 Set Item Pemain</div>
          <div class="input-row">
            <div class="form-group"><label>Username</label><input type="text" id="item-user" placeholder="Username..."/></div>
            <div class="form-group"><label>Value (max 500)</label><input type="number" id="item-val" placeholder="0" max="500"/></div>
            <div class="form-group"><label>Type</label>
              <select id="item-type">
                <option value="pBatu">pBatu (Batu Bersih)</option>
                <option value="pBatuk">pBatuk (Batu Kotor)</option>
                <option value="pFish">pFish (Ikan)</option>
                <option value="pPenyu">pPenyu (Penyu)</option>
                <option value="pDolphin">pDolphin (Dolpin)</option>
                <option value="pHiu">pHiu (Hiu)</option>
                <option value="pMegalodon">pMegalodon (Megalodon)</option>
                <option value="pCaught">pCaught (Umpan Mancing)</option>
                <option value="pPadi">pPadi (Padi)</option>
                <option value="pAyam">pAyam (Ayam)</option>
                <option value="pSemen">pSemen (Semen)</option>
                <option value="pEmas">pEmas (Emas)</option>
                <option value="pSusu">pSusu (Susu Sapi)</option>
                <option value="pMinyak">pMinyak (Minyak)</option>
                <option value="pAyamKemas">pAyamKemas (Ayam Kemas)</option>
                <option value="pAyamPotong">pAyamPotong (Ayam Potong)</option>
                <option value="pAyamHidup">pAyamHidup (Ayam Hidup)</option>
                <option value="pBulu">pBulu (Bulu Ayam)</option>
              </select>
            </div>
            <button class="btn btn-primary btn-sm" onclick="setItem()" style="flex-shrink:0;margin-bottom:0">SET</button>
          </div>
          <div class="error-msg" id="item-err"></div>
          <div class="success-msg" id="item-ok"></div>
        </div>

        <!-- Set Account -->
        <div class="card">
          <div class="card-title">🗃️ Set Akun Pemain</div>
          <div class="input-row">
            <div class="form-group"><label>Username</label><input type="text" id="acc-user" placeholder="Username..."/></div>
            <div class="form-group"><label>Value (max 700)</label><input type="number" id="acc-val" placeholder="0" max="700"/></div>
            <div class="form-group"><label>Type</label>
              <select id="acc-type">
                <option value="pDrugs">pDrugs (Drugs)</option>
                <option value="pMicin">pMicin (Marijuana)</option>
                <option value="pSteroid">pSteroid (Steroid)</option>
                <option value="pComponent">pComponent (Component)</option>
                <option value="pMetall">pMetall (Besi)</option>
                <option value="pFood">pFood (Makanan)</option>
                <option value="pDrink">pDrink (Minuman)</option>
              </select>
            </div>
            <button class="btn btn-primary btn-sm" onclick="setAccount()" style="flex-shrink:0;margin-bottom:0">SET</button>
          </div>
          <div class="error-msg" id="acc-err"></div>
          <div class="success-msg" id="acc-ok"></div>
        </div>

        <!-- Set Property -->
        <div class="card">
          <div class="card-title">🔧 Set Properti Pemain</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px" id="prop-grid">
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
      </div>

      <!-- Admin Log Page -->
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

<!-- Toast -->
<div id="toast"></div>

<script>
// ─── State ─────────────────────────────────────────────────────────────────────
let currentUser = '';
let tempLoginUser = '';
let sidebarOpen = false;
let isMobile = window.innerWidth <= 768;

window.addEventListener('resize', () => { isMobile = window.innerWidth <= 768; });

// ─── Loading ───────────────────────────────────────────────────────────────────
function startLoading() {
  const bar = document.getElementById('loading-bar');
  const text = document.getElementById('loading-text');
  const msgs = ['Initializing...','Connecting to database...','Loading modules...','Verifying session...','Ready!'];
  let pct = 0, i = 0;
  const iv = setInterval(() => {
    pct += Math.random() * 22 + 8;
    if (pct > 100) pct = 100;
    bar.style.width = pct + '%';
    if (i < msgs.length) text.textContent = msgs[i++];
    if (pct >= 100) {
      clearInterval(iv);
      setTimeout(() => {
        document.getElementById('loading-screen').classList.add('hidden');
        checkAuth();
      }, 400);
    }
  }, 280);
}

// ─── Auth ──────────────────────────────────────────────────────────────────────
async function checkAuth() {
  try {
    const r = await fetch('/api/check-auth');
    if (r.ok) {
      const d = await r.json();
      enterApp(d.username);
    } else {
      showAuth();
    }
  } catch { showAuth(); }
}

function showAuth() {
  document.getElementById('auth-wrapper').classList.remove('hidden');
  document.getElementById('login-box').style.display = '';
  document.getElementById('adminkey-box').style.display = 'none';
}

async function doLogin() {
  const user = document.getElementById('login-user').value.trim();
  const pass = document.getElementById('login-pass').value;
  const errEl = document.getElementById('login-error');
  errEl.classList.remove('show');
  if (!user || !pass) { showErr(errEl, 'Username dan password wajib diisi'); return; }
  try {
    const r = await fetch('/api/login', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,password:pass})});
    const d = await r.json();
    if (!r.ok) { showErr(errEl, d.error || 'Login gagal'); return; }
    tempLoginUser = d.username;
    document.getElementById('login-box').style.display = 'none';
    document.getElementById('adminkey-box').style.display = '';
    document.getElementById('admin-key').focus();
  } catch { showErr(errEl, 'Koneksi error'); }
}

async function doVerifyKey() {
  const key = document.getElementById('admin-key').value.trim();
  const errEl = document.getElementById('key-error');
  errEl.classList.remove('show');
  if (!key) { showErr(errEl, 'Admin key wajib diisi'); return; }
  try {
    const r = await fetch('/api/verify-admin-key', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:tempLoginUser,admin_key:key})});
    const d = await r.json();
    if (!r.ok) { showErr(errEl, d.error || 'Verifikasi gagal'); return; }
    enterApp(d.username);
  } catch { showErr(errEl, 'Koneksi error'); }
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
  const app = document.getElementById('app');
  app.style.display = 'flex';
  app.classList.add('visible');
  document.getElementById('sidebar-username').textContent = username;
  document.getElementById('admin-name-top').textContent = username;
  document.getElementById('user-avatar').textContent = username.charAt(0).toUpperCase();
  // Desktop: open sidebar by default
  if (!isMobile) openSidebar();
  showPage('dashboard');
}

// ─── Sidebar ───────────────────────────────────────────────────────────────────
function toggleSidebar() {
  if (isMobile) {
    const sb = document.getElementById('sidebar');
    const ov = document.getElementById('sidebar-overlay');
    sidebarOpen = !sidebarOpen;
    sb.classList.toggle('open', sidebarOpen);
    ov.classList.toggle('show', sidebarOpen);
  } else {
    const sb = document.getElementById('sidebar');
    const main = document.getElementById('main');
    sidebarOpen = !sidebarOpen;
    sb.classList.toggle('collapsed', !sidebarOpen);
    main.classList.toggle('expanded', !sidebarOpen);
  }
}

function openSidebar() {
  const sb = document.getElementById('sidebar');
  const main = document.getElementById('main');
  sidebarOpen = true;
  sb.classList.remove('collapsed');
  main.classList.remove('expanded');
}

// ─── Pages ─────────────────────────────────────────────────────────────────────
const pageTitles = {dashboard:'Dashboard',getcord:'Getcord List',set:'Set Menu',adminlog:'Admin Log'};

function showPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('active');
  document.getElementById('page-title').textContent = pageTitles[name] || name;
  const navItems = document.querySelectorAll('.nav-item');
  const idx = {dashboard:0,getcord:1,set:2,adminlog:3};
  if (navItems[idx[name]]) navItems[idx[name]].classList.add('active');
  if (isMobile) { sidebarOpen=false; document.getElementById('sidebar').classList.remove('open'); document.getElementById('sidebar-overlay').classList.remove('show'); }
  if (name==='getcord') loadGetcord();
  if (name==='adminlog') loadAdminLog();
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
    tbody.innerHTML = d.map(c => {
      const cord = ` ${c.x.toFixed(4)}, ${c.y.toFixed(4)}, ${c.z.toFixed(4)}, ${c.a.toFixed(4)}`;
      return ` <tr>
        <td><span class="badge badge-blue">${c.id}</span></td>
        <td><strong>${escHtml(c.name)}</strong></td>
        <td class="cord-text">${c.x.toFixed(4)}</td>
        <td class="cord-text">${c.y.toFixed(4)}</td>
        <td class="cord-text">${c.z.toFixed(4)}</td>
        <td class="cord-text">${c.a.toFixed(4)}</td>
        <td><button class="btn btn-copy btn-sm" onclick="copyText('${cord.trim()}',this)">📋 Copy</button></td>
        <td><button class="btn btn-danger" onclick="deleteGetcord(${c.id},this)">🗑️ Hapus</button></td>
      </tr>`;
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
async function setMoney() {
  const user = document.getElementById('money-user').value.trim();
  const val = parseInt(document.getElementById('money-val').value);
  const type = document.getElementById('money-type').value;
  resetMsg('money-err','money-ok');
  if (!user) { showMsg('money-err','Username wajib diisi'); return; }
  if (isNaN(val) || val < 0) { showMsg('money-err','Value tidak valid'); return; }
  if (val > 500000000) { showMsg('money-err','Value melebihi 500 juta'); return; }
  try {
    const r = await fetch('/api/set/money',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,type,value:val})});
    const d = await r.json();
    if (!r.ok) { showMsg('money-err', d.error||'Gagal'); return; }
    showMsg('money-ok','Berhasil set '+type+' untuk '+user+' = '+val);
    showToast('Berhasil!','success');
  } catch { showMsg('money-err','Koneksi error'); }
}

// ─── Set Item ─────────────────────────────────────────────────────────────────
async function setItem() {
  const user = document.getElementById('item-user').value.trim();
  const val = parseInt(document.getElementById('item-val').value);
  const type = document.getElementById('item-type').value;
  resetMsg('item-err','item-ok');
  if (!user) { showMsg('item-err','Username wajib diisi'); return; }
  if (isNaN(val) || val < 0) { showMsg('item-err','Value tidak valid'); return; }
  if (val > 500) { showMsg('item-err','Value melebihi 500'); return; }
  try {
    const r = await fetch('/api/set/item',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,type,value:val})});
    const d = await r.json();
    if (!r.ok) { showMsg('item-err', d.error||'Gagal'); return; }
    showMsg('item-ok','Berhasil set '+type+' untuk '+user+' = '+val);
    showToast('Berhasil!','success');
  } catch { showMsg('item-err','Koneksi error'); }
}

// ─── Set Account ──────────────────────────────────────────────────────────────
async function setAccount() {
  const user = document.getElementById('acc-user').value.trim();
  const val = parseInt(document.getElementById('acc-val').value);
  const type = document.getElementById('acc-type').value;
  resetMsg('acc-err','acc-ok');
  if (!user) { showMsg('acc-err','Username wajib diisi'); return; }
  if (isNaN(val) || val < 0) { showMsg('acc-err','Value tidak valid'); return; }
  if (val > 700) { showMsg('acc-err','Value melebihi 700'); return; }
  try {
    const r = await fetch('/api/set/account',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,type,value:val})});
    const d = await r.json();
    if (!r.ok) { showMsg('acc-err', d.error||'Gagal'); return; }
    showMsg('acc-ok','Berhasil set '+type+' untuk '+user+' = '+val);
    showToast('Berhasil!','success');
  } catch { showMsg('acc-err','Koneksi error'); }
}

// ─── Set Property ─────────────────────────────────────────────────────────────
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

// ─── Admin Log ────────────────────────────────────────────────────────────────
async function loadAdminLog() {
  const el = document.getElementById('log-list');
  el.innerHTML = '<div style="text-align:center;color:var(--textmuted);padding:28px">Memuat log...</div>';
  try {
    const r = await fetch('/api/admin-log');
    const d = await r.json();
    if (!r.ok || !Array.isArray(d) || d.length===0) {
      el.innerHTML='<div style="text-align:center;color:var(--textmuted);padding:28px">Belum ada log</div>';
      return;
    }
    el.innerHTML = d.map(l => `
      <div class="log-item">
        <div class="log-user">👤 ${escHtml(l.user_id)}</div>
        <div class="log-action">${escHtml(l.action)}</div>
        <div class="log-date">🕒 ${escHtml(l.date)}</div>
      </div>`).join('');
  } catch { el.innerHTML='<div style="text-align:center;color:var(--red);padding:28px">Error memuat log</div>'; }
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

// ─── Main ──────────────────────────────────────────────────────────────────────

func main() {
	initDB()

	mux := http.NewServeMux()

	// Static page
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(htmlPage))
	})

	// Auth endpoints
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/verify-admin-key", handleVerifyAdminKey)
	mux.HandleFunc("/api/logout", handleLogout)
	mux.HandleFunc("/api/check-auth", handleCheckAuth)

	// Protected endpoints
	mux.HandleFunc("/api/getcord", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handleGetcordList(w, r)
	}))
	mux.HandleFunc("/api/getcord/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handleDeleteGetcord(w, r)
	}))
	mux.HandleFunc("/api/check-user", authMiddleware(handleCheckUser))
	mux.HandleFunc("/api/set/money", authMiddleware(handleSetMoney))
	mux.HandleFunc("/api/set/item", authMiddleware(handleSetItem))
	mux.HandleFunc("/api/set/account", authMiddleware(handleSetAccount))
	mux.HandleFunc("/api/set/property", authMiddleware(handleSetProperty))
	mux.HandleFunc("/api/admin-log", authMiddleware(handleAdminLog))

	port := getEnv("PORT", "8080")
	addr := ":" + port
	log.Printf("🚀 Dewata Nation RP Admin Panel running on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
