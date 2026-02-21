package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
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
	host := getEnv("DB_HOST", "208.84.103.75")
	port := getEnv("DB_PORT", "3306")
	user := getEnv("DB_USER", "u1649_NtHPQzNRvz")
	pass := getEnv("DB_PASS", "qJHEEZZraPLuQGGOtHPSvWT=")
	name := getEnv("DB_NAME", "s1649_Dewata")

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
	// user_id is INT, no auto-increment id column — order by date DESC
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
	var list []LogEntry
	for rows.Next() {
		var e LogEntry
		var rawDate []byte
		if err := rows.Scan(&e.UserID, &e.Action, &rawDate); err == nil {
			e.Date = string(rawDate)
			list = append(list, e)
		}
	}
	if list == nil {
		list = []LogEntry{}
	}
	jsonResp(w, 200, list)
}

// lookupAccountID returns the integer account ID for a given username (pName)
// Falls back to 0 if not found or DB unavailable
func lookupAccountID(username string) int {
	if db == nil {
		return 0
	}
	var id int
	// Try common ID column names used in SAMP scripts
	for _, col := range []string{"ID", "pID", "id", "AccountID"} {
		err := db.QueryRow("SELECT `"+col+"` FROM accounts WHERE pName=? LIMIT 1", username).Scan(&id)
		if err == nil {
			return id
		}
	}
	return 0
}

func logAction(username, action string) {
	if db == nil {
		return
	}
	uid := lookupAccountID(username)
	db.Exec("INSERT INTO admin_log (user_id, action, date) VALUES (?, ?, ?)",
		uid, action, time.Now().Format("2006-01-02 15:04:05"))
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
  --topbar:64px;
}

/* ── Reset ── */
*{box-sizing:border-box;margin:0;padding:0}
html{font-size:16px;-webkit-text-size-adjust:100%}
body{background:var(--bg);color:var(--text);font-family:'Exo 2',sans-serif;min-height:100vh;overflow-x:hidden;-webkit-font-smoothing:antialiased}

/* ── Loading ── */
#loading-screen{position:fixed;inset:0;background:var(--bg);z-index:9999;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:20px;padding:24px;transition:opacity 0.5s}
#loading-screen.hidden{opacity:0;pointer-events:none}
.loading-logo{width:clamp(80px,20vw,120px);height:clamp(80px,20vw,120px);border-radius:16px;object-fit:cover;box-shadow:0 0 40px var(--accentglow)}
.loading-bar-wrap{width:min(280px,85vw);height:4px;background:var(--surface3);border-radius:99px;overflow:hidden}
.loading-bar{height:100%;width:0%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:99px;transition:width 0.3s}
.loading-text{font-family:'Rajdhani',sans-serif;font-size:12px;letter-spacing:3px;color:var(--textmuted);text-transform:uppercase;text-align:center}

/* ── Auth ── */
#auth-wrapper{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:var(--bg);z-index:100;padding:16px;overflow-y:auto}
#auth-wrapper.hidden{display:none}
.auth-box{background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:clamp(24px,5vw,40px);width:100%;max-width:420px;position:relative;overflow:hidden;margin:auto}
.auth-box::before{content:'';position:absolute;top:-60px;right:-60px;width:180px;height:180px;background:radial-gradient(circle,var(--accentglow),transparent 70%);pointer-events:none}
.auth-banner-wrap{width:100%;border-radius:12px;margin-bottom:20px;overflow:hidden;background:var(--surface2);aspect-ratio:16/5;display:flex;align-items:center;justify-content:center}
.auth-banner{width:100%;height:100%;object-fit:cover;display:block}
.auth-banner-fallback{font-family:'Rajdhani',sans-serif;font-size:20px;font-weight:700;color:var(--accent);letter-spacing:2px;text-align:center;padding:16px}
.auth-title{font-family:'Rajdhani',sans-serif;font-size:clamp(20px,5vw,26px);font-weight:700;letter-spacing:2px;color:var(--accent);margin-bottom:6px}
.auth-sub{font-size:13px;color:var(--textmuted);margin-bottom:24px}
.form-group{margin-bottom:16px}
.form-group label{display:block;font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--textmuted);margin-bottom:8px;font-weight:600}
.form-group input,.form-group select{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:12px 16px;color:var(--text);font-family:'Exo 2',sans-serif;font-size:14px;outline:none;transition:border-color 0.2s;-webkit-appearance:none;appearance:none}
.form-group input:focus,.form-group select:focus{border-color:var(--accent)}
.form-group select{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath fill='%236a8099' d='M6 8L0 0h12z'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 14px center;padding-right:36px}
.btn{width:100%;padding:13px;border:none;border-radius:10px;font-family:'Rajdhani',sans-serif;font-size:16px;font-weight:700;letter-spacing:2px;cursor:pointer;transition:all 0.2s;text-transform:uppercase;touch-action:manipulation}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#0a0c10}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 24px var(--accentglow)}
.btn-primary:active{transform:translateY(0)}
.btn-danger{background:var(--red);color:#fff;padding:9px 16px;width:auto;font-size:13px;border-radius:8px;letter-spacing:1px}
.btn-sm{padding:9px 16px;width:auto;font-size:13px;border-radius:8px;letter-spacing:1px}
.btn-copy{background:var(--surface3);color:var(--accent);border:1px solid var(--border)}
.btn-copy:hover{background:var(--accentglow)}
.auth-error{background:rgba(232,48,48,0.1);border:1px solid var(--red);border-radius:8px;padding:10px 14px;font-size:13px;color:var(--red);margin-bottom:14px;display:none}
.auth-error.show{display:block}

/* ── App Layout ── */
#app{display:none;min-height:100vh}
#app.visible{display:flex}

/* ── Sidebar ── */
#sidebar{
  width:var(--sidebar);
  background:var(--surface);
  border-right:1px solid var(--border);
  display:flex;flex-direction:column;
  transition:transform 0.3s cubic-bezier(0.4,0,0.2,1);
  position:fixed;top:0;bottom:0;left:0;
  z-index:50;overflow:hidden;
  will-change:transform;
}
/* Desktop: sidebar collapsed = slide left */
#sidebar.collapsed{transform:translateX(calc(-1 * var(--sidebar)))}
/* Mobile: sidebar hidden by default, shown when .open */
.sidebar-header{padding:18px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px;flex-shrink:0}
.sidebar-logo-wrap{width:40px;height:40px;border-radius:10px;overflow:hidden;flex-shrink:0;background:var(--surface2);display:flex;align-items:center;justify-content:center}
.sidebar-logo{width:100%;height:100%;object-fit:cover;display:block}
.sidebar-logo-fallback{font-size:20px;line-height:1}
.sidebar-title{font-family:'Rajdhani',sans-serif;font-size:17px;font-weight:700;color:var(--accent);letter-spacing:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sidebar-nav{flex:1;overflow-y:auto;overflow-x:hidden;padding:12px 8px}
.nav-item{display:flex;align-items:center;gap:12px;padding:12px 14px;border-radius:12px;cursor:pointer;transition:all 0.2s;color:var(--textmuted);margin-bottom:4px;font-weight:500;white-space:nowrap;user-select:none;border:1px solid transparent;-webkit-tap-highlight-color:transparent}
.nav-item:hover{background:var(--surface3);color:var(--text)}
.nav-item:active{transform:scale(0.98)}
.nav-item.active{background:linear-gradient(135deg,rgba(232,160,32,0.15),rgba(240,192,64,0.08));color:var(--accent);border-color:rgba(232,160,32,0.2)}
.nav-icon{font-size:18px;flex-shrink:0;width:24px;text-align:center}
.sidebar-footer{padding:14px;border-top:1px solid var(--border);flex-shrink:0}
.sidebar-user{display:flex;align-items:center;gap:10px;margin-bottom:12px;min-width:0}
.user-avatar{width:38px;height:38px;background:var(--accentglow);border:1px solid var(--accent);border-radius:50%;display:flex;align-items:center;justify-content:center;font-family:'Rajdhani',sans-serif;font-weight:700;color:var(--accent);flex-shrink:0;font-size:16px}
.user-info{flex:1;min-width:0;overflow:hidden}
.user-name{font-weight:600;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.user-role{font-size:10px;color:var(--accent);letter-spacing:1px;text-transform:uppercase}

/* ── Main ── */
#main{flex:1;margin-left:var(--sidebar);transition:margin-left 0.3s cubic-bezier(0.4,0,0.2,1);display:flex;flex-direction:column;min-height:100vh;min-width:0}
#main.expanded{margin-left:0}

/* ── Topbar ── */
#topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:0 20px;height:var(--topbar);display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:40;flex-shrink:0}
#menu-toggle{background:none;border:1px solid var(--border);border-radius:10px;padding:8px 11px;cursor:pointer;color:var(--text);font-size:18px;transition:all 0.2s;flex-shrink:0;-webkit-tap-highlight-color:transparent;touch-action:manipulation}
#menu-toggle:hover{background:var(--surface3);border-color:var(--accent);color:var(--accent)}
.topbar-title{font-family:'Rajdhani',sans-serif;font-size:clamp(16px,3vw,20px);font-weight:700;color:var(--accent);letter-spacing:1px;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.topbar-status{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--textmuted);flex-shrink:0;max-width:140px;overflow:hidden}
.topbar-status span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green);flex-shrink:0}

/* ── Page Content ── */
#content{flex:1;padding:clamp(14px,3vw,28px);overflow-x:hidden}
.page{display:none}
.page.active{display:block}

/* ── Cards ── */
.card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:clamp(16px,3vw,24px);margin-bottom:18px}
.card-title{font-family:'Rajdhani',sans-serif;font-size:17px;font-weight:700;color:var(--accent);letter-spacing:1px;margin-bottom:16px;display:flex;align-items:center;gap:10px}
.page-title{font-family:'Rajdhani',sans-serif;font-size:clamp(22px,5vw,28px);font-weight:700;color:var(--text);letter-spacing:2px;margin-bottom:6px}
.page-sub{color:var(--textmuted);font-size:13px;margin-bottom:20px;line-height:1.5}

/* ── Dashboard Banner ── */
.dash-banner-wrap{width:100%;border-radius:16px;overflow:hidden;margin-bottom:20px;background:var(--surface2);aspect-ratio:16/5;min-height:100px;max-height:220px;display:flex;align-items:center;justify-content:center;box-shadow:0 8px 32px rgba(0,0,0,0.4)}
.dash-banner{width:100%;height:100%;object-fit:cover;display:block}
.dash-banner-fallback{font-family:'Rajdhani',sans-serif;font-size:clamp(16px,4vw,24px);font-weight:700;color:var(--accent);letter-spacing:3px;text-align:center;padding:20px}

.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;margin-bottom:16px}
.info-card{background:var(--surface2);border:1px solid var(--border);border-radius:14px;padding:18px}
.info-label{font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--textmuted);margin-bottom:8px;font-weight:600}
.info-value{font-family:'Rajdhani',sans-serif;font-size:clamp(16px,3vw,22px);font-weight:700;color:var(--text);margin-bottom:12px;word-break:break-all;line-height:1.3}
.info-copy-btn{display:inline-flex;align-items:center;gap:6px;background:var(--surface3);border:1px solid var(--border);color:var(--accent);padding:7px 14px;border-radius:8px;font-size:12px;font-family:'Rajdhani',sans-serif;letter-spacing:1px;cursor:pointer;transition:all 0.2s;font-weight:600;touch-action:manipulation}
.info-copy-btn:hover{background:var(--accentglow);border-color:var(--accent)}

/* ── Table ── */
.table-wrap{overflow-x:auto;border-radius:12px;border:1px solid var(--border);-webkit-overflow-scrolling:touch}
table{width:100%;border-collapse:collapse;font-size:13px;min-width:520px}
thead th{background:var(--surface2);padding:12px 14px;text-align:left;font-family:'Rajdhani',sans-serif;font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--textmuted);border-bottom:1px solid var(--border);white-space:nowrap}
tbody td{padding:11px 14px;border-bottom:1px solid rgba(30,45,69,0.5);vertical-align:middle}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--surface2)}
.cord-text{font-family:monospace;font-size:11px;color:var(--accent2)}
.badge{display:inline-block;padding:3px 10px;border-radius:99px;font-size:11px;font-weight:600;font-family:'Rajdhani',sans-serif;letter-spacing:1px}
.badge-green{background:rgba(32,192,96,0.15);color:var(--green);border:1px solid rgba(32,192,96,0.3)}
.badge-blue{background:rgba(32,136,232,0.15);color:var(--blue);border:1px solid rgba(32,136,232,0.3)}

/* ── Set Form ── */
.set-card{background:var(--surface2);border:1px solid var(--border);border-radius:14px;padding:18px}
.set-title{font-family:'Rajdhani',sans-serif;font-size:14px;font-weight:700;color:var(--accent);letter-spacing:1px;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border)}
/* Input row stacks on small screens */
.input-row{display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:10px;margin-bottom:12px;align-items:flex-end}
.input-row .form-group{margin-bottom:0}
.prop-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}
.success-msg{background:rgba(32,192,96,0.1);border:1px solid var(--green);border-radius:8px;padding:10px 14px;font-size:13px;color:var(--green);margin-top:10px;display:none}
.success-msg.show{display:block}
.error-msg{background:rgba(232,48,48,0.1);border:1px solid var(--red);border-radius:8px;padding:10px 14px;font-size:13px;color:var(--red);margin-top:10px;display:none}
.error-msg.show{display:block}

/* ── Log ── */
.log-item{display:flex;align-items:flex-start;gap:10px;padding:12px 0;border-bottom:1px solid rgba(30,45,69,0.5);flex-wrap:wrap}
.log-item:last-child{border-bottom:none}
.log-user{font-family:'Rajdhani',sans-serif;font-size:13px;font-weight:700;color:var(--accent);min-width:110px;flex-shrink:0}
.log-action{font-size:13px;flex:1;color:var(--text);min-width:120px;word-break:break-word}
.log-date{font-size:11px;color:var(--textmuted);white-space:nowrap;flex-shrink:0}

/* ── Toast ── */
#toast{position:fixed;bottom:20px;right:16px;left:16px;max-width:340px;margin:0 auto;background:var(--surface3);border:1px solid var(--border);border-radius:12px;padding:13px 18px;font-size:13px;font-weight:600;box-shadow:0 8px 32px rgba(0,0,0,0.5);z-index:9999;transform:translateY(100px);opacity:0;transition:all 0.3s}
#toast.show{transform:translateY(0);opacity:1}
#toast.success{border-color:var(--green);color:var(--green)}
#toast.error{border-color:var(--red);color:var(--red)}

/* ── Overlay ── */
#sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:49;backdrop-filter:blur(2px)}
#sidebar-overlay.show{display:block}

/* ── Animations ── */
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.page.active{animation:fadeIn 0.25s ease}
@keyframes pulse{0%,100%{box-shadow:0 0 6px var(--green)}50%{box-shadow:0 0 12px var(--green)}}
.status-dot{animation:pulse 2s infinite}

@keyframes exportpulse{0%{width:15%}50%{width:85%}100%{width:15%}}

/* ── Scrollbar ── */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--surface)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:99px}
::-webkit-scrollbar-thumb:hover{background:var(--accent)}

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
  .page-title{font-size:20px;letter-spacing:1px}
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

/* Desktop large: wider sidebar option */
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
  var bar = document.getElementById('loading-bar');
  var text = document.getElementById('loading-text');
  var msgs = ['Initializing...','Connecting to database...','Loading modules...','Verifying session...','Ready!'];
  var pct = 0, i = 0;
  var iv = setInterval(function() {
    pct += Math.random() * 22 + 8;
    if (pct > 100) pct = 100;
    bar.style.width = pct + '%';
    if (i < msgs.length) text.textContent = msgs[i++];
    if (pct >= 100) {
      clearInterval(iv);
      setTimeout(function() {
        document.getElementById('loading-screen').classList.add('hidden');
        checkAuth();
      }, 400);
    }
  }, 280);
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
var pageTitles = {dashboard:'Dashboard',getcord:'Getcord List',set:'Set Menu',adminlog:'Admin Log',backup:'Backup Database'};

function showPage(name) {
  // Inject backup template on first use
  if (name === 'backup' && !document.getElementById('page-backup')) {
    var tpl = document.getElementById('tpl-backup');
    var node = tpl.content.cloneNode(true);
    document.getElementById('content').appendChild(node);
  }
  document.querySelectorAll('.page').forEach(function(p) { p.classList.remove('active'); });
  document.querySelectorAll('.nav-item').forEach(function(n) { n.classList.remove('active'); });
  document.getElementById('page-'+name).classList.add('active');
  document.getElementById('page-title').textContent = pageTitles[name] || name;
  var navItems = document.querySelectorAll('.nav-item');
  var idx = {dashboard:0,getcord:1,set:2,adminlog:3,backup:4};
  if (navItems[idx[name]]) navItems[idx[name]].classList.add('active');
  // Close drawer on mobile after nav
  if (isDrawerMode() && sidebarOpen) {
    sidebarOpen = false;
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('sidebar-overlay').classList.remove('show');
  }
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
        html += '<div style="background:rgba(232,160,32,0.1);border:1px solid rgba(232,160,32,0.3);border-radius:8px;padding:6px 10px;font-size:11px;color:var(--accent);min-width:80px;text-align:center">'+
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
	initDB()

	mux := http.NewServeMux()

	// Static files: icon folder
	mux.Handle("/icon/", http.StripPrefix("/icon/", http.FileServer(http.Dir("icon"))))

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
	mux.HandleFunc("/api/set/gun", authMiddleware(handleSetGun))
	mux.HandleFunc("/api/get-gun-slots", authMiddleware(handleGetGunSlots))
	mux.HandleFunc("/api/admin-log", authMiddleware(handleAdminLog))
	mux.HandleFunc("/api/backup/export", authMiddleware(handleBackupExport))

	port := getEnv("PORT", "8080")
	addr := ":" + port
	log.Printf("Dewata Nation RP Admin Panel running on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
