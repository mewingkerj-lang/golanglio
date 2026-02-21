package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

func main() {

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// ENV DATABASE (SET DI RAILWAY)
	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		dsn = "root:password@tcp(127.0.0.1:3306)/dewata"
	}

	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", loginPage)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/adminkey", adminKeyHandler)
	http.HandleFunc("/dashboard", dashboardHandler)

	fmt.Println("Running on :" + port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func md5hash(text string) string {
	hash := md5.Sum([]byte(text))
	return strings.ToLower(hex.EncodeToString(hash[:]))
}

func hashit(salt, password string) string {
	step3 := md5hash(salt) + md5hash(password)
	step3 = strings.ToLower(step3)
	step4 := md5hash(step3)
	return strings.ToLower(step4)
}

/* ================= LOGIN ================= */

func loginPage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, loginHTML())
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	username := r.FormValue("username")
	password := r.FormValue("password")

	var dbPass, salt string
	err := db.QueryRow("SELECT pPassword, pass_salt FROM accounts WHERE pName=?", username).Scan(&dbPass, &salt)

	if err != nil {
		fmt.Fprint(w, "User tidak ditemukan")
		return
	}

	if hashit(salt, password) != dbPass {
		fmt.Fprint(w, "Password salah")
		return
	}

	http.SetCookie(w, &http.Cookie{Name: "user", Value: username})
	fmt.Fprint(w, adminKeyHTML())
}

/* ================= ADMIN KEY ================= */

func adminKeyHandler(w http.ResponseWriter, r *http.Request) {

	cookie, _ := r.Cookie("user")
	username := cookie.Value
	key := r.FormValue("adminkey")

	var dbKey string
	err := db.QueryRow("SELECT pAdminKey FROM admin WHERE Name=?", username).Scan(&dbKey)

	if err != nil || key != dbKey {
		fmt.Fprint(w, "Admin key salah")
		return
	}

	http.Redirect(w, r, "/dashboard", 302)
}

/* ================= DASHBOARD ================= */

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, dashboardHTML())
}

/* ================= HTML ================= */

func loginHTML() string {
	return `
<!DOCTYPE html>
<html>
<head>
<title>DewataNation Admin</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{margin:0;font-family:Arial;background:#0f172a;color:white;display:flex;justify-content:center;align-items:center;height:100vh}
.card{background:#1e293b;padding:30px;border-radius:10px;width:90%;max-width:400px}
input{width:100%;padding:10px;margin:10px 0;border:none;border-radius:5px}
button{width:100%;padding:10px;background:#06b6d4;border:none;color:white;border-radius:5px;cursor:pointer}
img{width:100%;margin-bottom:15px;border-radius:8px}
</style>
</head>
<body>
<div class="card">
<img src="https://logo-dewata-nationrp.edgeone.app/IMG-20260131-WA0425.jpg">
<h3>Login Panel</h3>
<form method="POST" action="/login">
<input name="username" placeholder="Username">
<input name="password" type="password" placeholder="Password">
<button>Login</button>
</form>
</div>
</body>
</html>`
}

func adminKeyHTML() string {
	return `
<!DOCTYPE html>
<html>
<head>
<style>
body{background:#0f172a;color:white;font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh}
.card{background:#1e293b;padding:30px;border-radius:10px;width:90%;max-width:400px}
input,button{width:100%;padding:10px;margin:10px 0;border:none;border-radius:5px}
button{background:#22c55e;color:white}
</style>
</head>
<body>
<div class="card">
<h3>Input Admin Key</h3>
<form method="POST" action="/adminkey">
<input name="adminkey" placeholder="Admin Key">
<button>Verify</button>
</form>
</div>
</body>
</html>`
}

func dashboardHTML() string {
	return `
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{margin:0;font-family:Arial;background:#0f172a;color:white}
.sidebar{width:250px;background:#1e293b;height:100vh;position:fixed;left:-250px;transition:0.3s;padding-top:60px}
.sidebar a{display:block;padding:15px;color:white;text-decoration:none}
.sidebar a:hover{background:#334155}
.open{left:0}
.content{margin-left:20px;padding:20px}
.topbar{background:#1e293b;padding:15px}
button{padding:8px 12px;background:#06b6d4;border:none;color:white;border-radius:5px;cursor:pointer}
</style>
<script>
function toggleSidebar(){
document.getElementById("sidebar").classList.toggle("open");
}
function copyText(text){
navigator.clipboard.writeText(text);
alert("Copied: "+text);
}
</script>
</head>
<body>

<div class="topbar">
<button onclick="toggleSidebar()">☰</button>
DewataNation Admin Panel
</div>

<div id="sidebar" class="sidebar">
<a href="#">Dashboard</a>
<a href="#">Getcord List</a>
<a href="#">Set Menu</a>
<a href="#">Admin Log View</a>
</div>

<div class="content">
<h2>Dashboard</h2>
<p>Selamat datang di Admin Control Panel DewataNation Roleplay</p>

<p>Server IP:</p>
<button onclick="copyText('208.84.103.75:7103')">208.84.103.75:7103</button>

<p>WhatsApp:</p>
<button onclick="copyText('https://chat.whatsapp.com/GQ1V4a5ieKbHiXZLxqQx99')">
Copy WhatsApp Link
</button>

</div>

</body>
</html>`
}
