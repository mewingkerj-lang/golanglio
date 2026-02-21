package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", homeHandler)

	fmt.Println("Server running on port:", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {

	html := `
<!DOCTYPE html>
<html>
<head>
<title>Renzy - Backend Developer</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body {
	margin: 0;
	font-family: Arial, sans-serif;
	background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
	color: white;
	text-align: center;
}
.container { padding: 50px 20px; }
.card {
	background: rgba(255,255,255,0.1);
	backdrop-filter: blur(10px);
	border-radius: 15px;
	padding: 30px;
	margin: 20px auto;
	max-width: 500px;
	box-shadow: 0 0 20px rgba(0,0,0,0.5);
}
h1 { font-size: 40px; margin-bottom: 10px; }
h2 { color: #00d9ff; }
.skills span {
	display: inline-block;
	background: #00d9ff;
	color: black;
	padding: 8px 15px;
	border-radius: 20px;
	margin: 5px;
	font-weight: bold;
}
footer {
	margin-top: 40px;
	color: #ccc;
	font-size: 14px;
}
</style>
</head>
<body>
<div class="container">
<h1>Renzy</h1>
<h2>Backend Developer</h2>

<div class="card">
	<h3>Skills</h3>
	<div class="skills">
		<span>Golang</span>
		<span>TypeScript</span>
		<span>PHP</span>
		<span>Python</span>
		<span>JavaScript</span>
	</div>
</div>

<div class="card">
	<h3>About Me</h3>
	<p>I build scalable APIs, authentication systems, and modern backend architectures.</p>
</div>

<footer>
© 2026 Renzy Backend Dev
</footer>

</div>
</body>
</html>
`
	fmt.Fprint(w, html)
}
