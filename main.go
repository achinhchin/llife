package main

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var cfg struct {
	Port   int    `json:"port"`
	Domain string `json:"domain"`
	Hash   string `json:"hash"`
	Secret string `json:"secret"`
}

const life = 30 * 24 * time.Hour

var (
	mu    sync.Mutex
	fails int
	lock  time.Time
)

func save() {
	b, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile("settings.json", b, 0600)
}

func rnd(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

func kdf(p string, salt []byte) []byte {
	k, _ := pbkdf2.Key(sha256.New, p, salt, 600000, 32)
	return k
}

func sign(exp string) string {
	m := hmac.New(sha256.New, []byte(cfg.Secret))
	m.Write([]byte(exp))
	return exp + "." + hex.EncodeToString(m.Sum(nil))
}

func authed(r *http.Request) bool {
	c, err := r.Cookie("llife")
	if err != nil {
		return false
	}
	e, _, ok := strings.Cut(c.Value, ".")
	t, _ := strconv.ParseInt(e, 10, 64)
	return ok && t > time.Now().Unix() && hmac.Equal([]byte(c.Value), []byte(sign(e)))
}

func check(p string) bool {
	s, h, ok := strings.Cut(cfg.Hash, "$")
	salt, _ := hex.DecodeString(s)
	want, _ := hex.DecodeString(h)
	return ok && subtle.ConstantTimeCompare(kdf(p, salt), want) == 1
}

func safe(n string) string {
	u, err := url.Parse(n)
	if err != nil || n == "" || cfg.Domain == "" {
		return "/"
	}
	d := strings.TrimPrefix(cfg.Domain, ".")
	if (u.Scheme == "https" || u.Scheme == "http") && (u.Hostname() == d || strings.HasSuffix(u.Hostname(), "."+d)) {
		return n
	}
	return "/"
}

func cookie(r *http.Request, v string, age int) *http.Cookie {
	c := &http.Cookie{Name: "llife", Value: v, Path: "/", MaxAge: age, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"}
	if cfg.Domain != "" && strings.HasSuffix(strings.Split(r.Host, ":")[0], strings.TrimPrefix(cfg.Domain, ".")) {
		c.Domain = cfg.Domain
	}
	return c
}

func main() {
	pass := flag.String("pass", "", "set passcode")
	flag.Parse()
	if b, err := os.ReadFile("settings.json"); err == nil {
		json.Unmarshal(b, &cfg)
	}
	if cfg.Port == 0 {
		cfg.Port = 1235
	}
	if cfg.Secret == "" {
		cfg.Secret = hex.EncodeToString(rnd(32))
		save()
	}
	if *pass != "" {
		salt := rnd(16)
		cfg.Hash = hex.EncodeToString(salt) + "$" + hex.EncodeToString(kdf(*pass, salt))
		save()
		fmt.Println("passcode set")
		return
	}
	if cfg.Hash == "" {
		log.Fatal("no passcode: run ./llife -pass <code>")
	}
	fs := http.FileServer(http.Dir("web"))
	http.HandleFunc("GET /api/check", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if authed(r) {
			w.WriteHeader(204)
		} else {
			w.WriteHeader(401)
		}
	})
	http.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		n := safe(r.FormValue("next"))
		mu.Lock()
		locked := time.Now().Before(lock)
		mu.Unlock()
		ok := !locked && check(r.FormValue("code"))
		mu.Lock()
		if ok {
			fails = 0
		} else if !locked {
			if fails++; fails >= 5 {
				fails, lock = 0, time.Now().Add(15*time.Minute)
			}
		}
		mu.Unlock()
		if !ok {
			http.Redirect(w, r, "/?e=1&next="+url.QueryEscape(n), 303)
			return
		}
		http.SetCookie(w, cookie(r, sign(strconv.FormatInt(time.Now().Add(life).Unix(), 10)), int(life.Seconds())))
		http.Redirect(w, r, n, 303)
	})
	http.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, cookie(r, "", -1))
		http.Redirect(w, r, "/", 303)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if authed(r) || r.URL.Path == "/style.css" {
			fs.ServeHTTP(w, r)
		} else {
			http.ServeFile(w, r, "web/login.html")
		}
	})
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", cfg.Port), nil))
}
