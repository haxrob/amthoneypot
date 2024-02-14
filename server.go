package main

import (
    "crypto/rand"
    "fmt"
    "log"
    "net/http"
    "net/http/httputil"
    "os"
    "strings"
    "time"
    color "github.com/TwiN/go-color"
)

func whiteList(url string) bool {
    switch url[1:] {
    case "logon.htm", "invalid.htm", "logo.gif", "styles.css", "run.gif":
        return true
    }
    return false
}

func parseAuthHeader(r *http.Request) map[string]string {
    auth := make(map[string]string)
    h := r.Header.Get("Authorization")
    if len(h) > 0 {
        s := strings.Split(h, ",")
        for _, v := range s {
            z := strings.Split(v, "=")
            z0 := strings.Trim(z[0], "\" ")
            z1 := strings.Trim(z[1], "\" ")
            auth[z0] = z1
        }
    }
    return auth
}

func doAuth(w http.ResponseWriter, r *http.Request) (bool, bool) {
    auth := parseAuthHeader(r)
    fmt.Println(color.Ize(color.Blue, "Login attempt: "), r.RemoteAddr)
    fmt.Println(color.Ize(color.Blue, "Credentials: "), auth)
    
    if auth["Digest username"] == "admin" && auth["response"] == "" {
        return true, false
    }

    digest := "C10000000000000000000000000000"
    b := make([]byte, 32)
    rand.Read(b)
    nonce := fmt.Sprintf("%x", b)[:32]

    w.Header().Set("WWW-Authenticate", `Digest realm="Digest:`+digest+`", nonce="`+nonce+`", stale="false", qop="auth"`)
    w.WriteHeader(http.StatusUnauthorized)
    return false, true
}

func handler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Server", "Intel(R) Active Management Technology 9.1.34")

    p := r.URL.Path
    if p == "/" {
        http.Redirect(w, r, "logon.htm", 301)
        return 
    }

    content := p[1:]
    if !whiteList(p) {
        authSuccess, responseWritten := doAuth(w, r)
        if !authSuccess {
            if !responseWritten {
                http.ServeFile(w, r, "static/invalid.htm")
            }
            return 
        }
    }

    http.ServeFile(w, r, "static/"+content)
}

func Log(handler http.Handler, logFile string) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        rAddress := color.Ize(color.Yellow, "Remote:"+r.RemoteAddr)
        t := time.Now().Format(time.RFC850)
        dump, err := httputil.DumpRequest(r, false)
        if err == nil {
            entry := fmt.Sprintf("%s\n%s\n%s", t, rAddress, dump)
            f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
            if err != nil {
                log.Println(color.Ize(color.Red, "error opening log file:"), err)
            }
            defer f.Close()

            _, err = f.WriteString(entry)
            if err != nil {
                log.Println(color.Ize(color.Red, "error writing to log file:"), err)
            }
        }
        handler.ServeHTTP(w, r)
    })
}

func main() {
    logFile := "amthoneypot.log"
    if len(os.Args) > 1 {
        logFile = os.Args[1]
    }

    port := ":16992"
    fmt.Println(color.Ize(color.Green, "Starting server on port"+port))

    http.HandleFunc("/", handler)
    err := http.ListenAndServe(port, Log(http.DefaultServeMux, logFile))
    if err != nil {
        log.Fatal(color.Ize(color.Red, "Server failed to start:"), err)
    }
}
