package main

import (
    "fmt"
    "net/http"
    "log"
    "strings"
    "crypto/rand"
)

// no authentication for the following requests 
func whiteList(url string) bool {
	
	switch url[1:] {
		case
			"logon.htm",
			"invalid.htm",
			"logo.gif",
			"styles.css",
			"run.gif":
			return true
	}
	return false
}

func handler(w http.ResponseWriter, r *http.Request) {
	
	// Only set no cache when testing locally
	//w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Server", "Intel(R) Active Management Technology 9.1.33")

	p := r.URL.Path

	// AMT will redirect on /
	if p == "/" {
		http.Redirect(w, r, "logon.htm", 301)
	}
	
	// trailing filename in URL
	content := p[1:]

	// don't do auth for some resources
	if whiteList(p) == false {
		if doAuth(w, r) == false {
			content = "invalid.htm"
		}
	} 
	
	http.ServeFile(w, r, "static/" + content)
}

func parseAuthHeader(r *http.Request) map[string]string {
	
	auth := make(map[string]string)
	h := r.Header.Get("Authorization")

	if len(h) > 0 {
		s := strings.Split(h, ",")
		// neaten things up
		for _, v := range(s) {
			z := strings.Split(v, "=")
			z0 := strings.Trim(z[0], "\" ")
			z1 := strings.Trim(z[1], "\" ")
			auth[z0] = z1
		}
	}
	return auth
}

func doAuth(w http.ResponseWriter, r *http.Request) bool {

	auth := parseAuthHeader(r)
	
	// user is admin, response is null someone is doing something naughty!
	if auth["Digest username"] == "admin" && auth["response"] == "" {
		return true
	}

	// appears to be static?
	digest := "C90B0000000000000000000000000000"

	b := make([]byte, 32)
	rand.Read(b)
	nonce := fmt.Sprintf("%x", b)[:32]

	w.Header().Set("WWW-Authenticate", "Kerberos")
	w.Header().Set("WWW-Authenticate", "Negotiate")
	w.Header().Set("WWW-Authenticate", "Digest realm=\"Digest:" + digest + "\", nonce=\"" + nonce +   "\",stale=\"false\",qop=\"auth\"")
	
	// need to be explicit otherwise WriteHeader will override content type
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(401)
	return false

}

// Log address, http method, URL, username and if the response header item was set to null which would indicate 
// the known vulnerability was being used
func Log(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := parseAuthHeader(r)
		if authHeader["response"] == "" {
			authHeader["response"] = "empty"
		}
		log.Println(r.RemoteAddr, r.Method, r.URL, authHeader["Digest username"], authHeader["response"])
		handler.ServeHTTP(w, r)
	})
}

func main() {
    http.HandleFunc("/", handler) 
    http.ListenAndServe(":16992", Log(http.DefaultServeMux))
} 
