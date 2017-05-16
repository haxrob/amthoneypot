package main

import (
    "fmt"
    "github.com/sevlyar/go-daemon"
    "flag"
    "syscall"
    "net/http"
    "net/http/httputil"
    "log"
    "strings"
    "crypto/rand"
    "os"
    "time"
)

var (
	signal = flag.String("s", "", `send signal to the daemon
		quit — graceful shutdown
		stop — fast shutdown
		reload — reloading the configuration file`)
)

func main() {
	flag.Parse()
	daemon.AddCommand(daemon.StringFlag(signal, "quit"), syscall.SIGQUIT, termHandler)
	daemon.AddCommand(daemon.StringFlag(signal, "stop"), syscall.SIGTERM, termHandler)
	daemon.AddCommand(daemon.StringFlag(signal, "reload"), syscall.SIGHUP, reloadHandler)

	cntxt := &daemon.Context{
		PidFileName: "pid",
		PidFilePerm: 0644,
		LogFileName: "log",
		LogFilePerm: 0640,
		WorkDir:     "./",
		Umask:       027,
		Args:        []string{"[go-daemon sample]"},
	}

	if len(daemon.ActiveFlags()) > 0 {
		d, err := cntxt.Search()
		if err != nil {
			log.Fatalln("Unable send signal to the daemon:", err)
		}
		daemon.SendCommands(d)
		return
	}

	d, err := cntxt.Reborn()
	if err != nil {
		log.Fatalln(err)
	}
	if d != nil {
		return
	}
	defer cntxt.Release()

	log.Println("- - - - - - - - - - - - - - -")
	log.Println("daemon started")

	go worker()

	err = daemon.ServeSignals()
	if err != nil {
		log.Println("Error:", err)
	}
	log.Println("daemon terminated")
}

var (
	stop = make(chan struct{})
	done = make(chan struct{})
)

func worker() {
	for {
		time.Sleep(time.Second)
		if _, ok := <-stop; ok {
			break
		}
	}
	done <- struct{}{}
}

func termHandler(sig os.Signal) error {
	log.Println("terminating...")
	stop <- struct{}{}
	if sig == syscall.SIGQUIT {
		<-done
	}
	return daemon.ErrStop
}

func reloadHandler(sig os.Signal) error {
	log.Println("configuration reloaded")
	return nil
}

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
	
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Server", "Intel(R) Active Management Technology 9.1.34")

	p := r.URL.Path

	// AMT will redirect on /
	if p == "/" {
		http.Redirect(w, r, "logon.htm", 301)
	}

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

	digest := "C10000000000000000000000000000"

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

func Log(handler http.Handler, logFile string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		//log.Println(r.RemoteAddr, r.Method, r.URL)
		rAddress := "Remote:" + r.RemoteAddr

		t := time.Now().Format(time.RFC850)

		dump, err := httputil.DumpRequest(r, false)

		if err == nil {
			
			entry := fmt.Sprintf("%s\n%s\n%s", t, rAddress, dump)

			f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Println("error ", err)
			}
			defer f.Close()

			_, err = f.WriteString(entry)
			if err != nil {
				log.Println("error writing: ", err)
			}

		}

		handler.ServeHTTP(w, r)
	})
}

func serve() {
	if len(os.Args) != 2 {
		fmt.Println("usage: ./server <log file>")
		os.Exit(1)
	}

	logFile := os.Args[1]

    http.HandleFunc("/", handler) 
    http.ListenAndServe(":16992", Log(http.DefaultServeMux, logFile))
} 
