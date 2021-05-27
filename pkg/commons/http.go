package commons

import (
	"io"
	"net/http"
	"net/http/httputil"
	"os"
	"time"
)

func SetCookie(w http.ResponseWriter, name, value string, validHours time.Duration) {

	ck := http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
		SameSite: http.SameSiteDefaultMode,
		Path:     "/",
		Expires:  time.Now().Add(validHours * time.Hour),
	}
	http.SetCookie(w, &ck)
}

func OutputHTML(w http.ResponseWriter, req *http.Request, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer file.Close()
	fi, _ := file.Stat()
	http.ServeContent(w, req, file.Name(), fi.ModTime(), file)
	// http.ServeContent(w, req, file.Name(), time.Now(), file)
}

func DumpRequest(writer io.Writer, header string, r *http.Request) error {
	data, err := httputil.DumpRequest(r, true)
	if err != nil {
		return err
	}
	writer.Write([]byte("\n" + header + ": \n"))
	writer.Write(data)
	return nil
}
