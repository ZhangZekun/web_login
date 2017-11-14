package main
import (
        "io/ioutil"
        "log"
        "net/http"
        "os"
        "strings"
)

func staticResource(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.LastIndex(path, ".") != -1 {				//如果Ｐａｔｈ中有.XXX的文件请求
			request_type := path[strings.LastIndex(path, "."):]
			switch request_type {
			case ".css":
					w.Header().Set("content-type", "text/css")
			case ".js":
					w.Header().Set("content-type", "text/javascript")
			default:
			}
		}
		var newPath string
		if path == "/" || path == "/index.html" {
			w.Header().Set("content-type", "text/html")
			newPath = "./index.html"
		} else {
			newPath = "." + path
		}
        fin, err := os.Open(newPath)
        defer fin.Close()
        if err != nil {
                log.Fatal("static resource:", err)
        } 
        fd, _ := ioutil.ReadAll(fin)
        w.Write(fd)
}


func logIn(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if r.Form["username"][0] == "aaa" && r.Form["password"][0] == "bbb" {
		w.Write([]byte("您成功登录了　"))
	} else {
		w.Write([]byte("账号/密码错误"))
	}
}

func main() {
	http.HandleFunc("/", staticResource)
	http.HandleFunc("/login", logIn)
        err := http.ListenAndServe(":8080", nil)
        if err != nil {
                log.Fatal("ListenAndServe:", err)
        } 
}