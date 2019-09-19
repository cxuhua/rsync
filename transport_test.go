package rsync

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
	"time"
)

type x struct {
}

var i = 0

func (s *x) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	i++
	res.Write([]byte(fmt.Sprintf("%s do=%d", req.URL.Path, i)))
}

func TestHttp2(t *testing.T) {
	server := &http.Server{
		Addr:    ":443",
		Handler: &x{},
	}
	go func() {

		tr := http.Transport{
			MaxIdleConns:        5,
			MaxIdleConnsPerHost: 2,
			MaxConnsPerHost:     5,
			IdleConnTimeout:     time.Second * 20,
		}
		c := http.Client{
			Transport: &tr,
		}
		//ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		//defer cancel()
		//req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.xginx.com/", nil)
		//req, err := http.NewRequest(http.MethodGet, "https://www.xginx.com/", nil)
		//if err != nil {
		//	panic(err)
		//}

		for {
			res, err := c.Get("https://www.xginx.com/")
			if err != nil {
				panic(err)
			}
			x, err := ioutil.ReadAll(res.Body)
			if err != nil {
				panic(err)
			}
			log.Println(string(x))
			time.Sleep(time.Second)
		}
	}()
	if err := server.ListenAndServeTLS("keys/www.xginx.com.pem", "keys/www.xginx.com.key"); err != nil {
		panic(err)
	}
}
