# net/http包分析：追溯到socket

[TOC]

## 完整的代码

~~~go
package main

import (
    "fmt"
    "net/http"
    "strings"
    "log"
)

func sayhelloName(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()  //解析参数，默认是不会解析的
    fmt.Println(r.Form)  //这些信息是输出到服务器端的打印信息
    fmt.Println("path", r.URL.Path)
    fmt.Println("scheme", r.URL.Scheme)
    fmt.Println(r.Form["url_long"])
    for k, v := range r.Form {
        fmt.Println("key:", k)
        fmt.Println("val:", strings.Join(v, ""))
    }
    fmt.Fprintf(w, "Hello astaxie!") //这个写入到w的是输出到客户端的
}

func main() {
    http.HandleFunc("/", sayhelloName)       //设置访问的路由
    err := http.ListenAndServe(":9090", nil) //设置监听的端口
    if err != nil {
        log.Fatal("ListenAndServe: ", err)
    }
}
~~~

## 分析 http.HandleFunc("/", sayhelloName)

### 1.综述

这一个语句的主要作用是注册路由信息到一个默认的路由DefaultServeMux，即将“/”和对应的处理函数sayhelloName进行注册。DefaultServeMux是ServeMux的一个实例，这个类用于存储特定路由和对应的处理函数，在对HTTP请求进行分析时，遍历ServerMux中所有路由信息，找到对应的处理函数进行处理。

~~~go
type ServeMux struct {
	mu    sync.RWMutex
	m     map[string]muxEntry
	hosts bool // whether any patterns contain hostnames
}

type muxEntry struct {
	explicit bool
	h        Handler
	pattern  string
}
~~~

### 2.逐步跳转分析

~~~go
//点击http.HandleFunc("/", sayhelloName)跳转
//该函数用默认的ServerMux实例DefaultServeMux去处理
func HandleFunc(pattern string, handler func(ResponseWriter, *Request)) {
	DefaultServeMux.HandleFunc(pattern, handler)
}
~~~

~~~go
//点击上面的HandleFunc函数跳转
//ServerMux的方法HandleFunc，注意到HandlerFunc(handler)，这是将一个fun类型转为Handler类型
//因为只有转为Handler类型，并能在Handler上实现serverHttp()
func (mux *ServeMux) HandleFunc(pattern string, handler func(ResponseWriter, *Request)) {
	mux.Handle(pattern, HandlerFunc(handler))
}

//此处为额外信息
type HandlerFunc func(ResponseWriter, *Request)

// ServeHTTP calls f(w, r).
func (f HandlerFunc) ServeHTTP(w ResponseWriter, r *Request) {
	f(w, r)
}
~~~

~~~go
//点击上面的mux.Handle进行跳转
//此函数就是将一个pattern（路由信息）和对应Handler（处理函数）存储到路由总表上。
//关键是mux.m[pattern] = muxEntry{explicit: true, h: handler, pattern: pattern}
func (mux *ServeMux) Handle(pattern string, handler Handler) {
	mux.mu.Lock()
	defer mux.mu.Unlock()

	if pattern == "" {
		panic("http: invalid pattern " + pattern)
	}
	if handler == nil {
		panic("http: nil handler")
	}
	if mux.m[pattern].explicit {
		panic("http: multiple registrations for " + pattern)
	}

	mux.m[pattern] = muxEntry{explicit: true, h: handler, pattern: pattern}
}
~~~

## 分析err := http.ListenAndServe(":9090", nil) 

### 1.综述

该函数主要作用就是通过新建一个TCPListener，监听9090端口。当有请求发送到服务器时，新建一个连接net.conn，每个连接都用一个routine进行处理，实现并行处理多个TCP连接。具体分析过程分为两个步骤：

* Listen
* serve

~~~go
//该函数新建了一个Server实例，其Addr变量为端口值，即":8080", Handler变量为nil（nil表示我们将使用上文提到的默认路由DefaultMux，具体为什么是这样，下文会提到）
func ListenAndServe(addr string, handler Handler) error {
	server := &Server{Addr: addr, Handler: handler}
	return server.ListenAndServe()
}
~~~

~~~go
//点击ListenAndServe()跳转
//这里的代码结构很清晰，主要有两行比较重要
//ln, err := net.Listen("tcp", addr) 指明使用TCP协议，监听8080端口，返回一个TCPListener(该类具体作用下文会提到)
//srv.Serve(tcpKeepAliveListener{ln.(*net.TCPListener)}) 服务器对一个TCPListener进行服务
//下面重点分析这两行
func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.Serve(tcpKeepAliveListener{ln.(*net.TCPListener)})
}
~~~

### 分析ln, err := net.Listen("tcp", addr)

#### 1.综述

指明使用TCP协议，监听8080端口，返回一个TCPListener

#### 2.逐步跳转分析

~~~go
//点击跳转
//resolveAddrList("listen", net, laddr, noDeadline)返回一个Addr列表
//switch la := addrs.first(isIPv4).(type) 找出Addr中第一个用IPv4的Addr，根据Addr类型，创建一个对应的Listener。
//重点看一下l, err = ListenTCP(net, la)，因为这个会涉及到更底层的东西
func Listen(net, laddr string) (Listener, error) {
	addrs, err := resolveAddrList("listen", net, laddr, noDeadline)
	if err != nil {
		return nil, &OpError{Op: "listen", Net: net, Source: nil, Addr: nil, Err: err}
	}
	var l Listener
	switch la := addrs.first(isIPv4).(type) {
	case *TCPAddr:
		l, err = ListenTCP(net, la)
	case *UnixAddr:
		l, err = ListenUnix(net, la)
	default:
		return nil, &OpError{Op: "listen", Net: net, Source: nil, Addr: la, Err: &AddrError{Err: "unexpected address type", Addr: laddr}}
	}
	if err != nil {
		return nil, err // l is non-nil interface containing nil pointer
	}
	return l, nil
}

//辅助信息，TCPAddr类型，它实现了Addr类型的接口，具体就不贴出来。
type TCPAddr struct {
	IP   IP
	Port int
	Zone string // IPv6 scoped addressing zone
}
~~~

~~~go
//点击上文的l, err = ListenTCP(net, la)，跳转到这里。
//这里就是根据net(即“TCP”)以及TCPAddr（包含有IP和Port）,来创建一个"文件描述单元"。将该“文件描述单元”作为TCPListener的变量。（这个和socket有很大关系，但没接触过网络编程，暂时还不太清楚）
//重点研究fd, err := internetSocket(net, laddr, nil, noDeadline, syscall.SOCK_STREAM, 0, "listen", noCancel)
func ListenTCP(net string, laddr *TCPAddr) (*TCPListener, error) {
	switch net {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, &OpError{Op: "listen", Net: net, Source: nil, Addr: laddr.opAddr(), Err: UnknownNetworkError(net)}
	}
	if laddr == nil {
		laddr = &TCPAddr{}
	}
	fd, err := internetSocket(net, laddr, nil, noDeadline, syscall.SOCK_STREAM, 0, "listen", noCancel)
	if err != nil {
		return nil, &OpError{Op: "listen", Net: net, Source: nil, Addr: laddr, Err: err}
	}
	return &TCPListener{fd}, nil
}
~~~

~~~go
// Internet sockets (TCP, UDP, IP)
//这里调用socket函数返回一个netDF变量，即文件描述单元
func internetSocket(net string, laddr, raddr sockaddr, deadline time.Time, sotype, proto int, mode string, cancel <-chan struct{}) (fd *netFD, err error) {
	family, ipv6only := favoriteAddrFamily(net, laddr, raddr, mode)
	return socket(net, family, sotype, proto, ipv6only, laddr, raddr, deadline, cancel)
}
~~~

~~~go
//查看socket函数
//此处有大量关于socket的代码，我暂时还不懂0 0.不过目测大致意思就是创建一个socket，这个socket与netFD变量有很大关系0 0.
//TCPListener要利用到这个socket来获取请求。

// socket returns a network file descriptor that is ready for
// asynchronous I/O using the network poller.
func socket(net string, family, sotype, proto int, ipv6only bool, laddr, raddr sockaddr, deadline time.Time, cancel <-chan struct{}) (fd *netFD, err error) {
	s, err := sysSocket(family, sotype, proto)
	if err != nil {
		return nil, err
	}
	if err = setDefaultSockopts(s, family, sotype, ipv6only); err != nil {
		closeFunc(s)
		return nil, err
	}
	if fd, err = newFD(s, family, sotype, net); err != nil {
		closeFunc(s)
		return nil, err
	}

	// This function makes a network file descriptor for the
	// following applications:
	//
	// - An endpoint holder that opens a passive stream
	//   connection, known as a stream listener
	//
	// - An endpoint holder that opens a destination-unspecific
	//   datagram connection, known as a datagram listener
	//
	// - An endpoint holder that opens an active stream or a
	//   destination-specific datagram connection, known as a
	//   dialer
	//
	// - An endpoint holder that opens the other connection, such
	//   as talking to the protocol stack inside the kernel
	//
	// For stream and datagram listeners, they will only require
	// named sockets, so we can assume that it's just a request
	// from stream or datagram listeners when laddr is not nil but
	// raddr is nil. Otherwise we assume it's just for dialers or
	// the other connection holders.

	if laddr != nil && raddr == nil {
		switch sotype {
		case syscall.SOCK_STREAM, syscall.SOCK_SEQPACKET:
			if err := fd.listenStream(laddr, listenerBacklog); err != nil {
				fd.Close()
				return nil, err
			}
			return fd, nil
		case syscall.SOCK_DGRAM:
			if err := fd.listenDatagram(laddr); err != nil {
				fd.Close()
				return nil, err
			}
			return fd, nil
		}
	}
	if err := fd.dial(laddr, raddr, deadline, cancel); err != nil {
		fd.Close()
		return nil, err
	}
	return fd, nil
}
~~~

### 分析srv.Serve()

#### 1.综述

srv.Serve(tcpKeepAliveListener{ln.(*net.TCPListener)}) ，服务器对一个TCPListener进行服务。可同时服务多个客户的请求。

#### 2.逐步跳转分析

~~~go
// Serve accepts incoming connections on the Listener l, creating a
// new service goroutine for each. The service goroutines read requests and
// then call srv.Handler to reply to them.
// Serve always returns a non-nil error.

//这里用一个for循环，可以不断接受客户的请求
//rw, e := l.Accept() rw是net.Conn类型，表示一个连接，有Read和Write方法。
//c := srv.newConn(rw) 将连接rw和服务器server封装在一起，构成conn变量c
//go c.serve() 运用routine对该连接进行服务。因为采用go routine，所以可以重新开始循环，接受其他请求。类似于在一个线程中跑c.serve()
//重点研究一下c.serve()
func (srv *Server) Serve(l net.Listener) error {
	defer l.Close()
	if fn := testHookServerServe; fn != nil {
		fn(srv, l)
	}
	var tempDelay time.Duration // how long to sleep on accept failure
	if err := srv.setupHTTP2(); err != nil {
		return err
	}
	for {
		rw, e := l.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				srv.logf("http: Accept error: %v; retrying in %v", e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return e
		}
		tempDelay = 0
		c := srv.newConn(rw)
		c.setState(c.rwc, StateNew) // before Serve can return
		go c.serve()
	}
}


//辅助信息
// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
~~~

~~~go
// Serve a new connection.
//在一个for循环里面处理该连接的所有请求，在一次循环中，获得一个req和一个w(即response)。
//重点是serverHandler{c.server}.ServeHTTP(w, w.req)， 用于处理这一次请求。
//即调用serverHandler.serveHTTP
func (c *conn) serve() {
	c.remoteAddr = c.rwc.RemoteAddr().String()
	defer func() {
		if err := recover(); err != nil {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			c.server.logf("http: panic serving %v: %v\n%s", c.remoteAddr, err, buf)
		}
		if !c.hijacked() {
			c.close()
			c.setState(c.rwc, StateClosed)
		}
	}()

	if tlsConn, ok := c.rwc.(*tls.Conn); ok {
		if d := c.server.ReadTimeout; d != 0 {
			c.rwc.SetReadDeadline(time.Now().Add(d))
		}
		if d := c.server.WriteTimeout; d != 0 {
			c.rwc.SetWriteDeadline(time.Now().Add(d))
		}
		if err := tlsConn.Handshake(); err != nil {
			c.server.logf("http: TLS handshake error from %s: %v", c.rwc.RemoteAddr(), err)
			return
		}
		c.tlsState = new(tls.ConnectionState)
		*c.tlsState = tlsConn.ConnectionState()
		if proto := c.tlsState.NegotiatedProtocol; validNPN(proto) {
			if fn := c.server.TLSNextProto[proto]; fn != nil {
				h := initNPNRequest{tlsConn, serverHandler{c.server}}
				fn(c.server, tlsConn, h)
			}
			return
		}
	}

	c.r = &connReader{r: c.rwc}
	c.bufr = newBufioReader(c.r)
	c.bufw = newBufioWriterSize(checkConnErrorWriter{c}, 4<<10)

	for {
		w, err := c.readRequest()
		if c.r.remain != c.server.initialReadLimitSize() {
			// If we read any bytes off the wire, we're active.
			c.setState(c.rwc, StateActive)
		}
		if err != nil {
			if err == errTooLarge {
				// Their HTTP client may or may not be
				// able to read this if we're
				// responding to them and hanging up
				// while they're still writing their
				// request.  Undefined behavior.
				io.WriteString(c.rwc, "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n431 Request Header Fields Too Large")
				c.closeWriteAndWait()
				return
			}
			if err == io.EOF {
				return // don't reply
			}
			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				return // don't reply
			}
			var publicErr string
			if v, ok := err.(badRequestError); ok {
				publicErr = ": " + string(v)
			}
			io.WriteString(c.rwc, "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n400 Bad Request"+publicErr)
			return
		}

		// Expect 100 Continue support
		req := w.req
		if req.expectsContinue() {
			if req.ProtoAtLeast(1, 1) && req.ContentLength != 0 {
				// Wrap the Body reader with one that replies on the connection
				req.Body = &expectContinueReader{readCloser: req.Body, resp: w}
			}
		} else if req.Header.get("Expect") != "" {
			w.sendExpectationFailed()
			return
		}

		// HTTP cannot have multiple simultaneous active requests.[*]
		// Until the server replies to this request, it can't read another,
		// so we might as well run the handler in this goroutine.
		// [*] Not strictly true: HTTP pipelining.  We could let them all process
		// in parallel even if their responses need to be serialized.
		serverHandler{c.server}.ServeHTTP(w, w.req)
		if c.hijacked() {
			return
		}
		w.finishRequest()
		if !w.shouldReuseConnection() {
			if w.requestBodyLimitHit || w.closedRequestBodyEarly() {
				c.closeWriteAndWait()
			}
			return
		}
		c.setState(c.rwc, StateIdle)
	}
}

~~~

~~~go
// serverHandler delegates to either the server's Handler or
// DefaultServeMux and also handles "OPTIONS *" requests.
//在本例子中，使用的是DefaultServeMux作为Server的路由。
//调用handler.ServeHTTP(rw, req)， 即DefaultServeMux.ServeHTTP(rw, req)
//注意到即DefaultServeMux时ServerMux的一个实例，所以调用了ServerMux.ServeHTTP(rw, req) --->>>
type serverHandler struct {
	srv *Server
}

func (sh serverHandler) ServeHTTP(rw ResponseWriter, req *Request) {
	handler := sh.srv.Handler //注意到handler是我们    err := http.ListenAndServe(":9090", nil)的第二个参数，即nil
	if handler == nil {
		handler = DefaultServeMux
	}
	if req.RequestURI == "*" && req.Method == "OPTIONS" {
		handler = globalOptionsHandler{}
	}
	handler.ServeHTTP(rw, req)
}
~~~

~~~go
// ServeHTTP dispatches the request to the handler whose
// pattern most closely matches the request URL.

//mux.Handler(r)遍历注册的所有路由信息，找到一个最长匹配，返回处理函数h
//h.ServeHTTP(w, r)就是让h自己调用自己。具体看下面代码
func (mux *ServeMux) ServeHTTP(w ResponseWriter, r *Request) {
	if r.RequestURI == "*" {
		if r.ProtoAtLeast(1, 1) {
			w.Header().Set("Connection", "close")
		}
		w.WriteHeader(StatusBadRequest)
		return
	}
  h, _ := mux.Handler(r)		//h是对应于请求r的处理函数，如r.Path==“/”时，h=sayHelloWorld()
	h.ServeHTTP(w, r)			//
}

//辅助信息
// The HandlerFunc type is an adapter to allow the use of
// ordinary functions as HTTP handlers.  If f is a function
// with the appropriate signature, HandlerFunc(f) is a
// Handler that calls f.

//sayHelloWorld()在注册到路由中被转化为HandlerFunc，HandlerFunc实现了ServeHTTP，所以也是一个Handler。调用自身。
type HandlerFunc func(ResponseWriter, *Request)

// ServeHTTP calls f(w, r).
func (f HandlerFunc) ServeHTTP(w ResponseWriter, r *Request) {
	f(w, r)
}
~~~

## 总结

1. 注册路由，将sayHelloWorld()添加到路由，对应路径为"/"。该路由为DefaultMux
2. 创建一个Server实例，server := &Server{Addr: addr, Handler: handler}
3. 根据“：9090”，创建一个TCPListener，TCPListener有一个netDF变量，（称为Ｎｅｔｗｏｒｋ　ｆｉｌｅ　ｄｅｓｃｒｉｂｅｒ)
4. 在一个For循环中，不断调用rw, e := l.Accept()。每次有新请求到达时创建一个连接，调用go c.serve()服务该连接。用routine使得服务多个用户的请求成为可能
5. 在c.serve()中，同样在一个For循环中，服务器不断读入用户的请求，进行处理。直到TCP连接断开后，该routine才退出。在服务时，调用serverHandler{c.server}.ServeHTTP(w, w.req)，处理请求
6. serverHandler.ServeHTTP调用c.server.ServeHTTP(w, w.req)。又因为本例中选用的是DefaultMux，他是一个ServerMux类型，所以会调用ServerMux.ServeHTTP。该函数就是遍历路由信息表，找到和请求路径匹配的处理函数h（严格的讲，是一个Handler对象）
7. 调用h.ServeHTTP（res, req）正式处理请求。注意到在本例中，h.ServeHTTP（）和sayHelloWorld(res, req)是等价的。

## 疑惑和不解之处

TCPListener中的netFD类型变量，暂时还不是特别清楚它的原理。它是在fd_windows.go文件定义的一个struct，和比较底层的东西相关，暂时还看不懂0 0。不过我觉得有点像是与计网所说的”欢迎套接字“相关的一个变量？稍微查了一下，也没找到相关资料。如果对这个有所了解的同学，可以交流一下哈。

type netFD struct {

	// locking/lifetime of sysfd + serialize access to Read and Write methods
	fdmu fdMutex
	
	// immutable until Close
	sysfd         syscall.Handle
	family        int
	sotype        int
	isConnected   bool
	skipSyncNotif bool
	net           string
	laddr         Addr
	raddr         Addr
	
	rop operation // read operation
	wop operation // write operation
	
	// wait server

没有接触过socket编程，一些东西看不懂0 0。以后如果有更多了解，再继续更深入地追溯吧。先占个坑