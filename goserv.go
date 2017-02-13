package main

import (
    "bytes"
    "fmt"
    "net"
    "strings"
    "time"
)

type RequestData struct {
    body string
    headers map[string]string
    method string
    path string
    protocol string
    query map[string]string
}

type ResponseData struct {
    body string
    code uint
    codeText string
    headers map[string]string
    protocol string
}

// ReadRequestData reads the input stream from a connection and parses the data
// in to headers and body content.
func ReadRequestData(conn net.Conn) RequestData {
    // This function should be more robust than simply reading everything the client
    // sends over the stream. This is to prevent the client from continuously
    // sending data until the server runs out of memory. This function should also
    // specify a read deadline to avoid a slow lorice attack.

    // This function should make sure to only read as many bytes as the headers
    // specify. This avoids an attack where the client can send and endless stream
    // of random data and lock up the server, creating a DoS.

    var ret RequestData

    rawRequestData := make([]byte, 1024)
    // readLen, _ := conn.Read(rawRequestData)
    // fmt.Println(string(rawRequestData[:readLen]))
    conn.Read(rawRequestData)

    // To read headers
    // 1. Read raw data in
    // 2. Set endOfHeaders flag to false
    // 3. Process lines to end of byte slice
    // 4. If endOfHeaders hasn't been set, repeat from step 1
    // 5. If endOfHeaders has been set, process input data
    // NOTE: Don't forget to handle if a header stretches across
    //       a read border!
    lastIndex := bytes.Index(rawRequestData, []byte{13, 10})
    requestLine := rawRequestData[:lastIndex]
    lastIndex += 2
    method, path, query, protocol := ParseRequestLine(requestLine)
    ret.method = method
    ret.path = path
    ret.query = query
    ret.protocol = protocol

    headers := make(map[string]string)
    counter := 0
    // continueLine := ""
    for {
        counter++
        nextIndex := bytes.Index(rawRequestData[lastIndex:], []byte{13, 10})
        if nextIndex == -1 {
            // We hit a read boundary and the headers cross it
            // continueLine := rawRequestData[lastIndex:]
            break
        }

        lineLength := (nextIndex + lastIndex) - lastIndex
        if lineLength == 0 {
            break
        }
        headerLine := rawRequestData[lastIndex:(lastIndex + nextIndex)]
        headerKey := strings.Trim(string(bytes.Split(headerLine, []byte(": "))[0]), "\r\n ")
        headerValue := strings.Trim(string(bytes.Split(headerLine, []byte(": "))[1]), "\r\n ")
        headers[strings.ToLower(headerKey)] = headerValue
        lastIndex += (lineLength + 2)
    }
    ret.headers = headers

    return ret
}

// ParseRequestLine takes a standard HTTP request line and parses out the parts
// in to separate variables. The query string keys and values are placed in a
// map.
func ParseRequestLine(requestLine []byte) (string, string, map[string]string, string) {
    parts := bytes.Split(requestLine, []byte(" "))
    method := strings.ToUpper(string(parts[0]))
    // BUG(wilkua): ParseRequestLine doesn't account for query strings yet
    path := string(parts[1])
    protocol := string(parts[2])
    query := make(map[string]string)
    return method, path, query, protocol
}

// BuildResponseBuffer takes a ResponseData structure and builds it in to a
// byte array to be written to the connection stream.
func BuildResponseBuffer(response ResponseData) []byte {
    var ret []byte
    ret = append(ret, []byte(response.protocol)...) // HTTP1.1
    ret = append(ret, []byte(" ")...)
    ret = append(ret, []byte(string(response.code))...) // 200
    ret = append(ret, []byte(response.codeText)...) // OK
    
    response.headers["content-length"] = string(len(response.body))
    for key, value := range(response.headers) {
        ret = append(ret, []byte(key)...)
        ret = append(ret, []byte(": ")...)
        ret = append(ret, []byte(value)...)
        ret = append(ret, []byte("\r\n")...)
    }
    ret = append(ret, []byte("\r\n")...)
    ret = append(ret, []byte(response.body)...)
    return ret
}

func HandleConnection(conn net.Conn) {
    defer conn.Close()

    request := ReadRequestData(conn)

    var response ResponseData
    response.code = 200
    response.codeText = "OK"
    response.protocol = request.protocol

    conn.Write(BuildResponseBuffer(response))

    // 127.0.0.1 - - [2017/02/08T19:28:31Z] "GET / HTTP/1.0" 200 1545
    fmt.Printf("%s %s %s [%s] \"%s %s %s\" %d %d\n", 
        conn.RemoteAddr(),
        "-",
        "-",
        time.Now().UTC().Format("2006/01/02T15:04:05Z"),
        request.method,
        request.path,
        request.protocol,
        response.code,
        len(response.body))
}

func main() {
    ln, err := net.Listen("tcp", ":8080")
    if err != nil {
        fmt.Println("Failed to bind to port 8080")
        return
    }
    fmt.Println("\nServer started on port 8080")
    for {
        conn, err := ln.Accept()
        if err == nil {
            go HandleConnection(conn)
        } else {
            fmt.Println("Error while receiving connection")
        }
    }
}

