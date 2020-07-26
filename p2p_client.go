package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"math/big"
	"net"
	"os"
	"strings"
)

type QuicServer struct {
	conn net.PacketConn
	QuicConn quic.Listener
	tlsConfig *tls.Config
	remoteTlsConfig *tls.Config
}
func (self *QuicServer)MakeHoleTo(addr string) {
	remote_addr, _ :=net.ResolveUDPAddr("udp",addr)
	self.conn.WriteTo([]byte("00000000"),remote_addr)
}
func (self *QuicServer)LocalAddr() net.Addr {
	return self.conn.LocalAddr()
}

func (self *QuicServer) SetTlsConfig(config *tls.Config)  {
	self.tlsConfig=config
}
func (self *QuicServer)SetRemoteTlsConfig(config *tls.Config)  {
	self.remoteTlsConfig=config
}
func (self *QuicServer)GenerateRemoteTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}
}
func (self *QuicServer)GenerateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}

func (self *QuicServer)Bind(lAddr string)error  {
	udpAddr, err := net.ResolveUDPAddr("udp", lAddr)
	if(err!=nil){
		return err
	}
	self.conn,_= net.ListenUDP(udpAddr.Network(),udpAddr)
	self.QuicConn,_=quic.Listen(self.conn,self.tlsConfig,nil);
	println("func (self *QuicServer)Bind(lAddr string)error>::have bind ",self.QuicConn.Addr().String())
	return nil
}

func (self *QuicServer)Connect(remoteAddr string) (quic.Session, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if(err!=nil){
		return nil,err
	}
	session,err:=quic.Dial(self.conn,udpAddr,udpAddr.String(),self.remoteTlsConfig,nil)
	if(err!=nil){
		return nil,err
	}

	println("func (self *QuicServer)Connect(remoteAddr string) (quic.Session, error) >>:have connected ",udpAddr.String())
	return session,err
}
func (self *QuicServer)Accept()(quic.Session,error)  {

	return self.QuicConn.Accept(context.Background())
}
func (self *QuicServer)Close()  {
	self.QuicConn.Close()
	self.conn.Close()
}
//func handle_stream(stream quic.Stream)  {
//		buff:=make([]byte,1024)
//		n,_:=stream.Read(buff)
//		fmt.Println("from ",stream.StreamID().InitiatedBy().String(),">>:",string(buff[0:n]))
//
//}
func handle_conn(conn quic.Session,server *QuicServer)  {

		stream, err := conn.AcceptStream(context.Background())
		if (err != nil) {
			println(err)
			return
		}
		//go handle_stream(stream)
	buff:=make([]byte,1024)
	n,_:=stream.Read(buff)
	str:=string(buff[0:n])
	strs:=strings.Split(str,"$")
	cmd:=strs[0]
	if(cmd=="echo") {
		username := "Unkown"
		for k, v := range userMap {
			if v == conn.RemoteAddr().String() {
				username = k
			}
		}
		fmt.Println("from", username, conn.RemoteAddr().String(), stream.StreamID().StreamNum(), ">>:",strs[1] )
	}
	if(cmd=="Connect"){

		addr:=userMap[strs[1]]
		println(str,"-->",addr)
		server.Connect(addr)
		stream.Write([]byte("AlreadyConn " + strs[1]))
	}

}
func recv_server(server *QuicServer)  {
	for;;{
		conn,err:=server.Accept()
		if(err!=nil){
			println(err)
			return
		}
		go handle_conn(conn,server)
	}
}

func send_message(server *QuicServer,user string,msg string)  {

	addr:=userMap[user]
	conn,err:=server.Connect(addr)
	if(err!=nil){
		server_conn,_:=server.Connect(server_addr)
		server_stream,_:=server_conn.OpenStream()
		server_stream.Write([]byte("helpconnect "+user))
		buff:=make([]byte,1024)
		n,_:=server_stream.Read(buff)
		str:=string(buff[0:n])
		println(str)
		strs:=strings.Split(str,"$")
		cmd:=strs[0]
		if(cmd=="HaveConnect"){
			conn,_:=server.Connect(addr)
			stream,_:=conn.OpenStream()
			stream.Write([]byte("echo$"+msg))
		}
	}else {
		stream,_:=conn.OpenStream()
		stream.Write([]byte("echo$"+msg))
	}


}
var userMap = make(map[string]string)
var local_addr="localhost:8082"


var server_addr="localhost:8080"
func interact_with_server(server *QuicServer,msg string)  {

	server_conn,err:=server.Connect(server_addr)
	if(err!=nil){
		return
	}

	buff:=make([]byte,1024)
	stream,_:=server_conn.OpenStream()
	stream.Write([]byte(msg))

	println("start recv from server!")
	n,err:=stream.Read(buff)
	if(err!=nil){
		println("n,err:=stream.Read(buff) Error!")
		println(err.Error())
		//panic(err)
		return
	}
	line:=string(buff[0:n])
	println(line)
	line_s:=strings.Split(line,"$")
	cmd:=line_s[0]
	//println("cmd>>:",cmd)
	if(cmd=="updateusers"){
		println("开始更新用户！")
		//data_bytes:=buff[0:n]
		//println(string(buff))
		json_data:=[]byte(line_s[1])
		json.Unmarshal(json_data,&userMap)
		//if(len(userMap)==0){
		//	continue
		//}
		println("当前在线用户：")
		for k,v:=range userMap{
			println(k,v)
		}
		println("请按回车继续")
	}


}
func main()  {

	server := new(QuicServer)
	server.SetTlsConfig(server.GenerateTLSConfig())
	server.SetRemoteTlsConfig(server.GenerateRemoteTLSConfig())
	server.Bind(local_addr)
	go recv_server(server)

	for;;{
		print(">>:")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan() // use `for scanner.Scan()` to keep reading
		line := scanner.Text()

		//打印接受到的信息

		//
		if len(line)==0{
			continue
		}
		line_s:=strings.Split(line," ")
		cmd:=line_s[0]
		if(cmd=="send"){
			userName:=line_s[1]
			message:=line_s[2]
			go send_message(server,userName,message)
			continue
		}

		go interact_with_server(server,line)
		//println(cmd)

		//fmt.Println("captured:",line)

	}


}
