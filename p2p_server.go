

package main

import (
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
	"strings"
)

type QuicServer struct {
	conn net.PacketConn
	QuicConn quic.Listener
	tlsConfig *tls.Config
	remoteTlsConfig *tls.Config
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
		panic(err)
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
var userMap map[string]string= make(map[string]string)
func handle_stream(conn quic.Session,stream quic.Stream,server *QuicServer){
		//defer stream.Close()
		buff:=make([]byte,1024)
		n,err:=stream.Read(buff)
		if(err!=nil){
			println("handle_stream(conn quic.Session,stream quic.Stream)",err.Error())
			return
		}
		str:=string(buff[0:n])
		println(str)
		strs:=strings.Split(str," ")
		//str_len= len(strs)
		if(strs[0]=="login") {
			println(strs[1],"has login, addr:",conn.RemoteAddr().String())
			userName:=strs[1];
			userMap[userName]=conn.RemoteAddr().String()
			//userMap.Range(func(key, value interface{}) bool {
			//	fmt.Println(key,value)
			//	return true
			//})
			json_data,err:=json.Marshal(&userMap)
			if(err!=nil){
				println(err.Error())

			}
			msg:="updateusers$"+string(json_data)
			stream.Write([]byte(msg))
			fmt.Println(msg)


		}
		if(strs[0]=="getusers"){
			json_data,err:=json.Marshal(&userMap)
			if(err!=nil){
				println(err.Error())

			}
			msg:="updateusers$"+string(json_data)
			stream.Write([]byte(msg))
			fmt.Println(msg)

		}
		if(strs[0]=="helpconnect"){
			user:=strs[1]
			addr:=userMap[user]
			conn_1,_:=server.Connect(addr)
			stream_1,_:=conn_1.OpenStream()
			for k,v:=range userMap{
				if(v==conn.RemoteAddr().String()){
					r_user:=k
					stream_1.Write([]byte("Connect$" + r_user))
					break;
				}
			}


			n,_:=stream_1.Read(buff)
			str:=string(buff[0:n])
			println(str)
			strs=strings.Split(str," ")

			cmd:=strs[0]
			//usr:=strs[1]
			if(cmd=="AlreadyConn"){
				stream.Write([]byte("HaveConnect$" + user))
			}


		}

}
func handle_conn(conn quic.Session,server *QuicServer)  {
	stream, err := conn.AcceptStream(context.Background())
	if(err!=nil){
		println("handle_conn(conn quic.Session)",err.Error())
		return
	}
	go handle_stream(conn,stream,server)

}


func main()  {
	local_addr:="localhost:8080"
	server := new(QuicServer)
	server.SetTlsConfig(server.GenerateTLSConfig())
	server.SetRemoteTlsConfig(server.GenerateRemoteTLSConfig())
	server.Bind(local_addr)
	for;;{
		conn,err:=server.Accept()
		if(err!=nil){
			println("main()",err)
			continue
		}
		go handle_conn(conn,server)
	}

}
