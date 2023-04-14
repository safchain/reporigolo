package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type OpCode = uint32

const (
	NextBulk OpCode = iota + 1
)

type Op struct {
	Code  OpCode
	Value uint32
}

func (o *Op) MarshalBinary(data []byte) {
	binary.BigEndian.PutUint32(data[0:], o.Code)
	binary.BigEndian.PutUint32(data[4:], o.Value)
}

func (o *Op) UnmarshalBinary(data []byte) {
	o.Code = binary.BigEndian.Uint32(data[0:])
	o.Value = binary.BigEndian.Uint32(data[4:])
}

type Client struct {
	conn  net.Conn
	fd    int
	bytes []byte
}

func NewClient(shm, uds string) (*Client, error) {
	fd, err := unix.Open(shm, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}

	bytes, err := unix.Mmap(fd, 0, 4*os.Getpagesize(), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, err
	}

	conn, err := net.Dial("unix", uds)
	if err != nil {
		return nil, err
	}

	return &Client{
		conn:  conn,
		fd:    fd,
		bytes: bytes,
	}, nil
}

func (c *Client) execOp(op *Op) {
	switch op.Code {
	case NextBulk:
		fmt.Printf("Data: %d\n", c.bytes[op.Value])
	}
}

func (c *Client) run(ctx context.Context) {
	var op Op
	var data [12]byte

	for {
		select {
		case <-ctx.Done():
		default:
			n, err := c.conn.Read(data[:])
			if err != nil {
				// TODO
				continue
			}

			if n < len(data) {
				// TODO
				continue
			}

			op.UnmarshalBinary(data[:])

			fmt.Printf("%d %d\n", op.Code, op.Value)

			c.execOp(&op)
		}
	}
}

func (c *Client) Start() {
	go c.run(context.Background())
}

type Server struct {
	sync.RWMutex

	clients  []*RemoteClient
	listener net.Listener
	bytes    []byte
}

type RemoteClient struct {
	conn net.Conn
}

func NewServer(shm, uds string, size int) (*Server, error) {
	os.RemoveAll(uds)
	os.RemoveAll(shm)

	listener, err := net.Listen("unix", uds)
	if err != nil {
		return nil, err
	}

	fd, err := unix.Open(shm, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, unix.S_ISUID|unix.S_ISGID)
	if err != nil {
		return nil, err
	}

	f := os.NewFile(uintptr(fd), "ring")
	f.Truncate(int64(size * os.Getpagesize()))

	bytes, err := unix.Mmap(fd, 0, size*os.Getpagesize(), unix.PROT_WRITE|unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		// TODO
		return nil, err
	}

	return &Server{
		listener: listener,
		bytes:    bytes,
	}, nil
}

func (s *Server) accept(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				// TODO
				continue
			}

			s.Lock()
			s.clients = append(s.clients, &RemoteClient{conn: conn})
			s.Unlock()
		}
	}
}

func (s *Server) publish(ctx context.Context) {
	var data [12]byte
	var i uint32

	for {
		select {
		case <-ctx.Done():
		default:
			s.bytes[i] = byte(i)
			op := Op{Code: NextBulk, Value: i1}
			op.MarshalBinary(data[:])

			s.RLock()
			for _, client := range s.clients {
				client.conn.Write(data[:])
			}
			s.RUnlock()

			time.Sleep(time.Second)

			i++
		}
	}
}

func (s *Server) run(ctx context.Context) {
	go s.accept(ctx)
	s.publish(ctx)
}

func main() {
	cm := flag.Bool("client", false, "client mode")
	flag.Parse()

	if *cm {
		client, err := NewClient("/dev/shm/ring", "/tmp/ring.sock")
		if err != nil {
			panic(err)
		}
		client.run(context.Background())
	} else {
		server, err := NewServer("/dev/shm/ring", "/tmp/ring.sock", 4)
		if err != nil {
			panic(err)
		}

		server.run(context.Background())
	}
}
