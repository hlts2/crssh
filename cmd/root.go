package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

var (
	host string
	port uint
)

var rootCmd = &cobra.Command{
	Use:   "crssh",
	Short: "penetration testing tool for ssh",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("argument not found")
		}
		fmt.Println(args)
		return nil
	},
}

func init() {
	rootCmd.Flags().StringVarP(&host, "user", "u", "root", "set user name")
	rootCmd.Flags().UintVarP(&port, "port", "p", 22, "set port number")
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}
