// Copyright © 2017 Oleg Bulatov <oleg@bulatov.me>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"net/http"
	"os"

	"github.com/docker/distribution/registry/client/auth"
	"github.com/spf13/cobra"

	"github.com/dmage/registry/pkg/client"
	"github.com/dmage/registry/pkg/httplog"
)

// RootCmd represents the base command when called without any subcommands.
var RootCmd = &cobra.Command{
	Use:   "registry",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

var rootCmdHost string
var rootCmdUser string
var rootCmdPassword string
var rootCmdVerbose bool

func init() {
	RootCmd.PersistentFlags().StringVarP(&rootCmdHost, "host", "H", "index.docker.io", "use the specified Docker Registry")
	RootCmd.PersistentFlags().StringVarP(&rootCmdUser, "user", "u", "", "use the specified username")
	RootCmd.PersistentFlags().StringVarP(&rootCmdPassword, "password", "p", "", "use the specified password")
	RootCmd.PersistentFlags().BoolVarP(&rootCmdVerbose, "verbose", "v", false, "print http requests")
}

func newClient() *client.Client {
	var creds auth.CredentialStore
	if rootCmdUser != "" || rootCmdPassword != "" {
		creds = &client.BasicCredentials{
			Username: rootCmdUser,
			Password: rootCmdPassword,
		}
	}

	var transport http.RoundTripper
	if rootCmdVerbose {
		transport = &httplog.RoundTripper{}
	}

	return client.New(rootCmdHost, creds, transport)
}
