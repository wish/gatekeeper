package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/wish/gatekeeper/verifier"
)

var rulesetPath string

var rootCmd = &cobra.Command{
	Use:   "gatekeeper",
	Short: "Gatekeeper verifies your Kubernetes files against custom rulesets",
	Long:  `Verify your Kubernetes files using custom rulesets.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if !viper.IsSet("gopath") {
			fmt.Println("Error: GOPATH is not set.")
			os.Exit(1)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 1 {
			// Parse ruleset
			ruleSet := verifier.ParseRuleset(rulesetPath)

			// Verify folder
			if errs := verifier.Verify(ruleSet, args[0]); len(errs) > 0 {
				for i, err := range errs {
					fmt.Println(strconv.Itoa(i+1) + ". " + err.Error())
				}
				os.Exit(1)
			}
		} else {
			fmt.Println("You must pass exactly one argument.")
			os.Exit(1)
		}
	},
}

// Execute executes the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.Flags().StringVarP(&rulesetPath, "ruleset", "r", "", "Path to the ruleset jsonnet file")
}

func initConfig() {
	viper.BindEnv("gopath", "GOPATH")
}
