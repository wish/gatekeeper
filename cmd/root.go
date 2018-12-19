package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/gobuffalo/packr"
	"github.com/spf13/cobra"

	"github.com/wish/gatekeeper/verifier"
)

var rulesetPath string

var rootCmd = &cobra.Command{
	Use:   "gatekeeper",
	Short: "Gatekeeper verifies your Kubernetes files against custom rulesets",
	Long:  `Verify your Kubernetes files using custom rulesets.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 1 {
			// Get gatekeeper function definitions
			box := packr.NewBox("../function_definitions")
			gatekeeperFunctions, err := box.FindString("gatekeeper.jsonnet")
			if err != nil {
				fmt.Println("Error: Could not get gatekeeper.jsonnet from packr.")
				os.Exit(1)
			}

			// Parse ruleset
			ruleSet := verifier.ParseRuleset(rulesetPath, gatekeeperFunctions)

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
}
