package cmd

import (
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print Yasso's version in screen",
	Run: func(cmd *cobra.Command, args []string) {
		Println(Clearln + "Yasso Version is 0.1.2")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
