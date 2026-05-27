package iamctl

import (
	"context"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"gorm.io/gorm"

	"github.com/nathan-tsien/iam/internal/config"
	"github.com/nathan-tsien/iam/internal/db"
	apprepo "github.com/nathan-tsien/iam/internal/repo/app"
	superadminrepo "github.com/nathan-tsien/iam/internal/repo/superadmin"
	"github.com/nathan-tsien/iam/internal/secret"
)

// Execute runs the iamctl command tree.
func Execute() error {
	return rootCmd.Execute()
}

var rootCmd = &cobra.Command{
	Use:   "iamctl",
	Short: "Operator CLI for IAM app registry and super-admin grants",
}

func init() {
	rootCmd.AddCommand(appsCmd)
	rootCmd.AddCommand(superAdminsCmd)
}

var appsCmd = &cobra.Command{
	Use:   "apps",
	Short: "Manage registered consumer applications",
}

var appsCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Register a new app and print its HMAC secret once",
	RunE:  runAppsCreate,
}

var appsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered apps",
	RunE:  runAppsList,
}

var appsDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Soft-disable an app by slug",
	RunE:  runAppsDisable,
}

var (
	createSlug         string
	createDisplayName  string
	createJWTAudience  string
	createMailFromName string
	createWebhookURL   string
	disableSlug        string
)

func init() {
	appsCreateCmd.Flags().StringVar(&createSlug, "slug", "", "Unique app slug (required)")
	appsCreateCmd.Flags().StringVar(&createDisplayName, "display-name", "", "Human-readable name (required)")
	appsCreateCmd.Flags().StringVar(&createJWTAudience, "jwt-audience", "", "JWT aud claim (defaults to slug)")
	appsCreateCmd.Flags().StringVar(&createMailFromName, "mail-from-name", "", "Outbound mail display name")
	appsCreateCmd.Flags().StringVar(&createWebhookURL, "webhook-url", "", "Webhook delivery URL")
	_ = appsCreateCmd.MarkFlagRequired("slug")
	_ = appsCreateCmd.MarkFlagRequired("display-name")

	appsDisableCmd.Flags().StringVar(&disableSlug, "slug", "", "App slug to disable (required)")
	_ = appsDisableCmd.MarkFlagRequired("slug")

	appsCmd.AddCommand(appsCreateCmd, appsListCmd, appsDisableCmd)
}

func runAppsCreate(cmd *cobra.Command, _ []string) error {
	gormDB, err := openDB()
	if err != nil {
		return err
	}

	plain, hash, err := secret.Generate()
	if err != nil {
		return err
	}

	row, err := apprepo.NewRepo(gormDB).Create(context.Background(), apprepo.CreateInput{
		Slug:           createSlug,
		DisplayName:    createDisplayName,
		JWTAudience:    createJWTAudience,
		MailFromName:   createMailFromName,
		WebhookURL:     createWebhookURL,
		HMACSecretHash: hash,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "App created\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  id:           %s\n", row.ID)
	fmt.Fprintf(cmd.OutOrStdout(), "  slug:         %s\n", row.Slug)
	fmt.Fprintf(cmd.OutOrStdout(), "  jwt_audience: %s\n", row.JWTAudience)
	fmt.Fprintf(cmd.OutOrStdout(), "  hmac_secret:  %s\n", plain)
	fmt.Fprintln(cmd.OutOrStdout(), "Store the HMAC secret securely; it cannot be retrieved again.")
	return nil
}

func runAppsList(cmd *cobra.Command, _ []string) error {
	gormDB, err := openDB()
	if err != nil {
		return err
	}

	rows, err := apprepo.NewRepo(gormDB).List(context.Background())
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SLUG\tDISPLAY NAME\tJWT AUDIENCE\tDISABLED")
	for _, row := range rows {
		disabled := "no"
		if row.DisabledAt != nil {
			disabled = "yes"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", row.Slug, row.DisplayName, row.JWTAudience, disabled)
	}
	return w.Flush()
}

func runAppsDisable(cmd *cobra.Command, _ []string) error {
	if strings.TrimSpace(disableSlug) == apprepo.SystemAppSlug {
		return fmt.Errorf("cannot disable system app %q", apprepo.SystemAppSlug)
	}

	gormDB, err := openDB()
	if err != nil {
		return err
	}
	return apprepo.NewRepo(gormDB).Disable(context.Background(), disableSlug)
}

var superAdminsCmd = &cobra.Command{
	Use:   "super-admins",
	Short: "Manage cross-app super-admin grants",
}

var superAdminsGrantCmd = &cobra.Command{
	Use:   "grant",
	Short: "Grant super-admin privileges to a _iam app user",
	RunE:  runSuperAdminsGrant,
}

var (
	grantUserID   string
	grantByUserID string
)

func init() {
	superAdminsGrantCmd.Flags().StringVar(&grantUserID, "user-id", "", "User UUID in the _iam app (required)")
	superAdminsGrantCmd.Flags().StringVar(&grantByUserID, "granted-by", "", "Granting user UUID (optional)")
	_ = superAdminsGrantCmd.MarkFlagRequired("user-id")
	superAdminsCmd.AddCommand(superAdminsGrantCmd)
}

func runSuperAdminsGrant(cmd *cobra.Command, _ []string) error {
	userID, err := uuid.Parse(grantUserID)
	if err != nil {
		return fmt.Errorf("parse user-id: %w", err)
	}

	var grantedBy *uuid.UUID
	if grantByUserID != "" {
		id, err := uuid.Parse(grantByUserID)
		if err != nil {
			return fmt.Errorf("parse granted-by: %w", err)
		}
		grantedBy = &id
	}

	gormDB, err := openDB()
	if err != nil {
		return err
	}

	if err := superadminrepo.NewRepo(gormDB).Grant(context.Background(), userID, grantedBy); err != nil {
		return err
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Super-admin grant created.")
	return nil
}

func openDB() (*gorm.DB, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	return db.Open(cfg.DatabaseURL, cfg.DatabaseSchema, cfg.AppEnv)
}
