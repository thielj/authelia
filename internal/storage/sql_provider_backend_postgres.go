package storage

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/utils"
)

// PostgreSQLProvider is a PostgreSQL provider.
type PostgreSQLProvider struct {
	SQLProvider
}

// NewPostgreSQLProvider a PostgreSQL provider.
func NewPostgreSQLProvider(config *schema.Configuration, caCertPool *x509.CertPool) (provider *PostgreSQLProvider) {
	provider = &PostgreSQLProvider{
		SQLProvider: NewSQLProvider(config, providerPostgres, "pgx", config.Storage.PostgreSQL.Schema, dsnPostgreSQL(config.Storage.PostgreSQL, caCertPool)),
	}

	// All providers have differing SELECT existing table statements.
	provider.sqlSelectExistingTables = queryPostgreSelectExistingTables

	// Specific alterations to this provider.
	// PostgreSQL doesn't have a UPSERT statement but has an ON CONFLICT operation instead.
	provider.sqlUpsertDuoDevice = fmt.Sprintf(queryFmtUpsertDuoDevicePostgreSQL, tableDuoDevices)
	provider.sqlUpsertTOTPConfig = fmt.Sprintf(queryFmtUpsertTOTPConfigurationPostgreSQL, tableTOTPConfigurations)
	provider.sqlUpsertPreferred2FAMethod = fmt.Sprintf(queryFmtUpsertPreferred2FAMethodPostgreSQL, tableUserPreferences)
	provider.sqlUpsertEncryptionValue = fmt.Sprintf(queryFmtUpsertEncryptionValuePostgreSQL, tableEncryption)
	provider.sqlUpsertOAuth2BlacklistedJTI = fmt.Sprintf(queryFmtUpsertOAuth2BlacklistedJTIPostgreSQL, tableOAuth2BlacklistedJTI)
	provider.sqlInsertOAuth2ConsentPreConfiguration = fmt.Sprintf(queryFmtInsertOAuth2ConsentPreConfigurationPostgreSQL, tableOAuth2ConsentPreConfiguration)

	provider.rebind()

	return provider
}

func dsnPostgreSQL(config *schema.StoragePostgreSQL, globalCACertPool *x509.CertPool) (dsn string) {
	dsnConfig, _ := pgx.ParseConfig("")

	dsnConfig.Host = config.Address.SocketHostname()
	dsnConfig.Port = uint16(config.Address.Port())
	dsnConfig.Database = config.Database
	dsnConfig.User = config.Username
	dsnConfig.Password = config.Password
	dsnConfig.TLSConfig = loadPostgreSQLTLSConfig(config, globalCACertPool)
	dsnConfig.ConnectTimeout = config.Timeout
	dsnConfig.RuntimeParams = map[string]string{
		"search_path":      config.Schema,
		"application_name": driverParameterAppName,
	}

	if dsnConfig.Port == 0 && config.Address.IsUnixDomainSocket() {
		dsnConfig.Port = 5432
	}

	return stdlib.RegisterConnConfig(dsnConfig)
}

func loadPostgreSQLTLSConfig(config *schema.StoragePostgreSQL, globalCACertPool *x509.CertPool) (tlsConfig *tls.Config) {
	if config.TLS != nil {
		return utils.NewTLSConfig(config.TLS, globalCACertPool)
	}

	return loadPostgreSQLLegacyTLSConfig(config, globalCACertPool)
}

//nolint:staticcheck // Used for legacy purposes.
func loadPostgreSQLLegacyTLSConfig(config *schema.StoragePostgreSQL, globalCACertPool *x509.CertPool) (tlsConfig *tls.Config) {
	if config.SSL == nil {
		return nil
	}

	var (
		ca    *x509.Certificate
		certs []tls.Certificate
	)

	ca, certs = loadPostgreSQLLegacyTLSConfigFiles(config)

	switch config.SSL.Mode {
	case "disable":
		return nil
	default:
		var caCertPool *x509.CertPool

		switch ca {
		case nil:
			caCertPool = globalCACertPool
		default:
			caCertPool = globalCACertPool.Clone()
			caCertPool.AddCert(ca)
		}

		tlsConfig = &tls.Config{
			Certificates:       certs,
			RootCAs:            caCertPool,
			InsecureSkipVerify: true, //nolint:gosec
		}

		switch {
		case config.SSL.Mode == "require" && config.SSL.RootCertificate != "" || config.SSL.Mode == "verify-ca":
			tlsConfig.VerifyPeerCertificate = newPostgreSQLVerifyCAFunc(tlsConfig)
		case config.SSL.Mode == "verify-full":
			tlsConfig.InsecureSkipVerify = false
			tlsConfig.ServerName = config.Address.Hostname()
		}
	}

	return tlsConfig
}

//nolint:staticcheck // Used for legacy purposes.
func loadPostgreSQLLegacyTLSConfigFiles(config *schema.StoragePostgreSQL) (ca *x509.Certificate, certs []tls.Certificate) {
	var (
		err error
	)

	if config.SSL.RootCertificate != "" {
		var caPEMBlock []byte

		if caPEMBlock, err = os.ReadFile(config.SSL.RootCertificate); err != nil {
			return nil, nil
		}

		if ca, err = x509.ParseCertificate(caPEMBlock); err != nil {
			return nil, nil
		}
	}

	if config.SSL.Certificate != "" && config.SSL.Key != "" {
		var (
			keyPEMBlock  []byte
			certPEMBlock []byte
		)

		if keyPEMBlock, err = os.ReadFile(config.SSL.Key); err != nil {
			return nil, nil
		}

		if certPEMBlock, err = os.ReadFile(config.SSL.Certificate); err != nil {
			return nil, nil
		}

		var cert tls.Certificate

		if cert, err = tls.X509KeyPair(certPEMBlock, keyPEMBlock); err != nil {
			return nil, nil
		}

		certs = []tls.Certificate{cert}
	}

	return ca, certs
}

func newPostgreSQLVerifyCAFunc(config *tls.Config) func(certificates [][]byte, _ [][]*x509.Certificate) (err error) {
	return func(certificates [][]byte, _ [][]*x509.Certificate) (err error) {
		certs := make([]*x509.Certificate, len(certificates))

		var cert *x509.Certificate

		for i, asn1Data := range certificates {
			if cert, err = x509.ParseCertificate(asn1Data); err != nil {
				return errors.New("failed to parse certificate from server: " + err.Error())
			}

			certs[i] = cert
		}

		// Leave DNSName empty to skip hostname verification.
		opts := x509.VerifyOptions{
			Roots:         config.RootCAs,
			Intermediates: x509.NewCertPool(),
		}

		// Skip the first cert because it's the leaf. All others
		// are intermediates.
		for _, cert = range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}

		_, err = certs[0].Verify(opts)

		return err
	}
}
