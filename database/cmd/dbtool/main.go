// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"github.com/btcsuite/btcutil"
	"github.com/jrick/logrotate/rotator"
	"os"
	"path/filepath"
	"strings"

	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btclog"
	flags "github.com/jessevdk/go-flags"
)

const (
	// blockDbNamePrefix is the prefix for the btcd block database.
	blockDbNamePrefix = "blocks"
)

var (
	log             btclog.Logger
	shutdownChannel = make(chan error)
)

// loadBlockDB opens the block database and returns a handle to it.
func loadBlockDB() (database.DB, error) {
	// The database name is based on the database type.
	dbName := blockDbNamePrefix + "_" + cfg.DbType
	dbPath := filepath.Join(cfg.DataDir, dbName)

	log.Infof("Loading block database from '%s'", dbPath)
	db, err := database.Open(cfg.DbType, dbPath, activeNetParams.Net)
	if err != nil {
		// Return the error if it's not because the database doesn't
		// exist.
		if dbErr, ok := err.(database.Error); !ok || dbErr.ErrorCode !=
			database.ErrDbDoesNotExist {

			return nil, err
		}

		// Create the db if it does not exist.
		err = os.MkdirAll(cfg.DataDir, 0700)
		if err != nil {
			return nil, err
		}
		db, err = database.Create(cfg.DbType, dbPath, activeNetParams.Net)
		if err != nil {
			return nil, err
		}
	}

	log.Info("Block database loaded")
	return db, nil
}

// logWriter implements an io.Writer that outputs to both standard output and
// the write-end pipe of an initialized log rotator.
type logWriter struct{}

var logRotator *rotator.Rotator

func (logWriter) Write(p []byte) (n int, err error) {
	os.Stdout.Write(p)
	logRotator.Write(p)
	return len(p), nil
}

func initLogRotator(logFile string) {
	logDir, _ := filepath.Split(logFile)
	err := os.MkdirAll(logDir, 0700)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create log directory: %v\n", err)
		os.Exit(1)
	}
	//r, err := rotator.New(logFile, 10*1024, false, 3)
	// 不删除日志文件
	r, err := rotator.New(logFile, 10*1024, false, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create file rotator: %v\n", err)
		os.Exit(1)
	}

	logRotator = r
}

// realMain is the real main function for the utility.  It is necessary to work
// around the fact that deferred functions do not run when os.Exit() is called.
func realMain() error {
	// Setup logging.
	defaultLogDir := filepath.Join(btcutil.AppDataDir("btcd", false), "logs")
	initLogRotator(filepath.Join(defaultLogDir, "rehandle.log"))
	backendLogger := btclog.NewBackend(logWriter{})
	defer os.Stdout.Sync()
	log = backendLogger.Logger("MAIN")
	dbLog := backendLogger.Logger("BCDB")
	dbLog.SetLevel(btclog.LevelDebug)
	database.UseLogger(dbLog)

	// Setup the parser options and commands.
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	parserFlags := flags.Options(flags.HelpFlag | flags.PassDoubleDash)
	parser := flags.NewNamedParser(appName, parserFlags)
	parser.AddGroup("Global Options", "", cfg)
	parser.AddCommand("insecureimport",
		"Insecurely import bulk block data from bootstrap.dat",
		"Insecurely import bulk block data from bootstrap.dat.  "+
			"WARNING: This is NOT secure because it does NOT "+
			"verify chain rules.  It is only provided for testing "+
			"purposes.", &importCfg)
	parser.AddCommand("loadheaders",
		"Time how long to load headers for all blocks in the database",
		"", &headersCfg)
	parser.AddCommand("fetchblock",
		"Fetch the specific block hash from the database", "",
		&fetchBlockCfg)
	parser.AddCommand("fetchblockregion",
		"Fetch the specified block region from the database", "",
		&blockRegionCfg)

	parser.AddCommand("rehandleblocks",
		"Rehandle with all block in the database", "",
		&rehandleBlocksCfg)

	// Parse command line and invoke the Execute function for the specified
	// command.
	if _, err := parser.Parse(); err != nil {
		if e, ok := err.(*flags.Error); ok && e.Type == flags.ErrHelp {
			parser.WriteHelp(os.Stderr)
		} else {
			log.Error(err)
		}

		return err
	}

	return nil
}

func main() {
	// Work around defer not working after os.Exit()
	if err := realMain(); err != nil {
		os.Exit(1)
	}
}
