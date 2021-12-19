// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
)

// blockRegionCmd defines the configuration options for the fetchblockregion
// command.
type rehandleBlocksCmd struct{}

var (
	// blockRegionCfg defines the configuration options for the command.
	rehandleBlocksCfg = rehandleBlocksCmd{}
)

// Execute is the main entry point for the command.  It's invoked by the parser.
func (cmd *rehandleBlocksCmd) Execute(args []string) error {
	// Setup the global config options and ensure they are valid.
	if err := setupGlobalConfig(); err != nil {
		return err
	}

	if len(args) != 0 {
		return errors.New("no parameters is required")
	}

	// Load the block database.
	db, err := loadBlockDB()
	if err != nil {
		return err
	}
	defer db.Close()

	config := &blockchain.Config{
		DB:           db,
		Interrupt:    nil,
		ChainParams:  &chaincfg.MainNetParams,
		Checkpoints:  nil,
		TimeSource:   blockchain.NewMedianTime(),
		SigCache:     nil,
		IndexManager: nil,
		HashCache:    nil,
	}
	oldBlockchain, err := blockchain.NewTest(config)
	if err != nil {
		return err
	}
	// Start from height 0
	blockchainState := &blockchain.BestStateModified{
		Hash:            *config.ChainParams.GenesisHash,
		Height:          0,
		BlockTotoalSize: 0,
		OriginTotalSize: 0,
		NumTxns:         0,
		TxnsTotalSize:   0,
		UTXOSetSize:     0,
		Delta:           6,
		DiscardSize:     make([]int, 0, 6),
	}

	var cur int32 = 0
	bestHeight := oldBlockchain.BestSnapshot().Height
	//var bestHeight int32= 100
	var block *btcutil.Block
	for cur <= bestHeight {
		block, err = oldBlockchain.BlockByHeight(cur)
		if err != nil {
			return err
		}
		// re-handle
		_ = blockchainState.Update(block)

		log.Infof("Time %d, Block Height %d, Block Hash %v, Origin Storage %dB, Storage %dB, UTXOSize %d, ",
			block.MsgBlock().Header.Timestamp.Unix(),
			cur,
			blockchainState.Hash,
			blockchainState.OriginTotalSize,
			blockchainState.BlockTotoalSize,
			blockchainState.UTXOSetSize)
		cur++
	}

	return nil
}

// Usage overrides the usage display for the command.
func (cmd *rehandleBlocksCmd) Usage() string {
	return ""
}
