// Copyright (c) 2013-2018 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

// BestStateModified store
// transaction number, transaction total size, block number, block total size
// utxo set size
type BestStateModified struct {
	Hash            chainhash.Hash // The hash of the best block.
	Height          int32          // The height of the block.
	BlockTotoalSize uint64         // The total size of the block.
	OriginTotalSize uint64
	NumTxns         uint64 // The number of txns in the block.
	TxnsTotalSize   uint64 // The total size of the transaction in best chain
	UTXOSetSize     uint64 // The size of UTXO set
	Delta           int
	DiscardSize     []int
}

func (b *BestStateModified) Update(block *btcutil.Block) error {
	b.OriginTotalSize += uint64(block.MsgBlock().SerializeSize())

	msgBlockModified := wire.NewMsgBlockModifiedFromMsgBlock(block.MsgBlock())

	b.Hash = msgBlockModified.BlockHash()
	b.Height += 1
	b.BlockTotoalSize += uint64(msgBlockModified.SerializeSize())

	b.NumTxns += uint64(len(msgBlockModified.Transactions))
	b.TxnsTotalSize += 1
	b.UTXOSetSize = b.UTXOSetSize + uint64(len(msgBlockModified.Transactions[0].TxOuts))
	for i := 1; i < len(msgBlockModified.Transactions); i++ {
		b.TxnsTotalSize += uint64(msgBlockModified.Transactions[i].SerializeSize())
		b.UTXOSetSize = b.UTXOSetSize - uint64(len(msgBlockModified.Transactions[i].TxIns)) + uint64(len(msgBlockModified.Transactions[i].TxOuts))
	}

	if len(b.DiscardSize) < b.Delta {
		b.DiscardSize = append(b.DiscardSize, msgBlockModified.Extras.SerializeSize())
	} else {
		b.BlockTotoalSize -= uint64(b.DiscardSize[0])
		b.DiscardSize = append(b.DiscardSize[1:], msgBlockModified.Extras.SerializeSize())
	}

	return nil
}
