// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

type MsgBlockModified struct {
	Header       BlockHeader
	Transactions []*MsgTxPruned
	Extras       BlockExtras
}

// AddTransaction adds a transaction to the message.
func (msg *MsgBlockModified) AddTransaction(tx *MsgTxPruned) error {
	msg.Transactions = append(msg.Transactions, tx)
	return nil

}

// ClearTransactions removes all transactions from the message.
func (msg *MsgBlockModified) ClearTransactions() {
	msg.Transactions = make([]*MsgTxPruned, 0, defaultTransactionAlloc)
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding blocks stored to disk, such as in a database, as
// opposed to decoding blocks from the wire.
func (msg *MsgBlockModified) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	err := readBlockHeader(r, pver, &msg.Header)
	if err != nil {
		return err
	}

	txCount, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	// Prevent more transactions than could possibly fit into a block.
	// It would be possible to cause memory exhaustion and panics without
	// a sane upper bound on this count.
	if txCount > maxTxPerBlock {
		str := fmt.Sprintf("too many transactions to fit into a block "+
			"[count %d, max %d]", txCount, maxTxPerBlock)
		return messageError("MsgBlock.BtcDecode", str)
	}

	msg.Transactions = make([]*MsgTxPruned, 0, txCount)
	for i := uint64(0); i < txCount; i++ {
		tx := MsgTxPruned{}
		err := tx.BtcDecode(r, pver, enc)
		if err != nil {
			return err
		}
		msg.Transactions = append(msg.Transactions, &tx)
	}

	return readBlockExtras(r, pver, &msg.Extras)
}

func (msg *MsgBlockModified) Deserialize(r io.Reader) error {
	return msg.BtcDecode(r, 0, BaseEncoding)
}

// DeserializeTxLoc decodes r in the same manner Deserialize does, but it takes
// a byte buffer instead of a generic reader and returns a slice containing the
// start and length of each transaction within the raw data that is being
// deserialized.
func (msg *MsgBlockModified) DeserializeTxLoc(r *bytes.Buffer) ([]TxLoc, error) {
	fullLen := r.Len()

	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of existing wire protocol functions.
	err := readBlockHeader(r, 0, &msg.Header)
	if err != nil {
		return nil, err
	}

	txCount, err := ReadVarInt(r, 0)
	if err != nil {
		return nil, err
	}

	// Prevent more transactions than could possibly fit into a block.
	// It would be possible to cause memory exhaustion and panics without
	// a sane upper bound on this count.
	if txCount > maxTxPerBlock {
		str := fmt.Sprintf("too many transactions to fit into a block "+
			"[count %d, max %d]", txCount, maxTxPerBlock)
		return nil, messageError("MsgBlock.DeserializeTxLoc", str)
	}

	// Deserialize each transaction while keeping track of its location
	// within the byte stream.
	msg.Transactions = make([]*MsgTxPruned, 0, txCount)
	txLocs := make([]TxLoc, txCount)
	for i := uint64(0); i < txCount; i++ {
		txLocs[i].TxStart = fullLen - r.Len()
		tx := MsgTxPruned{}
		err := tx.Deserialize(r)
		if err != nil {
			return nil, err
		}
		msg.Transactions = append(msg.Transactions, &tx)
		txLocs[i].TxLen = (fullLen - r.Len()) - txLocs[i].TxStart
	}

	return txLocs, nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding blocks to be stored to disk, such as in a
// database, as opposed to encoding blocks for the wire.
func (msg *MsgBlockModified) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	err := writeBlockHeader(w, pver, &msg.Header)
	if err != nil {
		return err
	}

	err = WriteVarInt(w, pver, uint64(len(msg.Transactions)))
	if err != nil {
		return err
	}

	for _, tx := range msg.Transactions {
		err = tx.BtcEncode(w, pver, enc)
		if err != nil {
			return err
		}
	}
	return writeBlockExtras(w, pver, &msg.Extras)
}

// Serialize encodes the block to w using a format that suitable for long-term
// storage such as a database while respecting the Version field in the block.
// This function differs from BtcEncode in that BtcEncode encodes the block to
// the bitcoin wire protocol in order to be sent across the network.  The wire
// encoding can technically differ depending on the protocol version and doesn't
// even really need to match the format of a stored block at all.  As of the
// time this comment was written, the encoded block is the same in both
// instances, but there is a distinct difference and separating the two allows
// the API to be flexible enough to deal with changes.
func (msg *MsgBlockModified) Serialize(w io.Writer) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcEncode.
	//
	// Passing WitnessEncoding as the encoding type here indicates that
	// each of the transactions should be serialized using the witness
	// serialization structure defined in BIP0141.
	return msg.BtcEncode(w, 0, WitnessEncoding)
}

// SerializeNoWitness encodes a block to w using an identical format to
// Serialize, with all (if any) witness data stripped from all transactions.
// This method is provided in additon to the regular Serialize, in order to
// allow one to selectively encode transaction witness data to non-upgraded
// peers which are unaware of the new encoding.
func (msg *MsgBlockModified) SerializeNoWitness(w io.Writer) error {
	return msg.BtcEncode(w, 0, BaseEncoding)
}

func (msg *MsgBlockModified) SerializeNoWitnessSize() int {
	n := blockHeaderLen + VarIntSerializeSize(uint64(len(msg.Transactions)))

	for _, tx := range msg.Transactions {
		n += tx.SerializeSize()
	}
	return n
}

// SerializeSize returns the number of bytes it would take to serialize the
// block, factoring in any witness data within transaction.
func (msg *MsgBlockModified) SerializeSize() int {
	// Block header bytes + Serialized varint size for the number of
	// transactions.
	n := blockHeaderLen + VarIntSerializeSize(uint64(len(msg.Transactions)))

	for _, tx := range msg.Transactions {
		n += tx.SerializeSize()
	}

	n += msg.Extras.SerializeSize()

	return n
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgBlockModified) Command() string {
	return CmdBlockModified
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgBlockModified) MaxPayloadLength(pver uint32) uint32 {
	// Block header at 80 bytes + transaction count + max transactions
	// which can vary up to the MaxBlockPayload (including the block header
	// and transaction count).
	return MaxBlockPayload
}

// BlockHash computes the block identifier hash for this block.
func (msg *MsgBlockModified) BlockHash() chainhash.Hash {
	return msg.Header.BlockHash()
}

// TxHashes returns a slice of hashes of all of transactions in this block.
func (msg *MsgBlockModified) TxHashes() ([]chainhash.Hash, error) {
	hashList := make([]chainhash.Hash, 0, len(msg.Transactions))
	for _, tx := range msg.Transactions {
		hashList = append(hashList, tx.TxHash())
	}
	return hashList, nil
}

func NewMsgBlockModifiedFromMsgBlock(block *MsgBlock) *MsgBlockModified {
	res := &MsgBlockModified{
		Header:       block.Header,
		Transactions: make([]*MsgTxPruned, 0, len(block.Transactions)),
		Extras:       BlockExtras{},
	}
	// coinbase transction
	res.Extras.UpdateVersion(block.Transactions[0])

	for i := 0; i < len(block.Transactions); i++ {
		res.Transactions = append(res.Transactions, NewMsgTxPrunedFromMsgTx(block.Transactions[i]))
		res.Extras.Update(block.Transactions[i])
	}
	return res
}

func NewMsgBlockModified(blockHeader *BlockHeader) *MsgBlockModified {
	return &MsgBlockModified{
		Header:       *blockHeader,
		Transactions: make([]*MsgTxPruned, 0, defaultTransactionAlloc),
		Extras:       BlockExtras{},
	}
}
