// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"io"
)

type BlockExtras struct {
	Version   int32
	InExtras  []*TxInExtra
	OutExtras []*TxOutExtra
}

// BlockHash computes the block identifier hash for the given block header.
func (e *BlockExtras) BlockHash() chainhash.Hash {
	// Encode the header and double sha256 everything prior to the number of
	// transactions.  Ignore the error returns since there is no way the
	// encode could fail except being out of memory which would cause a
	// run-time panic.
	buf := bytes.NewBuffer(make([]byte, 0, MaxBlockHeaderPayload))
	_ = writeBlockExtras(buf, 0, e)

	return chainhash.DoubleHashH(buf.Bytes())
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding block headers stored to disk, such as in a
// database, as opposed to decoding block headers from the wire.
func (e *BlockExtras) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	return readBlockExtras(r, pver, e)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding block headers to be stored to disk, such as in a
// database, as opposed to encoding block headers for the wire.
func (e *BlockExtras) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	return writeBlockExtras(w, pver, e)
}

// Deserialize decodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field.
func (e *BlockExtras) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of readBlockHeader.
	return readBlockExtras(r, 0, e)
}

// Serialize encodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field.
func (e *BlockExtras) Serialize(w io.Writer) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of writeBlockHeader.
	return writeBlockExtras(w, 0, e)
}
func (e *BlockExtras) SerializeSize() int {
	n := 8 + VarIntSerializeSize(uint64(len(e.InExtras))) +
		VarIntSerializeSize(uint64(len(e.OutExtras)))
	for _, txInExtra := range e.InExtras {
		n += txInExtra.SerializeSize()
	}
	for _, txOutExtra := range e.OutExtras {
		n += 32
		n += txOutExtra.SerializeSize()
	}

	return n
}
func (e *BlockExtras) UpdateVersion(tx *MsgTx) {
	e.Version = tx.Version
}

func (e *BlockExtras) Update(tx *MsgTx) {
	for i := 0; i < len(tx.TxIn); i++ {
		e.InExtras = append(e.InExtras, NewTxInExtra(tx.TxIn[i].SignatureScript))
	}
	for i := 0; i < len(tx.TxOut); i++ {
		e.OutExtras = append(e.OutExtras, NewTxOutExtra(tx.TxOut[i].Value, tx.TxOut[i].PkScript))
	}
}

func NewBlockExtra(version int32, inExtras []*TxInExtra, outExtras []*TxOutExtra) *BlockExtras {
	return &BlockExtras{
		Version:   version,
		InExtras:  inExtras,
		OutExtras: outExtras,
	}
}

// readBlockHeader reads a bitcoin block header from r.  See Deserialize for
// decoding block headers stored to disk, such as in a database, as opposed to
// decoding from the wire.
func readBlockExtras(r io.Reader, pver uint32, be *BlockExtras) error {
	var err error
	err = readElements(r, &be.Version)
	if err != nil {
		return err
	}
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	count, err = ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	be.InExtras = make([]*TxInExtra, count)
	for i := uint64(0); i < count; i++ {
		err = readTxInExtra(r, pver, be.Version, be.InExtras[i])
		if err != nil {
			return err
		}
	}

	count, err = ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	be.OutExtras = make([]*TxOutExtra, count)
	for i := uint64(0); i < count; i++ {
		// The pointer is set now in case a script buffer is borrowed
		// and needs to be returned to the pool on error.
		err = readTxOutExtra(r, pver, be.Version, be.OutExtras[i])
		if err != nil {
			return err
		}
	}

	return nil
}

// writeBlockHeader writes a bitcoin block header to w.  See Serialize for
// encoding block headers to be stored to disk, such as in a database, as
// opposed to encoding for the wire.
func writeBlockExtras(w io.Writer, pver uint32, be *BlockExtras) error {
	var err error
	err = writeElements(w, be.Version)
	if err != nil {
		return err
	}
	err = WriteVarInt(w, pver, uint64(len(be.InExtras)))
	if err != nil {
		return err
	}
	for i := 0; i < len(be.InExtras); i++ {
		err = writeTxInExtra(w, pver, be.Version, be.InExtras[i])
		if err != nil {
			return err
		}
	}
	err = WriteVarInt(w, pver, uint64(len(be.OutExtras)))
	if err != nil {
		return err
	}
	for i := 0; i < len(be.OutExtras); i++ {
		err = WriteTxOutExtra(w, pver, be.Version, be.OutExtras[i])
		if err != nil {
			return err
		}
	}
	return nil
}
