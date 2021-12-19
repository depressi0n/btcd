// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"io"
)

type TxInExtra struct {
	SignatureScript []byte
}

func (t *TxInExtra) SerializeSize() int {
	// Outpoint Hash 32 bytes + Outpoint Index 4 bytes + Sequence 4 bytes +
	// serialized varint size for the length of SignatureScript +
	// SignatureScript bytes.
	return VarIntSerializeSize(uint64(len(t.SignatureScript))) +
		len(t.SignatureScript)
}

func NewTxInExtra(signatureScript []byte) *TxInExtra {
	return &TxInExtra{
		SignatureScript: signatureScript,
	}
}

type TxOutExtra struct {
	Value    int64
	PkScript []byte
}

func (t *TxOutExtra) SerializeSize() int {
	// Value 8 bytes + serialized varint size for the length of PkScript +
	// PkScript bytes.
	return 8 + VarIntSerializeSize(uint64(len(t.PkScript))) + len(t.PkScript)
}

func (t *TxOutExtra) Hash() chainhash.Hash {
	// Value 8 bytes + serialized varint size for the length of PkScript +
	// PkScript bytes.
	buf := bytes.NewBuffer(make([]byte, 0, t.SerializeSize()))
	err := binarySerializer.PutUint64(buf, littleEndian, uint64(t.Value))
	if err != nil {
		return chainhash.Hash{}
	}
	err = WriteVarBytes(buf, 0, t.PkScript)
	if err != nil {
		return chainhash.Hash{}
	}
	return chainhash.DoubleHashH(buf.Bytes())
}

func NewTxOutExtra(value int64, pkScript []byte) *TxOutExtra {
	return &TxOutExtra{
		Value:    value,
		PkScript: pkScript,
	}
}

type MsgTxPruned struct {
	Version int32
	TxIns   []chainhash.Hash
	TxOuts  []chainhash.Hash
}

type MsgTxModified struct {
	Version    int32
	TxIns      []chainhash.Hash
	TxOuts     []chainhash.Hash
	TxInExtra  []*TxInExtra
	TxOutExtra []*TxOutExtra
	LockTime   uint32
}

// AddTxIn adds a transaction input to the message.
func (msg *MsgTxModified) AddTxIn(ti chainhash.Hash) {
	msg.TxIns = append(msg.TxIns, ti)
}
func (msg *MsgTxPruned) AddTxIn(ti chainhash.Hash) {
	msg.TxIns = append(msg.TxIns, ti)
}

func (msg *MsgTxModified) AddTxOut(to chainhash.Hash) {
	msg.TxOuts = append(msg.TxOuts, to)
}
func (msg *MsgTxPruned) AddTxOut(to chainhash.Hash) {
	msg.TxOuts = append(msg.TxOuts, to)
}

// TxHash generates the Hash for the transaction.
func (msg *MsgTxModified) TxHash() chainhash.Hash {
	// Encode the transaction and calculate double sha256 on the result.
	// Ignore the error returns since the only way the encode could fail
	// is being out of memory or due to nil pointers, both of which would
	// cause a run-time panic.
	buf := bytes.NewBuffer(make([]byte, 0, msg.SerializeSize()))
	_ = msg.Serialize(buf)
	return chainhash.DoubleHashH(buf.Bytes())
}
func (msg *MsgTxPruned) TxHash() chainhash.Hash {
	// Encode the transaction and calculate double sha256 on the result.
	// Ignore the error returns since the only way the encode could fail
	// is being out of memory or due to nil pointers, both of which would
	// cause a run-time panic.
	buf := bytes.NewBuffer(make([]byte, 0, msg.SerializeSize()))
	_ = msg.Serialize(buf)
	return chainhash.DoubleHashH(buf.Bytes())
}

// Copy creates a deep copy of a transaction so that the original does not get
// modified when the copy is manipulated.
func (msg *MsgTxModified) Copy() *MsgTxModified {
	// Create new tx and start by copying primitive values and making space
	// for the transaction inputs and outputs.
	newTx := MsgTxModified{
		Version:    msg.Version,
		TxIns:      make([]chainhash.Hash, 0, len(msg.TxIns)),
		TxOuts:     make([]chainhash.Hash, 0, len(msg.TxOuts)),
		TxInExtra:  make([]*TxInExtra, 0, len(msg.TxInExtra)),
		TxOutExtra: make([]*TxOutExtra, 0, len(msg.TxOutExtra)),
		LockTime:   msg.LockTime,
	}
	// Deep copy the old TxIns and TxOuts data.
	for _, oldTxIn := range msg.TxIns {
		tmp, _ := chainhash.NewHash(oldTxIn.CloneBytes())
		newTx.TxIns = append(newTx.TxIns, *tmp)
	}
	for _, oldTxOut := range msg.TxOuts {
		tmp, _ := chainhash.NewHash(oldTxOut.CloneBytes())
		newTx.TxIns = append(newTx.TxIns, *tmp)
	}
	// Deep copy the old Extra data
	for _, oldTxInExtra := range msg.TxInExtra {
		tmp := &TxInExtra{
			SignatureScript: make([]byte, len(oldTxInExtra.SignatureScript)),
		}
		copy(tmp.SignatureScript, oldTxInExtra.SignatureScript)
		newTx.TxInExtra = append(newTx.TxInExtra, tmp)
	}
	for _, oldTxOutExtra := range msg.TxOutExtra {
		// Deep copy the old PkScript
		var newScript []byte
		oldScript := oldTxOutExtra.PkScript
		oldScriptLen := len(oldScript)
		if oldScriptLen > 0 {
			newScript = make([]byte, oldScriptLen)
			copy(newScript, oldScript[:oldScriptLen])
		}

		// Create new txOut with the deep copied data and append it to
		// new Tx.
		newTxOut := TxOutExtra{
			Value:    oldTxOutExtra.Value,
			PkScript: newScript,
		}
		newTx.TxOutExtra = append(newTx.TxOutExtra, &newTxOut)
	}

	return &newTx
}
func (msg *MsgTxPruned) Copy() *MsgTxPruned {
	// Create new tx and start by copying primitive values and making space
	// for the transaction inputs and outputs.
	newTx := MsgTxPruned{
		Version: msg.Version,
		TxIns:   make([]chainhash.Hash, 0, len(msg.TxIns)),
		TxOuts:  make([]chainhash.Hash, 0, len(msg.TxOuts)),
	}
	// Deep copy the old TxIns and TxOuts data.
	for _, oldTxIn := range msg.TxIns {
		tmp, _ := chainhash.NewHash(oldTxIn.CloneBytes())
		newTx.TxIns = append(newTx.TxIns, *tmp)
	}
	for _, oldTxOut := range msg.TxOuts {
		tmp, _ := chainhash.NewHash(oldTxOut.CloneBytes())
		newTx.TxIns = append(newTx.TxIns, *tmp)
	}

	return &newTx
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding transactions stored to disk, such as in a
// database, as opposed to decoding transactions from the wire.
func (msg *MsgTxModified) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	version, err := binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return err
	}
	msg.Version = int32(version)

	var totalScriptSize uint64
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	msg.TxIns = make([]chainhash.Hash, count)
	for i := uint64(0); i < count; i++ {
		_, err = io.ReadFull(r, msg.TxIns[i][:])
		if err != nil {
			return err
		}
	}

	count, err = ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	msg.TxOuts = make([]chainhash.Hash, count)
	for i := uint64(0); i < count; i++ {
		_, err = io.ReadFull(r, msg.TxOuts[i][:])
		if err != nil {
			return err
		}
	}

	count, err = ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	msg.TxInExtra = make([]*TxInExtra, count)
	for i := uint64(0); i < count; i++ {
		err = readTxInExtra(r, pver, msg.Version, msg.TxInExtra[i])
		if err != nil {
			return err
		}
		totalScriptSize += uint64(len(msg.TxInExtra[i].SignatureScript))
	}

	count, err = ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	msg.TxOutExtra = make([]*TxOutExtra, count)
	for i := uint64(0); i < count; i++ {
		// The pointer is set now in case a script buffer is borrowed
		// and needs to be returned to the pool on error.
		err = readTxOutExtra(r, pver, msg.Version, msg.TxOutExtra[i])
		if err != nil {
			return err
		}
		totalScriptSize += uint64(len(msg.TxOutExtra[i].PkScript))
	}

	msg.LockTime, err = binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return err
	}

	// Create a single allocation to house all of the scripts and set each
	// input signature script and output public key script to the
	// appropriate subslice of the overall contiguous buffer.  Then, return
	// each individual script buffer back to the pool so they can be reused
	// for future deserializations.  This is done because it significantly
	// reduces the number of allocations the garbage collector needs to
	// track, which in turn improves performance and drastically reduces the
	// amount of runtime overhead that would otherwise be needed to keep
	// track of millions of small allocations.
	//
	// NOTE: It is no longer valid to call the returnScriptBuffers closure
	// after these blocks of code run because it is already done and the
	// scripts in the transaction inputs and outputs no longer point to the
	// buffers.
	var offset uint64
	scripts := make([]byte, totalScriptSize)
	for i := 0; i < len(msg.TxInExtra); i++ {
		// Copy the signature script into the contiguous buffer at the
		// appropriate offset.
		signatureScript := msg.TxInExtra[i].SignatureScript
		copy(scripts[offset:], signatureScript)

		// Reset the signature script of the transaction input to the
		// slice of the contiguous buffer where the script lives.
		scriptSize := uint64(len(signatureScript))
		end := offset + scriptSize
		msg.TxInExtra[i].SignatureScript = scripts[offset:end:end]
		offset += scriptSize

		// Return the temporary script buffer to the pool.
		scriptPool.Return(signatureScript)
	}
	for i := 0; i < len(msg.TxOutExtra); i++ {
		// Copy the public key script into the contiguous buffer at the
		// appropriate offset.
		pkScript := msg.TxOutExtra[i].PkScript
		copy(scripts[offset:], pkScript)

		// Reset the public key script of the transaction output to the
		// slice of the contiguous buffer where the script lives.
		scriptSize := uint64(len(pkScript))
		end := offset + scriptSize
		msg.TxOutExtra[i].PkScript = scripts[offset:end:end]
		offset += scriptSize

		// Return the temporary script buffer to the pool.
		scriptPool.Return(pkScript)
	}

	return nil
}
func (msg *MsgTxPruned) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	version, err := binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return err
	}
	msg.Version = int32(version)

	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	msg.TxIns = make([]chainhash.Hash, count)
	for i := uint64(0); i < count; i++ {
		_, err = io.ReadFull(r, msg.TxIns[i][:])
		if err != nil {
			return err
		}
	}

	count, err = ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	msg.TxOuts = make([]chainhash.Hash, count)
	for i := uint64(0); i < count; i++ {
		_, err = io.ReadFull(r, msg.TxOuts[i][:])
		if err != nil {
			return err
		}
	}

	count, err = ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	return nil
}

// Deserialize decodes a transaction from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field in the transaction.  This function differs from BtcDecode
// in that BtcDecode decodes from the bitcoin wire protocol as it was sent
// across the network.  The wire encoding can technically differ depending on
// the protocol version and doesn't even really need to match the format of a
// stored transaction at all.  As of the time this comment was written, the
// encoded transaction is the same in both instances, but there is a distinct
// difference and separating the two allows the API to be flexible enough to
// deal with changes.
func (msg *MsgTxModified) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcDecode.
	return msg.BtcDecode(r, 0, WitnessEncoding)
}
func (msg *MsgTxPruned) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcDecode.
	return msg.BtcDecode(r, 0, WitnessEncoding)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding transactions to be stored to disk, such as in a
// database, as opposed to encoding transactions for the wire.
func (msg *MsgTxModified) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	err := binarySerializer.PutUint32(w, littleEndian, uint32(msg.Version))
	if err != nil {
		return err
	}

	count := uint64(len(msg.TxIns))
	err = WriteVarInt(w, pver, count)
	if err != nil {
		return err
	}

	for _, ti := range msg.TxIns {
		_, err = w.Write(ti[:])
		if err != nil {
			return err
		}
	}

	count = uint64(len(msg.TxOuts))
	err = WriteVarInt(w, pver, count)
	if err != nil {
		return err
	}

	for _, to := range msg.TxOuts {
		_, err = w.Write(to[:])
		if err != nil {
			return err
		}
	}

	count = uint64(len(msg.TxInExtra))
	err = WriteVarInt(w, pver, count)
	if err != nil {
		return err
	}

	for _, tiextra := range msg.TxInExtra {
		err = WriteVarBytes(w, pver, tiextra.SignatureScript)
		if err != nil {
			return err
		}
	}

	count = uint64(len(msg.TxOutExtra))
	err = WriteVarInt(w, pver, count)
	if err != nil {
		return err
	}

	for _, toextra := range msg.TxOutExtra {
		err = WriteTxOutExtra(w, pver, msg.Version, toextra)
		if err != nil {
			return err
		}
	}
	return binarySerializer.PutUint32(w, littleEndian, msg.LockTime)
}
func (msg *MsgTxPruned) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	err := binarySerializer.PutUint32(w, littleEndian, uint32(msg.Version))
	if err != nil {
		return err
	}

	count := uint64(len(msg.TxIns))
	err = WriteVarInt(w, pver, count)
	if err != nil {
		return err
	}

	for _, ti := range msg.TxIns {
		_, err = w.Write(ti[:])
		if err != nil {
			return err
		}
	}

	count = uint64(len(msg.TxOuts))
	err = WriteVarInt(w, pver, count)
	if err != nil {
		return err
	}

	for _, to := range msg.TxOuts {
		_, err = w.Write(to[:])
		if err != nil {
			return err
		}
	}

	return nil
}

// Serialize encodes the transaction to w using a format that suitable for
// long-term storage such as a database while respecting the Version field in
// the transaction.  This function differs from BtcEncode in that BtcEncode
// encodes the transaction to the bitcoin wire protocol in order to be sent
// across the network.  The wire encoding can technically differ depending on
// the protocol version and doesn't even really need to match the format of a
// stored transaction at all.  As of the time this comment was written, the
// encoded transaction is the same in both instances, but there is a distinct
// difference and separating the two allows the API to be flexible enough to
// deal with changes.
func (msg *MsgTxModified) Serialize(w io.Writer) error {
	return msg.BtcEncode(w, 0, BaseEncoding)
}
func (msg *MsgTxPruned) Serialize(w io.Writer) error {
	return msg.BtcEncode(w, 0, BaseEncoding)
}

// baseSize returns the serialized size of the transaction without accounting
// for any witness data.
func (msg *MsgTxModified) baseSize() int {
	// Version 4 bytes + LockTime 4 bytes + Serialized varint size for the
	// number of transaction inputs and outputs.
	n := 8 + VarIntSerializeSize(uint64(len(msg.TxIns)))*2 +
		VarIntSerializeSize(uint64(len(msg.TxOuts)))*2

	for _, txInExtra := range msg.TxInExtra {
		n += 32
		n += txInExtra.SerializeSize()
	}

	for _, txOutExtra := range msg.TxOutExtra {
		n += 32
		n += txOutExtra.SerializeSize()
	}

	return n
}

// baseSize returns the serialized size of the transaction without accounting
// for any witness data.
func (msg *MsgTxPruned) baseSize() int {
	// Version 4 bytes + LockTime 4 bytes + Serialized varint size for the
	// number of transaction inputs and outputs.
	n := 8 + VarIntSerializeSize(uint64(len(msg.TxIns))) + len(msg.TxIns)*32 +
		VarIntSerializeSize(uint64(len(msg.TxOuts))) + len(msg.TxOuts)*32

	return n
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction.
func (msg *MsgTxModified) SerializeSize() int {
	n := msg.baseSize()
	return n
}

func (msg *MsgTxPruned) SerializeSize() int {
	n := msg.baseSize()
	return n
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgTxModified) Command() string {
	return CmdTxModified
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgTxModified) MaxPayloadLength(pver uint32) uint32 {
	return MaxBlockPayload
}

func (msg *MsgTxPruned) MaxPayloadLength(pver uint32) uint32 {
	return MaxBlockPayload
}

// PkScriptLocs returns a slice containing the start of each public key script
// within the raw serialized transaction.  The caller can easily obtain the
// length of each script by using len on the script available via the
// appropriate transaction output entry.
func (msg *MsgTxModified) PkScriptLocs() []int {
	numTxOut := len(msg.TxOuts)
	if numTxOut == 0 {
		return nil
	}
	n := 4 + VarIntSerializeSize(uint64(len(msg.TxIns)))*2 + len(msg.TxIns)*32 +
		VarIntSerializeSize(uint64(numTxOut))*2 + numTxOut*32

	for _, txInExtra := range msg.TxInExtra {
		n += txInExtra.SerializeSize()
	}
	// Calculate and set the appropriate offset for each public key script.
	pkScriptLocs := make([]int, numTxOut)
	for i, txOut := range msg.TxOutExtra {
		// The offset of the script in the transaction output is:
		//
		// Value 8 bytes + serialized varint size for the length of
		// PkScript.
		n += 8 + VarIntSerializeSize(uint64(len(txOut.PkScript)))
		pkScriptLocs[i] = n
		n += len(txOut.PkScript)
	}

	return pkScriptLocs
}

func NewMsgTxModified(version int32) *MsgTxModified {
	return &MsgTxModified{
		Version:    version,
		TxIns:      make([]chainhash.Hash, 0, defaultTxInOutAlloc),
		TxOuts:     make([]chainhash.Hash, 0, defaultTxInOutAlloc),
		TxInExtra:  make([]*TxInExtra, 0, defaultTxInOutAlloc),
		TxOutExtra: make([]*TxOutExtra, 0, defaultTxInOutAlloc),
	}
}
func NewMsgTxPruned(version int32) *MsgTxPruned {
	return &MsgTxPruned{
		Version: version,
		TxIns:   make([]chainhash.Hash, 0, defaultTxInOutAlloc),
		TxOuts:  make([]chainhash.Hash, 0, defaultTxInOutAlloc),
	}
}

func NewMsgTxPrunedFromMsgTx(tx *MsgTx) *MsgTxPruned {
	res := &MsgTxPruned{
		Version: tx.Version,
		TxIns:   make([]chainhash.Hash, 0, len(tx.TxIn)),
		TxOuts:  make([]chainhash.Hash, 0, len(tx.TxOut)),
	}
	for i := 0; i < len(tx.TxIn); i++ {
		res.TxIns = append(res.TxIns, chainhash.Hash{})
	}
	for i := 0; i < len(tx.TxOut); i++ {
		used := NewTxOutExtra(tx.TxOut[i].Value, tx.TxOut[i].PkScript)
		res.TxOuts = append(res.TxOuts, used.Hash())
	}
	return res
}
func NewMsgTxModifiedFromMsgTx(tx *MsgTx) *MsgTxModified {
	res := &MsgTxModified{
		Version:    tx.Version,
		TxIns:      make([]chainhash.Hash, 0, len(tx.TxIn)),
		TxOuts:     make([]chainhash.Hash, 0, len(tx.TxOut)),
		TxInExtra:  make([]*TxInExtra, 0, len(tx.TxIn)),
		TxOutExtra: make([]*TxOutExtra, 0, len(tx.TxOut)),
	}
	for i := 0; i < len(tx.TxIn); i++ {
		res.TxIns = append(res.TxIns, chainhash.Hash{})
		res.TxInExtra = append(res.TxInExtra, NewTxInExtra(tx.TxIn[i].SignatureScript))
	}
	for i := 0; i < len(tx.TxOut); i++ {
		res.TxOutExtra = append(res.TxOutExtra, NewTxOutExtra(tx.TxOut[i].Value, tx.TxOut[i].PkScript))
		res.TxOuts = append(res.TxOuts, res.TxOutExtra[i].Hash())
	}
	return res
}

// readTxIn reads the next sequence of bytes from r as a transaction input
// (TxIn).
func readTxInExtra(r io.Reader, pver uint32, version int32, ti *TxInExtra) error {
	var err error
	ti.SignatureScript, err = readScript(r, pver, MaxMessagePayload,
		"transaction input signature script")
	return err
}

// writeTxIn encodes ti to the bitcoin protocol encoding for a transaction
// input (TxIn) to w.
func writeTxInExtra(w io.Writer, pver uint32, version int32, ti *TxInExtra) error {
	err := WriteVarBytes(w, pver, ti.SignatureScript)
	return err
}

// readTxOut reads the next sequence of bytes from r as a transaction output
// (TxOut).
func readTxOutExtra(r io.Reader, pver uint32, version int32, to *TxOutExtra) error {
	err := readElement(r, &to.Value)
	if err != nil {
		return err
	}

	to.PkScript, err = readScript(r, pver, MaxMessagePayload,
		"transaction output public key script")
	return err
}

func WriteTxOutExtra(w io.Writer, pver uint32, version int32, to *TxOutExtra) error {
	err := binarySerializer.PutUint64(w, littleEndian, uint64(to.Value))
	if err != nil {
		return err
	}

	return WriteVarBytes(w, pver, to.PkScript)
}
