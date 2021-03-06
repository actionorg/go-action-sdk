package horizon

import (
	"encoding/json"

	"github.com/actionorg/go-action-sdk/support/errors"
	"github.com/actionorg/go-action-sdk/xdr"
)

func (herr *Error) Error() string {
	return `Horizon error: "` + herr.Problem.Title + `". Check horizon.Error.Problem for more information.`
}

// Envelope extracts the transaction envelope that triggered this error from the
// extra fields.
func (herr *Error) Envelope() (*xdr.TransactionEnvelope, error) {
	raw, ok := herr.Problem.Extras["envelope_xdr"]
	if !ok {
		return nil, ErrEnvelopeNotPopulated
	}

	var b64 string
	var result xdr.TransactionEnvelope

	err := json.Unmarshal(raw, &b64)
	if err != nil {
		return nil, errors.Wrap(err, "json decode failed")
	}

	err = xdr.SafeUnmarshalBase64(b64, &result)
	if err != nil {
		return nil, errors.Wrap(err, "xdr decode failed")
	}

	return &result, nil
}

// ResultCodes extracts a result code summary from the error, if possible.
func (herr *Error) ResultCodes() (*TransactionResultCodes, error) {
	if herr.Problem.Type != "transaction_failed" {
		return nil, ErrTransactionNotFailed
	}

	raw, ok := herr.Problem.Extras["result_codes"]
	if !ok {
		return nil, ErrResultCodesNotPopulated
	}

	var result TransactionResultCodes
	err := json.Unmarshal(raw, &result)
	if err != nil {
		return nil, errors.Wrap(err, "json decode failed")
	}

	return &result, nil
}
