package rzcfg

import "github.com/kyawmyintthein/rzerrors"

type GeneralConfigServerError struct {
	*rzerrors.RZError
	*rzerrors.ErrorWithID
}

func NewGeneralConfigServerError(code, msg string) *GeneralConfigServerError {
	return &GeneralConfigServerError{
		rzerrors.NewRZError(msg),
		rzerrors.NewErrorWithID(code),
	}
}

func (e *GeneralConfigServerError) Wrap(err error) *GeneralConfigServerError {
	e.RZError.Wrap(err)
	return e
}
