package factory

import (
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/gm"
	"github.com/pkg/errors"
)

const (
	// GuomiBasedFactoryName is the name of the factory of the guomi-based BCCSP implementation
	GuomiBasedFactoryName = "GM"
)

// GMFactory is the factory of the guomi-based BCCSP.
type GMFactory struct{}

// Name returns the name of this factory
func (f *GMFactory) Name() string {
	return GuomiBasedFactoryName
}

// Get returns an instance of BCCSP using Opts.
func (f *GMFactory) Get(config *FactoryOpts) (bccsp.BCCSP, error) {
	// Validate arguments
	if config == nil || config.SwOpts == nil {
		return nil, errors.New("Invalid config. It must not be nil.")
	}

	gmOpts := config.SwOpts

	var ks bccsp.KeyStore
	if gmOpts.Ephemeral == true {
		ks = gm.NewDummyKeyStore()
	} else if gmOpts.FileKeystore != nil {
		fks, err := gm.NewFileBasedKeyStore(nil, gmOpts.FileKeystore.KeyStorePath, false)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to initialize gm software key store")
		}
		ks = fks
	} else {
		// Default to dummy key store
		ks = gm.NewDummyKeyStore()
	}

	return gm.NewWithParams(gmOpts.SecLevel, gmOpts.HashFamily, ks)
}
