/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package gm

import (
	"crypto/sha256"
	"crypto/sha512"
	"github.com/tjfoc/gmsm/sm3"
	"reflect"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

// NewDefaultSecurityLevel returns a new instance of the guomi-based BCCSP
// at security level 256, hash family SHA2 and using FolderBasedKeyStore as KeyStore.
func NewDefaultSecurityLevel(keyStorePath string) (bccsp.BCCSP, error) {
	ks := &fileBasedKeyStore{}
	if err := ks.Init(nil, keyStorePath, false); err != nil {
		return nil, errors.Wrapf(err, "Failed initializing key store at [%v]", keyStorePath)
	}

	return NewWithParams(256, "SHA2", ks)
}

// NewDefaultSecurityLevel returns a new instance of the guomi-based BCCSP
// at security level 256, hash family SHA2 and using the passed KeyStore.
func NewDefaultSecurityLevelWithKeystore(keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	return NewWithParams(256, "SHA2", keyStore)
}

// NewWithParams returns a new instance of the guomi-based BCCSP
// set at the passed security level, hash family and KeyStore.
func NewWithParams(securityLevel int, hashFamily string, keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	// Init config
	conf := &config{}
	err := conf.setSecurityLevel(securityLevel, hashFamily)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed initializing configuration at [%v,%v]", securityLevel, hashFamily)
	}

	gmbccsp, err := New(keyStore)
	if err != nil {
		return nil, err
	}

	// Notice that errors are ignored here because some test will fail if one
	// of the following call fails.

	// Set the Encryptors
	gmbccsp.AddWrapper(reflect.TypeOf(&gmsm4PrivateKey{}), &gmsm4Encryptor{})

	// Set the Decryptors
	gmbccsp.AddWrapper(reflect.TypeOf(&gmsm4PrivateKey{}), &gmsm4Decryptor{})

	// Set the Signers
	gmbccsp.AddWrapper(reflect.TypeOf(&gmsm2PrivateKey{}), &gmsm2Signer{})
	gmbccsp.AddWrapper(reflect.TypeOf(&ecdsaPrivateKey{}), &ecdsaPrivateKeySigner{})

	// Set the Verifiers
	gmbccsp.AddWrapper(reflect.TypeOf(&gmsm2PrivateKey{}), &gmsm2PrivateKeyVerifier{})
	gmbccsp.AddWrapper(reflect.TypeOf(&gmsm2PublicKey{}), &gmsm2PublicKeyKeyVerifier{})
	gmbccsp.AddWrapper(reflect.TypeOf(&ecdsaPrivateKey{}), &ecdsaPrivateKeyVerifier{})
	gmbccsp.AddWrapper(reflect.TypeOf(&ecdsaPublicKey{}), &ecdsaPublicKeyKeyVerifier{})

	// Set the Hashers
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHAOpts{}), &hasher{hash: conf.hashFunction})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.GMSM3Opts{}), &hasher{hash: sm3.New})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA256Opts{}), &hasher{hash: sha256.New})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA384Opts{}), &hasher{hash: sha512.New384})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA3_256Opts{}), &hasher{hash: sha3.New256})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA3_384Opts{}), &hasher{hash: sha3.New384})

	// Set the key generators
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.GMSM2KeyGenOpts{}), &gmsm2KeyGenerator{})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.GMSM4KeyGenOpts{}), &gmsm4KeyGenerator{length: 32})

	// Set the key derivers
	gmbccsp.AddWrapper(reflect.TypeOf(&gmsm2PublicKey{}), &smPublicKeyKeyDeriver{})

	// Set the key importers
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.GMSM4ImportKeyOpts{}), &gmsm4ImportKeyOptsKeyImporter{})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.GMSM2PrivateKeyImportOpts{}), &gmsm2PrivateKeyImportOptsKeyImporter{})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.GMSM2PublicKeyImportOpts{}), &gmsm2PublicKeyImportOptsKeyImporter{})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAPKIXPublicKeyImportOpts{}), &ecdsaPKIXPublicKeyImportOptsKeyImporter{})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAPrivateKeyImportOpts{}), &ecdsaPrivateKeyImportOptsKeyImporter{})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{}), &ecdsaGoPublicKeyImportOptsKeyImporter{})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.X509PublicKeyImportOpts{}), &x509PublicKeyImportOptsKeyImporter{bccsp: gmbccsp})

	return gmbccsp, nil
}
