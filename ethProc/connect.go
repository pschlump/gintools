package ethProc

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
)

// # /Users/pschlump/go/src/gitlab.com/pschlump/ep_series_1/cryptovipers
// "gitlab.com/pschlump/ep_series_1/cryptovipers/lib/ViperToken"

// var eCfg *EthConfigData

func ConnectToEthereum() (err error) {

	if eCfg == nil {
		panic("Must setup configuration for ethProc first.  Call ethProc.Setup!")
	}

	var client *ethclient.Client
	client, err = ethclient.Dial(eCfg.URL_8545)
	if err != nil {
		return fmt.Errorf("Error connecting to Geth server: %s error:[%s]", eCfg.URL_8545, err)
	}
	eCfg.Client = client

	return
}
