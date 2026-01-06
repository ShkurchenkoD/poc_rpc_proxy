package chain

type BalanceResult struct {
	Chain    string         `json:"chain"`
	Address  string         `json:"address"`
	Balance  string         `json:"balance"`
	Unit     string         `json:"unit"`
	Decimals int            `json:"decimals"`
	Raw      map[string]any `json:"raw"`
}

type TransactionResult struct {
	Chain string         `json:"chain"`
	TxID  string         `json:"txid"`
	Raw   map[string]any `json:"raw"`
}

type SendResult struct {
	Chain   string         `json:"chain"`
	TxID    string         `json:"txid,omitempty"`
	Success bool           `json:"success"`
	Raw     map[string]any `json:"raw"`
}

type ResourceResult struct {
	Chain        string         `json:"chain"`
	Address      string         `json:"address"`
	EnergyLimit  string         `json:"energy_limit"`
	EnergyUsed   string         `json:"energy_used"`
	NetLimit     string         `json:"net_limit"`
	NetUsed      string         `json:"net_used"`
	FreeNetLimit string         `json:"free_net_limit"`
	FreeNetUsed  string         `json:"free_net_used"`
	Raw          map[string]any `json:"raw"`
}
