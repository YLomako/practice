package dnstunnel

type Config struct {
	LengthThreshold    int     `json:"length_threshold"`
	EntropyThreshold   float64 `json:"entropy_threshold"`
	BeaconJitter       float64 `json:"beacon_jitter"`
	EnableLengthCheck  bool    `json:"enable_length_check"`
	EnableEntropyCheck bool    `json:"enable_entropy_check"`
	EnableBeaconCheck  bool    `json:"enable_beacon_check"`
	BlockDuration      int     `json:"block_duration"`
	LogAllQueries      bool    `json:"log_all_queries"`
}

func DefaultConfig() Config {
	return Config{
		LengthThreshold:    20,
		EntropyThreshold:   3.5,
		BeaconJitter:       1.0,
		EnableLengthCheck:  true,
		EnableEntropyCheck: true,
		EnableBeaconCheck:  true,
		BlockDuration:      300,
		LogAllQueries:      false,
	}
}
