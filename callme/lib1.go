package callme

type StdErrorReturn struct {
	Status   string `json:"status"`
	Msg      string `json:",omitempty"`
	Code     string `json:",omitempty"`
	Location string `json:",omitempty"`
	LogUUID  string `json:",omitempty"`
}
