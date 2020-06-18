package netlink

import (
	"bytes"
	"io"
)

type TCPInfo struct {
	State                     uint8  `json:"state"`
	Ca_state                  uint8  `json:"ca_state"`
	Retransmits               uint8  `json:"retransmits"`
	Probes                    uint8  `json:"probes"`
	Backoff                   uint8  `json:"backoff"`
	Options                   uint8  `json:"options"`
	Snd_wscale                uint8  `json:"snd_wscale"`
	Rcv_wscale                uint8  `json:"rcv_wscale"`
	Delivery_rate_app_limited uint8  `json:"delivery_rate_app_limited"`
	Fastopen_client_fail      uint8  `json:"fastopen_client_fail"`
	Rto                       uint32 `json:"rto"`
	Ato                       uint32 `json:"ato"`
	Snd_mss                   uint32 `json:"snd_mss"`
	Rcv_mss                   uint32 `json:"rcv_mss"`
	Unacked                   uint32 `json:"unacked"`
	Sacked                    uint32 `json:"sacked"`
	Lost                      uint32 `json:"lost"`
	Retrans                   uint32 `json:"retrans"`
	Fackets                   uint32 `json:"fackets"`
	Last_data_sent            uint32 `json:"last_data_sent"`
	Last_ack_sent             uint32 `json:"last_ack_sent"`
	Last_data_recv            uint32 `json:"last_data_recv"`
	Last_ack_recv             uint32 `json:"last_ack_recv"`
	Pmtu                      uint32 `json:"pmtu"`
	Rcv_ssthresh              uint32 `json:"rcv_ssthresh"`
	Rtt                       uint32 `json:"rtt"`
	Rttvar                    uint32 `json:"rttvar"`
	Snd_ssthresh              uint32 `json:"snd_sshthresh"`
	Snd_cwnd                  uint32 `json:"send_cwnd"`
	Advmss                    uint32 `json:"advmss"`
	Reordering                uint32 `json:"reordering"`
	Rcv_rtt                   uint32 `json:"rcv_rtt"`
	Rcv_space                 uint32 `json:"rcv_space"`
	Total_retrans             uint32 `json:"total_retrains"`
	Pacing_rate               uint64 `json:"pacing_rate"`
	Max_pacing_rate           uint64 `json:"max_pacing_rate"`
	Bytes_acked               uint64 `json:"bytes_acked"`    /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
	Bytes_received            uint64 `json:"bytes_received"` /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
	Segs_out                  uint32 `json:"segs_out"`       /* RFC4898 tcpEStatsPerfSegsOut */
	Segs_in                   uint32 `json:"segs_in"`        /* RFC4898 tcpEStatsPerfSegsIn */
	Notsent_bytes             uint32 `json:"notsent_bytes"`
	Min_rtt                   uint32 `json:"min_rtt"`
	Data_segs_in              uint32 `json:"data_segs_in"`   /* RFC4898 tcpEStatsDataSegsIn */
	Data_segs_out             uint32 `json:"data_segs_out" ` /* RFC4898 tcpEStatsDataSegsOut */
	Delivery_rate             uint64 `json:"delivery_rate"`
	Busy_time                 uint64 `json:"busy_time"`      /* Time (usec) busy sending data */
	Rwnd_limited              uint64 `json:"rwnd_limited"`   /* Time (usec) limited by receive window */
	Sndbuf_limited            uint64 `json:"sndbuf_limited"` /* Time (usec) limited by send buffer */
	Delivered                 uint32 `json:"delivered"`
	Delivered_ce              uint32 `json:"delivered_ce"`
	Bytes_sent                uint64 `json:"bytes_sent"`    /* RFC4898 tcpEStatsPerfHCDataOctetsOut */
	Bytes_retrans             uint64 `json:"bytes_retrans"` /* RFC4898 tcpEStatsPerfOctetsRetrans */
	Dsack_dups                uint32 `json:"dsack_dups"`    /* RFC4898 tcpEStatsStackDSACKDups */
	Reord_seen                uint32 `json:"reord_seen"`    /* reordering events seen */
	Rcv_ooopack               uint32 `json:"rcv_ooopack"`   /* Out-of-order packets received */
	Snd_wnd                   uint32 `json:"snd_wnd"`       /* peer's advertised receive window after * scaling (bytes) */
}

func checkDeserErr(err error) error {
	if err == io.EOF {
		return nil
	}
	return err
}

func (t *TCPInfo) deserialize(b []byte) error {
	var err error
	rb := bytes.NewBuffer(b)

	t.State, err = rb.ReadByte()
	if err != nil {
		return checkDeserErr(err)
	}

	t.Ca_state, err = rb.ReadByte()
	if err != nil {
		return checkDeserErr(err)
	}

	t.Retransmits, err = rb.ReadByte()
	if err != nil {
		return checkDeserErr(err)
	}

	t.Probes, err = rb.ReadByte()
	if err != nil {
		return checkDeserErr(err)
	}

	t.Backoff, err = rb.ReadByte()
	if err != nil {
		return checkDeserErr(err)
	}
	t.Options, err = rb.ReadByte()
	if err != nil {
		return checkDeserErr(err)
	}

	scales, err := rb.ReadByte()
	if err != nil {
		return checkDeserErr(err)
	}
	t.Snd_wscale = scales >> 4  // first 4 bits
	t.Rcv_wscale = scales & 0xf // last 4 bits

	rateLimAndFastOpen, err := rb.ReadByte()
	if err != nil {
		return checkDeserErr(err)
	}
	t.Delivery_rate_app_limited = rateLimAndFastOpen >> 7 // get first bit
	t.Fastopen_client_fail = rateLimAndFastOpen >> 5 & 3  // get next two bits

	next := rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Rto = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Ato = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Snd_mss = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Rcv_mss = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Unacked = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Sacked = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Lost = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Retrans = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Fackets = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Last_data_sent = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Last_ack_sent = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Last_data_recv = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Last_ack_recv = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Pmtu = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Rcv_ssthresh = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Rtt = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Rttvar = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Snd_ssthresh = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Snd_cwnd = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Advmss = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Reordering = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Rcv_rtt = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Rcv_space = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Total_retrans = native.Uint32(next)

	next = rb.Next(8)
	if len(next) == 0 {
		return nil
	}
	t.Pacing_rate = native.Uint64(next)

	next = rb.Next(8)
	if len(next) == 0 {
		return nil
	}
	t.Max_pacing_rate = native.Uint64(next)

	next = rb.Next(8)
	if len(next) == 0 {
		return nil
	}
	t.Bytes_acked = native.Uint64(next)

	next = rb.Next(8)
	if len(next) == 0 {
		return nil
	}
	t.Bytes_received = native.Uint64(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Segs_out = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Segs_in = native.Uint32(next)
	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Notsent_bytes = native.Uint32(next)
	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Min_rtt = native.Uint32(next)
	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Data_segs_in = native.Uint32(next)
	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Data_segs_out = native.Uint32(next)

	next = rb.Next(8)
	if len(next) == 0 {
		return nil
	}
	t.Delivery_rate = native.Uint64(next)

	next = rb.Next(8)
	if len(next) == 0 {
		return nil
	}
	t.Busy_time = native.Uint64(next)

	next = rb.Next(8)
	if len(next) == 0 {
		return nil
	}
	t.Rwnd_limited = native.Uint64(next)

	next = rb.Next(8)
	if len(next) == 0 {
		return nil
	}
	t.Sndbuf_limited = native.Uint64(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Delivered = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Delivered_ce = native.Uint32(next)

	next = rb.Next(8)
	if len(next) == 0 {
		return nil
	}
	t.Bytes_sent = native.Uint64(next)

	next = rb.Next(8)
	if len(next) == 0 {
		return nil
	}
	t.Bytes_retrans = native.Uint64(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Dsack_dups = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Reord_seen = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Rcv_ooopack = native.Uint32(next)

	next = rb.Next(4)
	if len(next) == 0 {
		return nil
	}
	t.Snd_wnd = native.Uint32(next)
	return nil
}
