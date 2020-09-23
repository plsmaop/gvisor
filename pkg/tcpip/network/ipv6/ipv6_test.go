// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipv6

import (
	"encoding/hex"
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	addr1 = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	addr2 = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
	// The least significant 3 bytes are the same as addr2 so both addr2 and
	// addr3 will have the same solicited-node address.
	addr3 = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x02"
	addr4 = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x03"

	// Tests use the extension header identifier values as uint8 instead of
	// header.IPv6ExtensionHeaderIdentifier.
	hopByHopExtHdrID    = uint8(header.IPv6HopByHopOptionsExtHdrIdentifier)
	routingExtHdrID     = uint8(header.IPv6RoutingExtHdrIdentifier)
	fragmentExtHdrID    = uint8(header.IPv6FragmentExtHdrIdentifier)
	destinationExtHdrID = uint8(header.IPv6DestinationOptionsExtHdrIdentifier)
	noNextHdrID         = uint8(header.IPv6NoNextHeaderIdentifier)
)

// testReceiveICMP tests receiving an ICMP packet from src to dst. want is the
// expected Neighbor Advertisement received count after receiving the packet.
func testReceiveICMP(t *testing.T, s *stack.Stack, e *channel.Endpoint, src, dst tcpip.Address, want uint64) {
	t.Helper()

	// Receive ICMP packet.
	hdr := buffer.NewPrependable(header.IPv6MinimumSize + header.ICMPv6NeighborAdvertSize)
	pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborAdvertSize))
	pkt.SetType(header.ICMPv6NeighborAdvert)
	pkt.SetChecksum(header.ICMPv6Checksum(pkt, src, dst, buffer.VectorisedView{}))
	payloadLength := hdr.UsedLength()
	ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength: uint16(payloadLength),
		NextHeader:    uint8(header.ICMPv6ProtocolNumber),
		HopLimit:      255,
		SrcAddr:       src,
		DstAddr:       dst,
	})

	e.InjectInbound(ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: hdr.View().ToVectorisedView(),
	}))

	stats := s.Stats().ICMP.V6PacketsReceived

	if got := stats.NeighborAdvert.Value(); got != want {
		t.Fatalf("got NeighborAdvert = %d, want = %d", got, want)
	}
}

// testReceiveUDP tests receiving a UDP packet from src to dst. want is the
// expected UDP received count after receiving the packet.
func testReceiveUDP(t *testing.T, s *stack.Stack, e *channel.Endpoint, src, dst tcpip.Address, want uint64) {
	t.Helper()

	wq := waiter.Queue{}
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.EventIn)
	defer wq.EventUnregister(&we)
	defer close(ch)

	ep, err := s.NewEndpoint(udp.ProtocolNumber, ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}
	defer ep.Close()

	if err := ep.Bind(tcpip.FullAddress{Addr: dst, Port: 80}); err != nil {
		t.Fatalf("ep.Bind(...) failed: %v", err)
	}

	// Receive UDP Packet.
	hdr := buffer.NewPrependable(header.IPv6MinimumSize + header.UDPMinimumSize)
	u := header.UDP(hdr.Prepend(header.UDPMinimumSize))
	u.Encode(&header.UDPFields{
		SrcPort: 5555,
		DstPort: 80,
		Length:  header.UDPMinimumSize,
	})

	// UDP pseudo-header checksum.
	sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, src, dst, header.UDPMinimumSize)

	// UDP checksum
	sum = header.Checksum(header.UDP([]byte{}), sum)
	u.SetChecksum(^u.CalculateChecksum(sum))

	payloadLength := hdr.UsedLength()
	ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength: uint16(payloadLength),
		NextHeader:    uint8(udp.ProtocolNumber),
		HopLimit:      255,
		SrcAddr:       src,
		DstAddr:       dst,
	})

	e.InjectInbound(ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: hdr.View().ToVectorisedView(),
	}))

	stat := s.Stats().UDP.PacketsReceived

	if got := stat.Value(); got != want {
		t.Fatalf("got UDPPacketsReceived = %d, want = %d", got, want)
	}
}

func compareFragments(t *testing.T, packets []*stack.PacketBuffer, sourcePacket *stack.PacketBuffer, mtu uint32, isFrag bool, proto tcpip.TransportProtocolNumber) {
	t.Helper()

	// sourcePacket does not have its IP Header populated. Let's copy the one
	// from the first fragment.
	source := header.IPv6(packets[0].NetworkHeader().View())
	sourceIPHeadersLen := len(source)
	vv := buffer.NewVectorisedView(sourcePacket.Size(), sourcePacket.Views())
	source = append(source, vv.ToView()...)

	// Recompute the innerMTU, it will be used to verify the FragmentOffset is
	// correct.
	innerMTU := int(mtu) - sourceIPHeadersLen
	// Round the MTU down to align to 8 bytes.
	innerMTU &^= 7
	expectedIPPayloadLen := innerMTU + sourceIPHeadersLen - header.IPv6MinimumSize

	var reassembledPayload buffer.VectorisedView
	for i, fragment := range packets {
		// Confirm that the packet is valid.
		allBytes := buffer.NewVectorisedView(fragment.Size(), fragment.Views())
		fragmentIPHeaders := header.IPv6(allBytes.ToView())
		if !fragmentIPHeaders.IsValid(len(fragmentIPHeaders)) {
			t.Errorf("fragment #%d: IP packet is invalid:\n%s", i, hex.Dump(fragmentIPHeaders))
		}

		fragmentIPHeadersLength := fragment.NetworkHeader().View().Size()
		if fragmentIPHeadersLength != sourceIPHeadersLen {
			t.Errorf("fragment #%d: got fragmentIPHeadersLength = %d, want = %d", i, fragmentIPHeadersLength, sourceIPHeadersLen)
		}

		if got := len(fragmentIPHeaders); got > int(mtu) {
			t.Errorf("fragment #%d: got len(fragmentIPHeaders) = %d, want <= %d", i, got, int(mtu))
		}

		sourceIPHeader := source[:header.IPv6MinimumSize]
		fragmentIPHeader := fragmentIPHeaders[:header.IPv6MinimumSize]

		if i != len(packets)-1 {
			if got := int(fragmentIPHeaders.PayloadLength()); got != expectedIPPayloadLen {
				t.Errorf("fragment #%d: got fragmentIPHeaders.PayloadLength() = %d, want = %d", i, got, expectedIPPayloadLen)
			}
		}

		// We expect the IPv6 Header to be similar across each fragment, besides the
		// payload length.
		sourceIPHeader.SetPayloadLength(0)
		fragmentIPHeader.SetPayloadLength(0)

		if diff := cmp.Diff(fragmentIPHeader, sourceIPHeader); diff != "" {
			t.Errorf("fragment #%d: fragmentIPHeader mismatch (-want +got):\n%s", i, diff)
		}

		if fragment.NetworkProtocolNumber != sourcePacket.NetworkProtocolNumber {
			t.Errorf("fragment #%d: got fragment.NetworkProtocolNumber = %d, want = %d", i, fragment.NetworkProtocolNumber, sourcePacket.NetworkProtocolNumber)
		}

		if isFrag == true {
			// If the source packet was big enough that it needed fragmentation, let's
			// inspect the fragment header. Because no other extension headers are
			// supported, it will always be the last extension header.
			fragmentHeader := header.IPv6Fragment(fragmentIPHeaders[fragmentIPHeadersLength-header.IPv6FragmentHeaderSize : fragmentIPHeadersLength])

			if got, want := i < len(packets)-1, fragmentHeader.More(); got != want {
				t.Errorf("fragment #%d: got fragmentHeader.More() = %t, want = %t", i, got, want)
			}

			if got := fragmentHeader.NextHeader(); got != uint8(proto) {
				t.Errorf("fragment #%d: got fragmentHeader.NextHeader() = %d, want = %d", i, got, uint8(proto))
			}

			expectedOffset := uint16(i * innerMTU / header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit)
			if got := fragmentHeader.FragmentOffset(); got != expectedOffset {
				t.Errorf("fragment #%d: got fragmentHeader.FragmentOffset() = %d, want = %d", i, got, expectedOffset)
			}
		}

		// Store the reassembled payload as we parse each fragment. The payload
		// includes the Transport header and everything after.
		reassembledPayload.AppendView(fragment.TransportHeader().View())
		reassembledPayload.Append(fragment.Data)
	}

	result := reassembledPayload.ToView()
	if diff := cmp.Diff(result, buffer.View(source[sourceIPHeadersLen:])); diff != "" {
		t.Errorf("reassembledPayload mismatch (-want +got):\n%s", diff)
	}
}

// TestReceiveOnAllNodesMulticastAddr tests that IPv6 endpoints receive ICMP and
// UDP packets destined to the IPv6 link-local all-nodes multicast address.
func TestReceiveOnAllNodesMulticastAddr(t *testing.T) {
	tests := []struct {
		name            string
		protocolFactory stack.TransportProtocol
		rxf             func(t *testing.T, s *stack.Stack, e *channel.Endpoint, src, dst tcpip.Address, want uint64)
	}{
		{"ICMP", icmp.NewProtocol6(), testReceiveICMP},
		{"UDP", udp.NewProtocol(), testReceiveUDP},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocol{NewProtocol()},
				TransportProtocols: []stack.TransportProtocol{test.protocolFactory},
			})
			e := channel.New(10, 1280, linkAddr1)
			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(_) = %s", err)
			}

			// Should receive a packet destined to the all-nodes
			// multicast address.
			test.rxf(t, s, e, addr1, header.IPv6AllNodesMulticastAddress, 1)
		})
	}
}

// TestReceiveOnSolicitedNodeAddr tests that IPv6 endpoints receive ICMP and UDP
// packets destined to the IPv6 solicited-node address of an assigned IPv6
// address.
func TestReceiveOnSolicitedNodeAddr(t *testing.T) {
	tests := []struct {
		name            string
		protocolFactory stack.TransportProtocol
		rxf             func(t *testing.T, s *stack.Stack, e *channel.Endpoint, src, dst tcpip.Address, want uint64)
	}{
		{"ICMP", icmp.NewProtocol6(), testReceiveICMP},
		{"UDP", udp.NewProtocol(), testReceiveUDP},
	}

	snmc := header.SolicitedNodeAddr(addr2)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocol{NewProtocol()},
				TransportProtocols: []stack.TransportProtocol{test.protocolFactory},
			})
			e := channel.New(1, 1280, linkAddr1)
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}

			s.SetRouteTable([]tcpip.Route{
				{
					Destination: header.IPv6EmptySubnet,
					NIC:         nicID,
				},
			})

			// Should not receive a packet destined to the solicited node address of
			// addr2/addr3 yet as we haven't added those addresses.
			test.rxf(t, s, e, addr1, snmc, 0)

			if err := s.AddAddress(nicID, ProtocolNumber, addr2); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, ProtocolNumber, addr2, err)
			}

			// Should receive a packet destined to the solicited node address of
			// addr2/addr3 now that we have added added addr2.
			test.rxf(t, s, e, addr1, snmc, 1)

			if err := s.AddAddress(nicID, ProtocolNumber, addr3); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, ProtocolNumber, addr3, err)
			}

			// Should still receive a packet destined to the solicited node address of
			// addr2/addr3 now that we have added addr3.
			test.rxf(t, s, e, addr1, snmc, 2)

			if err := s.RemoveAddress(nicID, addr2); err != nil {
				t.Fatalf("RemoveAddress(%d, %s) = %s", nicID, addr2, err)
			}

			// Should still receive a packet destined to the solicited node address of
			// addr2/addr3 now that we have removed addr2.
			test.rxf(t, s, e, addr1, snmc, 3)

			// Make sure addr3's endpoint does not get removed from the NIC by
			// incrementing its reference count with a route.
			r, err := s.FindRoute(nicID, addr3, addr4, ProtocolNumber, false)
			if err != nil {
				t.Fatalf("FindRoute(%d, %s, %s, %d, false): %s", nicID, addr3, addr4, ProtocolNumber, err)
			}
			defer r.Release()

			if err := s.RemoveAddress(nicID, addr3); err != nil {
				t.Fatalf("RemoveAddress(%d, %s) = %s", nicID, addr3, err)
			}

			// Should not receive a packet destined to the solicited node address of
			// addr2/addr3 yet as both of them got removed, even though a route using
			// addr3 exists.
			test.rxf(t, s, e, addr1, snmc, 3)
		})
	}
}

// TestAddIpv6Address tests adding IPv6 addresses.
func TestAddIpv6Address(t *testing.T) {
	tests := []struct {
		name string
		addr tcpip.Address
	}{
		// This test is in response to b/140943433.
		{
			"Nil",
			tcpip.Address([]byte(nil)),
		},
		{
			"ValidUnicast",
			addr1,
		},
		{
			"ValidLinkLocalUnicast",
			lladdr0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{NewProtocol()},
			})
			if err := s.CreateNIC(1, &stubLinkEndpoint{}); err != nil {
				t.Fatalf("CreateNIC(_) = %s", err)
			}

			if err := s.AddAddress(1, ProtocolNumber, test.addr); err != nil {
				t.Fatalf("AddAddress(_, %d, nil) = %s", ProtocolNumber, err)
			}

			addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("stack.GetMainNICAddress(_, _) err = %s", err)
			}
			if addr.Address != test.addr {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = %s, want = %s", addr.Address, test.addr)
			}
		})
	}
}

func TestReceiveIPv6ExtHdrs(t *testing.T) {
	tests := []struct {
		name         string
		extHdr       func(nextHdr uint8) ([]byte, uint8)
		shouldAccept bool
	}{
		{
			name:         "None",
			extHdr:       func(nextHdr uint8) ([]byte, uint8) { return []byte{}, nextHdr },
			shouldAccept: true,
		},
		{
			name: "hopbyhop with unknown option skippable action",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Skippable unknown.
					62, 6, 1, 2, 3, 4, 5, 6,
				}, hopByHopExtHdrID
			},
			shouldAccept: true,
		},
		{
			name: "hopbyhop with unknown option discard action",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard unknown.
					127, 6, 1, 2, 3, 4, 5, 6,
				}, hopByHopExtHdrID
			},
			shouldAccept: false,
		},
		{
			name: "hopbyhop with unknown option discard and send icmp action",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP if option is unknown.
					191, 6, 1, 2, 3, 4, 5, 6,
				}, hopByHopExtHdrID
			},
			shouldAccept: false,
		},
		{
			name: "hopbyhop with unknown option discard and send icmp action unless multicast dest",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP unless packet is for multicast destination if
					// option is unknown.
					255, 6, 1, 2, 3, 4, 5, 6,
				}, hopByHopExtHdrID
			},
			shouldAccept: false,
		},
		{
			name:         "routing with zero segments left",
			extHdr:       func(nextHdr uint8) ([]byte, uint8) { return []byte{nextHdr, 0, 1, 0, 2, 3, 4, 5}, routingExtHdrID },
			shouldAccept: true,
		},
		{
			name:         "routing with non-zero segments left",
			extHdr:       func(nextHdr uint8) ([]byte, uint8) { return []byte{nextHdr, 0, 1, 1, 2, 3, 4, 5}, routingExtHdrID },
			shouldAccept: false,
		},
		{
			name:         "atomic fragment with zero ID",
			extHdr:       func(nextHdr uint8) ([]byte, uint8) { return []byte{nextHdr, 0, 0, 0, 0, 0, 0, 0}, fragmentExtHdrID },
			shouldAccept: true,
		},
		{
			name:         "atomic fragment with non-zero ID",
			extHdr:       func(nextHdr uint8) ([]byte, uint8) { return []byte{nextHdr, 0, 0, 0, 1, 2, 3, 4}, fragmentExtHdrID },
			shouldAccept: true,
		},
		{
			name:         "fragment",
			extHdr:       func(nextHdr uint8) ([]byte, uint8) { return []byte{nextHdr, 0, 1, 0, 1, 2, 3, 4}, fragmentExtHdrID },
			shouldAccept: false,
		},
		{
			name:         "No next header",
			extHdr:       func(nextHdr uint8) ([]byte, uint8) { return []byte{}, noNextHdrID },
			shouldAccept: false,
		},
		{
			name: "destination with unknown option skippable action",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Skippable unknown.
					62, 6, 1, 2, 3, 4, 5, 6,
				}, destinationExtHdrID
			},
			shouldAccept: true,
		},
		{
			name: "destination with unknown option discard action",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard unknown.
					127, 6, 1, 2, 3, 4, 5, 6,
				}, destinationExtHdrID
			},
			shouldAccept: false,
		},
		{
			name: "destination with unknown option discard and send icmp action",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP if option is unknown.
					191, 6, 1, 2, 3, 4, 5, 6,
				}, destinationExtHdrID
			},
			shouldAccept: false,
		},
		{
			name: "destination with unknown option discard and send icmp action unless multicast dest",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP unless packet is for multicast destination if
					// option is unknown.
					255, 6, 1, 2, 3, 4, 5, 6,
				}, destinationExtHdrID
			},
			shouldAccept: false,
		},
		{
			name: "routing - atomic fragment",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					// Routing extension header.
					fragmentExtHdrID, 0, 1, 0, 2, 3, 4, 5,

					// Fragment extension header.
					nextHdr, 0, 0, 0, 1, 2, 3, 4,
				}, routingExtHdrID
			},
			shouldAccept: true,
		},
		{
			name: "atomic fragment - routing",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					// Fragment extension header.
					routingExtHdrID, 0, 0, 0, 1, 2, 3, 4,

					// Routing extension header.
					nextHdr, 0, 1, 0, 2, 3, 4, 5,
				}, fragmentExtHdrID
			},
			shouldAccept: true,
		},
		{
			name: "hop by hop (with skippable unknown) - routing",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					// Hop By Hop extension header with skippable unknown option.
					routingExtHdrID, 0, 62, 4, 1, 2, 3, 4,

					// Routing extension header.
					nextHdr, 0, 1, 0, 2, 3, 4, 5,
				}, hopByHopExtHdrID
			},
			shouldAccept: true,
		},
		{
			name: "routing - hop by hop (with skippable unknown)",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					// Routing extension header.
					hopByHopExtHdrID, 0, 1, 0, 2, 3, 4, 5,

					// Hop By Hop extension header with skippable unknown option.
					nextHdr, 0, 62, 4, 1, 2, 3, 4,
				}, routingExtHdrID
			},
			shouldAccept: false,
		},
		{
			name:         "No next header",
			extHdr:       func(nextHdr uint8) ([]byte, uint8) { return []byte{}, noNextHdrID },
			shouldAccept: false,
		},
		{
			name: "hopbyhop (with skippable unknown) - routing - atomic fragment - destination (with skippable unknown)",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					// Hop By Hop extension header with skippable unknown option.
					routingExtHdrID, 0, 62, 4, 1, 2, 3, 4,

					// Routing extension header.
					fragmentExtHdrID, 0, 1, 0, 2, 3, 4, 5,

					// Fragment extension header.
					destinationExtHdrID, 0, 0, 0, 1, 2, 3, 4,

					// Destination extension header with skippable unknown option.
					nextHdr, 0, 63, 4, 1, 2, 3, 4,
				}, hopByHopExtHdrID
			},
			shouldAccept: true,
		},
		{
			name: "hopbyhop (with discard unknown) - routing - atomic fragment - destination (with skippable unknown)",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					// Hop By Hop extension header with discard action for unknown option.
					routingExtHdrID, 0, 65, 4, 1, 2, 3, 4,

					// Routing extension header.
					fragmentExtHdrID, 0, 1, 0, 2, 3, 4, 5,

					// Fragment extension header.
					destinationExtHdrID, 0, 0, 0, 1, 2, 3, 4,

					// Destination extension header with skippable unknown option.
					nextHdr, 0, 63, 4, 1, 2, 3, 4,
				}, hopByHopExtHdrID
			},
			shouldAccept: false,
		},
		{
			name: "hopbyhop (with skippable unknown) - routing - atomic fragment - destination (with discard unknown)",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					// Hop By Hop extension header with skippable unknown option.
					routingExtHdrID, 0, 62, 4, 1, 2, 3, 4,

					// Routing extension header.
					fragmentExtHdrID, 0, 1, 0, 2, 3, 4, 5,

					// Fragment extension header.
					destinationExtHdrID, 0, 0, 0, 1, 2, 3, 4,

					// Destination extension header with discard action for unknown
					// option.
					nextHdr, 0, 65, 4, 1, 2, 3, 4,
				}, hopByHopExtHdrID
			},
			shouldAccept: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocol{NewProtocol()},
				TransportProtocols: []stack.TransportProtocol{udp.NewProtocol()},
			})
			e := channel.New(0, 1280, linkAddr1)
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			if err := s.AddAddress(nicID, ProtocolNumber, addr2); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, ProtocolNumber, addr2, err)
			}

			wq := waiter.Queue{}
			we, ch := waiter.NewChannelEntry(nil)
			wq.EventRegister(&we, waiter.EventIn)
			defer wq.EventUnregister(&we)
			defer close(ch)
			ep, err := s.NewEndpoint(udp.ProtocolNumber, ProtocolNumber, &wq)
			if err != nil {
				t.Fatalf("NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, ProtocolNumber, err)
			}
			defer ep.Close()

			bindAddr := tcpip.FullAddress{Addr: addr2, Port: 80}
			if err := ep.Bind(bindAddr); err != nil {
				t.Fatalf("Bind(%+v): %s", bindAddr, err)
			}

			udpPayload := []byte{1, 2, 3, 4, 5, 6, 7, 8}
			udpLength := header.UDPMinimumSize + len(udpPayload)
			extHdrBytes, ipv6NextHdr := test.extHdr(uint8(header.UDPProtocolNumber))
			extHdrLen := len(extHdrBytes)
			hdr := buffer.NewPrependable(header.IPv6MinimumSize + extHdrLen + udpLength)

			// Serialize UDP message.
			u := header.UDP(hdr.Prepend(udpLength))
			u.Encode(&header.UDPFields{
				SrcPort: 5555,
				DstPort: 80,
				Length:  uint16(udpLength),
			})
			copy(u.Payload(), udpPayload)
			sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, addr1, addr2, uint16(udpLength))
			sum = header.Checksum(udpPayload, sum)
			u.SetChecksum(^u.CalculateChecksum(sum))

			// Copy extension header bytes between the UDP message and the IPv6
			// fixed header.
			copy(hdr.Prepend(extHdrLen), extHdrBytes)

			// Serialize IPv6 fixed header.
			payloadLength := hdr.UsedLength()
			ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
			ip.Encode(&header.IPv6Fields{
				PayloadLength: uint16(payloadLength),
				NextHeader:    ipv6NextHdr,
				HopLimit:      255,
				SrcAddr:       addr1,
				DstAddr:       addr2,
			})

			e.InjectInbound(ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
				Data: hdr.View().ToVectorisedView(),
			}))

			stats := s.Stats().UDP.PacketsReceived

			if !test.shouldAccept {
				if got := stats.Value(); got != 0 {
					t.Errorf("got UDP Rx Packets = %d, want = 0", got)
				}

				return
			}

			// Expect a UDP packet.
			if got := stats.Value(); got != 1 {
				t.Errorf("got UDP Rx Packets = %d, want = 1", got)
			}
			gotPayload, _, err := ep.Read(nil)
			if err != nil {
				t.Fatalf("Read(nil): %s", err)
			}
			if diff := cmp.Diff(buffer.View(udpPayload), gotPayload); diff != "" {
				t.Errorf("got UDP payload mismatch (-want +got):\n%s", diff)
			}

			// Should not have any more UDP packets.
			if gotPayload, _, err := ep.Read(nil); err != tcpip.ErrWouldBlock {
				t.Fatalf("got Read(nil) = (%x, _, %v), want = (_, _, %s)", gotPayload, err, tcpip.ErrWouldBlock)
			}
		})
	}
}

// fragmentData holds the IPv6 payload for a fragmented IPv6 packet.
type fragmentData struct {
	srcAddr tcpip.Address
	dstAddr tcpip.Address
	nextHdr uint8
	data    buffer.VectorisedView
}

func TestReceiveIPv6Fragments(t *testing.T) {
	const (
		udpPayload1Length = 256
		udpPayload2Length = 128
		// Used to test cases where the fragment blocks are not a multiple of
		// the fragment block size of 8 (RFC 8200 section 4.5).
		udpPayload3Length = 127
		udpPayload4Length = header.IPv6MaximumPayloadSize - header.UDPMinimumSize
		fragmentExtHdrLen = 8
		// Note, not all routing extension headers will be 8 bytes but this test
		// uses 8 byte routing extension headers for most sub tests.
		routingExtHdrLen = 8
	)

	udpGen := func(payload []byte, multiplier uint8, src, dst tcpip.Address) buffer.View {
		payloadLen := len(payload)
		for i := 0; i < payloadLen; i++ {
			payload[i] = uint8(i) * multiplier
		}

		udpLength := header.UDPMinimumSize + payloadLen

		hdr := buffer.NewPrependable(udpLength)
		u := header.UDP(hdr.Prepend(udpLength))
		u.Encode(&header.UDPFields{
			SrcPort: 5555,
			DstPort: 80,
			Length:  uint16(udpLength),
		})
		copy(u.Payload(), payload)
		sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, src, dst, uint16(udpLength))
		sum = header.Checksum(payload, sum)
		u.SetChecksum(^u.CalculateChecksum(sum))
		return hdr.View()
	}

	var udpPayload1Addr1ToAddr2Buf [udpPayload1Length]byte
	udpPayload1Addr1ToAddr2 := udpPayload1Addr1ToAddr2Buf[:]
	ipv6Payload1Addr1ToAddr2 := udpGen(udpPayload1Addr1ToAddr2, 1, addr1, addr2)

	var udpPayload1Addr3ToAddr2Buf [udpPayload1Length]byte
	udpPayload1Addr3ToAddr2 := udpPayload1Addr3ToAddr2Buf[:]
	ipv6Payload1Addr3ToAddr2 := udpGen(udpPayload1Addr3ToAddr2, 4, addr3, addr2)

	var udpPayload2Addr1ToAddr2Buf [udpPayload2Length]byte
	udpPayload2Addr1ToAddr2 := udpPayload2Addr1ToAddr2Buf[:]
	ipv6Payload2Addr1ToAddr2 := udpGen(udpPayload2Addr1ToAddr2, 2, addr1, addr2)

	var udpPayload3Addr1ToAddr2Buf [udpPayload3Length]byte
	udpPayload3Addr1ToAddr2 := udpPayload3Addr1ToAddr2Buf[:]
	ipv6Payload3Addr1ToAddr2 := udpGen(udpPayload3Addr1ToAddr2, 3, addr1, addr2)

	var udpPayload4Addr1ToAddr2Buf [udpPayload4Length]byte
	udpPayload4Addr1ToAddr2 := udpPayload4Addr1ToAddr2Buf[:]
	ipv6Payload4Addr1ToAddr2 := udpGen(udpPayload4Addr1ToAddr2, 4, addr1, addr2)

	tests := []struct {
		name             string
		expectedPayload  []byte
		fragments        []fragmentData
		expectedPayloads [][]byte
	}{
		{
			name: "No fragmentation",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: uint8(header.UDPProtocolNumber),
					data:    ipv6Payload1Addr1ToAddr2.ToVectorisedView(),
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Atomic fragment",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload1Addr1ToAddr2),
						[]buffer.View{
							// Fragment extension header.
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 0, 0, 0, 0, 0}),

							ipv6Payload1Addr1ToAddr2,
						},
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Atomic fragment with size not a multiple of fragment block size",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload3Addr1ToAddr2),
						[]buffer.View{
							// Fragment extension header.
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 0, 0, 0, 0, 0}),

							ipv6Payload3Addr1ToAddr2,
						},
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload3Addr1ToAddr2},
		},
		{
			name: "Two fragments",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1}),

							ipv6Payload1Addr1ToAddr2[:64],
						},
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload1Addr1ToAddr2)-64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 8, More = false, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1}),

							ipv6Payload1Addr1ToAddr2[64:],
						},
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Two fragments out of order",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload1Addr1ToAddr2)-64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 8, More = false, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1}),

							ipv6Payload1Addr1ToAddr2[64:],
						},
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1}),

							ipv6Payload1Addr1ToAddr2[:64],
						},
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Two fragments with different Next Header values",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1}),

							ipv6Payload1Addr1ToAddr2[:64],
						},
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload1Addr1ToAddr2)-64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 8, More = false, ID = 1
							// NextHeader value is different than the one in the first fragment, so
							// this NextHeader should be ignored.
							buffer.View([]byte{uint8(header.IPv6NoNextHeaderIdentifier), 0, 0, 64, 0, 0, 0, 1}),

							ipv6Payload1Addr1ToAddr2[64:],
						},
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Two fragments with last fragment size not a multiple of fragment block size",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1}),

							ipv6Payload3Addr1ToAddr2[:64],
						},
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload3Addr1ToAddr2)-64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 8, More = false, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1}),

							ipv6Payload3Addr1ToAddr2[64:],
						},
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload3Addr1ToAddr2},
		},
		{
			name: "Two fragments with first fragment size not a multiple of fragment block size",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+63,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1}),

							ipv6Payload3Addr1ToAddr2[:63],
						},
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload3Addr1ToAddr2)-63,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 8, More = false, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1}),

							ipv6Payload3Addr1ToAddr2[63:],
						},
					),
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments with different IDs",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1}),

							ipv6Payload1Addr1ToAddr2[:64],
						},
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload1Addr1ToAddr2)-64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 8, More = false, ID = 2
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 2}),

							ipv6Payload1Addr1ToAddr2[64:],
						},
					),
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments reassembled into a maximum UDP packet",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+65520,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1}),

							ipv6Payload4Addr1ToAddr2[:65520],
						},
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload4Addr1ToAddr2)-65520,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 8190, More = false, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 255, 240, 0, 0, 0, 1}),

							ipv6Payload4Addr1ToAddr2[65520:],
						},
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload4Addr1ToAddr2},
		},
		{
			name: "Two fragments with per-fragment routing header with zero segments left",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: routingExtHdrID,
					data: buffer.NewVectorisedView(
						routingExtHdrLen+fragmentExtHdrLen+64,
						[]buffer.View{
							// Routing extension header.
							//
							// Segments left = 0.
							buffer.View([]byte{fragmentExtHdrID, 0, 1, 0, 2, 3, 4, 5}),

							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1}),

							ipv6Payload1Addr1ToAddr2[:64],
						},
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: routingExtHdrID,
					data: buffer.NewVectorisedView(
						routingExtHdrLen+fragmentExtHdrLen+len(ipv6Payload1Addr1ToAddr2)-64,
						[]buffer.View{
							// Routing extension header.
							//
							// Segments left = 0.
							buffer.View([]byte{fragmentExtHdrID, 0, 1, 0, 2, 3, 4, 5}),

							// Fragment extension header.
							//
							// Fragment offset = 8, More = false, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1}),

							ipv6Payload1Addr1ToAddr2[64:],
						},
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Two fragments with per-fragment routing header with non-zero segments left",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: routingExtHdrID,
					data: buffer.NewVectorisedView(
						routingExtHdrLen+fragmentExtHdrLen+64,
						[]buffer.View{
							// Routing extension header.
							//
							// Segments left = 1.
							buffer.View([]byte{fragmentExtHdrID, 0, 1, 1, 2, 3, 4, 5}),

							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1}),

							ipv6Payload1Addr1ToAddr2[:64],
						},
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: routingExtHdrID,
					data: buffer.NewVectorisedView(
						routingExtHdrLen+fragmentExtHdrLen+len(ipv6Payload1Addr1ToAddr2)-64,
						[]buffer.View{
							// Routing extension header.
							//
							// Segments left = 1.
							buffer.View([]byte{fragmentExtHdrID, 0, 1, 1, 2, 3, 4, 5}),

							// Fragment extension header.
							//
							// Fragment offset = 9, More = false, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 72, 0, 0, 0, 1}),

							ipv6Payload1Addr1ToAddr2[64:],
						},
					),
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments with routing header with zero segments left",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						routingExtHdrLen+fragmentExtHdrLen+64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{routingExtHdrID, 0, 0, 1, 0, 0, 0, 1}),

							// Routing extension header.
							//
							// Segments left = 0.
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 1, 0, 2, 3, 4, 5}),

							ipv6Payload1Addr1ToAddr2[:64],
						},
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload1Addr1ToAddr2)-64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 9, More = false, ID = 1
							buffer.View([]byte{routingExtHdrID, 0, 0, 72, 0, 0, 0, 1}),

							ipv6Payload1Addr1ToAddr2[64:],
						},
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Two fragments with routing header with non-zero segments left",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						routingExtHdrLen+fragmentExtHdrLen+64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{routingExtHdrID, 0, 0, 1, 0, 0, 0, 1}),

							// Routing extension header.
							//
							// Segments left = 1.
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 1, 1, 2, 3, 4, 5}),

							ipv6Payload1Addr1ToAddr2[:64],
						},
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload1Addr1ToAddr2)-64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 9, More = false, ID = 1
							buffer.View([]byte{routingExtHdrID, 0, 0, 72, 0, 0, 0, 1}),

							ipv6Payload1Addr1ToAddr2[64:],
						},
					),
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments with routing header with zero segments left across fragments",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						// The length of this payload is fragmentExtHdrLen+8 because the
						// first 8 bytes of the 16 byte routing extension header is in
						// this fragment.
						fragmentExtHdrLen+8,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{routingExtHdrID, 0, 0, 1, 0, 0, 0, 1}),

							// Routing extension header (part 1)
							//
							// Segments left = 0.
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 1, 1, 0, 2, 3, 4, 5}),
						},
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						// The length of this payload is
						// fragmentExtHdrLen+8+len(ipv6Payload1Addr1ToAddr2) because the last 8 bytes of
						// the 16 byte routing extension header is in this fagment.
						fragmentExtHdrLen+8+len(ipv6Payload1Addr1ToAddr2),
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 1, More = false, ID = 1
							buffer.View([]byte{routingExtHdrID, 0, 0, 8, 0, 0, 0, 1}),

							// Routing extension header (part 2)
							buffer.View([]byte{6, 7, 8, 9, 10, 11, 12, 13}),

							ipv6Payload1Addr1ToAddr2,
						},
					),
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments with routing header with non-zero segments left across fragments",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						// The length of this payload is fragmentExtHdrLen+8 because the
						// first 8 bytes of the 16 byte routing extension header is in
						// this fragment.
						fragmentExtHdrLen+8,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{routingExtHdrID, 0, 0, 1, 0, 0, 0, 1}),

							// Routing extension header (part 1)
							//
							// Segments left = 1.
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 1, 1, 1, 2, 3, 4, 5}),
						},
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						// The length of this payload is
						// fragmentExtHdrLen+8+len(ipv6Payload1Addr1ToAddr2) because the last 8 bytes of
						// the 16 byte routing extension header is in this fagment.
						fragmentExtHdrLen+8+len(ipv6Payload1Addr1ToAddr2),
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 1, More = false, ID = 1
							buffer.View([]byte{routingExtHdrID, 0, 0, 8, 0, 0, 0, 1}),

							// Routing extension header (part 2)
							buffer.View([]byte{6, 7, 8, 9, 10, 11, 12, 13}),

							ipv6Payload1Addr1ToAddr2,
						},
					),
				},
			},
			expectedPayloads: nil,
		},
		// As per RFC 6946, IPv6 atomic fragments MUST NOT interfere with "normal"
		// fragmented traffic.
		{
			name: "Two fragments with atomic",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1}),

							ipv6Payload1Addr1ToAddr2[:64],
						},
					),
				},
				// This fragment has the same ID as the other fragments but is an atomic
				// fragment. It should not interfere with the other fragments.
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload2Addr1ToAddr2),
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = false, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 0, 0, 0, 0, 1}),

							ipv6Payload2Addr1ToAddr2,
						},
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload1Addr1ToAddr2)-64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 8, More = false, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1}),

							ipv6Payload1Addr1ToAddr2[64:],
						},
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload2Addr1ToAddr2, udpPayload1Addr1ToAddr2},
		},
		{
			name: "Two interleaved fragmented packets",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1}),

							ipv6Payload1Addr1ToAddr2[:64],
						},
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+32,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 2
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 2}),

							ipv6Payload2Addr1ToAddr2[:32],
						},
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload1Addr1ToAddr2)-64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 8, More = false, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1}),

							ipv6Payload1Addr1ToAddr2[64:],
						},
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload2Addr1ToAddr2)-32,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 4, More = false, ID = 2
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 32, 0, 0, 0, 2}),

							ipv6Payload2Addr1ToAddr2[32:],
						},
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2, udpPayload2Addr1ToAddr2},
		},
		{
			name: "Two interleaved fragmented packets from different sources but with same ID",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1}),

							ipv6Payload1Addr1ToAddr2[:64],
						},
					),
				},
				{
					srcAddr: addr3,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+32,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1}),

							ipv6Payload1Addr3ToAddr2[:32],
						},
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload1Addr1ToAddr2)-64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 8, More = false, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1}),

							ipv6Payload1Addr1ToAddr2[64:],
						},
					),
				},
				{
					srcAddr: addr3,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload1Addr1ToAddr2)-32,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 4, More = false, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 32, 0, 0, 0, 1}),

							ipv6Payload1Addr3ToAddr2[32:],
						},
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2, udpPayload1Addr3ToAddr2},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocol{NewProtocol()},
				TransportProtocols: []stack.TransportProtocol{udp.NewProtocol()},
			})
			e := channel.New(0, 1280, linkAddr1)
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			if err := s.AddAddress(nicID, ProtocolNumber, addr2); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, ProtocolNumber, addr2, err)
			}

			wq := waiter.Queue{}
			we, ch := waiter.NewChannelEntry(nil)
			wq.EventRegister(&we, waiter.EventIn)
			defer wq.EventUnregister(&we)
			defer close(ch)
			ep, err := s.NewEndpoint(udp.ProtocolNumber, ProtocolNumber, &wq)
			if err != nil {
				t.Fatalf("NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, ProtocolNumber, err)
			}
			defer ep.Close()

			bindAddr := tcpip.FullAddress{Addr: addr2, Port: 80}
			if err := ep.Bind(bindAddr); err != nil {
				t.Fatalf("Bind(%+v): %s", bindAddr, err)
			}

			for _, f := range test.fragments {
				hdr := buffer.NewPrependable(header.IPv6MinimumSize)

				// Serialize IPv6 fixed header.
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength: uint16(f.data.Size()),
					NextHeader:    f.nextHdr,
					HopLimit:      255,
					SrcAddr:       f.srcAddr,
					DstAddr:       f.dstAddr,
				})

				vv := hdr.View().ToVectorisedView()
				vv.Append(f.data)

				e.InjectInbound(ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: vv,
				}))
			}

			if got, want := s.Stats().UDP.PacketsReceived.Value(), uint64(len(test.expectedPayloads)); got != want {
				t.Errorf("got UDP Rx Packets = %d, want = %d", got, want)
			}

			for i, p := range test.expectedPayloads {
				gotPayload, _, err := ep.Read(nil)
				if err != nil {
					t.Fatalf("(i=%d) Read(nil): %s", i, err)
				}
				if diff := cmp.Diff(buffer.View(p), gotPayload); diff != "" {
					t.Errorf("(i=%d) got UDP payload mismatch (-want +got):\n%s", i, diff)
				}
			}

			if gotPayload, _, err := ep.Read(nil); err != tcpip.ErrWouldBlock {
				t.Fatalf("(last) got Read(nil) = (%x, _, %v), want = (_, _, %s)", gotPayload, err, tcpip.ErrWouldBlock)
			}
		})
	}
}

func TestInvalidIPv6Fragments(t *testing.T) {
	const (
		nicID             = 1
		fragmentExtHdrLen = 8
	)

	payloadGen := func(payloadLen int) []byte {
		payload := make([]byte, payloadLen)
		for i := 0; i < len(payload); i++ {
			payload[i] = 0x30
		}
		return payload
	}

	tests := []struct {
		name                   string
		fragments              []fragmentData
		wantMalformedIPPackets uint64
		wantMalformedFragments uint64
	}{
		{
			name: "fragments reassembled into a payload exceeding the max IPv6 payload size",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+(header.IPv6MaximumPayloadSize+1)-16,
						[]buffer.View{
							// Fragment extension header.
							// Fragment offset = 8190, More = false, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0,
								((header.IPv6MaximumPayloadSize + 1) - 16) >> 8,
								((header.IPv6MaximumPayloadSize + 1) - 16) & math.MaxUint8,
								0, 0, 0, 1}),
							// Payload length = 16
							payloadGen(16),
						},
					),
				},
			},
			wantMalformedIPPackets: 1,
			wantMalformedFragments: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{
					NewProtocol(),
				},
			})
			e := channel.New(0, 1500, linkAddr1)
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			if err := s.AddAddress(nicID, ProtocolNumber, addr2); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, ProtocolNumber, addr2, err)
			}

			for _, f := range test.fragments {
				hdr := buffer.NewPrependable(header.IPv6MinimumSize)

				// Serialize IPv6 fixed header.
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength: uint16(f.data.Size()),
					NextHeader:    f.nextHdr,
					HopLimit:      255,
					SrcAddr:       f.srcAddr,
					DstAddr:       f.dstAddr,
				})

				vv := hdr.View().ToVectorisedView()
				vv.Append(f.data)

				e.InjectInbound(ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: vv,
				}))
			}

			if got, want := s.Stats().IP.MalformedPacketsReceived.Value(), test.wantMalformedIPPackets; got != want {
				t.Errorf("got Stats.IP.MalformedPacketsReceived = %d, want = %d", got, want)
			}
			if got, want := s.Stats().IP.MalformedFragmentsReceived.Value(), test.wantMalformedFragments; got != want {
				t.Errorf("got Stats.IP.MalformedFragmentsReceived = %d, want = %d", got, want)
			}
		})
	}
}

func TestWriteStats(t *testing.T) {
	const nPackets = 3
	tests := []struct {
		name          string
		setup         func(*testing.T, *stack.Stack)
		allowPackets  int
		expectSent    int
		expectDropped int
		expectWritten int
	}{
		{
			name: "Accept all",
			// No setup needed, tables accept everything by default.
			setup:         func(*testing.T, *stack.Stack) {},
			allowPackets:  math.MaxInt32,
			expectSent:    nPackets,
			expectDropped: 0,
			expectWritten: nPackets,
		}, {
			name: "Accept all with error",
			// No setup needed, tables accept everything by default.
			setup:         func(*testing.T, *stack.Stack) {},
			allowPackets:  nPackets - 1,
			expectSent:    nPackets - 1,
			expectDropped: 0,
			expectWritten: nPackets - 1,
		}, {
			name: "Drop all",
			setup: func(t *testing.T, stk *stack.Stack) {
				// Install Output DROP rule.
				t.Helper()
				ipt := stk.IPTables()
				filter, ok := ipt.GetTable(stack.FilterTable, true /* ipv6 */)
				if !ok {
					t.Fatalf("failed to find filter table")
				}
				ruleIdx := filter.BuiltinChains[stack.Output]
				filter.Rules[ruleIdx].Target = stack.DropTarget{}
				if err := ipt.ReplaceTable(stack.FilterTable, filter, true /* ipv6 */); err != nil {
					t.Fatalf("failed to replace table: %v", err)
				}
			},
			allowPackets:  math.MaxInt32,
			expectSent:    0,
			expectDropped: nPackets,
			expectWritten: nPackets,
		}, {
			name: "Drop some",
			setup: func(t *testing.T, stk *stack.Stack) {
				// Install Output DROP rule that matches only 1
				// of the 3 packets.
				t.Helper()
				ipt := stk.IPTables()
				filter, ok := ipt.GetTable(stack.FilterTable, true /* ipv6 */)
				if !ok {
					t.Fatalf("failed to find filter table")
				}
				// We'll match and DROP the last packet.
				ruleIdx := filter.BuiltinChains[stack.Output]
				filter.Rules[ruleIdx].Target = stack.DropTarget{}
				filter.Rules[ruleIdx].Matchers = []stack.Matcher{&limitedMatcher{nPackets - 1}}
				// Make sure the next rule is ACCEPT.
				filter.Rules[ruleIdx+1].Target = stack.AcceptTarget{}
				if err := ipt.ReplaceTable(stack.FilterTable, filter, true /* ipv6 */); err != nil {
					t.Fatalf("failed to replace table: %v", err)
				}
			},
			allowPackets:  math.MaxInt32,
			expectSent:    nPackets - 1,
			expectDropped: 1,
			expectWritten: nPackets,
		},
	}

	writers := []struct {
		name         string
		writePackets func(*stack.Route, stack.PacketBufferList) (int, *tcpip.Error)
	}{
		{
			name: "WritePacket",
			writePackets: func(rt *stack.Route, pkts stack.PacketBufferList) (int, *tcpip.Error) {
				nWritten := 0
				for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
					if err := rt.WritePacket(nil, stack.NetworkHeaderParams{}, pkt); err != nil {
						return nWritten, err
					}
					nWritten++
				}
				return nWritten, nil
			},
		}, {
			name: "WritePackets",
			writePackets: func(rt *stack.Route, pkts stack.PacketBufferList) (int, *tcpip.Error) {
				return rt.WritePackets(nil, pkts, stack.NetworkHeaderParams{})
			},
		},
	}

	for _, writer := range writers {
		t.Run(writer.name, func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					ep := testutil.NewMockLinkEndpoint(header.IPv6MinimumMTU, tcpip.ErrInvalidEndpointState, test.allowPackets)
					rt := buildRoute(t, ep)
					var pkts stack.PacketBufferList
					for i := 0; i < nPackets; i++ {
						pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
							ReserveHeaderBytes: header.UDPMinimumSize + int(rt.MaxHeaderLength()),
							Data:               buffer.NewView(0).ToVectorisedView(),
						})
						pkt.TransportHeader().Push(header.UDPMinimumSize)
						pkts.PushBack(pkt)
					}

					test.setup(t, rt.Stack())

					nWritten, _ := writer.writePackets(&rt, pkts)

					if got := int(rt.Stats().IP.PacketsSent.Value()); got != test.expectSent {
						t.Errorf("sent %d packets, but expected to send %d", got, test.expectSent)
					}
					if got := int(rt.Stats().IP.IPTablesOutputDropped.Value()); got != test.expectDropped {
						t.Errorf("dropped %d packets, but expected to drop %d", got, test.expectDropped)
					}
					if nWritten != test.expectWritten {
						t.Errorf("wrote %d packets, but expected WritePackets to return %d", nWritten, test.expectWritten)
					}
				})
			}
		})
	}
}

func buildRoute(t *testing.T, ep stack.LinkEndpoint) stack.Route {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{NewProtocol()},
	})
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC(1, _) failed: %s", err)
	}
	const (
		src = "\xfc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
		dst = "\xfc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
	)
	if err := s.AddAddress(1, ProtocolNumber, src); err != nil {
		t.Fatalf("AddAddress(1, %d, _) failed: %s", ProtocolNumber, err)
	}
	{
		subnet, err := tcpip.NewSubnet(dst, tcpip.AddressMask("\xfc\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"))
		if err != nil {
			t.Fatalf("NewSubnet(_, _) failed: %v", err)
		}
		s.SetRouteTable([]tcpip.Route{{
			Destination: subnet,
			NIC:         1,
		}})
	}
	rt, err := s.FindRoute(1, src, dst, ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("got FindRoute(1, _, _, %d, false) = %s, want = nil", ProtocolNumber, err)
	}
	return rt
}

// limitedMatcher is an iptables matcher that matches after a certain number of
// packets are checked against it.
type limitedMatcher struct {
	limit int
}

// Name implements Matcher.Name.
func (*limitedMatcher) Name() string {
	return "limitedMatcher"
}

// Match implements Matcher.Match.
func (lm *limitedMatcher) Match(stack.Hook, *stack.PacketBuffer, string) (bool, bool) {
	if lm.limit == 0 {
		return true, false
	}
	lm.limit--
	return false, false
}

type fragmentationTestCase struct {
	description       string
	mtu               uint32
	gso               *stack.GSO
	transHdrLen       int
	extraHdrLen       int
	payloadViewsSizes []int
	expectedFrags     int
	expectedError     *tcpip.Error
}

func buildFragmentationTestCases() []fragmentationTestCase {
	var manyPayloadViewsSizes [1000]int
	for i := range manyPayloadViewsSizes {
		manyPayloadViewsSizes[i] = 7
	}
	return []fragmentationTestCase{
		{
			description:       "NoFragmentation",
			mtu:               1280,
			gso:               &stack.GSO{},
			transHdrLen:       0,
			extraHdrLen:       header.IPv6MinimumSize,
			payloadViewsSizes: []int{1000},
			expectedFrags:     1,
			expectedError:     nil,
		},
		{
			description:       "Fragmented",
			mtu:               1280,
			gso:               &stack.GSO{},
			transHdrLen:       0,
			extraHdrLen:       header.IPv6MinimumSize,
			payloadViewsSizes: []int{2000},
			expectedFrags:     2,
			expectedError:     nil,
		},
		{
			description:       "NoFragmentationWithBigHeader",
			mtu:               2000,
			gso:               &stack.GSO{},
			transHdrLen:       16,
			extraHdrLen:       header.IPv6MinimumSize,
			payloadViewsSizes: []int{1000},
			expectedFrags:     1,
			expectedError:     nil,
		},
		{
			description:       "FragmentedWithGsoNil",
			mtu:               1280,
			gso:               nil,
			transHdrLen:       0,
			extraHdrLen:       header.IPv6MinimumSize,
			payloadViewsSizes: []int{1400},
			expectedFrags:     2,
			expectedError:     nil,
		},
		{
			description:       "FragmentedWithManyViews",
			mtu:               1500,
			gso:               &stack.GSO{},
			transHdrLen:       0,
			extraHdrLen:       header.IPv6MinimumSize,
			payloadViewsSizes: manyPayloadViewsSizes[:],
			expectedFrags:     5,
			expectedError:     nil,
		},
		{
			description:       "FragmentedWithManyViewsAndPrependableBytes",
			mtu:               1500,
			gso:               &stack.GSO{},
			transHdrLen:       0,
			extraHdrLen:       header.IPv6MinimumSize + 55,
			payloadViewsSizes: manyPayloadViewsSizes[:],
			expectedFrags:     5,
			expectedError:     nil,
		},
		{
			description:       "FragmentedWithBigHeader",
			mtu:               1280,
			gso:               &stack.GSO{},
			transHdrLen:       20,
			extraHdrLen:       header.IPv6MinimumSize,
			payloadViewsSizes: []int{1500},
			expectedFrags:     2,
			expectedError:     nil,
		},
		{
			description:       "FragmentedWithBigHeaderAndPrependableBytes",
			mtu:               1280,
			gso:               &stack.GSO{},
			transHdrLen:       20,
			extraHdrLen:       header.IPv6MinimumSize + 66,
			payloadViewsSizes: []int{1500},
			expectedFrags:     2,
			expectedError:     nil,
		},
		{
			description:       "FragmentedWithMTUSmallerThanHeaderAndPrependableBytes",
			mtu:               1280,
			gso:               &stack.GSO{},
			transHdrLen:       1500,
			extraHdrLen:       header.IPv6MinimumSize,
			payloadViewsSizes: []int{500},
			expectedFrags:     0,
			expectedError:     tcpip.ErrMessageTooLong,
		},
	}
}

func TestFragmentation(t *testing.T) {
	const ttl = 42

	fragTests := buildFragmentationTestCases()
	for _, ft := range fragTests {
		t.Run(ft.description, func(t *testing.T) {
			pkt := testutil.MakeRandPkt(ft.transHdrLen, ft.extraHdrLen, ft.payloadViewsSizes, header.IPv6ProtocolNumber)
			source := pkt.Clone()
			ep := testutil.NewMockLinkEndpoint(ft.mtu, nil, math.MaxInt32)
			r := buildRoute(t, ep)
			err := r.WritePacket(ft.gso, stack.NetworkHeaderParams{
				Protocol: tcp.ProtocolNumber,
				TTL:      ttl,
				TOS:      stack.DefaultTOS,
			}, pkt)
			if err != ft.expectedError {
				t.Errorf("got WritePacket() = %s, want = %s", err, ft.expectedError)
			}
			if got := len(ep.WrittenPackets); got != ft.expectedFrags {
				t.Errorf("got len(ep.WrittenPackets) = %d, want = %d", got, ft.expectedFrags)
			}
			if got := int(r.Stats().IP.PacketsSent.Value()); got != ft.expectedFrags {
				t.Errorf("got c.Route.Stats().IP.PacketsSent.Value() = %d, want = %d", got, ft.expectedFrags)
			}

			if len(ep.WrittenPackets) > 0 {
				compareFragments(t, ep.WrittenPackets, source, ft.mtu, ft.expectedFrags > 1, tcp.ProtocolNumber)
			}
		})
	}
}

func TestFragmentationWritePackets(t *testing.T) {
	const ttl = 42
	writePacketsTests := []struct {
		description  string
		insertBefore int
		insertAfter  int
	}{
		{
			description:  "SinglePacket",
			insertBefore: 0,
			insertAfter:  0,
		},
		{
			description:  "WithPacketBefore",
			insertBefore: 1,
			insertAfter:  0,
		},
		{
			description:  "WithPacketAfter",
			insertBefore: 0,
			insertAfter:  1,
		},
		{
			description:  "WithPacketBeforeAndAfter",
			insertBefore: 1,
			insertAfter:  1,
		},
	}
	tinyPacket := testutil.MakeRandPkt(header.TCPMinimumSize, header.IPv6MinimumSize, []int{1}, header.IPv6ProtocolNumber)

	fragTests := buildFragmentationTestCases()
	for _, writePacketsTest := range writePacketsTests {
		t.Run(writePacketsTest.description, func(t *testing.T) {
			for _, ft := range fragTests {
				t.Run(ft.description, func(t *testing.T) {
					var pkts stack.PacketBufferList
					for i := 0; i < writePacketsTest.insertBefore; i++ {
						pkts.PushBack(tinyPacket.Clone())
					}
					pkt := testutil.MakeRandPkt(ft.transHdrLen, ft.extraHdrLen, ft.payloadViewsSizes, header.IPv6ProtocolNumber)
					source := pkt
					pkts.PushBack(pkt.Clone())
					for i := 0; i < writePacketsTest.insertAfter; i++ {
						pkts.PushBack(tinyPacket.Clone())
					}

					ep := testutil.NewMockLinkEndpoint(ft.mtu, nil, math.MaxInt32)
					r := buildRoute(t, ep)

					wantTotalPackets := ft.expectedFrags + writePacketsTest.insertBefore + writePacketsTest.insertAfter
					if ft.expectedError != nil {
						wantTotalPackets = 0
					}
					n, err := r.WritePackets(ft.gso, pkts, stack.NetworkHeaderParams{
						Protocol: tcp.ProtocolNumber,
						TTL:      ttl,
						TOS:      stack.DefaultTOS,
					})
					if n != wantTotalPackets || err != ft.expectedError {
						t.Errorf("got WritePackets() = %d, %s, want = %d, %s", n, err, wantTotalPackets, ft.expectedError)
					}
					if got := len(ep.WrittenPackets); got != wantTotalPackets {
						t.Errorf("got len(ep.WrittenPackets) = %d, want = %d", got, wantTotalPackets)
					}
					if got := int(r.Stats().IP.PacketsSent.Value()); got != wantTotalPackets {
						t.Errorf("got c.Route.Stats().IP.PacketsSent.Value() = %d, want = %d", got, wantTotalPackets)
					}

					if wantTotalPackets == 0 {
						return
					}

					for i := 0; i < writePacketsTest.insertBefore; i++ {
						compareFragments(t, ep.WrittenPackets[:1], tinyPacket.Clone(), ft.mtu, false, tcp.ProtocolNumber)
						ep.WrittenPackets = ep.WrittenPackets[1:]
					}
					compareFragments(t, ep.WrittenPackets[:ft.expectedFrags], source, ft.mtu, ft.expectedFrags > 1, tcp.ProtocolNumber)
					ep.WrittenPackets = ep.WrittenPackets[ft.expectedFrags:]
					for i := 0; i < writePacketsTest.insertAfter; i++ {
						compareFragments(t, ep.WrittenPackets[:1], tinyPacket.Clone(), ft.mtu, false, tcp.ProtocolNumber)
						ep.WrittenPackets = ep.WrittenPackets[1:]
					}
				})
			}
		})
	}
}

// TestFragmentationErrors checks that errors are returned from WritePacket
// correctly.
func TestFragmentationErrors(t *testing.T) {
	const ttl = 42
	fragTests := []struct {
		description       string
		mtu               uint32
		transHdrLen       int
		payloadViewsSizes []int
		err               *tcpip.Error
		allowPackets      int
	}{
		{
			description:       "NoFrag",
			mtu:               2000,
			transHdrLen:       0,
			payloadViewsSizes: []int{1000},
			err:               tcpip.ErrAborted,
			allowPackets:      0,
		},
		{
			description:       "ErrorOnFirstFrag",
			mtu:               1300,
			transHdrLen:       0,
			payloadViewsSizes: []int{1500},
			err:               tcpip.ErrAborted,
			allowPackets:      0,
		},
		{
			description:       "ErrorOnSecondFrag",
			mtu:               1500,
			transHdrLen:       0,
			payloadViewsSizes: []int{2000},
			err:               tcpip.ErrAborted,
			allowPackets:      1,
		},
	}

	for _, ft := range fragTests {
		t.Run(ft.description, func(t *testing.T) {
			pkt := testutil.MakeRandPkt(ft.transHdrLen, header.IPv6MinimumSize, ft.payloadViewsSizes, header.IPv6ProtocolNumber)
			ep := testutil.NewMockLinkEndpoint(ft.mtu, ft.err, ft.allowPackets)
			r := buildRoute(t, ep)
			err := r.WritePacket(&stack.GSO{}, stack.NetworkHeaderParams{
				Protocol: tcp.ProtocolNumber,
				TTL:      ttl,
				TOS:      stack.DefaultTOS,
			}, pkt)
			if err != ft.err {
				t.Errorf("got WritePacket() = %s, want = %s", err, ft.err)
			}
			if got, want := len(ep.WrittenPackets), int(r.Stats().IP.PacketsSent.Value()); err != nil && got != want {
				t.Errorf("got len(ep.WrittenPackets) = %d, want = %d", got, want)
			}
		})
	}
}
