package easytier

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const (
	rpcCompressionNone = 1

	// EasyTier RPC descriptors use the generated service proto name, and method
	// indexes are one-based in easytier-rpc-build.
	ospfProtoName   = "OspfRouteRpc"
	ospfServiceName = "OspfRouteRpc"
	ospfMethodIndex = 1
)

type routeRPCConfig struct {
	MyPeerID     uint32
	RemotePeerID uint32
	NetworkName  string
	IPv4         netip.Prefix
	Hostname     string
	SessionID    uint64
	PeerRouteID  uint64
	InstanceID   [4]uint32
	ProxyCIDRs   []string
	PeerInfos    []routePeerInfo
	ConnInfos    []routeConnInfo
	Transaction  int64
}

type rpcDescriptor struct {
	DomainName  string
	ProtoName   string
	ServiceName string
	MethodIndex uint32
}

type rpcPacket struct {
	FromPeer      uint32
	ToPeer        uint32
	TransactionID int64
	Descriptor    rpcDescriptor
	Body          []byte
	IsRequest     bool
}

type syncRouteInfo struct {
	MyPeerID  uint32
	PeerInfos []routePeerInfo
	ConnInfos []routeConnInfo
}

type routePeerInfo struct {
	PeerID        uint32
	Cost          uint32
	IPv4          netip.Addr
	NetworkLength int
	ProxyCIDRs    []netip.Prefix
	Hostname      string
	UDPNATType    uint32
	TCPNATType    uint32
	FeatureFlags  peerFeatureFlags
	PeerRouteID   uint64
	IPv6          netip.Addr
	RelayPeerID   uint32
	Version       uint32
	Raw           []byte
}

type routeConnInfo struct {
	PeerID           uint32
	ConnectedPeerIDs []uint32
	Version          uint32
}

type peerFeatureFlags struct {
	IsPublicServer         bool
	AvoidRelayData         bool
	KCPInput               bool
	NoRelayKCP             bool
	SupportConnListSync    bool
	QUICInput              bool
	NoRelayQUIC            bool
	IsCredentialPeer       bool
	NeedP2P                bool
	DisableP2P             bool
	IPv6PublicAddrProvider bool
}

type protoField struct {
	Number   int
	WireType int
	Varint   uint64
	Bytes    []byte
}

func buildRouteSyncRequestPacket(config routeRPCConfig) (*Packet, error) {
	request, err := buildSyncRouteInfoRequest(config)
	if err != nil {
		return nil, err
	}
	rpcRequest := appendProtoBytes(nil, 2, request)
	rpcRequest = appendProtoVarint(rpcRequest, 3, 3000)

	payload := marshalRPCPacket(rpcPacket{
		FromPeer:      config.MyPeerID,
		ToPeer:        config.RemotePeerID,
		TransactionID: config.Transaction,
		Descriptor: rpcDescriptor{
			DomainName:  config.NetworkName,
			ProtoName:   ospfProtoName,
			ServiceName: ospfServiceName,
			MethodIndex: ospfMethodIndex,
		},
		Body:      rpcRequest,
		IsRequest: true,
	})
	return NewPacket(config.MyPeerID, config.RemotePeerID, PacketTypeRPCReq, payload), nil
}

func buildRouteSyncResponsePacket(req rpcPacket, myPeerID, remotePeerID uint32, sessionID uint64) *Packet {
	syncRouteInfoResponse := appendProtoVarint(nil, 1, 0)
	syncRouteInfoResponse = appendProtoVarint(syncRouteInfoResponse, 2, sessionID)

	rpcResponse := appendProtoBytes(nil, 1, syncRouteInfoResponse)
	rpcResponse = appendProtoVarint(rpcResponse, 3, 0)

	payload := marshalRPCPacket(rpcPacket{
		FromPeer:      myPeerID,
		ToPeer:        remotePeerID,
		TransactionID: req.TransactionID,
		Descriptor:    req.Descriptor,
		Body:          rpcResponse,
		IsRequest:     false,
	})
	return NewPacket(myPeerID, remotePeerID, PacketTypeRPCResp, payload)
}

func buildSyncRouteInfoRequest(config routeRPCConfig) ([]byte, error) {
	peerInfo, err := buildRoutePeerInfo(config)
	if err != nil {
		return nil, err
	}
	peerInfos := appendProtoBytes(nil, 1, peerInfo)
	for _, info := range config.PeerInfos {
		payload, err := buildStoredRoutePeerInfo(info)
		if err != nil {
			return nil, err
		}
		peerInfos = appendProtoBytes(peerInfos, 1, payload)
	}

	connPeerList := buildRouteConnPeerList(config)

	request := appendProtoVarint(nil, 1, uint64(config.MyPeerID))
	request = appendProtoVarint(request, 2, config.SessionID)
	// This lightweight client lets a full EasyTier peer initiate OSPF deltas.
	request = appendProtoVarint(request, 3, 0)
	request = appendProtoBytes(request, 4, peerInfos)
	request = appendProtoBytes(request, 7, connPeerList)
	return request, nil
}

func buildRouteConnPeerList(config routeRPCConfig) []byte {
	connInfos := config.ConnInfos
	if len(connInfos) == 0 {
		connInfos = []routeConnInfo{{
			PeerID:           config.MyPeerID,
			ConnectedPeerIDs: []uint32{config.RemotePeerID},
			Version:          1,
		}}
	}
	var connPeerList []byte
	for _, info := range connInfos {
		if info.PeerID == 0 || info.Version == 0 {
			continue
		}
		peerIDVersion := appendProtoVarint(nil, 1, uint64(info.PeerID))
		peerIDVersion = appendProtoVarint(peerIDVersion, 2, uint64(info.Version))
		connPeerInfo := appendProtoBytes(nil, 1, peerIDVersion)
		for _, connectedPeerID := range info.ConnectedPeerIDs {
			if connectedPeerID != 0 {
				connPeerInfo = appendProtoVarint(connPeerInfo, 2, uint64(connectedPeerID))
			}
		}
		connPeerList = appendProtoBytes(connPeerList, 1, connPeerInfo)
	}
	return connPeerList
}

func buildStoredRoutePeerInfo(info routePeerInfo) ([]byte, error) {
	if len(info.Raw) > 0 {
		return append([]byte(nil), info.Raw...), nil
	}
	payload := appendProtoVarint(nil, 1, uint64(info.PeerID))
	if info.IPv4.IsValid() {
		addr4 := info.IPv4.As4()
		ipv4 := appendProtoVarint(nil, 1, uint64(binary.BigEndian.Uint32(addr4[:])))
		payload = appendProtoBytes(payload, 4, ipv4)
	}
	for _, prefix := range info.ProxyCIDRs {
		payload = appendProtoBytes(payload, 5, []byte(prefix.String()))
	}
	if info.Cost != 0 {
		payload = appendProtoVarint(payload, 3, uint64(info.Cost))
	}
	if info.Hostname != "" {
		payload = appendProtoBytes(payload, 6, []byte(info.Hostname))
	}
	if info.UDPNATType != 0 {
		payload = appendProtoVarint(payload, 7, uint64(info.UDPNATType))
	}
	payload = appendProtoVarint(payload, 9, uint64(info.Version))
	if hasPeerFeatureFlags(info.FeatureFlags) {
		payload = appendProtoBytes(payload, 11, buildPeerFeatureFlags(info.FeatureFlags))
	}
	if info.PeerRouteID != 0 {
		payload = appendProtoVarint(payload, 12, info.PeerRouteID)
	}
	if info.NetworkLength > 0 {
		payload = appendProtoVarint(payload, 13, uint64(info.NetworkLength))
	}
	if info.IPv6.IsValid() {
		payload = appendProtoBytes(payload, 15, buildProtoIPv6Inet(info.IPv6))
	}
	if info.TCPNATType != 0 {
		payload = appendProtoVarint(payload, 17, uint64(info.TCPNATType))
	}
	return payload, nil
}

func hasPeerFeatureFlags(flags peerFeatureFlags) bool {
	return flags.IsPublicServer || flags.AvoidRelayData || flags.KCPInput || flags.NoRelayKCP || flags.SupportConnListSync || flags.QUICInput || flags.NoRelayQUIC || flags.IsCredentialPeer || flags.NeedP2P || flags.DisableP2P || flags.IPv6PublicAddrProvider
}

func buildPeerFeatureFlags(flags peerFeatureFlags) []byte {
	var payload []byte
	if flags.IsPublicServer {
		payload = appendProtoVarint(payload, 1, 1)
	}
	if flags.AvoidRelayData {
		payload = appendProtoVarint(payload, 2, 1)
	}
	if flags.KCPInput {
		payload = appendProtoVarint(payload, 3, 1)
	}
	if flags.NoRelayKCP {
		payload = appendProtoVarint(payload, 4, 1)
	}
	if flags.SupportConnListSync {
		payload = appendProtoVarint(payload, 5, 1)
	}
	if flags.QUICInput {
		payload = appendProtoVarint(payload, 6, 1)
	}
	if flags.NoRelayQUIC {
		payload = appendProtoVarint(payload, 7, 1)
	}
	if flags.IsCredentialPeer {
		payload = appendProtoVarint(payload, 8, 1)
	}
	if flags.NeedP2P {
		payload = appendProtoVarint(payload, 9, 1)
	}
	if flags.DisableP2P {
		payload = appendProtoVarint(payload, 10, 1)
	}
	if flags.IPv6PublicAddrProvider {
		payload = appendProtoVarint(payload, 11, 1)
	}
	return payload
}

func buildProtoIPv6Inet(addr netip.Addr) []byte {
	addr16 := addr.As16()
	ipv6 := appendProtoVarint(nil, 1, uint64(binary.BigEndian.Uint32(addr16[0:4])))
	ipv6 = appendProtoVarint(ipv6, 2, uint64(binary.BigEndian.Uint32(addr16[4:8])))
	ipv6 = appendProtoVarint(ipv6, 3, uint64(binary.BigEndian.Uint32(addr16[8:12])))
	ipv6 = appendProtoVarint(ipv6, 4, uint64(binary.BigEndian.Uint32(addr16[12:16])))
	return appendProtoBytes(nil, 1, ipv6)
}

func buildRoutePeerInfo(config routeRPCConfig) ([]byte, error) {
	addr := config.IPv4.Addr()
	if !addr.IsValid() || !addr.Is4() {
		return nil, fmt.Errorf("easytier route sync requires an ipv4 address")
	}
	addr4 := addr.As4()
	ipv4 := appendProtoVarint(nil, 1, uint64(binary.BigEndian.Uint32(addr4[:])))

	instID := appendProtoVarint(nil, 1, uint64(config.InstanceID[0]))
	instID = appendProtoVarint(instID, 2, uint64(config.InstanceID[1]))
	instID = appendProtoVarint(instID, 3, uint64(config.InstanceID[2]))
	instID = appendProtoVarint(instID, 4, uint64(config.InstanceID[3]))

	info := appendProtoVarint(nil, 1, uint64(config.MyPeerID))
	info = appendProtoBytes(info, 2, instID)
	info = appendProtoBytes(info, 4, ipv4)
	for _, cidr := range config.ProxyCIDRs {
		if cidr != "" {
			info = appendProtoBytes(info, 5, []byte(cidr))
		}
	}
	if config.Hostname != "" {
		info = appendProtoBytes(info, 6, []byte(config.Hostname))
	}
	info = appendProtoVarint(info, 9, 1)
	info = appendProtoBytes(info, 10, []byte("mihomo"))
	info = appendProtoBytes(info, 11, buildPeerFeatureFlags(peerFeatureFlags{SupportConnListSync: true}))
	info = appendProtoVarint(info, 12, config.PeerRouteID)
	info = appendProtoVarint(info, 13, uint64(config.IPv4.Bits()))
	return info, nil
}

func marshalRPCPacket(packet rpcPacket) []byte {
	descriptor := appendProtoBytes(nil, 1, []byte(packet.Descriptor.DomainName))
	descriptor = appendProtoBytes(descriptor, 2, []byte(packet.Descriptor.ProtoName))
	descriptor = appendProtoBytes(descriptor, 3, []byte(packet.Descriptor.ServiceName))
	descriptor = appendProtoVarint(descriptor, 4, uint64(packet.Descriptor.MethodIndex))

	compressionInfo := appendProtoVarint(nil, 1, rpcCompressionNone)
	compressionInfo = appendProtoVarint(compressionInfo, 2, rpcCompressionNone)

	payload := appendProtoVarint(nil, 1, uint64(packet.FromPeer))
	payload = appendProtoVarint(payload, 2, uint64(packet.ToPeer))
	payload = appendProtoVarint(payload, 3, uint64(packet.TransactionID))
	payload = appendProtoBytes(payload, 4, descriptor)
	payload = appendProtoBytes(payload, 5, packet.Body)
	if packet.IsRequest {
		payload = appendProtoVarint(payload, 6, 1)
	}
	payload = appendProtoVarint(payload, 7, 1)
	payload = appendProtoBytes(payload, 10, compressionInfo)
	return payload
}

func parseRPCPacket(payload []byte) (rpcPacket, error) {
	var packet rpcPacket
	for len(payload) > 0 {
		field, rest, err := consumeProtoField(payload)
		if err != nil {
			return packet, fmt.Errorf("%w: malformed rpc packet", err)
		}
		payload = rest
		switch field.WireType {
		case 0:
			switch field.Number {
			case 1:
				packet.FromPeer = uint32(field.Varint)
			case 2:
				packet.ToPeer = uint32(field.Varint)
			case 3:
				packet.TransactionID = int64(field.Varint)
			case 6:
				packet.IsRequest = field.Varint != 0
			}
		case 2:
			switch field.Number {
			case 4:
				desc, err := parseRPCDescriptor(field.Bytes)
				if err != nil {
					return packet, err
				}
				packet.Descriptor = desc
			case 5:
				packet.Body = append(packet.Body[:0], field.Bytes...)
			}
		default:
			return packet, fmt.Errorf("%w: unsupported rpc wire type %d", ErrInvalidPacket, field.WireType)
		}
	}
	return packet, nil
}

func parseRPCDescriptor(payload []byte) (rpcDescriptor, error) {
	var desc rpcDescriptor
	for len(payload) > 0 {
		field, rest, err := consumeProtoField(payload)
		if err != nil {
			return desc, fmt.Errorf("%w: malformed rpc descriptor", err)
		}
		payload = rest
		switch field.WireType {
		case 0:
			if field.Number == 4 {
				desc.MethodIndex = uint32(field.Varint)
			}
		case 2:
			switch field.Number {
			case 1:
				desc.DomainName = string(field.Bytes)
			case 2:
				desc.ProtoName = string(field.Bytes)
			case 3:
				desc.ServiceName = string(field.Bytes)
			}
		default:
			return desc, fmt.Errorf("%w: unsupported rpc descriptor wire type %d", ErrInvalidPacket, field.WireType)
		}
	}
	return desc, nil
}

func isRouteSyncRequest(packet rpcPacket, networkName string) bool {
	return packet.IsRequest && packet.Descriptor.DomainName == networkName && packet.Descriptor.ProtoName == ospfProtoName && packet.Descriptor.ServiceName == ospfServiceName && packet.Descriptor.MethodIndex == ospfMethodIndex
}

func parseRouteSyncRPCRequest(packet rpcPacket) (syncRouteInfo, error) {
	request, err := parseRPCRequestBody(packet.Body)
	if err != nil {
		return syncRouteInfo{}, err
	}
	return parseSyncRouteInfoRequest(request)
}

func rawRoutePeerInfoPayloads(packet rpcPacket) ([][]byte, error) {
	request, err := parseRPCRequestBody(packet.Body)
	if err != nil {
		return nil, err
	}
	return extractRawRoutePeerInfoPayloads(request)
}

func parseRPCRequestBody(payload []byte) ([]byte, error) {
	for len(payload) > 0 {
		field, rest, err := consumeProtoField(payload)
		if err != nil {
			return nil, err
		}
		payload = rest
		if field.Number == 2 && field.WireType == 2 {
			return append([]byte(nil), field.Bytes...), nil
		}
	}
	return nil, fmt.Errorf("%w: missing rpc request body", ErrInvalidPacket)
}

func parseSyncRouteInfoRequest(payload []byte) (syncRouteInfo, error) {
	var info syncRouteInfo
	for len(payload) > 0 {
		field, rest, err := consumeProtoField(payload)
		if err != nil {
			return info, err
		}
		payload = rest
		switch {
		case field.Number == 1 && field.WireType == 0:
			info.MyPeerID = uint32(field.Varint)
		case field.Number == 4 && field.WireType == 2:
			peerInfos, err := parseRoutePeerInfos(field.Bytes)
			if err != nil {
				return info, err
			}
			info.PeerInfos = peerInfos
		case field.Number == 5 && field.WireType == 2:
			connInfos, err := parseRouteConnBitmap(field.Bytes)
			if err != nil {
				return info, err
			}
			info.ConnInfos = connInfos
		case field.Number == 7 && field.WireType == 2:
			connInfos, err := parseRouteConnPeerList(field.Bytes)
			if err != nil {
				return info, err
			}
			info.ConnInfos = connInfos
		}
	}
	return info, nil
}

func parseRouteConnPeerList(payload []byte) ([]routeConnInfo, error) {
	var infos []routeConnInfo
	for len(payload) > 0 {
		field, rest, err := consumeProtoField(payload)
		if err != nil {
			return nil, err
		}
		payload = rest
		if field.Number != 1 || field.WireType != 2 {
			continue
		}
		info, err := parsePeerConnInfo(field.Bytes)
		if err != nil {
			return nil, err
		}
		if info.PeerID != 0 {
			infos = append(infos, info)
		}
	}
	return infos, nil
}

func parsePeerConnInfo(payload []byte) (routeConnInfo, error) {
	var info routeConnInfo
	for len(payload) > 0 {
		field, rest, err := consumeProtoField(payload)
		if err != nil {
			return info, err
		}
		payload = rest
		switch {
		case field.Number == 1 && field.WireType == 2:
			peerID, version, err := parsePeerIDVersion(field.Bytes)
			if err != nil {
				return info, err
			}
			info.PeerID = peerID
			info.Version = version
		case field.Number == 2 && field.WireType == 0:
			info.ConnectedPeerIDs = append(info.ConnectedPeerIDs, uint32(field.Varint))
		}
	}
	return info, nil
}

func parseRouteConnBitmap(payload []byte) ([]routeConnInfo, error) {
	var peerVersions []routeConnInfo
	var bitmap []byte
	for len(payload) > 0 {
		field, rest, err := consumeProtoField(payload)
		if err != nil {
			return nil, err
		}
		payload = rest
		switch {
		case field.Number == 1 && field.WireType == 2:
			peerID, version, err := parsePeerIDVersion(field.Bytes)
			if err != nil {
				return nil, err
			}
			if peerID != 0 {
				peerVersions = append(peerVersions, routeConnInfo{PeerID: peerID, Version: version})
			}
		case field.Number == 2 && field.WireType == 2:
			bitmap = append(bitmap[:0], field.Bytes...)
		}
	}
	for peerIdx := range peerVersions {
		for otherIdx, other := range peerVersions {
			if routeConnBitmapBit(bitmap, peerIdx*len(peerVersions)+otherIdx) {
				peerVersions[peerIdx].ConnectedPeerIDs = append(peerVersions[peerIdx].ConnectedPeerIDs, other.PeerID)
			}
		}
	}
	return peerVersions, nil
}

func parsePeerIDVersion(payload []byte) (uint32, uint32, error) {
	var peerID, version uint32
	for len(payload) > 0 {
		field, rest, err := consumeProtoField(payload)
		if err != nil {
			return 0, 0, err
		}
		payload = rest
		if field.WireType != 0 {
			continue
		}
		switch field.Number {
		case 1:
			peerID = uint32(field.Varint)
		case 2:
			version = uint32(field.Varint)
		}
	}
	return peerID, version, nil
}

func routeConnBitmapBit(bitmap []byte, bitIdx int) bool {
	byteIdx := bitIdx / 8
	if byteIdx < 0 || byteIdx >= len(bitmap) {
		return false
	}
	return bitmap[byteIdx]&(1<<uint(bitIdx%8)) != 0
}

func extractRawRoutePeerInfoPayloads(payload []byte) ([][]byte, error) {
	for len(payload) > 0 {
		field, rest, err := consumeProtoField(payload)
		if err != nil {
			return nil, err
		}
		payload = rest
		if field.Number == 4 && field.WireType == 2 {
			return extractRawRoutePeerInfos(field.Bytes)
		}
	}
	return nil, nil
}

func parseRoutePeerInfos(payload []byte) ([]routePeerInfo, error) {
	var infos []routePeerInfo
	for len(payload) > 0 {
		field, rest, err := consumeProtoField(payload)
		if err != nil {
			return nil, err
		}
		payload = rest
		if field.Number != 1 || field.WireType != 2 {
			continue
		}
		info, err := parseRoutePeerInfo(field.Bytes)
		if err != nil {
			return nil, err
		}
		if info.PeerID != 0 {
			infos = append(infos, info)
		}
	}
	return infos, nil
}

func extractRawRoutePeerInfos(payload []byte) ([][]byte, error) {
	var infos [][]byte
	for len(payload) > 0 {
		field, rest, err := consumeProtoField(payload)
		if err != nil {
			return nil, err
		}
		payload = rest
		if field.Number != 1 || field.WireType != 2 {
			continue
		}
		infos = append(infos, append([]byte(nil), field.Bytes...))
	}
	return infos, nil
}

func parseRoutePeerInfo(payload []byte) (routePeerInfo, error) {
	info := routePeerInfo{Raw: append([]byte(nil), payload...)}
	for len(payload) > 0 {
		field, rest, err := consumeProtoField(payload)
		if err != nil {
			return info, err
		}
		payload = rest
		switch {
		case field.Number == 1 && field.WireType == 0:
			info.PeerID = uint32(field.Varint)
		case field.Number == 3 && field.WireType == 0:
			info.Cost = uint32(field.Varint)
		case field.Number == 4 && field.WireType == 2:
			addr, err := parseProtoIPv4Addr(field.Bytes)
			if err != nil {
				return info, err
			}
			info.IPv4 = addr
		case field.Number == 5 && field.WireType == 2:
			prefix, err := netip.ParsePrefix(string(field.Bytes))
			if err == nil {
				info.ProxyCIDRs = append(info.ProxyCIDRs, prefix)
			}
		case field.Number == 6 && field.WireType == 2:
			info.Hostname = string(field.Bytes)
		case field.Number == 7 && field.WireType == 0:
			info.UDPNATType = uint32(field.Varint)
		case field.Number == 13 && field.WireType == 0:
			info.NetworkLength = int(field.Varint)
		case field.Number == 9 && field.WireType == 0:
			info.Version = uint32(field.Varint)
		case field.Number == 10 && field.WireType == 2:
			// easytier_version currently unused by mihomo lightweight client.
		case field.Number == 11 && field.WireType == 2:
			info.FeatureFlags = parsePeerFeatureFlags(field.Bytes)
		case field.Number == 12 && field.WireType == 0:
			info.PeerRouteID = field.Varint
		case field.Number == 15 && field.WireType == 2:
			addr, err := parseProtoIPv6Inet(field.Bytes)
			if err == nil {
				info.IPv6 = addr
			}
		case field.Number == 17 && field.WireType == 0:
			info.TCPNATType = uint32(field.Varint)
		}
	}
	return info, nil
}

func parsePeerFeatureFlags(payload []byte) peerFeatureFlags {
	var flags peerFeatureFlags
	for len(payload) > 0 {
		field, rest, err := consumeProtoField(payload)
		if err != nil {
			return flags
		}
		payload = rest
		if field.WireType != 0 {
			continue
		}
		value := field.Varint != 0
		switch field.Number {
		case 1:
			flags.IsPublicServer = value
		case 2:
			flags.AvoidRelayData = value
		case 3:
			flags.KCPInput = value
		case 4:
			flags.NoRelayKCP = value
		case 5:
			flags.SupportConnListSync = value
		case 6:
			flags.QUICInput = value
		case 7:
			flags.NoRelayQUIC = value
		case 8:
			flags.IsCredentialPeer = value
		case 9:
			flags.NeedP2P = value
		case 10:
			flags.DisableP2P = value
		case 11:
			flags.IPv6PublicAddrProvider = value
		}
	}
	return flags
}

func parseProtoIPv6Inet(payload []byte) (netip.Addr, error) {
	for len(payload) > 0 {
		field, rest, err := consumeProtoField(payload)
		if err != nil {
			return netip.Addr{}, err
		}
		payload = rest
		if field.Number != 1 || field.WireType != 2 {
			continue
		}
		return parseProtoIPv6Addr(field.Bytes)
	}
	return netip.Addr{}, fmt.Errorf("%w: missing ipv6 address", ErrInvalidPacket)
}

func parseProtoIPv6Addr(payload []byte) (netip.Addr, error) {
	var parts [4]uint32
	for len(payload) > 0 {
		field, rest, err := consumeProtoField(payload)
		if err != nil {
			return netip.Addr{}, err
		}
		payload = rest
		if field.Number < 1 || field.Number > 4 || field.WireType != 0 {
			continue
		}
		parts[field.Number-1] = uint32(field.Varint)
	}
	var bytes [16]byte
	binary.BigEndian.PutUint32(bytes[0:4], parts[0])
	binary.BigEndian.PutUint32(bytes[4:8], parts[1])
	binary.BigEndian.PutUint32(bytes[8:12], parts[2])
	binary.BigEndian.PutUint32(bytes[12:16], parts[3])
	addr := netip.AddrFrom16(bytes)
	if !addr.IsValid() {
		return netip.Addr{}, fmt.Errorf("%w: invalid ipv6 address", ErrInvalidPacket)
	}
	return addr, nil
}

func parseProtoIPv4Addr(payload []byte) (netip.Addr, error) {
	for len(payload) > 0 {
		field, rest, err := consumeProtoField(payload)
		if err != nil {
			return netip.Addr{}, err
		}
		payload = rest
		if field.Number != 1 || field.WireType != 0 {
			continue
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(field.Varint))
		return netip.AddrFrom4(b), nil
	}
	return netip.Addr{}, fmt.Errorf("%w: missing ipv4 address", ErrInvalidPacket)
}

func consumeProtoField(payload []byte) (protoField, []byte, error) {
	key, n := consumeProtoVarint(payload)
	if n <= 0 {
		return protoField{}, nil, fmt.Errorf("%w: malformed protobuf tag", ErrInvalidPacket)
	}
	payload = payload[n:]
	field := protoField{Number: int(key >> 3), WireType: int(key & 0x7)}
	switch field.WireType {
	case 0:
		value, n := consumeProtoVarint(payload)
		if n <= 0 {
			return field, nil, fmt.Errorf("%w: malformed protobuf varint", ErrInvalidPacket)
		}
		field.Varint = value
		return field, payload[n:], nil
	case 1:
		if len(payload) < 8 {
			return field, nil, fmt.Errorf("%w: malformed protobuf fixed64", ErrInvalidPacket)
		}
		return field, payload[8:], nil
	case 2:
		length, n := consumeProtoVarint(payload)
		if n <= 0 || uint64(len(payload[n:])) < length {
			return field, nil, fmt.Errorf("%w: malformed protobuf bytes", ErrInvalidPacket)
		}
		field.Bytes = payload[n : n+int(length)]
		return field, payload[n+int(length):], nil
	case 5:
		if len(payload) < 4 {
			return field, nil, fmt.Errorf("%w: malformed protobuf fixed32", ErrInvalidPacket)
		}
		return field, payload[4:], nil
	default:
		return field, nil, fmt.Errorf("%w: unsupported protobuf wire type %d", ErrInvalidPacket, field.WireType)
	}
}
