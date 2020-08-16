// Copyright 2020 The gVisor Authors.
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

package stack

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

var _ GroupAddressableEndpoint = (*AddressableEndpointState)(nil)
var _ AddressableEndpoint = (*AddressableEndpointState)(nil)

// AddressableEndpointState is an implementation of an AddressableEndpoint.
type AddressableEndpointState struct {
	networkEndpoint NetworkEndpoint

	// Lock ordering (from outer to inner lock ordering):
	//
	// AddressableEndpointState.mu
	//   addressState.mu
	mu struct {
		sync.RWMutex

		endpoints map[tcpip.Address]*addressState
		primary   []*addressState

		// groups holds the mapping between group addresses and the number of times
		// they have been joined.
		groups map[tcpip.Address]uint32
	}
}

// Init initializes the AddressableEndpointState with networkEndpoint.
//
// Must be called before calling any other function on m.
func (a *AddressableEndpointState) Init(networkEndpoint NetworkEndpoint) {
	a.networkEndpoint = networkEndpoint

	a.mu.Lock()
	defer a.mu.Unlock()
	a.mu.endpoints = make(map[tcpip.Address]*addressState)
	a.mu.groups = make(map[tcpip.Address]uint32)
}

// ReadOnlyAddressableEndpointState provides read-only access to an
// AddressableEndpointState.
type ReadOnlyAddressableEndpointState struct {
	inner *AddressableEndpointState
}

// AddrOrMatching returns an endpoint for the passed address that is consisdered
// bound to the wrapped AddressableEndpointState.
//
// If addr is an exact match with an existing address, that address will be
// returned. Otherwise, f is called with each address and the address that f
// returns true for will be returned.
//
// Returns nil of no address matches.
func (m ReadOnlyAddressableEndpointState) AddrOrMatching(addr tcpip.Address, spoofingOrPrimiscuous bool, f func(AddressEndpoint) bool) AddressEndpoint {
	m.inner.mu.RLock()
	defer m.inner.mu.RUnlock()

	if ep, ok := m.inner.mu.endpoints[addr]; ok {
		if ep.IsAssigned(spoofingOrPrimiscuous) && ep.IncRef() {
			return ep
		}
	}

	for _, ep := range m.inner.mu.endpoints {
		if ep.IsAssigned(spoofingOrPrimiscuous) && f(ep) && ep.IncRef() {
			return ep
		}
	}

	return nil
}

// Lookup returns the AddressEndpoint for the passed address.
//
// Returns nil if the passed address is not associated with the
// AddressableEndpointState.
func (m ReadOnlyAddressableEndpointState) Lookup(addr tcpip.Address) AddressEndpoint {
	m.inner.mu.RLock()
	defer m.inner.mu.RUnlock()

	ep, ok := m.inner.mu.endpoints[addr]
	if !ok {
		return nil
	}
	return ep
}

// ForEach calls f for each address pair.
//
// If f returns false, f will no longer be called.
func (m ReadOnlyAddressableEndpointState) ForEach(f func(AddressEndpoint) bool) {
	m.inner.mu.RLock()
	defer m.inner.mu.RUnlock()

	for _, ep := range m.inner.mu.endpoints {
		if !f(ep) {
			return
		}
	}
}

// ForEachPrimaryEndpoint calls f for each primary address.
//
// If f returns false, f will no longer be called.
func (m ReadOnlyAddressableEndpointState) ForEachPrimaryEndpoint(f func(AddressEndpoint)) {
	m.inner.mu.RLock()
	defer m.inner.mu.RUnlock()
	for _, ep := range m.inner.mu.primary {
		f(ep)
	}
}

// ReadOnly returns a readonly reference to a.
func (a *AddressableEndpointState) ReadOnly() ReadOnlyAddressableEndpointState {
	return ReadOnlyAddressableEndpointState{inner: a}
}

func (a *AddressableEndpointState) releaseAddressState(addrState *addressState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.releaseAddressStateLocked(addrState)
}

// releaseAddressState removes addrState from s's address state (primary and endpoints list).
//
// Preconditions: a.mu must be write locked.
func (a *AddressableEndpointState) releaseAddressStateLocked(addrState *addressState) {
	oldPrimary := a.mu.primary
	for i, s := range a.mu.primary {
		if s == addrState {
			a.mu.primary = append(a.mu.primary[:i], a.mu.primary[i+1:]...)
			oldPrimary[len(oldPrimary)-1] = nil
			break
		}
	}
	delete(a.mu.endpoints, addrState.addr.Address)
}

// AddAndAcquirePermanentAddress implements AddressableEndpoint.
func (a *AddressableEndpointState) AddAndAcquirePermanentAddress(addr tcpip.AddressWithPrefix, peb PrimaryEndpointBehavior, configType AddressConfigType, deprecated bool) (AddressEndpoint, *tcpip.Error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.addAndAcquireAddressLocked(addr, peb, configType, deprecated, true /* permanent */)
}

// AddAndAcquireTemporaryAddress adds a temporary address.
//
// Returns tcpip.ErrDuplicateAddress if the address exists.
//
// The temporary address's endpoint will be acquired and returned.
func (a *AddressableEndpointState) AddAndAcquireTemporaryAddress(addr tcpip.AddressWithPrefix, peb PrimaryEndpointBehavior) (AddressEndpoint, *tcpip.Error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.addAndAcquireAddressLocked(addr, peb, AddressConfigStatic, false /* deprecated */, false /* permanent */)
}

// addAndAcquireAddressLocked adds, acquires and returns a permanent or
// temporary address.
//
// If the addressable endpoint already has the address in a non-permanent state,
// and addAndAcquireAddressLocked is adding a permanent address, that address
// will be promoted in place and its properties set to the properties provided.
// If the address already exists in any other state, then
// tcpip.ErrDuplicateAddress will be returned, regardless the kind of address
// that is being added.
//
// Precondition: a.mu must be write locked.
func (a *AddressableEndpointState) addAndAcquireAddressLocked(addr tcpip.AddressWithPrefix, peb PrimaryEndpointBehavior, configType AddressConfigType, deprecated, permanent bool) (AddressEndpoint, *tcpip.Error) {
	// attemptAddToPrimary is false when a promoted is already in the primary
	// address list.
	attemptAddToPrimary := true
	addrState, ok := a.mu.endpoints[addr.Address]
	if ok {
		if !permanent {
			// We are adding a non-permanent address but the address exists. No need
			// to go any further since we can only promote existing temporary/expired
			// addresses to permanent.
			return nil, tcpip.ErrDuplicateAddress
		}

		addrState.mu.Lock()
		if addrState.mu.kind.IsPermanent() {
			addrState.mu.Unlock()
			// We are adding a permanent address but a permanent address already
			// exists.
			return nil, tcpip.ErrDuplicateAddress
		}

		if addrState.mu.refs == 0 {
			// This only happens when adding an address races with an address's
			// reference count reaching 0. Release the address's resources here
			// so we can create a new one below.
			a.releaseAddressStateLocked(addrState)
			addrState.mu.Unlock()
			addrState = nil
		} else {
			// We will now promote the address.
		loop:
			for i, s := range a.mu.primary {
				if s == addrState {
					switch peb {
					case CanBePrimaryEndpoint:
						// The address is already in the primary address list.
						attemptAddToPrimary = false
						break loop
					case FirstPrimaryEndpoint:
						if i == 0 {
							// The address is already first in the primary address list.
							attemptAddToPrimary = false
							break loop
						}
						a.mu.primary = append(a.mu.primary[:i], a.mu.primary[i+1:]...)
					case NeverPrimaryEndpoint:
						a.mu.primary = append(a.mu.primary[:i], a.mu.primary[i+1:]...)
						break loop
					}
				}
			}
		}
	}

	if addrState == nil {
		addrState = &addressState{
			addressableEndpointState: a,
			addr:                     addr,
		}
		a.mu.endpoints[addr.Address] = addrState
		addrState.mu.Lock()
	}

	// At this point we have an address we are either promoting from an expired or
	// temporary address to permanent, promoting an expired address to temporary,
	// or we are adding a new temporary or permanent address.
	//
	// The address MUST be write locked at this point.
	defer addrState.mu.Unlock()

	// The ref count is incremented because we may be promoting an address.
	if permanent {
		addrState.mu.kind = Permanent
		// We increment the reference count here because we may be promoting an
		// existing address which may have live reference to it.
		//
		// Increment by 2 because we return an acquired address and permanent
		// addresses' reference counts are biased by 1.
		addrState.mu.refs += 2
	} else {
		addrState.mu.kind = Temporary
		// We don't increment the reference count because we don't support promoting
		// to a temporary address - this temporary addresses must be new.
		//
		// The reference count is set to 1 because we return an acquired address
		// and temporary addresses' reference counts are not biased.
		addrState.mu.refs = 1
	}
	addrState.mu.deprecated = deprecated
	addrState.mu.configType = configType

	if attemptAddToPrimary {
		switch peb {
		case CanBePrimaryEndpoint:
			a.mu.primary = append(a.mu.primary, addrState)
		case FirstPrimaryEndpoint:
			// Shift all the endpoints by 1 to make room for the new address at the
			// front. We could have just created a new slice but this saves
			// allocations when the slice has capacity for the new address.
			primaryCount := len(a.mu.primary)
			a.mu.primary = append(a.mu.primary, nil)
			if n := copy(a.mu.primary[1:], a.mu.primary); n != primaryCount {
				panic(fmt.Sprintf("copied %d elements; expected = %d elements", n, primaryCount))
			}
			a.mu.primary[0] = addrState
		}
	}

	return addrState, nil
}

// RemovePermanentAddress implements AddressableEndpoint.
func (a *AddressableEndpointState) RemovePermanentAddress(addr tcpip.Address) *tcpip.Error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, ok := a.mu.groups[addr]; ok {
		panic(fmt.Sprintf("group address = %s must be removed with LeaveGroup", addr))
	}

	return a.removePermanentAddressLocked(addr)
}

// removePermanentAddressLocked is like RemovePermanentAddress but with locking
// requirements.
//
// Precondition: a.mu must be write locked.
func (a *AddressableEndpointState) removePermanentAddressLocked(addr tcpip.Address) *tcpip.Error {
	addrState, ok := a.mu.endpoints[addr]
	if !ok {
		return tcpip.ErrBadLocalAddress
	}

	return a.removePermanentEndpointLocked(addrState)
}

// RemovePermanentEndpoint removes the passed endpoint if it is associated with
// a and permanent.
func (a *AddressableEndpointState) RemovePermanentEndpoint(ep AddressEndpoint) *tcpip.Error {
	addrState, ok := ep.(*addressState)
	if !ok || addrState.addressableEndpointState != a {
		return tcpip.ErrInvalidEndpointState
	}

	return a.removePermanentEndpointLocked(addrState)
}

// removePermanentAddressLocked is like RemovePermanentAddress but with locking
// requirements.
//
// Precondition: a.mu must be write locked.
func (a *AddressableEndpointState) removePermanentEndpointLocked(addrState *addressState) *tcpip.Error {
	if !addrState.GetKind().IsPermanent() {
		return tcpip.ErrBadLocalAddress
	}

	addrState.SetKind(PermanentExpired)
	a.decAddressRefLocked(addrState)
	return nil
}

// decAddressRefLocked decremeents the reference count for addrState and
// releases it from s if addrState's reference count reaches 0.
func (a *AddressableEndpointState) decAddressRefLocked(addrState *addressState) {
	if addrState.decRef() {
		a.releaseAddressStateLocked(addrState)
	}
}

// AcquireAssignedAddress implements AddressableEndpoint.
func (a *AddressableEndpointState) AcquireAssignedAddress(localAddr tcpip.Address, allowTemp bool, tempPEB PrimaryEndpointBehavior) AddressEndpoint {
	a.mu.Lock()
	defer a.mu.Unlock()

	if addrState, ok := a.mu.endpoints[localAddr]; ok {
		if !addrState.IsAssigned(allowTemp) {
			return nil
		}

		if addrState.IncRef() {
			return addrState
		}

		a.releaseAddressStateLocked(addrState)
	}

	if !allowTemp {
		return nil
	}

	addr := localAddr.WithPrefix()
	addressEndpoint, err := a.addAndAcquireAddressLocked(addr, tempPEB, AddressConfigStatic, false /* deprecated */, false /* permanent */)
	if err != nil {
		// addAndAcquireAddressLocked only returns an error if the address is already assigned
		// but we just checked above if the address exists so we expect no error.
		panic(fmt.Sprintf("a.addAndAcquireAddressLocked(%s, %d, %d, false, false): %s", addr, tempPEB, AddressConfigStatic, err))
	}
	return addressEndpoint
}

// AcquirePrimaryAddress implements AddressableEndpoint.
func (a *AddressableEndpointState) AcquirePrimaryAddress(remoteAddr tcpip.Address, allowExpired bool) AddressEndpoint {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var deprecatedEndpoint *addressState
	for _, ep := range a.mu.primary {
		if !ep.IsAssigned(allowExpired) {
			continue
		}

		if !ep.Deprecated() {
			if ep.IncRef() {
				// ep is not deprecated, so return it immediately.
				//
				// If we kept track of a deprecated endpoint, decrement its reference
				// count since it was incremented when we decided to keep track of it.
				if deprecatedEndpoint != nil {
					a.decAddressRefLocked(deprecatedEndpoint)
					deprecatedEndpoint = nil
				}

				return ep
			}
		} else if deprecatedEndpoint == nil && ep.IncRef() {
			// We prefer an endpoint that is not deprecated, but we keep track of
			// ep in case a doesn't have any non-deprecated endpoints.
			//
			// If we end up finding a more preferred endpoint, ep's reference
			// count will be decremented when such an endpoint is found.
			deprecatedEndpoint = ep
		}
	}

	// a doesn't have any valid non-deprecated endpoints, so return
	// deprecatedEndpoint (which may be nil if a doesn't have any valid deprecated
	// endpoints either).
	if deprecatedEndpoint == nil {
		return nil
	}
	return deprecatedEndpoint
}

// PrimaryAddresses implements AddressableEndpoint.
func (a *AddressableEndpointState) PrimaryAddresses() []tcpip.AddressWithPrefix {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var addrs []tcpip.AddressWithPrefix
	for _, ep := range a.mu.primary {
		// Don't include tentative, expired or temporary endpoints
		// to avoid confusion and prevent the caller from using
		// those.
		switch ep.GetKind() {
		case PermanentTentative, PermanentExpired, Temporary:
			continue
		}

		addrs = append(addrs, ep.AddressWithPrefix())
	}

	return addrs
}

// PermanentAddresses implements AddressableEndpoint.
func (a *AddressableEndpointState) PermanentAddresses() []tcpip.AddressWithPrefix {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var addrs []tcpip.AddressWithPrefix
	for _, ep := range a.mu.endpoints {
		if !ep.GetKind().IsPermanent() {
			continue
		}

		addrs = append(addrs, ep.AddressWithPrefix())
	}

	return addrs
}

// JoinGroup implements GroupAddressableEndpoint.
func (a *AddressableEndpointState) JoinGroup(group tcpip.Address) (bool, *tcpip.Error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	joins, ok := a.mu.groups[group]
	if !ok {
		ep, err := a.addAndAcquireAddressLocked(group.WithPrefix(), NeverPrimaryEndpoint, AddressConfigStatic, false /* deprecated */, true /* permanent */)
		if err != nil {
			return false, err
		}
		// We have no need for the address endpoint.
		ep.DecRef()
	}

	a.mu.groups[group] = joins + 1
	return !ok, nil
}

// LeaveGroup implements GroupAddressableEndpoint.
func (a *AddressableEndpointState) LeaveGroup(group tcpip.Address) (bool, *tcpip.Error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	joins, ok := a.mu.groups[group]
	if !ok {
		return false, tcpip.ErrBadLocalAddress
	}

	if joins == 1 {
		a.removeGroupAddressLocked(group)
		delete(a.mu.groups, group)
		return true, nil
	}

	a.mu.groups[group] = joins - 1
	return false, nil
}

// IsInGroup implements GroupAddressableEndpoint.
func (a *AddressableEndpointState) IsInGroup(group tcpip.Address) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, ok := a.mu.groups[group]
	return ok
}

func (a *AddressableEndpointState) removeGroupAddressLocked(group tcpip.Address) {
	if err := a.removePermanentAddressLocked(group); err != nil {
		// removePermanentEndpointLocked would only return an error if group is
		// not bound to the addressable endpoint, but we know it MUST be assigned
		// since we have group in our map of groups.
		panic(fmt.Sprintf("error removing group address = %s: %s", group, err))
	}
}

// Cleanup forcefully leaves all groups and removes all permanent addresses.
func (a *AddressableEndpointState) Cleanup() {
	a.mu.Lock()
	defer a.mu.Unlock()

	for group := range a.mu.groups {
		a.removeGroupAddressLocked(group)
	}
	a.mu.groups = make(map[tcpip.Address]uint32)

	for _, ep := range a.mu.endpoints {
		// removePermanentEndpointLocked will return tcpip.ErrBadLocalAddress if ep
		// is not a permanent address.
		if err := a.removePermanentEndpointLocked(ep); err != nil && err != tcpip.ErrBadLocalAddress {
			panic(fmt.Sprintf("unexpected error from removePermanentEndpointLocked(%s): %s", ep.addr, err))
		}
	}
}

var _ AddressEndpoint = (*addressState)(nil)

// addressState holds state for an address.
type addressState struct {
	addressableEndpointState *AddressableEndpointState
	addr                     tcpip.AddressWithPrefix

	// Lock ordering (from outer to inner lock ordering):
	//
	// AddressableEndpointState.mu
	//   addressState.mu
	mu struct {
		sync.RWMutex

		refs       uint32
		kind       AddressKind
		configType AddressConfigType
		deprecated bool
	}
}

// NetworkEndpoint implements AddressEndpoint.
func (a *addressState) NetworkEndpoint() NetworkEndpoint {
	return a.addressableEndpointState.networkEndpoint
}

// AddressWithPrefix implements AddressEndpoint.
func (a *addressState) AddressWithPrefix() tcpip.AddressWithPrefix {
	return a.addr
}

// GetKind implements AddressEndpoint.
func (a *addressState) GetKind() AddressKind {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.mu.kind
}

// SetKind implements AddressEndpoint.
func (a *addressState) SetKind(kind AddressKind) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mu.kind = kind
}

// IsAssigned implements AddressEndpoint.
func (a *addressState) IsAssigned(allowExpired bool) bool {
	if !a.addressableEndpointState.networkEndpoint.Enabled() {
		return false
	}

	switch a.GetKind() {
	case PermanentTentative:
		return false
	case PermanentExpired:
		return allowExpired
	default:
		return true
	}
}

// IncRef implements AddressEndpoint.
func (a *addressState) IncRef() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mu.refs == 0 {
		return false
	}

	a.mu.refs++
	return true
}

// DecRef implements AddressEndpoint.
func (a *addressState) DecRef() {
	if !a.decRef() {
		return
	}

	a.addressableEndpointState.releaseAddressState(a)
}

// decRef decrements the reference count.
//
// Returns true if the endpoint needs to be released.
func (a *addressState) decRef() bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.mu.refs == 0 {
		panic(fmt.Sprintf("attempted to decrease ref count for AddressEndpoint w/ addr = %s when it is already released", a.addr))
	}

	a.mu.refs--

	// Non-expired permanent addresses must not have its reference count dropped
	// to 0.
	shouldRelease := a.mu.refs == 0
	if shouldRelease && a.mu.kind.IsPermanent() {
		panic(fmt.Sprintf("permanent addresses should be removed through the AddressableEndpoint: addr = %s, kind = %d", a.addr, a.mu.kind))
	}

	return shouldRelease
}

// ConfigType implements AddressEndpoint.
func (a *addressState) ConfigType() AddressConfigType {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.mu.configType
}

// SetDeprecated implements AddressEndpoint.
func (a *addressState) SetDeprecated(d bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mu.deprecated = d
}

// Deprecated implements AddressEndpoint.
func (a *addressState) Deprecated() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.mu.deprecated
}
