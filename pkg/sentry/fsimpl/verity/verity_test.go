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

package verity

import (
	"fmt"
	"io"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// rootName is the name of the root Merkle tree file.
const rootName = "root.verity"

// maxDataSize is the maximum data size written to the file for test.
const maxDataSize = 100000

// nextFileID is used to generate unique file names.
var nextFileID int64

// newVerityRoot creates a new verity mount, and returns the root. The
// underlying file system is tmpfs. If the error is not nil, then cleanup
// should be called when the root is no longer needed.
func newVerityRoot(ctx context.Context) (*vfs.VirtualFilesystem, vfs.VirtualDentry, func(), error) {
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		return nil, vfs.VirtualDentry{}, nil, fmt.Errorf("VFS init: %v", err)
	}

	vfsObj.MustRegisterFilesystemType("verity", FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})

	vfsObj.MustRegisterFilesystemType("tmpfs", tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})

	mntns, err := vfsObj.NewMountNamespace(ctx, auth.CredentialsFromContext(ctx), "", "verity", &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: InternalFilesystemOptions{
				RootMerkleFileName:           rootName,
				LowerName:                    "tmpfs",
				AllowRuntimeEnable:           true,
				NoCrashOnVerificationFailure: true,
			},
		},
	})
	if err != nil {
		return nil, vfs.VirtualDentry{}, nil, fmt.Errorf("failed to create verity root mount: %v", err)
	}
	root := mntns.Root()
	return vfsObj, root, func() {
		root.DecRef(ctx)
		mntns.DecRef(ctx)
	}, nil
}

// newFileFD creates a new file in the verity mount, and returns the FD. The FD
// points to a file that has random data generated.
func newFileFD(ctx context.Context, vfsObj *vfs.VirtualFilesystem, root vfs.VirtualDentry, filePath string, mode linux.FileMode) (*vfs.FileDescription, int, error) {
	creds := auth.CredentialsFromContext(ctx)
	lowerRoot := root.Dentry().Impl().(*dentry).lowerVD

	// Create the file in the underlying file system.
	lowerFD, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  lowerRoot,
		Start: lowerRoot,
		Path:  fspath.Parse(filePath),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDWR | linux.O_CREAT | linux.O_EXCL,
		Mode:  linux.ModeRegular | mode,
	})
	if err != nil {
		return nil, 0, err
	}

	// Generate random data to be written to the file.
	rand.Seed(time.Now().UnixNano())
	dataSize := rand.Intn(maxDataSize) + 1
	data := make([]byte, dataSize)
	rand.Read(data)

	// Write directly to the underlying FD, since verity FD is read-only.
	n, err := lowerFD.Write(ctx, usermem.BytesIOSequence(data), vfs.WriteOptions{})
	if err != nil {
		return nil, 0, err
	}

	if n != int64(len(data)) {
		return nil, 0, fmt.Errorf("lowerFD.Write got write length %d, want %d", n, len(data))
	}

	lowerFD.DecRef(ctx)

	// Now open the verity file descriptor.
	fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(filePath),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
		Mode:  linux.ModeRegular | mode,
	})
	return fd, dataSize, err
}

// TestOpen ensures that when a file is created, the corresponding Merkle tree
// file and the root Merkle tree file exist.
func TestOpen(t *testing.T) {
	ctx := contexttest.Context(t)
	vfsObj, root, cleanup, err := newVerityRoot(ctx)
	if err != nil {
		t.Fatalf("Failed to create new verity root: %v", err)
	}
	defer cleanup()

	filename := fmt.Sprintf("verity-test-file-%d", atomic.AddInt64(&nextFileID, 1))
	if _, _, err := newFileFD(ctx, vfsObj, root, filename, 0644); err != nil {
		t.Fatalf("Failed to create new file fd: %v", err)
	}

	// Ensure that the corresponding Merkle tree file is created.
	lowerRoot := root.Dentry().Impl().(*dentry).lowerVD
	if _, err = vfsObj.OpenAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  lowerRoot,
		Start: lowerRoot,
		Path:  fspath.Parse(merklePrefix + filename),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
	}); err != nil {
		t.Errorf("Failed to open Merkle tree file %s: %v", merklePrefix+filename, err)
	}

	// Ensure the root merkle tree file is created.
	if _, err = vfsObj.OpenAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  lowerRoot,
		Start: lowerRoot,
		Path:  fspath.Parse(merklePrefix + rootName),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
	}); err != nil {
		t.Errorf("Failed to open root Merkle tree file %s: %v", merklePrefix+rootName, err)
	}
}

// TestUntouchedFileSucceeds ensures that read/reopen an untouched verity file
// succeeds after enabling verity for it.
func TestUntouchedFileSucceeds(t *testing.T) {
	ctx := contexttest.Context(t)
	vfsObj, root, cleanup, err := newVerityRoot(ctx)
	if err != nil {
		t.Fatalf("Failed to create new verity root: %v", err)
	}
	defer cleanup()

	filename := fmt.Sprintf("verity-test-file-%d", atomic.AddInt64(&nextFileID, 1))
	fd, size, err := newFileFD(ctx, vfsObj, root, filename, 0644)
	if err != nil {
		t.Fatalf("Failed to create new file fd: %v", err)
	}

	// Enable verity on the file and confirms a normal read succeeds.
	var args arch.SyscallArguments
	args[1] = arch.SyscallArgument{Value: linux.FS_IOC_ENABLE_VERITY}
	if _, err := fd.Ioctl(ctx, nil /* uio */, args); err != nil {
		t.Fatalf("Ioctl failed: %v", err)
	}

	buf := make([]byte, size)
	n, err := fd.PRead(ctx, usermem.BytesIOSequence(buf), 0 /* offset */, vfs.ReadOptions{})
	if err != nil && err != io.EOF {
		t.Fatalf("fd.PRead failed: %v", err)
	}

	if n != int64(size) {
		t.Errorf("fd.PRead got read length %d, want %d", n, size)
	}

	// Ensure reopenning the verity enabled file succeeds.
	if _, err = vfsObj.OpenAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(filename),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
		Mode:  linux.ModeRegular,
	}); err != nil {
		t.Errorf("reopen enabled file failed: %v", err)
	}

}

// TestModifiedFileFails ensures that read from a modified verity file fails.
func TestModifiedFileFails(t *testing.T) {
	ctx := contexttest.Context(t)
	vfsObj, root, cleanup, err := newVerityRoot(ctx)
	if err != nil {
		t.Fatalf("Failed to create new verity root: %v", err)
	}
	defer cleanup()

	filename := fmt.Sprintf("verity-test-file-%d", atomic.AddInt64(&nextFileID, 1))
	fd, size, err := newFileFD(ctx, vfsObj, root, filename, 0644)
	if err != nil {
		t.Fatalf("Failed to create new file fd: %v", err)
	}

	// Enable verity on the file.
	var args arch.SyscallArguments
	args[1] = arch.SyscallArgument{Value: linux.FS_IOC_ENABLE_VERITY}
	if _, err := fd.Ioctl(ctx, nil /* uio */, args); err != nil {
		t.Fatalf("Ioctl failed: %v", err)
	}

	// Open a new lowerFD that's read/writable.
	lowerVD := fd.Impl().(*fileDescription).d.lowerVD

	lowerFD, err := vfsObj.OpenAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  lowerVD,
		Start: lowerVD,
	}, &vfs.OpenOptions{
		Flags: linux.O_RDWR,
	})
	if err != nil {
		t.Fatalf("Open lowerFD failed: %v", err)
	}

	// flip a random bit in the underlying file.
	randomPos := int64(rand.Intn(size))
	byteToModify := make([]byte, 1)
	if _, err := lowerFD.PRead(ctx, usermem.BytesIOSequence(byteToModify), randomPos, vfs.ReadOptions{}); err != nil {
		t.Fatalf("lowerFD.PRead failed: %v", err)
	}
	byteToModify[0] ^= 1
	if _, err := lowerFD.PWrite(ctx, usermem.BytesIOSequence(byteToModify), randomPos, vfs.WriteOptions{}); err != nil {
		t.Fatalf("lowerFD.PWrite failed: %v", err)
	}

	// Confirm that read from the modified file fails.
	buf := make([]byte, size)
	if _, err := fd.PRead(ctx, usermem.BytesIOSequence(buf), 0 /* offset */, vfs.ReadOptions{}); err == nil {
		t.Fatalf("fd.PRead succeeded with modified file")
	}
}

// TestModifiedMerkleFails ensures that read from a verity file fails if the
// corresponding Merkle tree file is modified.
func TestModifiedMerkleFails(t *testing.T) {
	ctx := contexttest.Context(t)
	vfsObj, root, cleanup, err := newVerityRoot(ctx)
	if err != nil {
		t.Fatalf("Failed to create new verity root: %v", err)
	}
	defer cleanup()

	filename := fmt.Sprintf("verity-test-file-%d", atomic.AddInt64(&nextFileID, 1))
	fd, size, err := newFileFD(ctx, vfsObj, root, filename, 0644)
	if err != nil {
		t.Fatalf("Failed to create new file fd: %v", err)
	}

	// Enable verity on the file.
	var args arch.SyscallArguments
	args[1] = arch.SyscallArgument{Value: linux.FS_IOC_ENABLE_VERITY}
	if _, err := fd.Ioctl(ctx, nil /* uio */, args); err != nil {
		t.Fatalf("Ioctl failed: %v", err)
	}

	// Open a new lowerMerkleFD that's read/writable.
	lowerMerkleVD := fd.Impl().(*fileDescription).d.lowerMerkleVD

	lowerMerkleFD, err := vfsObj.OpenAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  lowerMerkleVD,
		Start: lowerMerkleVD,
	}, &vfs.OpenOptions{
		Flags: linux.O_RDWR,
	})
	if err != nil {
		t.Fatalf("Open lowerMerkleFD failed: %v", err)
	}

	// flip a random bit in the Merkle tree file.
	stat, err := lowerMerkleFD.Stat(ctx, vfs.StatOptions{})
	if err != nil {
		t.Fatalf("Failed to get lowerMerkleFD stat: %v", err)
	}
	merkleSize := int(stat.Size)
	randomPos := int64(rand.Intn(merkleSize))
	byteToModify := make([]byte, 1)
	if _, err := lowerMerkleFD.PRead(ctx, usermem.BytesIOSequence(byteToModify), randomPos, vfs.ReadOptions{}); err != nil {
		t.Fatalf("lowerMerkleFD.PRead failed: %v", err)
	}
	byteToModify[0] ^= 1
	if _, err := lowerMerkleFD.PWrite(ctx, usermem.BytesIOSequence(byteToModify), randomPos, vfs.WriteOptions{}); err != nil {
		t.Fatalf("lowerMerkleFD.PWrite failed: %v", err)
	}

	// Confirm that read from a file with modified Merkle tree fails.
	buf := make([]byte, size)
	if _, err := fd.PRead(ctx, usermem.BytesIOSequence(buf), 0 /* offset */, vfs.ReadOptions{}); err == nil {
		fmt.Println(buf)
		t.Fatalf("fd.PRead succeeded with modified Merkle file")
	}
}
