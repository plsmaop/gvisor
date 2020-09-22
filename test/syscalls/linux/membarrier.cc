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

#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>

#include "test/util/cleanup.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

// This test defines the structure of all following tests, but uses memory
// fences instead of membarrier(2). This is a sanity test for the structure of
// the test itself.
TEST(MembarrierTest, NoMembarrier) {
  std::atomic<uint64_t> x{0};
  std::atomic<uint64_t> y{0};

  // FIXME(jamieliu): current test always passes on x86 regardless of fences (in
  // fact this test is Intel SDM Vol. 3A, Sec. 8.2.3.2 "Neither Loads Nor Stores
  // Are Reordered with Like Operations", Example 8-1 "Stores Are Not Reordered
  // with Other Stores" in a loop)

  std::atomic<bool> done{false};
  ScopedThread writer_thread([&] {
    while (!done.load(std::memory_order_relaxed)) {
      x.fetch_add(1, std::memory_order_relaxed);
      // std::atomic_thread_fence(std::memory_order_release);
      y.fetch_add(1, std::memory_order_relaxed);
    }
  });
  auto cleanup_done =
      Cleanup([&] { done.store(true, std::memory_order_relaxed); });
  constexpr int kIterations = 1000000;
  for (int i = 0; i < kIterations; i++) {
    auto cur_y = y.load(std::memory_order_relaxed);
    // std::atomic_thread_fence(std::memory_order_acquire);
    auto cur_x = x.load(std::memory_order_relaxed);
    ASSERT_GE(cur_x, cur_y);
  }
}

#if 0

enum membarrier_cmd {
  MEMBARRIER_CMD_QUERY                                = 0,
  MEMBARRIER_CMD_GLOBAL                               = (1 << 0),
  MEMBARRIER_CMD_GLOBAL_EXPEDITED                     = (1 << 1),
  MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED            = (1 << 2),
  MEMBARRIER_CMD_PRIVATE_EXPEDITED                    = (1 << 3),
  MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED           = (1 << 4),
  MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE          = (1 << 5),
  MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE = (1 << 6),
};

int membarrier(membarrier_cmd cmd, int flags) {
  return syscall(SYS_membarrier, cmd, flags);
}

PosixErrorOr<int> SupportedMembarrierCommands() {
  int cmds = membarrier(MEMBARRIER_CMD_QUERY, 0);
  if (cmds < 0) {
    if (errno == ENOSYS) {
      // No commands are supported.
      return 0;
    }
    return PosixError(errno, "membarrier(MEMBARRIER_CMD_QUERY) failed");
  }
  return cmds;
}

TEST(MembarrierTest, Global) {
  SKIP_IF((ASSERT_NO_ERRNO_AND_VALUE(SupportedMembarrierCommands()) &
           MEMBARRIER_CMD_GLOBAL) == 0);

  Mapping m = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED));
  auto x = static_cast<std::atomic<uint64_t>*>(m.ptr());
  auto y = x + 1;

  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process.
    while (true) {
      x->fetch_add(1, std::memory_order_relaxed);
      TEST_PCHECK(membarrier(MEMBARRIER_CMD_GLOBAL, 0) == 0);
      y->fetch_add(1, std::memory_order_relaxed);
    }
  }
  // In parent process.
  ASSERT_THAT(child_pid, SyscallSucceeds());
  auto cleanup_child = Cleanup([&] {
    EXPECT_THAT(kill(child_pid, SIGKILL), SyscallSucceeds());
    int status;
    ASSERT_THAT(waitpid(child_pid, &status, 0),
                SyscallSucceedsWithValue(child_pid));
    EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
        << " status " << status;
  });
  constexpr int kIterations = 1000000;
  for (int i = 0; i < kIterations; i++) {
    auto cur_y = y->load(std::memory_order_relaxed);
    std::atomic_signal_fence(std::memory_order_acq_rel);
    auto cur_x = x->load(std::memory_order_relaxed);
    ASSERT_GE(cur_x, cur_y);
  }
}

TEST(MembarrierTest, GlobalExpedited) {
  constexpr int kRequiredCommands = MEMBARRIER_CMD_GLOBAL_EXPEDITED |
                                    MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED;
  SKIP_IF((ASSERT_NO_ERRNO_AND_VALUE(SupportedMembarrierCommands()) &
           kRequiredCommands) != kRequiredCommands);

  Mapping m = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED));
  auto x = static_cast<std::atomic<uint64_t>*>(m.ptr());
  auto y = x + 1;

  ASSERT_THAT(membarrier(MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED, 0),
              SyscallSucceeds());

  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process.
    while (true) {
      x->fetch_add(1, std::memory_order_relaxed);
      TEST_PCHECK(membarrier(MEMBARRIER_CMD_GLOBAL_EXPEDITED, 0) == 0);
      y->fetch_add(1, std::memory_order_relaxed);
    }
  }
  // In parent process.
  ASSERT_THAT(child_pid, SyscallSucceeds());
  auto cleanup_child = Cleanup([&] {
    EXPECT_THAT(kill(child_pid, SIGKILL), SyscallSucceeds());
    int status;
    ASSERT_THAT(waitpid(child_pid, &status, 0),
                SyscallSucceedsWithValue(child_pid));
    EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
        << " status " << status;
  });
  constexpr int kIterations = 1000000;
  for (int i = 0; i < kIterations; i++) {
    auto cur_y = y->load(std::memory_order_relaxed);
    std::atomic_signal_fence(std::memory_order_acq_rel);
    auto cur_x = x->load(std::memory_order_relaxed);
    ASSERT_GE(cur_x, cur_y);
  }
}

TEST(MembarrierTest, PrivateExpedited) {
  constexpr int kRequiredCommands = MEMBARRIER_CMD_PRIVATE_EXPEDITED |
                                    MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED;
  SKIP_IF((ASSERT_NO_ERRNO_AND_VALUE(SupportedMembarrierCommands()) &
           kRequiredCommands) != kRequiredCommands);

  std::atomic<uint64_t> x{0};
  std::atomic<uint64_t> y{0};

  ASSERT_THAT(membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0),
              SyscallSucceeds());

  std::atomic<bool> done{false};
  ScopedThread writer_thread([&] {
    while (!done.load(std::memory_order_relaxed)) {
      x.fetch_add(1, std::memory_order_relaxed);
      ASSERT_THAT(membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0),
                  SyscallSucceeds());
      y.fetch_add(1, std::memory_order_relaxed);
    }
  });
  auto cleanup_done = Cleanup([&] {
    done.store(true, std::memory_order_relaxed);
  });
  constexpr int kIterations = 1000000;
  for (int i = 0; i < kIterations; i++) {
    auto cur_y = y.load(std::memory_order_relaxed);
    std::atomic_signal_fence(std::memory_order_acq_rel);
    auto cur_x = x.load(std::memory_order_relaxed);
    ASSERT_GE(cur_x, cur_y);
  }
}

#endif

}  // namespace

}  // namespace testing
}  // namespace gvisor
