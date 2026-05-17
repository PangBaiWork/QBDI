/*
 * This file is part of QBDI.
 *
 * Copyright 2017 - 2025 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <utility>

#include "llvm/Support/Error.h"
#include "llvm/Support/Process.h"

#include "QBDI/Memory.hpp"
#include "ExecBroker/ExecBroker.h"
#include "Utility/LogSys.h"

namespace QBDI {

ExecBroker::ExecBroker(std::unique_ptr<ExecBlock> _transferBlock,
                       const LLVMCPUs &llvmCPUs, VMInstanceRef vminstance)
    : transferBlock(std::move(_transferBlock)), blacklistMode(false) {
  pageSize = llvm::expectedToOptional(llvm::sys::Process::getPageSize())
                 .value_or(4096);
  initExecBrokerSequences(llvmCPUs);
}

void ExecBroker::changeVMInstanceRef(VMInstanceRef vminstance) {
  transferBlock->changeVMInstanceRef(vminstance);
}

size_t ExecBroker::getPatchRangeSize(rword start) const {
  if (blacklistMode) {
    const Range<rword> *curRange = blacklisted.getElementRange(start);
    if (curRange != nullptr) {
      return 0;
    }
    const auto &ranges = blacklisted.getRanges();
    auto it = std::lower_bound(
        ranges.cbegin(), ranges.cend(), start,
        [](const Range<rword> &range, rword value) {
          return range.end() <= value;
        });
    if (it != ranges.cend()) {
      return it->start() - start;
    }
    return static_cast<size_t>(-1);
  }

  const Range<rword> *curRange = instrumented.getElementRange(start);
  if (curRange != nullptr) {
    return curRange->end() - start;
  }
  return static_cast<size_t>(-1);
}

void ExecBroker::addInstrumentedRange(const Range<rword> &r) {
  if (blacklistMode) {
    QBDI_WARN(
        "addInstrumentedRange is ignored in blacklist mode; use "
        "removeInstrumentedRange to add a blacklisted range");
    return;
  }
  QBDI_DEBUG("Adding instrumented range [0x{:x}, 0x{:x}]", r.start(),
             r.end());
  instrumented.add(r);
}

void ExecBroker::removeInstrumentedRange(const Range<rword> &r) {
  if (blacklistMode) {
    QBDI_DEBUG("Adding blacklisted range [0x{:x}, 0x{:x}]", r.start(),
               r.end());
    blacklisted.add(r);
  } else {
    QBDI_DEBUG("Removing instrumented range [0x{:x}, 0x{:x}]", r.start(),
               r.end());
    instrumented.remove(r);
  }
}

void ExecBroker::removeAllInstrumentedRanges() {
  if (blacklistMode) {
    blacklisted.clear();
  } else {
    instrumented.clear();
  }
}

bool ExecBroker::addInstrumentedModule(const std::string &name) {
  if (blacklistMode) {
    QBDI_WARN(
        "addInstrumentedModule is ignored in blacklist mode; use "
        "removeInstrumentedModule to blacklist a module");
    return false;
  }
  bool instrumented = false;
  if (name.empty()) {
    return false;
  }

  for (const MemoryMap &m : getCurrentProcessMaps()) {
    if ((m.name == name) && (m.permission & QBDI::PF_EXEC)) {
      addInstrumentedRange(m.range);
      instrumented = true;
    }
  }
  return instrumented;
}

bool ExecBroker::addInstrumentedModuleFromAddr(rword addr) {
  for (const MemoryMap &m : getCurrentProcessMaps()) {
    if (m.range.contains(addr)) {
      if (not m.name.empty()) {
        return addInstrumentedModule(m.name);
      } else if (m.permission & QBDI::PF_EXEC) {
        addInstrumentedRange(m.range);
        return true;
      } else {
        return false;
      }
    }
  }
  return false;
}

bool ExecBroker::removeInstrumentedModule(const std::string &name) {
  bool removed = false;

  for (const MemoryMap &m : getCurrentProcessMaps()) {
    if (m.name == name) {
      removeInstrumentedRange(m.range);
      removed = true;
    }
  }
  return removed;
}

bool ExecBroker::removeInstrumentedModuleFromAddr(rword addr) {
  for (const MemoryMap &m : getCurrentProcessMaps()) {
    if (m.range.contains(addr)) {
      removeInstrumentedRange(m.range);
      if (not m.name.empty()) {
        removeInstrumentedModule(m.name);
      }
      return true;
    }
  }
  return false;
}

bool ExecBroker::instrumentAllExecutableMaps() {
  if (blacklistMode) {
    QBDI_WARN(
        "instrumentAllExecutableMaps is ignored in blacklist mode; use "
        "removeInstrumentedRange to add blacklist ranges");
    return false;
  }
  bool instrumented = false;

  for (const MemoryMap &m : getCurrentProcessMaps()) {
    if (m.permission & QBDI::PF_EXEC) {
      addInstrumentedRange(m.range);
      instrumented = true;
    }
  }
  return instrumented;
}

bool ExecBroker::canTransferExecution(GPRState *gprState) const {
  return getReturnPoint(gprState) ? true : false;
}

} // namespace QBDI
