// SPDX-License-Identifier: MIT
// Copyright (c) 2026 HyperBridge contributors
#include <cstdio>
namespace FEX::Windows::Logging {
void Raw(const char* Message) {
  fputs(Message, stderr);
}
} 
