// HBCAP001 wire format from STAND-DIFF. Diagnostic-only PE32 capture.
// Decoder query history is not installed in this source snapshot: Q count=0.
#pragma once
#include <mutex>
#include <cstdlib>
#include <FEXCore/fextl/unordered_set.h>
#include <FEXCore/fextl/vector.h>
#include <FEXCore/fextl/fmt.h>
#include <xxhash.h>
#include "StandWinIO.h"

namespace StandCodeCapture {
#ifdef _WIN32
struct Page {uint64_t address, hash; fextl::vector<uint8_t> data;};
struct Writer {
  std::mutex lock;
  void* file{};
  bool failed{};
  uint64_t records{},bytes{};
  fextl::unordered_set<uint64_t> seen;
  bool Put(const void* P,uint32_t N) {
    if(failed)return false;unsigned long Done=0;
    if(!WriteFile(file,P,N,&Done,nullptr)||Done!=N){failed=true;return false;}
    bytes+=N;return true;
  }
};
inline Writer* Open() {
  static Writer* W=[]()->Writer* {
    const auto* Path=getenv("MACRUNNER_FEX_CAPTURE");if(!Path||!*Path)return nullptr;
    const auto Name=fextl::fmt::format("{}.{}",Path,GetCurrentProcessId());
    auto F=CreateFileA(Name.c_str(),0x40000000,1,nullptr,1,0x80,nullptr);
    if(!F||F==reinterpret_cast<void*>(intptr_t{-1}))return nullptr;
    auto* W=new Writer;W->file=F;
    fextl::string Metadata="STAND32_CAPTURE_VERSION=1\nDECODER_QUERY_HISTORY=NOT_ENABLED\nCAP_BYTES=536870912\n";
#define OPT(E) Metadata+=fextl::fmt::format("FEX_" #E "={}\n",static_cast<int64_t>(FEXCore::Config::Get_##E()()))
    OPT(IS64BIT_MODE);OPT(MULTIBLOCK);OPT(MAXINST);OPT(SMCCHECKS);OPT(TSOENABLED);
    OPT(X87REDUCEDPRECISION);OPT(MONOHACKS);OPT(O0);OPT(FORCESVEWIDTH);
#undef OPT
    uint32_t N=Metadata.size();W->Put("HBCAP001",8);W->Put(&N,4);W->Put(Metadata.data(),N);return W;
  }();return W;
}
struct Capture {
  Writer* writer{};uint64_t fields[16]{};fextl::vector<Page> pages;
  Capture(FEXCore::Core::InternalThreadState* T,FEXCore::HLE::SyscallHandler* Handler,
          uint64_t RIP,uint64_t MaxInst,uint64_t Start,uint64_t Length,uint64_t Instructions) {
    writer=Open();if(!writer)return;
    fields[1]=RIP;fields[2]=MaxInst;fields[4]=Instructions;fields[5]=Start;fields[6]=Length;
    for(uint64_t Address:T->FrontendDecoder->GetDecodedBlockInfo()->CodePages){
      // Decoder spans may be sub-page (e.g. thunks). Readability of the actual
      // page is an NT memory fact, independent of the decoder's executable span.
      Page P{Address,0,{}};P.data.resize(4096);SIZE_T Read{};
      if(NtReadVirtualMemory(NtCurrentProcess(),reinterpret_cast<const void*>(Address),P.data.data(),4096,&Read)>=0&&Read==4096)
        P.hash=XXH3_64bits(P.data.data(),4096);
      else P.data.clear();
      pages.emplace_back(std::move(P));
    }
  }
  void Finish(uint64_t HostBytes,uint64_t Flags) {
    if(!writer)return;auto& W=*writer;std::lock_guard Guard(W.lock);
    if(W.failed)return;
    // Record cap is visible as a stopped file; final runner must classify loss.
    if(W.bytes>=536870912){W.failed=true;return;}
    for(const auto& P:pages)if(P.hash&&W.seen.insert(P.hash).second){
      const uint32_t Tag=0x50;W.Put(&Tag,4);W.Put(&P.hash,8);W.Put(P.data.data(),4096);
    }
    fields[0]=++W.records;fields[3]=Flags;fields[7]=HostBytes;fields[14]=pages.size();
    const uint32_t Tag=0x43;W.Put(&Tag,4);W.Put(fields,sizeof(fields));
    for(const auto& P:pages){const uint64_t Pair[]={P.address,P.hash};W.Put(Pair,sizeof(Pair));}
  }
};
#else
struct Capture {template<class... T>Capture(T...){ }void Finish(uint64_t,uint64_t){};};
#endif
}
