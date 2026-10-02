// STAND32 private diagnostic. Derived from STAND-DIFF stage4 first-K.
#pragma once
#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <mutex>
#include <new>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/fextl/unordered_map.h>
#include "StandWinIO.h"

namespace StandStateCapture {
constexpr uint32_t Capacity = 262144;
struct alignas(64) Slot {
  std::atomic<uint64_t> executions {0};
  uint64_t rip {};
  uint32_t records {};
};
struct alignas(64) WeightHeader {
  char magic[8];
  uint32_t version, slot_size, slots, capacity, cap_total, cap_per_block;
  uint64_t records, dropped_slots, failed, memory_timeouts;
  std::atomic<uint64_t> acknowledged_sequence {0};
};
static_assert(sizeof(WeightHeader) == 128 && sizeof(Slot) == 64 && offsetof(WeightHeader, acknowledged_sequence)==64);
struct Record {
  uint64_t rip, sequence, thread, fpcr, fpsr;
  uint32_t rflags, mxcsr;
  uint64_t gpr[16];
  __uint128_t xmm[16], ymm[16];
  uint32_t fsw;
  uint16_t fcw;
  uint8_t ftw, reduced;
  uint64_t mm[8][2];
  uint64_t fs_base, gs_base;
  uint16_t selectors[6]; // CS SS DS ES FS GS
  uint32_t segment_valid;
  uint64_t bases[6], descriptors[6];
  uint32_t guest_bits, sync_memory;
  uint64_t monotonic_ns, execution;
};
inline Slot* Slots;
inline WeightHeader* Weights;
inline uint32_t SlotCount;
inline uint64_t RecordCount;
inline std::mutex Lock;
inline fextl::unordered_map<uint64_t, Slot*> ByRIP;
inline void* File;
inline bool Failed;
inline uint64_t Option(const char* Name, uint64_t Default) {
  const auto* P=getenv(Name);return P&&*P?strtoull(P,nullptr,0):Default;
}
inline uint64_t Cap() {
  static const auto V=std::min<uint64_t>(Option("MACRUNNER_STAND32_CAP",128),524288);return V;
}
inline bool RIPAllowed(uint64_t RIP) {
  static const auto List=[] {
    fextl::vector<uint64_t> V;const char* P=getenv("MACRUNNER_STAND32_RIP_ALLOW");
    while(P&&*P&&V.size()<4096){char* End{};auto X=strtoull(P,&End,0);if(End==P)break;V.push_back(X);P=*End==','?End+1:End;}
    return V;
  }();
  if(!List.empty())return std::find(List.begin(),List.end(),RIP)!=List.end();
  return RIP>=Option("MACRUNNER_STAND32_RIP_MIN",0)&&RIP<Option("MACRUNNER_STAND32_RIP_MAX",1ULL<<32);
}
inline bool Enabled() {
  static const bool V=[] {const char* p=getenv("MACRUNNER_FEX_STAND_STATE");return p&&*p;}();return V;
}
inline uint64_t ArmMin() {static const auto V=Option("MACRUNNER_STAND32_ARM_RIP_MIN",0);return V;}
inline uint64_t ArmMax() {static const auto V=Option("MACRUNNER_STAND32_ARM_RIP_MAX",0);return V;}
inline std::atomic<uint64_t>& WindowGate() {
  static std::atomic<uint64_t> Armed{ArmMax()==0};return Armed;
}
inline bool WindowOpen(uint64_t RIP) {
  // Capture() holds Lock. Delay invasive memory snapshots until actual game
  // code starts; afterwards keep first-K coverage for every translated RIP.
  auto& Armed=WindowGate();
  if(!Armed.load(std::memory_order_acquire)&&RIP>=ArmMin()&&RIP<ArmMax())Armed.store(1,std::memory_order_release);
  if(!Armed.load(std::memory_order_acquire))return false;
  static const auto Start=std::chrono::steady_clock::now();
  static const auto Delay=Option("MACRUNNER_FEX_STAND_DELAY_MS",0);
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-Start).count()>=Delay;
}
#ifdef _WIN32
inline bool InitWeights() {
  if(Weights)return true;if(Failed)return false;
  const auto Name=fextl::fmt::format("{}.{}.hbweights",getenv("MACRUNNER_FEX_STAND_STATE"),GetCurrentProcessId());
  auto F=CreateFileA(Name.c_str(),0xc0000000,3,nullptr,1,0x80,nullptr);
  if(!F||F==reinterpret_cast<void*>(intptr_t{-1})){Failed=true;return false;}
  HANDLE M{};LARGE_INTEGER Size;Size.QuadPart=sizeof(WeightHeader)+Capacity*sizeof(Slot);
  auto Status=NtCreateSection(&M,SECTION_MAP_READ|SECTION_MAP_WRITE,nullptr,&Size,PAGE_READWRITE,SEC_COMMIT,F);
  void* P{};SIZE_T View=Size.QuadPart;
  if(Status>=0&&M)Status=NtMapViewOfSectionEx(M,NtCurrentProcess(),&P,nullptr,&View,0,PAGE_READWRITE,nullptr,0);
  if(M)CloseHandle(M);CloseHandle(F);
  if(Status<0||!P||View<static_cast<SIZE_T>(Size.QuadPart)){Failed=true;return false;}
  Weights=new(P) WeightHeader{};memcpy(Weights->magic,"HBWGHT32",8);
  Weights->version=1;Weights->slot_size=sizeof(Slot);Weights->capacity=Capacity;
  Weights->cap_total=Cap();Weights->cap_per_block=2;Slots=reinterpret_cast<Slot*>(Weights+1);
  return true;
}
inline Slot* GetSlot(uint64_t RIP) {
  if(!Enabled())return nullptr;std::lock_guard Guard(Lock);
  if(!InitWeights())return nullptr;
  if(auto It=ByRIP.find(RIP);It!=ByRIP.end())return It->second;
  if(SlotCount==Capacity){++Weights->dropped_slots;return nullptr;}
  auto* S=new(&Slots[SlotCount++]) Slot{};S->rip=RIP;ByRIP.emplace(RIP,S);Weights->slots=SlotCount;return S;
}
inline bool Put(const void* Data,uint32_t Size) {
  unsigned long Done=0;bool OK=WriteFile(File,Data,Size,&Done,nullptr)&&Done==Size;
  if(!OK){Failed=true;if(Weights)++Weights->failed;}return OK;
}
inline bool Open() {
  if(File)return !Failed;if(Failed)return false;
  const auto Name=fextl::fmt::format("{}.{}.hbstates",getenv("MACRUNNER_FEX_STAND_STATE"),GetCurrentProcessId());
  File=CreateFileA(Name.c_str(),0x40000000,1,nullptr,1,0x80,nullptr);
  if(!File||File==reinterpret_cast<void*>(intptr_t{-1})){File=nullptr;Failed=true;return false;}
  const auto Metadata=fextl::fmt::format(
    "{{\"record_size\":{},\"gpr_offset\":{},\"xmm_offset\":{},\"ymm_offset\":{},\"fsw_offset\":{},\"mm_offset\":{},\"fs_base_offset\":{},\"gs_base_offset\":{},\"selectors_offset\":{},\"bases_offset\":{},\"descriptors_offset\":{},\"guest_bits_offset\":{},\"monotonic_offset\":{},\"cap_per_block\":2,\"cap_total\":{},\"arm_rip_min\":{},\"arm_rip_max\":{},\"weight_scope\":\"from_recording_window\",\"entry_kind\":\"translated_entrypoint_first_K\",\"segment_order\":\"CS SS DS ES FS GS\",\"clock\":\"steady_clock_ns\",\"memory\":\"per_record_external_quiescent_snapshot_if_sync_memory\"}}",
    sizeof(Record),offsetof(Record,gpr),offsetof(Record,xmm),offsetof(Record,ymm),offsetof(Record,fsw),offsetof(Record,mm),
    offsetof(Record,fs_base),offsetof(Record,gs_base),offsetof(Record,selectors),offsetof(Record,bases),offsetof(Record,descriptors),
    offsetof(Record,guest_bits),offsetof(Record,monotonic_ns),Cap(),ArmMin(),ArmMax());
  uint32_t Header[4]={2,sizeof(Record),static_cast<uint32_t>(Metadata.size()),0};
  return Put("HBSTATE1",8)&&Put(Header,sizeof(Header))&&Put(Metadata.data(),Metadata.size());
}
// Full guest spill precedes this call. Never entered from a signal handler.
inline void Capture(FEXCore::Core::CpuStateFrame* Frame,FEXCore::Context::Context* CTX,Slot* Slt) {
  uint64_t FPCR,FPSR;asm volatile("mrs %0, fpcr\n\tmrs %1, fpsr":"=r"(FPCR),"=r"(FPSR));
  struct RestoreFP {uint64_t a,b;~RestoreFP(){asm volatile("msr fpcr, %0\n\tmsr fpsr, %1"::"r"(a),"r"(b):"memory");}} Restore{FPCR,FPSR};
  std::lock_guard Guard(Lock);
  if(!WindowOpen(Slt->rip)){Slt->executions.store(0,std::memory_order_relaxed);return;}
  if(Failed||RecordCount>=Cap()||Slt->records>=2||!Open())return;
  if(!RIPAllowed(Slt->rip))return;
  Record R{};const auto& S=Frame->State;
  R.rip=Slt->rip;R.sequence=RecordCount+1;R.thread=GetCurrentThreadId();R.fpcr=FPCR;R.fpsr=FPSR;
  R.rflags=CTX->ReconstructCompactedEFLAGS(Frame->Thread,false,nullptr,0);R.mxcsr=S.mxcsr;
  memcpy(R.gpr,S.gregs,sizeof(R.gpr));CTX->ReconstructXMMRegisters(Frame->Thread,R.xmm,R.ymm);
  for(unsigned i=0;i<16;++i)if(i<11||i>13)R.fsw|=(S.flags[FEXCore::X86State::X87FLAG_BASE+i]&1U)<<i;
  R.fsw|=(S.flags[FEXCore::X86State::X87FLAG_TOP_LOC]&7U)<<11;
  R.fcw=S.FCW;R.ftw=S.AbridgedFTW;R.reduced=FEXCore::Config::Get_X87REDUCEDPRECISION()();
  memcpy(R.mm,S.mm,sizeof(R.mm));R.fs_base=S.fs_cached;R.gs_base=S.gs_cached;
  const uint16_t Selectors[]={S.cs_idx,S.ss_idx,S.ds_idx,S.es_idx,S.fs_idx,S.gs_idx};
  const uint64_t Bases[]={S.cs_cached,S.ss_cached,S.ds_cached,S.es_cached,S.fs_cached,S.gs_cached};
  memcpy(R.selectors,Selectors,sizeof(Selectors));memcpy(R.bases,Bases,sizeof(Bases));
  for(unsigned i=0;i<6;++i){
    const auto Selector=Selectors[i];const auto Table=(Selector>>2)&1U;const auto Index=Selector>>3;
    if(S.segment_arrays[Table]&&Index<(Table?8192U:32U)){
      memcpy(&R.descriptors[i],S.segment_arrays[Table]+Index,8);R.segment_valid|=1U<<i;
    }
  }
  R.guest_bits=FEXCore::Config::Get_IS64BIT_MODE()()?64:32;
  R.monotonic_ns=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
  R.execution=Slt->executions.load(std::memory_order_acquire);
  R.sync_memory=Option("MACRUNNER_STAND32_SYNC_MEMORY",0)?1:0;
  if(Put(&R,sizeof(R))){
    ++RecordCount;++Slt->records;Weights->records=RecordCount;
    if(R.sync_memory){
      const auto Deadline=std::chrono::steady_clock::now()+std::chrono::seconds(15);
      while(Weights->acknowledged_sequence.load(std::memory_order_acquire)!=R.sequence){
        if(std::chrono::steady_clock::now()>=Deadline){++Weights->memory_timeouts;Failed=true;break;}
        LARGE_INTEGER Delay;Delay.QuadPart=-10000;NtDelayExecution(false,&Delay);
      }
    }
  }
}
#endif
} // namespace StandStateCapture
