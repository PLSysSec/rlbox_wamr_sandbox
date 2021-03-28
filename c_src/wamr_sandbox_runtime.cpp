#include "aot_runtime.h"
#include "wamr_sandbox.h"
#include "wasm_c_api.h"
#include "wasm_c_api_internal.h"

#include <deque>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <stdio.h>
#include <string>

#define DYN_CHECK(check, msg)                                                  \
  if (!(check)) {                                                              \
    std::cerr << msg << std::endl;                                             \
    std::abort();                                                              \
  }

struct WamrSandboxCallbackSlot
{
  uint32_t callback_index;
  void** func_ptr_slot;
  uint32_t* func_type_slot;
};

struct WamrSandboxInstance
{
  wasm_engine_t* engine;
  wasm_store_t* store;
  wasm_module_t* wasm_module;
  wasm_instance_t* instance;
  WASMExecEnv* exec_env;
  std::mutex callback_slot_mutex;
  std::deque<WamrSandboxCallbackSlot> free_callback_slots;
  std::map<uint32_t, WamrSandboxCallbackSlot> used_callback_slots;
  std::map<void*, uint32_t> internal_callbacks;
};

static inline wasm_byte_vec_t wamr_get_vec_from_file(
  const char* wamr_module_path)
{
  FILE* file = fopen(wamr_module_path, "rb");
  DYN_CHECK(file != nullptr, "Could not open AOT sandbox file");

  fseek(file, 0L, SEEK_END);
  size_t file_size = ftell(file);
  fseek(file, 0L, SEEK_SET);

  wasm_byte_vec_t binary;
  wasm_byte_vec_new_uninitialized(&binary, file_size);
  auto read_result = fread(binary.data, file_size, 1, file);
  DYN_CHECK(read_result == 1, "Could not read AOT sandbox file");

  fclose(file);
  return binary;
}

static inline WamrSandboxCallbackSlot wamr_get_callback_slot(
  WamrSandboxInstance* sbx,
  void* reserved_pointer,
  const uint32_t callback_table_offset)
{
  auto m = (AOTModule*)*(sbx->wasm_module);
  auto inst_aot = (AOTModuleInstance*)sbx->instance->inst_comm_rt;

  uint64_t indirect_func_table_start = m->import_func_count;
  uint64_t indirect_func_table_end = indirect_func_table_start + m->func_count;

  auto func_ptrs = (void**)inst_aot->func_ptrs.ptr;
  auto func_types = (uint32_t*)inst_aot->func_type_indexes.ptr;

  for (uint64_t idx = indirect_func_table_start, i = 0;
       idx < indirect_func_table_end;
       idx++, i++) {
    void* curr_func_ptr = func_ptrs[idx];
    if (curr_func_ptr == reserved_pointer) {
      func_ptrs[idx] = nullptr;

      WamrSandboxCallbackSlot ret;
      ret.callback_index = i - callback_table_offset;
      ret.func_ptr_slot = &(func_ptrs[idx]);
      ret.func_type_slot = &(func_types[idx]);
      return ret;
    }
  }

  DYN_CHECK(false, "Could not locate reserved callback pointer");
}

void* wamr_lookup_function(WamrSandboxInstance* sbx,
                               const char* func_name)
{
  auto inst_aot = (AOTModuleInstance*)sbx->instance->inst_comm_rt;

  for (size_t i = 0; i < inst_aot->export_func_count; i++) {
    auto func_comm_rt = ((AOTFunctionInstance*)inst_aot->export_funcs.ptr) + i;

    if (strcmp(func_name, func_comm_rt->func_name) == 0) {
      DYN_CHECK(!func_comm_rt->is_import_func,
                "Expected reserved callback slot to not be imported");
      void* raw_pointer = func_comm_rt->u.func.func_ptr;
      return raw_pointer;
    }
  }

  DYN_CHECK(false, "Could not find raw pointer for function");
}

static inline wasm_func_t* wamr_lookup_function_metadata(WamrSandboxInstance* inst, const char* fn_name)
{
  auto inst_aot = (AOTModuleInstance*)inst->instance->inst_comm_rt;
  bool found = false;
  size_t idx = 0;

  for (size_t i = 0; i < inst_aot->export_func_count; i++) {
    auto func_comm_rt = ((AOTFunctionInstance*)inst_aot->export_funcs.ptr) + i;
    if (strcmp(func_comm_rt->func_name, fn_name) == 0)
    {
      found = true;
      idx = i;
      break;
    }
  }

  DYN_CHECK(found, "Could not find symbol");

  auto& exports = *inst->instance->exports;
  wasm_func_t* ret = nullptr;

  for (size_t i = 0; i < exports.size; i++) {
    if (exports.data[i]) {
      auto func = wasm_extern_as_func(exports.data[i]);
      if (func && func->func_idx_rt == idx) {
        ret = func;
        break;
      }
    }
  }

  DYN_CHECK(ret != nullptr, "Could not find export with index");
  return ret;
}

// The callback table indexes are offset in some unspecified way
// What looks like index 3 to the host seems to be index 1 to the sbx
// Compute this offset
static uint32_t wamr_compute_callback_table_offset(WamrSandboxInstance* sbx)
{
  const char* func_name = "sandboxReservedCallbackSlot1";
  wasm_func_t* func_slot = wamr_lookup_function_metadata(sbx, func_name);
  uint32_t expected_index =
    wamr_run_function_return_u32(sbx, func_slot, 0, nullptr);
  void* reserved_pointer = wamr_lookup_function(sbx, func_name);

  auto m = (AOTModule*)*(sbx->wasm_module);
  auto inst_aot = (AOTModuleInstance*)sbx->instance->inst_comm_rt;

  uint64_t indirect_func_table_start = m->import_func_count;
  uint64_t indirect_func_table_end = indirect_func_table_start + m->func_count;

  auto func_ptrs = (void**)inst_aot->func_ptrs.ptr;

  for (uint64_t idx = indirect_func_table_start, i = 0;
       idx < indirect_func_table_end;
       idx++, i++) {
    void* curr_func_ptr = func_ptrs[idx];
    if (curr_func_ptr == reserved_pointer) {
      return i - expected_index;
    }
  }

  DYN_CHECK(false, "Could not compute callback table offset");
}

static inline void wamr_initialize_callback_slots(WamrSandboxInstance* sbx)
{
  const uint32_t callback_table_offset =
    wamr_compute_callback_table_offset(sbx);
  const std::string prefix = "sandboxReservedCallbackSlot";

  for (size_t i = 1; i <= 128; i++) {
    const std::string func_name = prefix + std::to_string(i);
    void* raw_ptr = wamr_lookup_function(sbx, func_name.c_str());
    WamrSandboxCallbackSlot slot =
      wamr_get_callback_slot(sbx, raw_ptr, callback_table_offset);
    sbx->free_callback_slots.push_back(slot);
  }
}

WamrSandboxInstance* wamr_load_module(const char* wamr_module_path)
{
  WamrSandboxInstance* ret = new WamrSandboxInstance();

  auto engine = wasm_engine_new();
  DYN_CHECK(engine != nullptr, "Could not create wasm engine");
  ret->engine = engine;

  auto store = wasm_store_new(engine);
  DYN_CHECK(store != nullptr, "Could not create wasm store");
  ret->store = store;

  wasm_byte_vec_t binary = wamr_get_vec_from_file(wamr_module_path);

  auto wasm_module = wasm_module_new(store, &binary);

  DYN_CHECK(wasm_module != nullptr, "Could not create wasm wasm_module");
  ret->wasm_module = wasm_module;

  auto instance = wasm_instance_new(store, wasm_module, nullptr, nullptr);
  DYN_CHECK(instance != nullptr, "Could not create wasm instance");
  ret->instance = instance;

  auto inst_aot = (AOTModuleInstance*)instance->inst_comm_rt;

  // Backtrace support (WAMR_BUILD_DUMP_CALL_STACK) is disabled as this adds a
  // lot of code to the TCB for very little gain. We should be able to set this
  // to zero, but its not clear that the wamr runtime would be ok with this. Set
  // this to something small so that any attempt to use this stack will fault.
  const uint32_t backtrace_stack_size = 1;
  auto exec_env = wasm_exec_env_create((WASMModuleInstanceCommon*)inst_aot, backtrace_stack_size);
  DYN_CHECK(exec_env != nullptr, "Could not create wasm exec_env");
  ret->exec_env = exec_env;

  wamr_initialize_callback_slots(ret);

  wasm_byte_vec_delete(&binary);

  return ret;
}

void wamr_drop_module(WamrSandboxInstance* inst)
{
  wasm_exec_env_destroy(inst->exec_env);
  wasm_instance_delete(inst->instance);
  wasm_module_delete(inst->wasm_module);
  wasm_store_delete(inst->store);
  wasm_engine_delete(inst->engine);
  delete inst;
}

void* wamr_get_heap_base(WamrSandboxInstance* inst)
{
  wasm_instance_t* instance = (wasm_instance_t*)inst->instance;
  AOTModuleInstance* module_inst = (AOTModuleInstance*)instance->inst_comm_rt;
  auto memory_count = module_inst->memory_count;
  DYN_CHECK(memory_count == 1,
            "Found multiple memories in wasm module. Expected 1.");

  void* heap_start =
    module_inst->global_table_data.memory_instances[0].memory_data.ptr;
  return heap_start;
}

size_t wamr_get_heap_size(WamrSandboxInstance* inst)
{
  const size_t gb = 1 * 1024 * 1024 * 1024;
  return 4 * gb;
}

void wamr_set_curr_instance(WamrSandboxInstance* inst) {}
void wamr_clear_curr_instance(WamrSandboxInstance* inst) {}

static std::optional<wasm_val_t> wamr_run_function_helper(
  WamrSandboxInstance* inst,
  void* func_ptr,
  int argc,
  WamrValue* argv)
{
  auto f = (wasm_func_t*)func_ptr;

  DYN_CHECK(argc == f->func_type->params->num_elems,
            "Wrong number of arguments");

  auto result_count = f->func_type->results->num_elems;
  DYN_CHECK(result_count == 0 || result_count == 1,
            "Multiple results not supported");

  wasm_val_t args[argc == 0 ? 1 : argc];

  for (int i = 0; i < argc; i++) {
    // enums are the same for first 4 members --- i32, i64, f32, f64
    args[i].kind = (wasm_valkind_enum)argv[i].val_type;
    // union is at most 64-bits
    args[i].of.i64 = (int64_t)argv[i].u64;
  }

  wasm_val_t result;
  auto trap = wasm_func_call(f, args, &result);

  DYN_CHECK(trap == nullptr, "Wasm function trapped");

  if (result_count == 1) {
    return result;
  } else {
    return {};
  }
}

uintptr_t wamr_get_func_call_env_param(WamrSandboxInstance* inst) {
  return (uintptr_t) inst->exec_env;
}

void wamr_run_function_return_void(WamrSandboxInstance* inst_ptr,
                                   void* func_ptr,
                                   int argc,
                                   WamrValue* argv)
{
  auto ret = wamr_run_function_helper(inst_ptr, func_ptr, argc, argv);
  DYN_CHECK(!ret.has_value(), "Expected void return");
  return;
}

uint32_t wamr_run_function_return_u32(WamrSandboxInstance* inst_ptr,
                                      void* func_ptr,
                                      int argc,
                                      WamrValue* argv)
{
  auto ret = wamr_run_function_helper(inst_ptr, func_ptr, argc, argv);
  DYN_CHECK(ret.has_value() && ret->kind == WASM_I32, "Expected valid return");
  return ret->of.i32;
}

uint64_t wamr_run_function_return_u64(WamrSandboxInstance* inst_ptr,
                                      void* func_ptr,
                                      int argc,
                                      WamrValue* argv)
{
  auto ret = wamr_run_function_helper(inst_ptr, func_ptr, argc, argv);
  DYN_CHECK(ret.has_value() && ret->kind == WASM_I64, "Expected valid return");
  return ret->of.i64;
}

float wamr_run_function_return_f32(WamrSandboxInstance* inst_ptr,
                                   void* func_ptr,
                                   int argc,
                                   WamrValue* argv)
{
  auto ret = wamr_run_function_helper(inst_ptr, func_ptr, argc, argv);
  DYN_CHECK(ret.has_value() && ret->kind == WASM_F32, "Expected valid return");
  return ret->of.f32;
}

double wamr_run_function_return_f64(WamrSandboxInstance* inst_ptr,
                                    void* func_ptr,
                                    int argc,
                                    WamrValue* argv)
{
  auto ret = wamr_run_function_helper(inst_ptr, func_ptr, argc, argv);
  DYN_CHECK(ret.has_value() && ret->kind == WASM_F64, "Expected valid return");
  return ret->of.f64;
}

static inline bool wasm_type_matches(uint8 value_type,
                                     WamrValueType value_type2)
{
  if (value_type == VALUE_TYPE_VOID &&
      value_type2 == WamrValueType::WamrValueType_Void) {
    return true;
  }
  if (value_type == VALUE_TYPE_I32 &&
      value_type2 == WamrValueType::WamrValueType_I32) {
    return true;
  }
  if (value_type == VALUE_TYPE_I64 &&
      value_type2 == WamrValueType::WamrValueType_I64) {
    return true;
  }
  if (value_type == VALUE_TYPE_F32 &&
      value_type2 == WamrValueType::WamrValueType_F32) {
    return true;
  }
  if (value_type == VALUE_TYPE_F64 &&
      value_type2 == WamrValueType::WamrValueType_F64) {
    return true;
  }
  return false;
}

static inline bool wamr_signature_matches(AOTFuncType& func_type,
                                          WamrFunctionSignature& csig)
{
  if (func_type.param_count != csig.parameter_cnt) {
    return false;
  }

  if (func_type.result_count == 0 &&
      csig.ret != WamrValueType::WamrValueType_Void) {
    return false;
  }

  // don't support multi returns
  if (func_type.result_count > 1) {
    return false;
  }

  uint64_t type_arr_size_1 =
    ((uint64_t)func_type.param_count) + func_type.result_count;
  uint64_t type_arr_size = offsetof(AOTFuncType, types) + type_arr_size_1;
  uint8_t* types = func_type.types;

  for (uint32_t i = 0; i < func_type.param_count; i++) {
    if (!wasm_type_matches(func_type.types[i], csig.parameters[i])) {
      return false;
    }
  }

  const uint64_t ret_types_start = func_type.param_count;
  const uint64_t ret_types_end = ret_types_start + func_type.result_count;

  for (uint64_t i = ret_types_start; i < ret_types_end; i++) {
    if (!wasm_type_matches(func_type.types[i], csig.ret)) {
      return false;
    }
  }

  return true;
}

static inline uint32_t wamr_find_type_index(WamrSandboxInstance* inst,
                                            WamrFunctionSignature& csig)
{
  auto m = (AOTModule*)*(inst->wasm_module);
  auto inst_aot = (AOTModuleInstance*)inst->instance->inst_comm_rt;

  uint64_t func_type_count = m->func_type_count;
  AOTFuncType** func_types = m->func_types;

  for (uint64_t i = 0; i < func_type_count; i++) {
    if (wamr_signature_matches(*(func_types[i]), csig)) {
      return i;
    }
  }

  DYN_CHECK(false, "Function type index not found");
}

uint32_t wamr_register_callback(WamrSandboxInstance* inst,
                                WamrFunctionSignature csig,
                                const void* func_ptr)
{
  auto m = (AOTModule*)*(inst->wasm_module);
  auto inst_aot = (AOTModuleInstance*)inst->instance->inst_comm_rt;

  uint32_t type_index = wamr_find_type_index(inst, csig);

  const std::lock_guard<std::mutex> lock(inst->callback_slot_mutex);

  DYN_CHECK(inst->free_callback_slots.size() > 0,
            "No free callback slots left");

  WamrSandboxCallbackSlot slot = inst->free_callback_slots.front();
  inst->free_callback_slots.pop_front();
  inst->used_callback_slots[slot.callback_index] = slot;

  *slot.func_type_slot = type_index;
  *slot.func_ptr_slot = const_cast<void*>(func_ptr);

  return slot.callback_index;
}

void wamr_unregister_callback(WamrSandboxInstance* inst, uint32_t slot_num)
{
  auto m = (AOTModule*)*(inst->wasm_module);
  auto inst_aot = (AOTModuleInstance*)inst->instance->inst_comm_rt;

  const std::lock_guard<std::mutex> lock(inst->callback_slot_mutex);
  auto iter = inst->used_callback_slots.find(slot_num);
  DYN_CHECK(iter != inst->used_callback_slots.end(),
            "Could not find the given callback slot to unregister");

  WamrSandboxCallbackSlot slot = iter->second;
  inst->used_callback_slots.erase(iter);
  inst->free_callback_slots.push_back(slot);

  *slot.func_ptr_slot = nullptr;
}


uint32_t wamr_register_internal_callback(WamrSandboxInstance* inst,
                                         WamrFunctionSignature csig,
                                         const void* func_ptr)
{
  auto iter = inst->internal_callbacks.find(const_cast<void*>(func_ptr));
  if (iter != inst->internal_callbacks.end()) {
    // already created internal callback
    return iter->second;
  }

  auto ret = wamr_register_callback(inst, csig, func_ptr);
  return ret;
}
