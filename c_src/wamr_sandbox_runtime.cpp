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
  std::map<const std::string, uint32_t> symbol_map;
  std::mutex callback_slot_mutex;
  std::deque<WamrSandboxCallbackSlot> free_callback_slots;
  std::map<uint32_t, WamrSandboxCallbackSlot> used_callback_slots;
  std::map<void*, uint32_t> internal_callbacks;
};

static std::once_flag wamr_init;

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
  void* reserved_pointer)
{
  auto m = (AOTModule*)*(sbx->wasm_module);
  auto inst_aot = (AOTModuleInstance*)sbx->instance->inst_comm_rt;

  uint64_t indirect_func_table_start = m->import_func_count;
  uint64_t indirect_func_table_end = indirect_func_table_start + m->func_count;

  auto func_ptrs = (void**)inst_aot->func_ptrs.ptr;
  auto func_types = (uint32_t*)inst_aot->func_type_indexes.ptr;
  //TODO: fix
  const uint64_t magic_offset = 2;

  for (uint64_t idx = indirect_func_table_start, i = 0; idx < indirect_func_table_end;
       idx++, i++) {
    void* curr_func_ptr = func_ptrs[idx];
    if (curr_func_ptr == reserved_pointer) {
      func_ptrs[idx] = nullptr;

      WamrSandboxCallbackSlot ret;
      ret.callback_index = i - magic_offset;
      ret.func_ptr_slot = &(func_ptrs[idx]);
      ret.func_type_slot = &(func_types[idx]);
      return ret;
    }
  }

  DYN_CHECK(false, "Could not locate reserved callback pointer");
}

static inline void* wamr_lookup_func_raw_ptr(WamrSandboxInstance* sbx,
                                             std::string func_name)
{
  auto inst_aot = (AOTModuleInstance*)sbx->instance->inst_comm_rt;

  for (size_t i = 0; i < inst_aot->export_func_count; i++) {
    auto func_comm_rt = ((AOTFunctionInstance*)inst_aot->export_funcs.ptr) + i;

    if (func_name == func_comm_rt->func_name) {
      DYN_CHECK(!func_comm_rt->is_import_func,
                "Expected reserved callback slot to not be imported");
      void* raw_pointer = func_comm_rt->u.func.func_ptr;
      return raw_pointer;
    }
  }

  DYN_CHECK(false, "Could not find raw pointer for function");
}

static inline void* wamr_lookup_func_raw_ptr_idx(WamrSandboxInstance* sbx,
                                             uint32_t func_idx)
{
  auto inst_aot = (AOTModuleInstance*)sbx->instance->inst_comm_rt;

  for (size_t i = 0; i < inst_aot->export_func_count; i++) {
    auto func_comm_rt = ((AOTFunctionInstance*)inst_aot->export_funcs.ptr) + i;

    if (func_idx == func_comm_rt->func_index) {
      DYN_CHECK(!func_comm_rt->is_import_func,
                "Expected reserved callback slot to not be imported");
      void* raw_pointer = func_comm_rt->u.func.func_ptr;
      return raw_pointer;
    }
  }

  DYN_CHECK(false, "Could not find raw pointer for function");
}

static inline void wamr_initialize_callback_slots(WamrSandboxInstance* sbx)
{
  const std::string prefix = "sandboxReservedCallbackSlot";

  for (size_t i = 1; i <= 128; i++) {
    const std::string func_name = prefix + std::to_string(i);
    void* raw_ptr = wamr_lookup_func_raw_ptr(sbx, func_name);
    WamrSandboxCallbackSlot slot = wamr_get_callback_slot(sbx, raw_ptr);
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
  for (size_t i = 0; i < inst_aot->export_func_count; i++) {
    auto func_comm_rt = ((AOTFunctionInstance*)inst_aot->export_funcs.ptr) + i;
    ret->symbol_map[func_comm_rt->func_name] = i;
  }

  wamr_initialize_callback_slots(ret);

  wasm_byte_vec_delete(&binary);

  return ret;
}

void wamr_drop_module(WamrSandboxInstance *inst) {
  wasm_instance_delete(inst->instance);
  wasm_module_delete(inst->wasm_module);
  wasm_store_delete(inst->store);
  wasm_engine_delete(inst->engine);
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

void* wamr_lookup_function(WamrSandboxInstance* inst, const char* fn_name)
{
  auto& symbol_map = inst->symbol_map;
  auto tmp = symbol_map.size();
  auto iter = symbol_map.find(std::string(fn_name));
  DYN_CHECK(iter != symbol_map.end(), "Could not find symbol");
  auto idx = iter->second;

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

  wasm_val_t args[argc];

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
  if (func_type.result_count != 1) {
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

uint32_t wamr_register_internal_callback(WamrSandboxInstance* inst, WamrFunctionSignature csig, const void* func_ptr)
{
  auto func_slot = (wasm_func_t*) func_ptr;

  auto inst_aot = (AOTModuleInstance*)inst->instance->inst_comm_rt;
  auto func_comm_rt = ((AOTFunctionInstance*)inst_aot->export_funcs.ptr) + func_slot->func_idx_rt;

  DYN_CHECK(!func_comm_rt->is_import_func,
                "Expected reserved callback slot to not be imported");
  void* raw_func_ptr = func_comm_rt->u.func.func_ptr;

  auto iter = inst->internal_callbacks.find(raw_func_ptr);
  if(iter != inst->internal_callbacks.end()){
    // already created internal callback
    return iter->second;
  }

  auto ret = wamr_register_callback(inst, csig, raw_func_ptr);
  return ret;
}