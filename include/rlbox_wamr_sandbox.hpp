#pragma once

#include "wamr_sandbox.h"

#include <cstdint>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
// RLBox allows applications to provide a custom shared lock implementation
#ifndef RLBOX_USE_CUSTOM_SHARED_LOCK
#  include <shared_mutex>
#endif
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#define RLBOX_WAMR_UNUSED(...) (void)__VA_ARGS__

// Use the same convention as rlbox to allow applications to customize the
// shared lock
#ifndef RLBOX_USE_CUSTOM_SHARED_LOCK
#  define RLBOX_SHARED_LOCK(name) std::shared_timed_mutex name
#  define RLBOX_ACQUIRE_SHARED_GUARD(name, ...)                                \
    std::shared_lock<std::shared_timed_mutex> name(__VA_ARGS__)
#  define RLBOX_ACQUIRE_UNIQUE_GUARD(name, ...)                                \
    std::unique_lock<std::shared_timed_mutex> name(__VA_ARGS__)
#else
#  if !defined(RLBOX_SHARED_LOCK) || !defined(RLBOX_ACQUIRE_SHARED_GUARD) ||   \
    !defined(RLBOX_ACQUIRE_UNIQUE_GUARD)
#    error                                                                     \
      "RLBOX_USE_CUSTOM_SHARED_LOCK defined but missing definitions for RLBOX_SHARED_LOCK, RLBOX_ACQUIRE_SHARED_GUARD, RLBOX_ACQUIRE_UNIQUE_GUARD"
#  endif
#endif

namespace rlbox {

namespace detail {
  // relying on the dynamic check settings (exception vs abort) in the rlbox lib
  inline void dynamic_check(bool check, const char* const msg);
}

namespace wamr_detail {

  template<typename T>
  constexpr bool false_v = false;

  // https://stackoverflow.com/questions/6512019/can-we-get-the-type-of-a-lambda-argument
  namespace return_argument_detail {
    template<typename Ret, typename... Rest>
    Ret helper(Ret (*)(Rest...));

    template<typename Ret, typename F, typename... Rest>
    Ret helper(Ret (F::*)(Rest...));

    template<typename Ret, typename F, typename... Rest>
    Ret helper(Ret (F::*)(Rest...) const);

    template<typename F>
    decltype(helper(&F::operator())) helper(F);
  } // namespace return_argument_detail

  template<typename T>
  using return_argument =
    decltype(return_argument_detail::helper(std::declval<T>()));

  ///////////////////////////////////////////////////////////////

  // https://stackoverflow.com/questions/37602057/why-isnt-a-for-loop-a-compile-time-expression
  namespace compile_time_for_detail {
    template<std::size_t N>
    struct num
    {
      static const constexpr auto value = N;
    };

    template<class F, std::size_t... Is>
    inline void compile_time_for_helper(F func, std::index_sequence<Is...>)
    {
      (func(num<Is>{}), ...);
    }
  } // namespace compile_time_for_detail

  template<std::size_t N, typename F>
  inline void compile_time_for(F func)
  {
    compile_time_for_detail::compile_time_for_helper(
      func, std::make_index_sequence<N>());
  }

  ///////////////////////////////////////////////////////////////

  template<typename T, typename = void>
  struct convert_type_to_wasm_type
  {
    static_assert(std::is_void_v<T>, "Missing specialization");
    using type = void;
    static constexpr enum WamrValueType wamr_type = WamrValueType_Void;
  };

  template<typename T>
  struct convert_type_to_wasm_type<
    T,
    std::enable_if_t<(std::is_integral_v<T> || std::is_enum_v<T>)&&sizeof(T) <=
                     sizeof(uint32_t)>>
  {
    using type = uint32_t;
    static constexpr enum WamrValueType wamr_type = WamrValueType_I32;
  };

  template<typename T>
  struct convert_type_to_wasm_type<
    T,
    std::enable_if_t<(std::is_integral_v<T> ||
                      std::is_enum_v<T>)&&sizeof(uint32_t) < sizeof(T) &&
                     sizeof(T) <= sizeof(uint64_t)>>
  {
    using type = uint64_t;
    static constexpr enum WamrValueType wamr_type = WamrValueType_I64;
  };

  template<typename T>
  struct convert_type_to_wasm_type<T,
                                   std::enable_if_t<std::is_same_v<T, float>>>
  {
    using type = T;
    static constexpr enum WamrValueType wamr_type = WamrValueType_F32;
  };

  template<typename T>
  struct convert_type_to_wasm_type<T,
                                   std::enable_if_t<std::is_same_v<T, double>>>
  {
    using type = T;
    static constexpr enum WamrValueType wamr_type = WamrValueType_F64;
  };

  template<typename T>
  struct convert_type_to_wasm_type<
    T,
    std::enable_if_t<std::is_pointer_v<T> || std::is_class_v<T>>>
  {
    // pointers are 32 bit indexes in wasm
    // class paramters are passed as a pointer to an object in the stack or heap
    using type = uint32_t;
    static constexpr enum WamrValueType wamr_type = WamrValueType_I32;
  };

  ///////////////////////////////////////////////////////////////

  namespace prepend_arg_type_detail {
    template<typename T, typename T_ArgNew>
    struct helper;

    template<typename T_ArgNew, typename T_Ret, typename... T_Args>
    struct helper<T_Ret(T_Args...), T_ArgNew>
    {
      using type = T_Ret(T_ArgNew, T_Args...);
    };
  }

  template<typename T_Func, typename T_ArgNew>
  using prepend_arg_type =
    typename prepend_arg_type_detail::helper<T_Func, T_ArgNew>::type;

  ///////////////////////////////////////////////////////////////

  namespace change_return_type_detail {
    template<typename T, typename T_RetNew>
    struct helper;

    template<typename T_RetNew, typename T_Ret, typename... T_Args>
    struct helper<T_Ret(T_Args...), T_RetNew>
    {
      using type = T_RetNew(T_Args...);
    };
  }

  template<typename T_Func, typename T_RetNew>
  using change_return_type =
    typename change_return_type_detail::helper<T_Func, T_RetNew>::type;

  ///////////////////////////////////////////////////////////////

  namespace change_class_arg_types_detail {
    template<typename T, typename T_ArgNew>
    struct helper;

    template<typename T_ArgNew, typename T_Ret, typename... T_Args>
    struct helper<T_Ret(T_Args...), T_ArgNew>
    {
      using type =
        T_Ret(std::conditional_t<std::is_class_v<T_Args>, T_ArgNew, T_Args>...);
    };
  }

  template<typename T_Func, typename T_ArgNew>
  using change_class_arg_types =
    typename change_class_arg_types_detail::helper<T_Func, T_ArgNew>::type;

} // namespace wamr_detail

class rlbox_wamr_sandbox;

struct rlbox_wamr_sandbox_thread_data
{
  rlbox_wamr_sandbox* sandbox;
  uint32_t last_callback_invoked;
};

#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES

rlbox_wamr_sandbox_thread_data* get_rlbox_wamr_sandbox_thread_data();
#  define RLBOX_WAMR_SANDBOX_STATIC_VARIABLES()                                \
    thread_local rlbox::rlbox_wamr_sandbox_thread_data                         \
      rlbox_wamr_sandbox_thread_info{ 0, 0 };                                  \
    namespace rlbox {                                                          \
      rlbox_wamr_sandbox_thread_data* get_rlbox_wamr_sandbox_thread_data()     \
      {                                                                        \
        return &rlbox_wamr_sandbox_thread_info;                                \
      }                                                                        \
    }                                                                          \
    static_assert(true, "Enforce semi-colon")

#endif

class rlbox_wamr_sandbox
{
public:
  using T_LongLongType = int32_t;
  using T_LongType = int32_t;
  using T_IntType = int32_t;
  using T_PointerType = uint32_t;
  using T_ShortType = int16_t;

private:
  WamrSandboxInstance* sandbox = nullptr;
  uintptr_t heap_base;
  uintptr_t exec_env = 0;
  void* malloc_index = 0;
  void* free_index = 0;
  size_t return_slot_size = 0;
  T_PointerType return_slot = 0;

  static const size_t MAX_CALLBACKS = 128;
  mutable RLBOX_SHARED_LOCK(callback_mutex);
  void* callback_unique_keys[MAX_CALLBACKS]{ 0 };
  void* callbacks[MAX_CALLBACKS]{ 0 };
  uint32_t callback_slot_assignment[MAX_CALLBACKS]{ 0 };
  mutable std::map<const void*, uint32_t> internal_callbacks;
  mutable std::map<uint32_t, const void*> slot_assignments;

#ifndef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
  thread_local static inline rlbox_wamr_sandbox_thread_data thread_data{ 0, 0 };
#endif

  template<typename T_Formal, typename T_Actual>
  inline WamrValue serialize_arg(T_PointerType* allocations, T_Actual arg)
  {
    WamrValue ret;
    using T = T_Formal;
    if constexpr ((std::is_integral_v<T> || std::is_enum_v<T>)&&sizeof(T) <=
                  sizeof(uint32_t)) {
      static_assert(wamr_detail::convert_type_to_wasm_type<T>::wamr_type ==
                    WamrValueType_I32);
      ret.val_type = WamrValueType_I32;
      ret.u32 = static_cast<uint32_t>(arg);
    } else if constexpr ((std::is_integral_v<T> ||
                          std::is_enum_v<T>)&&sizeof(T) <= sizeof(uint64_t)) {
      static_assert(wamr_detail::convert_type_to_wasm_type<T>::wamr_type ==
                    WamrValueType_I64);
      ret.val_type = WamrValueType_I64;
      ret.u64 = static_cast<uint64_t>(arg);
    } else if constexpr (std::is_same_v<T, float>) {
      static_assert(wamr_detail::convert_type_to_wasm_type<T>::wamr_type ==
                    WamrValueType_F32);
      ret.val_type = WamrValueType_F32;
      ret.f32 = arg;
    } else if constexpr (std::is_same_v<T, double>) {
      static_assert(wamr_detail::convert_type_to_wasm_type<T>::wamr_type ==
                    WamrValueType_F64);
      ret.val_type = WamrValueType_F64;
      ret.f64 = arg;
    } else if constexpr (std::is_class_v<T>) {
      auto sandboxed_ptr = this->impl_malloc_in_sandbox(sizeof(T));
      *allocations = sandboxed_ptr;
      allocations++;

      auto ptr = reinterpret_cast<T*>(
        this->impl_get_unsandboxed_pointer<T>(sandboxed_ptr));
      *ptr = arg;

      // sanity check that pointers are stored as i32s
      static_assert(wamr_detail::convert_type_to_wasm_type<T*>::wamr_type ==
                    WamrValueType_I32);
      ret.val_type = WamrValueType_I32;
      ret.u32 = sandboxed_ptr;
    } else {
      static_assert(wamr_detail::false_v<T>,
                    "Unexpected case for serialize_arg");
    }
    return ret;
  }

  template<typename T_Ret, typename... T_FormalArgs, typename... T_ActualArgs>
  inline void serialize_args(T_PointerType* /* allocations */,
                             WamrValue* /* out_wamr_args */,
                             T_Ret (*/* func_ptr */)(T_FormalArgs...),
                             T_ActualArgs... /* args */)
  {
    static_assert(sizeof...(T_FormalArgs) == 0);
    static_assert(sizeof...(T_ActualArgs) == 0);
  }

  template<typename T_Ret,
           typename T_FormalArg,
           typename... T_FormalArgs,
           typename T_ActualArg,
           typename... T_ActualArgs>
  inline void serialize_args(T_PointerType* allocations,
                             WamrValue* out_wamr_args,
                             T_Ret (*func_ptr)(T_FormalArg, T_FormalArgs...),
                             T_ActualArg arg,
                             T_ActualArgs... args)
  {
    RLBOX_WAMR_UNUSED(func_ptr);
    *out_wamr_args = serialize_arg<T_FormalArg>(allocations, arg);
    out_wamr_args++;

    using T_Curried = T_Ret (*)(T_FormalArgs...);
    T_Curried curried_func_ptr = nullptr;

    serialize_args(allocations,
                   out_wamr_args,
                   curried_func_ptr,
                   std::forward<T_ActualArgs>(args)...);
  }

  template<typename T_Ret, typename... T_FormalArgs, typename... T_ActualArgs>
  inline void serialize_return_and_args(T_PointerType* allocations,
                                        WamrValue* out_wamr_args,
                                        T_Ret (*func_ptr)(T_FormalArgs...),
                                        T_ActualArgs&&... args)
  {

    if constexpr (std::is_class_v<T_Ret>) {
      auto sandboxed_ptr = this->impl_malloc_in_sandbox(sizeof(T_Ret));
      *allocations = sandboxed_ptr;
      allocations++;

      // sanity check that pointers are stored as i32s
      static_assert(wamr_detail::convert_type_to_wasm_type<T_Ret*>::wamr_type ==
                    WamrValueType_I32);
      out_wamr_args->val_type = WamrValueType_I32;
      out_wamr_args->u32 = sandboxed_ptr;
      out_wamr_args++;
    }

    serialize_args(allocations,
                   out_wamr_args,
                   func_ptr,
                   std::forward<T_ActualArgs>(args)...);
  }

  template<typename T_FormalRet, typename T_ActualRet>
  inline auto serialize_to_sandbox(T_ActualRet arg)
  {
    if constexpr (std::is_class_v<T_FormalRet>) {
      // structs returned as pointers into wasm memory/wasm stack
      auto ptr = reinterpret_cast<T_FormalRet*>(
        impl_get_unsandboxed_pointer<T_FormalRet*>(arg));
      T_FormalRet ret = *ptr;
      return ret;
    } else {
      return arg;
    }
  }

  template<uint32_t N, typename T_Ret, typename... T_Args>
  static typename wamr_detail::convert_type_to_wasm_type<T_Ret>::type
  callback_interceptor(
    void* /* vmContext */,
    typename wamr_detail::convert_type_to_wasm_type<T_Args>::type... params)
  {
#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    auto& thread_data = *get_rlbox_wamr_sandbox_thread_data();
#endif
    thread_data.last_callback_invoked = N;
    using T_Func = T_Ret (*)(T_Args...);
    T_Func func;
    {
      RLBOX_ACQUIRE_SHARED_GUARD(lock, thread_data.sandbox->callback_mutex);
      func = reinterpret_cast<T_Func>(thread_data.sandbox->callbacks[N]);
    }
    // Callbacks are invoked through function pointers, cannot use std::forward
    // as we don't have caller context for T_Args, which means they are all
    // effectively passed by value
    return func(thread_data.sandbox->serialize_to_sandbox<T_Args>(params)...);
  }

  template<uint32_t N, typename T_Ret, typename... T_Args>
  static void callback_interceptor_promoted(
    void* /* vmContext */,
    typename wamr_detail::convert_type_to_wasm_type<T_Ret>::type ret,
    typename wamr_detail::convert_type_to_wasm_type<T_Args>::type... params)
  {
#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    auto& thread_data = *get_rlbox_wamr_sandbox_thread_data();
#endif
    thread_data.last_callback_invoked = N;
    using T_Func = T_Ret (*)(T_Args...);
    T_Func func;
    {
      RLBOX_ACQUIRE_SHARED_GUARD(lock, thread_data.sandbox->callback_mutex);
      func = reinterpret_cast<T_Func>(thread_data.sandbox->callbacks[N]);
    }
    // Callbacks are invoked through function pointers, cannot use std::forward
    // as we don't have caller context for T_Args, which means they are all
    // effectively passed by value
    auto ret_val =
      func(thread_data.sandbox->serialize_to_sandbox<T_Args>(params)...);
    // Copy the return value back
    auto ret_ptr = reinterpret_cast<T_Ret*>(
      thread_data.sandbox->template impl_get_unsandboxed_pointer<T_Ret*>(ret));
    *ret_ptr = ret_val;
  }

  template<typename T_Ret, typename... T_Args>
  static inline constexpr unsigned int get_param_count(
    T_Ret (*/* dummy for template inference */)(T_Args...) = nullptr)
  {
    // Class return types as promoted to args
    constexpr bool promoted = std::is_class_v<T_Ret>;
    if constexpr (promoted) {
      return sizeof...(T_Args) + 1;
    } else {
      return sizeof...(T_Args);
    }
  }

  template<typename T_Ret, typename... T_Args>
  inline WamrFunctionSignature get_wamr_signature(
    WamrValueType* param_types_buffer,
    T_Ret (*/* dummy for template inference */)(T_Args...) = nullptr) const
  {
    // Class return types as promoted to args
    constexpr bool promoted = std::is_class_v<T_Ret>;

    if constexpr (promoted) {
      WamrValueType ret_type = WamrValueType::WamrValueType_Void;
      WamrValueType param_types[] = {
        wamr_detail::convert_type_to_wasm_type<T_Ret>::wamr_type,
        wamr_detail::convert_type_to_wasm_type<T_Args>::wamr_type...
      };

      memcpy(param_types_buffer, param_types, sizeof(param_types));

      WamrFunctionSignature signature{ ret_type,
                                       sizeof(param_types) /
                                         sizeof(WamrValueType),
                                       param_types_buffer };
      return signature;
    } else {
      WamrValueType ret_type =
        wamr_detail::convert_type_to_wasm_type<T_Ret>::wamr_type;
      WamrValueType param_types[] = {
        wamr_detail::convert_type_to_wasm_type<T_Args>::wamr_type...
      };

      memcpy(param_types_buffer, param_types, sizeof(param_types));

      WamrFunctionSignature signature{ ret_type,
                                       sizeof(param_types) /
                                         sizeof(WamrValueType),
                                       param_types_buffer };
      return signature;
    }
  }

  void ensure_return_slot_size(size_t size)
  {
    if (size > return_slot_size) {
      if (return_slot_size) {
        impl_free_in_sandbox(return_slot);
      }
      return_slot = impl_malloc_in_sandbox(size);
      detail::dynamic_check(
        return_slot != 0,
        "Error initializing return slot. Sandbox may be out of memory!");
      return_slot_size = size;
    }
  }

protected:
  // Set external_loads_exist to true, if the host application loads the
  // library wamr_module_path outside of rlbox_wamr_sandbox such as via dlopen
  // or the Windows equivalent
  inline void impl_create_sandbox(const char* wamr_module_path)
  {
    detail::dynamic_check(sandbox == nullptr, "Sandbox already initialized");
    sandbox = wamr_load_module(wamr_module_path);
    detail::dynamic_check(sandbox != nullptr, "Sandbox could not be created");

    heap_base = reinterpret_cast<uintptr_t>(impl_get_memory_location());
    // Check that the address space is larger than the sandbox heap i.e. 4GB
    // sandbox heap, host has to have more than 4GB
    static_assert(sizeof(uintptr_t) > sizeof(T_PointerType));
    // Check that the heap is aligned to the pointer size i.e. 32-bit pointer =>
    // aligned to 4GB. The implementations of
    // impl_get_unsandboxed_pointer_no_ctx and impl_get_sandboxed_pointer_no_ctx
    // below rely on this.
    uintptr_t heap_offset_mask = std::numeric_limits<T_PointerType>::max();
    detail::dynamic_check((heap_base & heap_offset_mask) == 0,
                          "Sandbox heap not aligned to 4GB");

    // cache these for performance
    exec_env = wamr_get_func_call_env_param(sandbox);
    malloc_index = impl_lookup_symbol("malloc");
    free_index = impl_lookup_symbol("free");
  }

  inline void impl_destroy_sandbox()
  {
    if (return_slot_size) {
      impl_free_in_sandbox(return_slot);
    }
    wamr_drop_module(sandbox);
  }

  template<typename T>
  inline void* impl_get_unsandboxed_pointer(T_PointerType p) const
  {
    if constexpr (std::is_function_v<std::remove_pointer_t<T>>) {
      RLBOX_ACQUIRE_UNIQUE_GUARD(lock, callback_mutex);
      auto found = slot_assignments.find(p);
      if (found != slot_assignments.end()) {
        auto ret = found->second;
        return const_cast<void*>(ret);
      } else {
        return nullptr;
      }
    } else {
      return reinterpret_cast<void*>(heap_base + p);
    }
  }

  template<typename T>
  inline T_PointerType impl_get_sandboxed_pointer(const void* p) const
  {
    if constexpr (std::is_function_v<std::remove_pointer_t<T>>) {
      RLBOX_ACQUIRE_UNIQUE_GUARD(lock, callback_mutex);

      uint32_t slot_number = 0;
      auto found = internal_callbacks.find(p);
      if (found != internal_callbacks.end()) {
        slot_number = found->second;
      } else {
        WamrValueType param_types[get_param_count(static_cast<T>(nullptr))];
        WamrFunctionSignature sig =
          get_wamr_signature(param_types, static_cast<T>(nullptr));
        slot_number = wamr_register_internal_callback(sandbox, sig, p);
        internal_callbacks[p] = slot_number;
        slot_assignments[slot_number] = p;
      }
      return static_cast<T_PointerType>(slot_number);
    } else {
      return static_cast<T_PointerType>(reinterpret_cast<uintptr_t>(p));
    }
  }

  template<typename T>
  static inline void* impl_get_unsandboxed_pointer_no_ctx(
    T_PointerType p,
    const void* example_unsandboxed_ptr,
    rlbox_wamr_sandbox* (*expensive_sandbox_finder)(
      const void* example_unsandboxed_ptr))
  {
    if constexpr (std::is_function_v<std::remove_pointer_t<T>>) {
      // swizzling function pointers needs access to the function pointer tables
      // and thus cannot be done without context
      auto sandbox = expensive_sandbox_finder(example_unsandboxed_ptr);
      return sandbox->impl_get_unsandboxed_pointer<T>(p);
    } else {
      // grab the memory base from the example_unsandboxed_ptr
      uintptr_t heap_base_mask =
        std::numeric_limits<uintptr_t>::max() &
        ~(static_cast<uintptr_t>(std::numeric_limits<T_PointerType>::max()));
      uintptr_t computed_heap_base =
        reinterpret_cast<uintptr_t>(example_unsandboxed_ptr) & heap_base_mask;
      uintptr_t ret = computed_heap_base | p;
      return reinterpret_cast<void*>(ret);
    }
  }

  template<typename T>
  static inline T_PointerType impl_get_sandboxed_pointer_no_ctx(
    const void* p,
    const void* example_unsandboxed_ptr,
    rlbox_wamr_sandbox* (*expensive_sandbox_finder)(
      const void* example_unsandboxed_ptr))
  {
    if constexpr (std::is_function_v<std::remove_pointer_t<T>>) {
      // swizzling function pointers needs access to the function pointer tables
      // and thus cannot be done without context
      auto sandbox = expensive_sandbox_finder(example_unsandboxed_ptr);
      return sandbox->impl_get_sandboxed_pointer<T>(p);
    } else {
      // Just clear the memory base to leave the offset
      RLBOX_WAMR_UNUSED(example_unsandboxed_ptr);
      uintptr_t ret = reinterpret_cast<uintptr_t>(p) &
                      std::numeric_limits<T_PointerType>::max();
      return static_cast<T_PointerType>(ret);
    }
  }

  static inline bool impl_is_in_same_sandbox(const void* p1, const void* p2)
  {
    uintptr_t heap_base_mask = std::numeric_limits<uintptr_t>::max() &
                               ~(std::numeric_limits<T_PointerType>::max());
    return (reinterpret_cast<uintptr_t>(p1) & heap_base_mask) ==
           (reinterpret_cast<uintptr_t>(p2) & heap_base_mask);
  }

  inline bool impl_is_pointer_in_sandbox_memory(const void* p)
  {
    size_t length = impl_get_total_memory();
    uintptr_t p_val = reinterpret_cast<uintptr_t>(p);
    return p_val >= heap_base && p_val < (heap_base + length);
  }

  inline bool impl_is_pointer_in_app_memory(const void* p)
  {
    return !(impl_is_pointer_in_sandbox_memory(p));
  }

  inline size_t impl_get_total_memory() { return wamr_get_heap_size(sandbox); }

  inline void* impl_get_memory_location()
  {
    return wamr_get_heap_base(sandbox);
  }

  void* impl_lookup_symbol(const char* func_name)
  {
    return wamr_lookup_function(sandbox, func_name);
  }

  template<typename T, typename T_Converted, typename... T_Args>
  auto impl_invoke_with_func_ptr(T_Converted* func_ptr, T_Args&&... params)
  {
#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    auto& thread_data = *get_rlbox_wamr_sandbox_thread_data();
#endif
    thread_data.sandbox = this;
    wamr_set_curr_instance(sandbox);

    // WASM functions are mangled in the following manner
    // 1. All primitive types are left as is and follow an LP32 machine model
    // (as opposed to the possibly 64-bit application)
    // 2. All pointers are changed to u32 types
    // 3. Returned class are returned as an out parameter before the actual
    // function parameters
    // 4. All class parameters are passed as pointers (u32 types)
    // 5. The heap address is passed in as the first argument to the function
    //
    // RLBox accounts for the first 2 differences in T_Converted type, but we
    // need to handle the rest

    // Handle point 3
    using T_Ret = wamr_detail::return_argument<T_Converted>;
    if constexpr (std::is_class_v<T_Ret>) {
      using T_Conv1 = wamr_detail::change_return_type<T_Converted, void>;
      using T_Conv2 = wamr_detail::prepend_arg_type<T_Conv1, T_PointerType>;
      auto func_ptr_conv =
        reinterpret_cast<T_Conv2*>(reinterpret_cast<uintptr_t>(func_ptr));
      ensure_return_slot_size(sizeof(T_Ret));
      impl_invoke_with_func_ptr<T>(func_ptr_conv, return_slot, params...);

      auto ptr = reinterpret_cast<T_Ret*>(
        impl_get_unsandboxed_pointer<T_Ret*>(return_slot));
      T_Ret ret = *ptr;
      return ret;
    }

    // Handle point 4
    constexpr size_t alloc_length = [&] {
      if constexpr (sizeof...(params) > 0) {
        return ((std::is_class_v<T_Args> ? 1 : 0) + ...);
      } else {
        return 0;
      }
    }();

    // 0 arg functions create 0 length arrays which is not allowed
    T_PointerType allocations_buff[alloc_length == 0 ? 1 : alloc_length];
    T_PointerType* allocations = allocations_buff;

    auto serialize_class_arg =
      [&](auto arg) -> std::conditional_t<std::is_class_v<decltype(arg)>,
                                          T_PointerType,
                                          decltype(arg)> {
      using T_Arg = decltype(arg);
      if constexpr (std::is_class_v<T_Arg>) {
        auto slot = impl_malloc_in_sandbox(sizeof(T_Arg));
        auto ptr =
          reinterpret_cast<T_Arg*>(impl_get_unsandboxed_pointer<T_Arg*>(slot));
        *ptr = arg;
        allocations[0] = slot;
        allocations++;
        return slot;
      } else {
        return arg;
      }
    };

    // 0 arg functions don't use serialize
    RLBOX_WAMR_UNUSED(serialize_class_arg);

    using T_ConvNoClass =
      wamr_detail::change_class_arg_types<T_Converted, T_PointerType>;

    // Handle Point 5
    using T_ConvHeap = wamr_detail::prepend_arg_type<T_ConvNoClass, uintptr_t>;

    // Function invocation
    auto func_ptr_conv =
      reinterpret_cast<T_ConvHeap*>(reinterpret_cast<uintptr_t>(func_ptr));

    using T_NoVoidRet =
      std::conditional_t<std::is_void_v<T_Ret>, uint32_t, T_Ret>;
    T_NoVoidRet ret;

    if constexpr (std::is_void_v<T_Ret>) {
      RLBOX_WAMR_UNUSED(ret);
      func_ptr_conv(exec_env, serialize_class_arg(params)...);
    } else {
      ret = func_ptr_conv(exec_env, serialize_class_arg(params)...);
    }

    for (size_t i = 0; i < alloc_length; i++) {
      impl_free_in_sandbox(allocations_buff[i]);
    }

    wamr_clear_curr_instance(sandbox);
    if constexpr (!std::is_void_v<T_Ret>) {
      return ret;
    }
  }

  inline T_PointerType impl_malloc_in_sandbox(size_t size)
  {
    detail::dynamic_check(size <= std::numeric_limits<uint32_t>::max(),
                          "Attempting to malloc more than the heap size");
    using T_Func = void*(size_t);
    using T_Converted = T_PointerType(uint32_t);
    T_PointerType ret = impl_invoke_with_func_ptr<T_Func, T_Converted>(
      reinterpret_cast<T_Converted*>(malloc_index),
      static_cast<uint32_t>(size));
    return ret;
  }

  inline void impl_free_in_sandbox(T_PointerType p)
  {
    using T_Func = void(void*);
    using T_Converted = void(T_PointerType);
    impl_invoke_with_func_ptr<T_Func, T_Converted>(
      reinterpret_cast<T_Converted*>(free_index), p);
  }

  template<typename T_Ret, typename... T_Args>
  inline T_PointerType impl_register_callback(void* key, void* callback)
  {
    bool found = false;
    uint32_t found_loc = 0;
    void* chosen_interceptor = nullptr;

    RLBOX_ACQUIRE_UNIQUE_GUARD(lock, callback_mutex);

    // need a compile time for loop as we we need I to be a compile time value
    // this is because we are setting the I'th callback ineterceptor
    wamr_detail::compile_time_for<MAX_CALLBACKS>([&](auto I) {
      constexpr auto i = I.value;
      if (!found && callbacks[i] == nullptr) {
        found = true;
        found_loc = i;

        if constexpr (std::is_class_v<T_Ret>) {
          chosen_interceptor = reinterpret_cast<void*>(
            callback_interceptor_promoted<i, T_Ret, T_Args...>);
        } else {
          chosen_interceptor =
            reinterpret_cast<void*>(callback_interceptor<i, T_Ret, T_Args...>);
        }
      }
    });

    detail::dynamic_check(
      found,
      "Could not find an empty slot in sandbox function table. This would "
      "happen if you have registered too many callbacks, or unsandboxed "
      "too many function pointers. You can file a bug if you want to "
      "increase the maximum allowed callbacks or unsadnboxed functions "
      "pointers");

    WamrValueType param_types[get_param_count<T_Ret, T_Args...>()];
    WamrFunctionSignature sig =
      get_wamr_signature<T_Ret, T_Args...>(param_types);
    uint32_t slot_number =
      wamr_register_callback(sandbox, sig, chosen_interceptor);

    callback_unique_keys[found_loc] = key;
    callbacks[found_loc] = callback;
    callback_slot_assignment[found_loc] = slot_number;
    slot_assignments[slot_number] = callback;

    return static_cast<T_PointerType>(slot_number);
  }

  static inline std::pair<rlbox_wamr_sandbox*, void*>
  impl_get_executed_callback_sandbox_and_key()
  {
#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    auto& thread_data = *get_rlbox_wamr_sandbox_thread_data();
#endif
    auto sandbox = thread_data.sandbox;
    auto callback_num = thread_data.last_callback_invoked;
    void* key = sandbox->callback_unique_keys[callback_num];
    return std::make_pair(sandbox, key);
  }

  template<typename T_Ret, typename... T_Args>
  inline void impl_unregister_callback(void* key)
  {
    bool found = false;
    uint32_t i = 0;
    {
      RLBOX_ACQUIRE_UNIQUE_GUARD(lock, callback_mutex);
      for (; i < MAX_CALLBACKS; i++) {
        if (callback_unique_keys[i] == key) {
          wamr_unregister_callback(sandbox, callback_slot_assignment[i]);
          callback_unique_keys[i] = nullptr;
          callbacks[i] = nullptr;
          callback_slot_assignment[i] = 0;
          found = true;
          break;
        }
      }
    }

    detail::dynamic_check(
      found, "Internal error: Could not find callback to unregister");

    return;
  }
};

} // namespace rlbox