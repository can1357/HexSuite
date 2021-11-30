#pragma once
#define NO_TV_STREAMS
#define __EA64__

// Disable certain warnings hex-rays causes.
//
#ifdef _MSC_VER
	#pragma warning(disable:4267)
	#pragma warning(disable:4244)
#endif

// Include type traits, use a hacky macro to make sure hexrays does not use is_pod but 
// instead is_trivially_copyable, include hex-rays, undefine the hack.
//
#include <type_traits>
#define is_pod is_trivially_copyable
#include <hexrays.hpp>
#undef is_pod

// Basic wrappers for syntax.
//
namespace hex
{
	inline const til_t* local_type_lib() { return get_idati(); }

	template<typename Plugin>
	constexpr auto init = +[ ] () -> plugmod_t* { return new Plugin{}; };
	template<typename Plugin>
	constexpr auto init_hexray = +[ ] () -> plugmod_t* { return init_hexrays_plugin() ? new Plugin{} : nullptr; };
};