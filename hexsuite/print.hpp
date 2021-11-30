#pragma once
#include "ida.hpp"

namespace hex
{
	// Prints a qstring into a std::string.
	//
	inline std::string to_string( const qstring& s ) { return std::string{ s.c_str(), s.size() }; }

	// Wrapper around T::print(&Qstring) -> std::string.
	//
	template<typename T>
	concept Printable = requires( T&& x, qstring q ) { x.print( &q ); };
	template<Printable T>
	inline std::string to_string( T&& x ) 
	{
		qstring result = {};
		x.print( &result );
		return to_string( result );
	}
	template<Printable T>
	inline std::string to_string( T* x ) { return to_string( *x ); }
};