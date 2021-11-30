#pragma once
#include "ida.hpp"

// Lambda wrappers around common visitor types.
//
namespace hex
{
	// Operand visitor:
	//
	template<typename F>
	struct mop_visitor
	{
		struct storage : mop_visitor_t
		{
			F functor;
			storage( F&& functor ) : functor( std::forward<F>( functor ) ) {}
			inline int visit_mop( mop_t* op, const tinfo_t* type, bool is_target ) override { return functor( op, type, is_target ); }
		} storage;
		mop_visitor( F&& functor ) : storage( std::forward<F>( functor ) ) {}
		operator mop_visitor_t&() { return storage; }
	};
	template<typename F> mop_visitor( F&& )->mop_visitor<F>;

	// Instruction visitor:
	//
	template<typename F>
	struct minsn_visitor
	{
		struct storage : minsn_visitor_t
		{
			F functor;
			storage( F&& functor ) : functor( std::forward<F>( functor ) ) {}
			inline int visit_mins() override { return functor( curins ); }
		} storage;
		minsn_visitor( F&& functor ) : storage( std::forward<F>( functor ) ) {}
		operator minsn_visitor_t&() { return storage; }
	};
	template<typename F> minsn_visitor( F&& )->minsn_visitor<F>;
};