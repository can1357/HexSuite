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
			inline int visit_minsn() { return functor( curins ); }
		} storage;
		minsn_visitor( F&& functor ) : storage( std::forward<F>( functor ) ) {}
		operator minsn_visitor_t&() { return storage; }
	};
	template<typename F> minsn_visitor( F&& )->minsn_visitor<F>;

	
	// Ctree visitors:
	//
	namespace detail
	{
		template<typename F, typename... Tx>
		concept CtreeCallableWith = requires( F && x ) { x( std::declval<Tx>()... ); };
	};
	template<bool Pre, bool Post, typename F>
	struct basic_ctree_visitor : ctree_visitor_t
	{
		F functor;
		basic_ctree_visitor( int cv_flags, F&& functor ) : ctree_visitor_t( cv_flags ), functor( std::forward<F>( functor ) ) {}

		int visit_insn( cinsn_t* e ) override 
		{
			if constexpr ( Pre && detail::CtreeCallableWith<F, ctree_visitor_t&, cinsn_t*> )
				return functor( *this, e );
			else if constexpr ( Pre && detail::CtreeCallableWith<F, cinsn_t*> )
				return functor( e );
			return 0; 
		}
		int visit_expr( cexpr_t* e ) override 
		{
			if constexpr ( Pre && detail::CtreeCallableWith<F, ctree_visitor_t&, cexpr_t*> )
				return functor( *this, e );
			else if constexpr ( Pre && detail::CtreeCallableWith<F, cexpr_t*> )
				return functor( e );
			return 0;
		}
		int leave_insn( cinsn_t* e ) override
		{
			if constexpr ( Pre && detail::CtreeCallableWith<F, ctree_visitor_t&, cinsn_t*> )
				return functor( *this, e );
			else if constexpr ( Pre && detail::CtreeCallableWith<F, cinsn_t*> )
				return functor( e );
			return 0;
		}
		int leave_expr( cexpr_t* e ) override
		{
			if constexpr ( Post && detail::CtreeCallableWith<F, ctree_visitor_t&, cexpr_t*> )
				return functor( *this, e );
			else if constexpr ( Post && detail::CtreeCallableWith<F, cexpr_t*> )
				return functor( e );
			return 0;
		}
	};
	template<typename F>
	struct ctree_pre_visitor : basic_ctree_visitor<true, false, F>
	{
		ctree_pre_visitor( F&& functor, int flags = CV_FAST ) : basic_ctree_visitor<true, false, F>( flags, std::forward<F>( functor ) ) {}
	};
	template<typename F> ctree_pre_visitor( F&& )->ctree_pre_visitor<F>;

	template<typename F>
	struct ctree_post_visitor : basic_ctree_visitor<false, true, F>
	{
		ctree_post_visitor( F&& functor, int flags = CV_FAST ) : basic_ctree_visitor<false, true, F>( flags | CV_POST, std::forward<F>( functor ) ) {}
	};
	template<typename F> ctree_post_visitor( F&& )->ctree_post_visitor<F>;
};
