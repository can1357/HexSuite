#pragma once
#include <span>
#include "ida.hpp"

// Lambda wrappers around common optimizer types.
//
namespace hex
{
	// Define common installable component type.
	//
	struct component 
	{ 
		virtual void set_state( bool enable ) = 0;
		void install() { set_state( true ); }
		void uninstall() { set_state( false ); }
	};

	// Component list type.
	//
	struct component_list
	{
		std::span<component* const> list;
		bool state;
		constexpr component_list( std::span<component* const> list, bool state = false ) : list( list ), state( state ) {}

		constexpr void set_state( bool enable )
		{
			if ( std::exchange( state, enable ) != enable )
				for ( auto* c : list )
					c->set_state( enable );
		}
		constexpr void install() { set_state( true ); }
		constexpr void uninstall() { set_state( false ); }
	};

	// Instruction optimizer:
	//
	template<typename F>
	struct insn_optimizer : component
	{
		struct storage : optinsn_t
		{
			F functor;
			storage( F&& functor ) : functor( std::forward<F>( functor ) ) {}
			inline int func( mblock_t* block, minsn_t* ins, int optflags ) override { return functor( block, ins, optflags ); }
		} storage;
		insn_optimizer( F&& functor ) : storage( std::forward<F>( functor ) ) {}
		operator optinsn_t&() { return storage; }
		void set_state( bool enable ) override { enable ? ( void ) install_optinsn_handler( &storage ) : ( void ) remove_optinsn_handler( &storage ); }
	};
	template<typename F> insn_optimizer( F&& )->insn_optimizer<F>;

	// Block optimizer:
	//
	template<typename F>
	struct block_optimizer : component
	{
		struct storage : optblock_t
		{
			F functor;
			storage( F&& functor ) : functor( std::forward<F>( functor ) ) {}
			inline int func( mblock_t* block ) override { return functor( block ); }
		} storage;
		block_optimizer( F&& functor ) : storage( std::forward<F>( functor ) ) {}
		operator optblock_t&() { return storage; }
		void set_state( bool enable ) override { enable ? ( void ) install_optblock_handler( &storage ) : ( void ) remove_optblock_handler( &storage ); }
	};
	template<typename F> block_optimizer( F&& )->block_optimizer<F>;

	// Microcode filter:
	//
	template<typename F>
	struct microcode_filter : component
	{
		struct storage : microcode_filter_t
		{
			F functor;
			storage( F&& functor ) : functor( std::forward<F>( functor ) ) {}
			
			bool match( codegen_t& cdg ) override { return true; }
			merror_t apply( codegen_t& cdg ) override { return functor( cdg ) ? MERR_OK : MERR_INSN; }
		} storage;
		microcode_filter( F&& functor ) : storage( std::forward<F>( functor ) ) {}
		operator microcode_filter_t&() { return storage; }
		void set_state( bool enable ) override { install_microcode_filter( &storage, enable ); }
	};
	template<typename F> microcode_filter( F&& )->microcode_filter<F>;

	// Hexrays callback.
	//
	template<typename F>
	struct hexrays_callback : component
	{
		F functor;
		hexrays_callback( F&& functor ) : functor( std::forward<F>( functor ) ) {}
		static ssize_t callback( void* ud, hexrays_event_t evt, va_list va )  { return ( *( ( decltype( &functor ) ) ud ) )( evt, va ); }
		void set_state( bool enable ) override { enable ? ( void ) install_hexrays_callback( &callback, &functor ) : ( void ) remove_hexrays_callback( &callback, &functor ); }
	};
	template<typename F> hexrays_callback( F&& )->hexrays_callback<F>;

	namespace detail
	{
		inline auto fill_from( va_list a, std::type_identity<std::tuple<>> ) 
		{
			return std::tuple{};
		}
		template<typename T, typename... Tx>
		inline auto fill_from( va_list a, std::type_identity<std::tuple<T, Tx...>> ) 
		{
			std::tuple t1{ va_arg( a, T ) };
			std::tuple t2 = fill_from( a, std::type_identity<std::tuple<Tx...>>{} );
			return std::tuple_cat( std::move( t1 ), std::move( t2 ) );
		}

		template<typename T>
		struct clambda_args;
		template<typename R, typename S, typename... Tx>
		struct clambda_args<R(S::*)(Tx...) const>
		{
			using type = std::tuple<Tx...>;
		};
		
		template<hexrays_event_t Evt>
		struct event_filter_gen
		{
			template<typename F>
			inline constexpr auto operator()( F&& func ) const
			{
				using args = typename clambda_args<decltype( &F::operator() )>::type;

				return hex::hexrays_callback( [f = std::forward<F>(func)](hexrays_event_t e, va_list a)->ssize_t
				{
					if ( e != Evt )
						return 0;
					else
						return std::apply( f, fill_from( a, std::type_identity<args>{} ) );
				} );
			}
		};
	};
	template<hexrays_event_t Evt>
	constexpr detail::event_filter_gen<Evt> hexrays_callback_for = {};
};
