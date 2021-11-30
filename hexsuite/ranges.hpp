#pragma once
#include <ranges>
#include <span>
#include "ida.hpp"

// Implement range wrappers.
//
namespace hex
{
	// Succesor/Predecessor iteration.
	//
	inline auto successors( mblock_t* blk ) 
	{
		return blk->succset | std::views::transform( [ blk ] ( int id ) { return blk->mba->get_mblock( id ); } );
	}
	inline auto predecessors( mblock_t* blk )
	{
		return blk->predset | std::views::transform( [ blk ] ( int id ) { return blk->mba->get_mblock( id ); } );
	}

	// Instruction iteration.
	//
	namespace detail
	{
		template<typename T> concept HasNext = requires( T * x ) { x = x->next; };
		template<typename T> concept HasNextb = requires( T * x ) { x = x->nextb; };

		template<typename T>
		struct list_iterator
		{
			using iterator_category = std::bidirectional_iterator_tag;
			using value_type =        T*;
			using difference_type =   ptrdiff_t;
			
			T* at = nullptr;

			// Iteration.
			//
			list_iterator& operator++() requires HasNext<T> { at = at->next; return *this; }
			list_iterator& operator--() requires HasNext<T> { at = at->prev; return *this; }
			list_iterator& operator++() requires HasNextb<T> { at = at->nextb; return *this; }
			list_iterator& operator--() requires HasNextb<T> { at = at->prevb; return *this; }
			list_iterator operator++( int ) { auto s = *this; operator++(); return s; }
			list_iterator operator--( int ) { auto s = *this; operator--(); return s; }

			// Comparison.
			//
			bool operator==( const list_iterator& rhs ) const { return at == rhs.at; }
			bool operator!=( const list_iterator& rhs ) const { return at != rhs.at; }
			
			// Redirection to value type.
			//
			value_type operator*() const { return at; }
			value_type operator->() const { return at; }
		};
		struct instruction_range : std::ranges::view_base
		{
			using iterator = list_iterator<minsn_t>;

			mblock_t* blk;
			iterator begin() const { return iterator{ blk->head }; }
			iterator end() const { return iterator{ nullptr }; }
			size_t size() const { return std::distance( begin(), end() ); }
			bool empty() const noexcept { return begin() == end(); }
		};
		struct bblock_range : std::ranges::view_base
		{
			using iterator = list_iterator<mblock_t>;

			mblock_t* blk;
			iterator begin() const { return iterator{ blk }; }
			iterator end() const { return iterator{ nullptr }; }
			size_t size() const { return std::distance( begin(), end() ); }
			bool empty() const noexcept { return begin() == end(); }
		};
	};
	inline auto instructions( mblock_t* blk ) { return detail::instruction_range{ .blk = blk }; }
	inline auto basic_blocks( mba_t* mba ) { return detail::bblock_range{ .blk = mba->blocks }; }

	// Type iteration.
	//
	namespace detail
	{
		struct type_iterator
		{
			using iterator_category = std::forward_iterator_tag;
			using value_type =        const char*;
			using difference_type =   ptrdiff_t;
			
			const char* at = nullptr;
			const til_t* library = nullptr;
			int flags = 0;

			// Iteration.
			//
			type_iterator& operator++() { at = next_named_type( library, at, flags ); return *this; }
			type_iterator operator++( int ) { auto s = *this; operator++(); return s; }

			// Comparison.
			//
			bool operator==( const type_iterator& rhs ) const { return at == rhs.at; }
			bool operator!=( const type_iterator& rhs ) const { return at != rhs.at; }
			
			// Redirection to value type.
			//
			value_type operator*() const { return at; }
			value_type operator->() const { return at; }
		};
		struct type_range : std::ranges::view_base
		{
			using iterator = type_iterator;

			const til_t* library = nullptr;
			int flags = 0;

			iterator begin() const { return iterator{ first_named_type( library, flags ), library, flags }; }
			iterator end() const { return iterator{ nullptr, library, flags }; }
			size_t size() const { return std::distance( begin(), end() ); }
			bool empty() const noexcept { return begin() == end(); }
		};
	};
	inline auto named_types( int flags = NTF_TYPE | NTF_SYMM, const til_t* lib = local_type_lib() ) { return detail::type_range{ .library = lib, .flags = flags }; }
};