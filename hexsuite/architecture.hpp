#pragma once
#include <memory>
#include "ida.hpp"

namespace hex
{
	// Operand types.
	//
	struct helper { const char* name; };
	struct global { ea_t address; };
	struct block { int id; };
	struct reg
	{
		mreg_t r;
		int width;
		constexpr reg( mreg_t r, int w = NOSIZE ) : r( r ), width( w ) {}
		reg( uint16_t r, int w = NOSIZE ) : reg( reg2mreg( r ), w ) {}
	};
	inline reg phys_reg( int r, int w ) { return reg( reg2mreg( r ), w ); }

	struct operand : mop_t
	{
		// Null.
		operand() { mop_t::t = mop_z; }
		// Helpers.
		operand( hex::helper h ) { mop_t::make_helper( h.name ); }
		// Globals.
		operand( hex::global g ) { mop_t::make_gvar( g.address ); }
		// Block references.
		operand( hex::block b ) { mop_t::make_blkref( b.id ); }
		// Stack references.
		operand( mba_t* m, ptrdiff_t o ) { mop_t::make_stkvar( m, o ); }
		// Instruction results.
		operand( minsn_t* i ) { mop_t::make_insn( i ); mop_t::size = mop_t::d->d.size; }
		operand( std::unique_ptr<minsn_t> i ) : operand( i.release() ) {}
		// Registers.
		operand( reg r ) { mop_t::make_reg( r.r, r.width ); }
		operand( reg r1, reg r2 ) { mop_t::make_reg_pair( r1.r, r2.r, r1.width ); }
		// Integral immediates.
		operand( uint64_t i, int w ) { mop_t::make_number( i, w ); }
		operand( int64_t i, int w ) { mop_t::make_number( ( uint64_t ) i, w ); }
		// Floating point immediates.
		operand( float f ) { mop_t::make_fpnum( &f, sizeof( float ) ); }
		operand( double f ) { mop_t::make_fpnum( &f, sizeof( double ) ); }
		// Call types.
		operand( mcallinfo_t* c ) { mop_t::t = mop_f; mop_t::f = c; mop_t::size = c->return_type.is_void() ? 0 : c->return_type.get_size(); }
		operand( std::unique_ptr<mcallinfo_t> c ) : operand( c.release() ) {}

		// Propagate from original type.
		operand( mop_t&& op ) { mop_t::swap( op ); }

		// Move via swap.
		operand( operand&& o ) noexcept { mop_t::swap( o ); }
		operand& operator=( operand&& o ) noexcept { mop_t::swap( o ); return *this; }
		
		// Copy.
		operand( const operand& o ) { mop_t::assign( o ); }
		operand& operator=( const operand& o ) { mop_t::assign( o ); return *this; }
	};
	struct call_arg : mcallarg_t
	{
		call_arg( hex::operand op, tinfo_t type, qstring name = {} ) 
		{
			mop_t::swap( op );
			mcallarg_t::type = type;
			mcallarg_t::name = std::move( name );
		}
	};

	// Creates a simple call-info.
	//
	struct pure_t {};

	namespace detail
	{
		constexpr inline void push_arg( mcallinfo_t* ci ) {}
		template<typename T, typename... Tx>
		inline void push_arg( mcallinfo_t* ci, T&& t, Tx&&... rest ) 
		{
			ci->args.push_back( std::forward<T>( t ) );
			push_arg( ci, std::forward<Tx>( rest )... );
		}
	};

	template<typename... Tx>
	inline std::unique_ptr<mcallinfo_t> call_info( tinfo_t ret, Tx&&... args ) 
	{
		auto ci = std::make_unique<mcallinfo_t>();
		ci->cc = CM_CC_FASTCALL;
		ci->callee = BADADDR;
		ci->solid_args = 0;
		ci->call_spd = 0;
		ci->stkargs_top = 0;
		ci->role = ROLE_UNK;
		ci->flags = FCI_FINAL | FCI_PROP;
		ci->return_type = ret;
		detail::push_arg( ci.get(), std::forward<Tx>( args )... );
		return ci;
	}
	template<typename... Tx>
	inline std::unique_ptr<mcallinfo_t> call_info( pure_t, tinfo_t ret, Tx&&... args ) 
	{
		auto ci = call_info( ret, std::forward<Tx>( args )... );
		ci->flags |= FCI_PURE;
		return ci;
	}
	// Creates an instruction.
	//
	inline std::unique_ptr<minsn_t> minsn( ea_t ea, mcode_t opcode, operand l, operand r, operand d ) 
	{
		auto result = std::make_unique<minsn_t>( ea );
		result->opcode = opcode;
		result->l.swap( l );
		result->r.swap( r );
		result->d.swap( d );
		return result;
	}

	// Map every opcode.
	//
#define __decl_n(op)   inline std::unique_ptr<minsn_t> make_##op( ea_t ea ) { return minsn( ea, m_##op, {}, {}, {} ); }
#define __decl_l(op)   inline std::unique_ptr<minsn_t> make_##op( ea_t ea, operand l ) { return minsn( ea, m_##op, std::move( l ), {}, {} ); }
#define __decl_d(op)   inline std::unique_ptr<minsn_t> make_##op( ea_t ea, operand d ) { return minsn( ea, m_##op, {}, {}, std::move( d ) ); }
#define __decl_ld(op)  inline std::unique_ptr<minsn_t> make_##op( ea_t ea, operand l, operand d ) { return minsn( ea, m_##op, std::move( l ), {}, std::move( d ) ); }
#define __decl_rd(op)  inline std::unique_ptr<minsn_t> make_##op( ea_t ea, operand r, operand d ) { return minsn( ea, m_##op, {}, std::move( r ), std::move( d ) ); }
#define __decl_lr(op)  inline std::unique_ptr<minsn_t> make_##op( ea_t ea, operand l, operand r ) { return minsn( ea, m_##op, std::move( l ), std::move( r ), {} ); }
#define __decl_lrd(op) inline std::unique_ptr<minsn_t> make_##op( ea_t ea, operand l, operand r, operand d ) { return minsn( ea, m_##op, std::move( l ), std::move( r ), std::move( d ) ); }
	__decl_n( nop );     // nop                       // no operation
	__decl_lrd( stx );   // stx  l,    {r=sel, d=off} // store register to memory     *F
	__decl_lrd( ldx );   // ldx  {l=sel,r=off}, d     // load register from memory    *F
	__decl_ld( ldc );    // ldc  l=const,     d       // load constant
	__decl_ld( mov );    // mov  l,           d       // move                         *F
	__decl_ld( neg );    // neg  l,           d       // negate
	__decl_ld( lnot );   // lnot l,           d       // logical not
	__decl_ld( bnot );   // bnot l,           d       // bitwise not
	__decl_ld( xds );    // xds  l,           d       // extend (signed)
	__decl_ld( xdu );    // xdu  l,           d       // extend (unsigned)
	__decl_ld( low );    // low  l,           d       // take low part
	__decl_ld( high );   // high l,           d       // take high part
	__decl_lrd( add );   // add  l,   r,      d       // l + r -> dst
	__decl_lrd( sub );   // sub  l,   r,      d       // l - r -> dst
	__decl_lrd( mul );   // mul  l,   r,      d       // l * r -> dst
	__decl_lrd( udiv );  // udiv l,   r,      d       // l / r -> dst
	__decl_lrd( sdiv );  // sdiv l,   r,      d       // l / r -> dst
	__decl_lrd( umod );  // umod l,   r,      d       // l % r -> dst
	__decl_lrd( smod );  // smod l,   r,      d       // l % r -> dst
	__decl_lrd( or );    // or   l,   r,      d       // bitwise or
	__decl_lrd( and );   // and  l,   r,      d       // bitwise and
	__decl_lrd( xor );   // xor  l,   r,      d       // bitwise xor
	__decl_lrd( shl );   // shl  l,   r,      d       // shift logical left
	__decl_lrd( shr );   // shr  l,   r,      d       // shift logical right
	__decl_lrd( sar );   // sar  l,   r,      d       // shift arithmetic right
	__decl_lrd( cfadd ); // cfadd l,  r,    d=carry   // calculate carry    bit of (l+r)
	__decl_lrd( ofadd ); // ofadd l,  r,    d=overf   // calculate overflow bit of (l+r)
	__decl_lrd( cfshl ); // cfshl l,  r,    d=carry   // calculate carry    bit of (l<<r)
	__decl_lrd( cfshr ); // cfshr l,  r,    d=carry   // calculate carry    bit of (l>>r)
	__decl_ld( sets );   // sets  l,          d=byte  SF=1          Sign
	__decl_lrd( seto );  // seto  l,  r,      d=byte  OF=1          Overflow of (l-r)
	__decl_lrd( setp );  // setp  l,  r,      d=byte  PF=1          Unordered/Parity  *F
	__decl_lrd( setnz ); // setnz l,  r,      d=byte  ZF=0          Not Equal         *F
	__decl_lrd( setz );  // setz  l,  r,      d=byte  ZF=1          Equal             *F
	__decl_lrd( setae ); // setae l,  r,      d=byte  CF=0          Above or Equal    *F
	__decl_lrd( setb );  // setb  l,  r,      d=byte  CF=1          Below             *F
	__decl_lrd( seta );  // seta  l,  r,      d=byte  CF=0 & ZF=0   Above             *F
	__decl_lrd( setbe ); // setbe l,  r,      d=byte  CF=1 | ZF=1   Below or Equal    *F
	__decl_lrd( setg );  // setg  l,  r,      d=byte  SF=OF & ZF=0  Greater
	__decl_lrd( setge ); // setge l,  r,      d=byte  SF=OF         Greater or Equal
	__decl_lrd( setl );  // setl  l,  r,      d=byte  SF!=OF        Less
	__decl_lrd( setle ); // setle l,  r,      d=byte  SF!=OF | ZF=1 Less or Equal
	__decl_ld( jcnd );   // jcnd   l,         d       // d is mop_v or mop_b
	__decl_lrd( jnz );   // jnz    l, r,      d       // ZF=0          Not Equal      *F
	__decl_lrd( jz );    // jz     l, r,      d       // ZF=1          Equal          *F
	__decl_lrd( jae );   // jae    l, r,      d       // CF=0          Above or Equal *F
	__decl_lrd( jb );    // jb     l, r,      d       // CF=1          Below          *F
	__decl_lrd( ja );    // ja     l, r,      d       // CF=0 & ZF=0   Above          *F
	__decl_lrd( jbe );   // jbe    l, r,      d       // CF=1 | ZF=1   Below or Equal *F
	__decl_lrd( jg );    // jg     l, r,      d       // SF=OF & ZF=0  Greater
	__decl_lrd( jge );   // jge    l, r,      d       // SF=OF         Greater or Equal
	__decl_lrd( jl );    // jl     l, r,      d       // SF!=OF        Less
	__decl_lrd( jle );   // jle    l, r,      d       // SF!=OF | ZF=1 Less or Equal
	__decl_lr( jtbl );   // jtbl   l, r=mcases        // Table jump
	__decl_rd( ijmp );   // ijmp       {r=sel, d=off} // indirect unconditional jump
	__decl_l( goto );    // goto   l                  // l is mop_v or mop_b
	__decl_ld( call );   // call   l          d       // l is mop_v or mop_b or mop_h
	__decl_lrd( icall ); // icall  {l=sel, r=off} d   // indirect call
	__decl_n( ret );     // ret
	__decl_l( push );    // push   l
	__decl_d( pop );     // pop               d
	__decl_d( und );     // und               d       // undefine
	__decl_lrd( ext );   // ext  in1, in2,  out1      // external insn, not microcode *F
	__decl_ld( f2i );    // f2i    l,    d       int(l) => d; convert fp -> integer   +F
	__decl_ld( f2u );    // f2u    l,    d       uint(l)=> d; convert fp -> uinteger  +F
	__decl_ld( i2f );    // i2f    l,    d       fp(l)  => d; convert integer -> fp   +F
	__decl_ld( u2f );    // i2f    l,    d       fp(l)  => d; convert uinteger -> fp  +F
	__decl_ld( f2f );    // f2f    l,    d       l      => d; change fp precision     +F
	__decl_ld( fneg );   // fneg   l,    d       -l     => d; change sign             +F
	__decl_lrd( fadd );  // fadd   l, r, d       l + r  => d; add                     +F
	__decl_lrd( fsub );  // fsub   l, r, d       l - r  => d; subtract                +F
	__decl_lrd( fmul );  // fmul   l, r, d       l * r  => d; multiply                +F
	__decl_lrd( fdiv );  // fdiv   l, r, d       l / r  => d; divide                  +F
#undef __decl_n   
#undef __decl_l   
#undef __decl_d   
#undef __decl_ld  
#undef __decl_rd  
#undef __decl_lr  
#undef __decl_lrd
};