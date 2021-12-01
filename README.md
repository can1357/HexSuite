# HexSuite
HexSuite is a header only wrapper around Hex-Rays API in C++20 designed to simplify the use of Hex-Rays and IDA APIs by modern C++ features.
Some of the features it currently supports are as follows:


- One-click linking to Hex-Rays API using Visual Studio.

- Instruction wrappers and easy memory-management under `hexsuite/architecture.hpp`:

```cpp
auto ci = hex::call_info(
	hex::pure_t{},
	tinfo_t{ BT_INT32 },
	hex::call_arg{ hex::reg( eax_arg, 4 ), tinfo_t{ BT_INT32 } },
	hex::call_arg{ hex::reg( ecx_arg, 4 ), tinfo_t{ BT_INT32 } }
);
auto call = hex::make_call( cg.insn.ea, hex::helper( extr ), std::move( ci ) );
auto mov =  hex::make_mov( cg.insn.ea, std::move( call ), hex::reg( reg, 4 ) );
```

- Lambda visitors under `hexsuite/visitors.hpp`:

```cpp
blk->for_all_insns( hex::minsn_visitor( [ & ] ( minsn_t* i )
{
	msg( "Instruction/Subinstruction: %s\n", hex::to_string( i ).c_str() );
} ) );
```

- Lambda optimizers and microcode filters under `hexsuite/components.hpp`:

```cpp
hex::microcode_filter filter = [ ] ( codegen_t& cg )
{
	if ( cg.insn.itype == NN_vmxoff )
		msg( "Found __vmxoff\n" );
	return false;
};
filter.install();
```

- C++ range wrappers under `hexsuite/ranges.hpp`:

```cpp
void list_types() {
	for ( const char* type_name : hex::named_types() )
		msg( "%s\n", type_name );
}
size_t count_instructions( mba_t* mba ) {
	size_t n = 0;
	for ( mblock_t* blk : hex::basic_blocks( mba ) )
	{
		msg( "Successors = %llu\n", hex::successors( blk ).size() );
		for ( minsn_t* ins : hex::instructions( blk ) )
			n++;
	}
	return n;
}
```

- More stuff on the way!



## Usage
If you're using Visual Studio:

1) Add a new environment variable using `SystemPropertiesAdvanced.exe` like so `IDA_PATH = S:\IDA Pro\`.
1) Unpack the SDK into `%IDA_PATH%sdk`.
2) Add the `HexSuite.vcxproj` into your solution by using `Solution > Add > Existing Project`.
3) Right click on the References tab of the dynamic library (which will be your plugin) and add a reference to HexSuite.
4) Profit.

If you're not using Visual Studio, simply include the directory, however you will be responsible for linking against Hex-Rays API.

Note that in either case you need a STL library and a compiler fully supporting C++20.



## License
HexSuite is licensed under BSD-3-Clause License.
