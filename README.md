### HexSuite

##### Header only wrapper around Hex-Rays API in C++20.

------



### Supported Features

------

- One-click linking to Hex-Rays API using Visual Studio.
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
size_t count_operands( mba_t* mba ) {
	size_t n = 0;
	for ( mblock_t* blk : hex::basic_blocks( mba ) )
	{
		msg( "Successors = %llu\n", hex::successors( blk ).size() );
		for ( minsn_t* ins : hex::instructions( blk ) )
			for ( mop_t* op : hex::operands( ins ) )
				n++;
	}
	return n;
}
```

- More stuff on the way!



### Usage

------

If you're using Visual Studio:

1) Add a new environment variable using `SystemPropertiesAdvanced.exe` like so `IDA_PATH = S:\IDA Pro\`.
2) Add the `HexSuite.vcxproj` into your solution by using `Solution > Add > Existing Project`.
3) Right click on the References tab of the dynamic library (which will be your plugin) and add a reference to HexSuite.
4) Profit.

If you're not using Visual Studio, simply include the directory, however you will be responsible for linking against Hex-Rays API.

Note that in either case you need a STL library and a compiler fully supporting C++20.



### License

------

HexSuite is licensed under BSD-3-Clause License.