#include "pin.H"
#include <iostream>
#include <signal.h>
#include <fstream>
#include <map>

#define MALLOC "malloc"
#define FREE "free"
#define CALL "call"
#define ALLOCATED 1
#define FREED 2

std::ofstream TraceFile;
map<ADDRINT, int> mem_addr_table;
map<ADDRINT, int> mem_alloc_table;
ADDRINT mem_addr = 0;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
		"o", "memcheck.out", "specify trace file name");


/* Analysis routines */

//Check if malloc'd memory is freed or not.
void checkLeak()
{
	while(!mem_addr_table.empty())
	{
		cerr << mem_addr_table.begin()->second << " bytes allocated at ";
		cerr << "0x" << hex << mem_addr_table.begin()->first << " but never freed." << endl;
		mem_addr_table.erase(mem_addr_table.begin());
	}

}

//Signal handler for SIGINT
static BOOL Intercept(THREADID, INT32 sig, CONTEXT *, BOOL, const EXCEPTION_INFO *, VOID *)
{
	checkLeak();
	return TRUE;
}

//Check and maintain malloc address allocation
VOID Get_Argument(CHAR * name, ADDRINT addr)
{
	//If called from MALLOC, save the return address in temporary value
	if(strcmp(name, MALLOC) == 0)
	{
		mem_addr = addr;
	}
	//If called from CALL, check if target address is valid
	else if(strcmp(name, CALL) == 0)	
	{
		if(mem_alloc_table[addr] == FREED)
		{
			cerr << hex << "0x"  << addr << " is used after being freed. Exiting." << endl;
			exit(1);
		}	
	}
	//If called from FREE, check validations for used address
	else
	{
		if(mem_alloc_table[addr] == ALLOCATED)
		{
			mem_addr_table.erase(addr);
			mem_alloc_table[addr] = FREED;
		}
		else if(mem_alloc_table[addr] == FREED)
		{	
			cerr << "Double free of 0x" << hex << addr << ", Exiting." << endl;;
			exit(1);
		}
		else
		{
			cerr << "Attempt to free 0x" << hex << addr << ". Not a valid allocated memory. Exiting." << endl;
			exit(1);
		}
	}
}

//Store entry into Memory table and mark address as ALLOCATED
VOID Ret_Malloc(ADDRINT ret)
{
	mem_addr_table[ret] = mem_addr;
	mem_alloc_table[ret] = ALLOCATED;
}


/* ===================================================================== */
/* Instrumentation routines                                              */
/* ===================================================================== */
VOID Instruction(INS ins, VOID *v)
{
	if(INS_IsCall(ins))
	{
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Get_Argument, IARG_ADDRINT, CALL, IARG_BRANCH_TARGET_ADDR, IARG_END);
	}

}

// Instrument the malloc() and free() functions.  Print the input argument
VOID Image(IMG img, VOID *v)
{
	//  Find the malloc() function.
	RTN mallocRtn = RTN_FindByName(img, MALLOC);
	if (RTN_Valid(mallocRtn))
	{
		RTN_Open(mallocRtn);

		// Instrument malloc() to print the input argument value and the return value.
		RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)Get_Argument, IARG_ADDRINT, MALLOC, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);

		RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)Ret_Malloc, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

		RTN_Close(mallocRtn);
	}

	// Find the free() function.
	RTN freeRtn = RTN_FindByName(img, FREE);
	if (RTN_Valid(freeRtn))
	{
		RTN_Open(freeRtn);
		// Instrument free() to print the input argument value.
		RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)Get_Argument, IARG_ADDRINT, FREE,IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
		RTN_Close(freeRtn);
	}

}

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
	TraceFile.close();
	checkLeak();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
	cerr << "This tool produces a trace of calls to malloc." << endl;
	cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
	// Initialize pin & symbol manager
	PIN_InitSymbols();
	if( PIN_Init(argc,argv) )
	{
		return Usage();
	}

	//Register Signal handler for SIGINT
	PIN_InterceptSignal(SIGINT, Intercept, 0);
	PIN_UnblockSignal(SIGINT, TRUE);

	// Write to a file since cout and cerr maybe closed by the application
	TraceFile.open(KnobOutputFile.Value().c_str());
	TraceFile << hex;
	TraceFile.setf(ios::showbase);

	// Register Image to be called to instrument functions.
	IMG_AddInstrumentFunction(Image, 0);
	// Register Instructions to instrument function
	INS_AddInstrumentFunction(Instruction, 0);
	PIN_AddFiniFunction(Fini, 0);

	// Never returns
	PIN_StartProgram();

	return 0;
}
