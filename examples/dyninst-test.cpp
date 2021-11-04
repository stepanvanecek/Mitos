#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <link.h>

#include <iostream>
#include "CodeObject.h"
#include "InstructionDecoder.h"
using namespace std;
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;




int main(int argc, char **argv)
{

    // void *handle = dlopen(NULL, RTLD_LAZY);
    // if (handle == NULL) {
    //     fprintf(stderr, "dlopen() failed: %s\n", dlerror());
    //     exit(EXIT_FAILURE);
    // }
    // printf("xx1\n");

    void * const handle = dlopen(NULL, RTLD_LAZY);
    assert(handle != 0);
    // Get the link map
    const struct link_map * link_map = 0;
    const int ret = dlinfo(handle, RTLD_DI_LINKMAP, &link_map);
    const struct link_map * const loaded_link_map = link_map;
    assert(ret == 0);
    assert(link_map != 0);
    printf("%llu\n", (long long)link_map->l_addr);


    while (link_map->l_prev) {
      link_map = link_map->l_prev;
    }
    while (link_map) {
      printf("%llu - %s \n", (long long)link_map->l_addr, link_map->l_name);
      link_map = link_map->l_next;
    }

    // const struct link_map *lm = 0;
    // if (dlinfo(handle, RTLD_DI_LINKMAP, lm) == -1) {
    //     fprintf(stderr, "RTLD_DI_SERINFOSIZE failed: %s\n", dlerror());
    //     exit(EXIT_FAILURE);
    // }
    //     printf("xx2\n");
    //
    // printf("%p\n", lm->l_addr);

    void *array[10];
    char **strings;
    int size, i;

    size = backtrace (array, 10);
    strings = backtrace_symbols (array, size);
    if (strings != NULL)
    {

      printf ("Obtained %d stack frames.\n", size);
      for (i = 0; i < size; i++)
        printf ("%s\n", strings[i]);
    }

    free (strings);
    std::cout << "main ptr: " << (void*)&main << '\n';

    //char* bin_name = (argc == 2) ? ((char*)argv[1]) : "/u/home/vanecek/sshfs/sv_mitos/build/mitos_1634658399/data/samples.csv";
    char* bin_name = "/u/home/vanecek/sshfs/heatdir_orig/heat";

    SymtabCodeSource *sts;
	CodeObject *co;
	Instruction instr;
	SymtabAPI::Symtab *symTab;
	std::string binaryPathStr(bin_name);
	bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
	if(isParsable == false){
		const char *error = "error: file can not be parsed";
		cout << error;
		return - 1;
	}
	sts = new SymtabCodeSource(bin_name);
    std::vector<SymtabAPI::Statement::Ptr> stats;
    Dyninst::Offset ip = 0xf16;
    int sym_success = symTab->getSourceLines(stats, ip);
    if(sym_success)
    {
        cout << "file " << stats[0]->getFile() << " line: "  << stats[0]->getLine();
    }
    cout << "cnt : " << stats.size() << endl;

	co = new CodeObject(sts);
	//parse the binary given as a command line arg
	co->parse();

	//get list of all functions in the binary
	const CodeObject::funclist &all = co->funcs();
	if(all.size() == 0){
		const char *error = "error: no functions in file";
		cout << error;
		return - 1;
	}
	auto fit = all.begin();
	Function *f = *fit;
	//create an Instruction decoder which will convert the binary opcodes to strings
	InstructionDecoder decoder(f->isrc()->getPtrToInstruction(f->addr()),
				   InstructionDecoder::maxInstructionLength,
				   f->region()->getArch());
	for(;fit != all.end(); ++fit){
		Function *f = *fit;
		//get address of entry point for current function
		Address crtAddr = f->addr();
		int instr_count = 0;
		instr = decoder.decode((unsigned char *)f->isrc()->getPtrToInstruction(crtAddr));
		auto fbl = f->blocks().end();
		fbl--;
		Block *b = *fbl;
		Address lastAddr = b->end();
		//if current function has zero instructions, d o n t output it
		if(crtAddr == lastAddr)
			continue;
		cout << "\n\n\"" << f->name() << "\" :";
		while(crtAddr < lastAddr){
			//decode current instruction
			instr = decoder.decode((unsigned char *)f->isrc()->getPtrToInstruction(crtAddr));
			cout << "\n" << hex << crtAddr;
			cout << ": \"" << instr.format() << "\"";
			//go to the address of the next instruction
			crtAddr += instr.size();
			instr_count++;
		}
	}
	return 0;
}
