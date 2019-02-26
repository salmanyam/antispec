# compute anti-spec of CGC sample programs with Angr
import numpy
import random
import os
import sys
import string

import inspect, re
import pyvex


def varname(p):
    for line in inspect.getframeinfo(inspect.currentframe().f_back)[3]:
        m = re.search(r'\bvarname\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', line)
        if m:
            return m.group(1)

# load the known sources into a dictionary in the format of
# {function-name:[return-type, [parameter1-type, parameter2-type,...]], ...}
def loadKnownSources(fn):
    fh = file(fn,'r')
    if fh==None:
        raise IOError("error occurred when opening file: " + fn)
    contents = fh.readlines()
    fh.close()

    sourcelist = {}
    n=0
    #rx = re.compile("(?<=[\s:~])(\w+)\s*\(([\w\s,<>\[\].=&':/*]*?)\)\s*(const)?\s*(?={)")
    rx = re.compile("\s*(unsigned|signed|\s*)?(int|ssize_t|size_t|void|long|short|float|double)\s*(\w+)\s*\(([\w+\s,<>\[\].=&':/*]*?)\)\s*(const)?;")
    for line in contents:
        line=line.lstrip().rstrip()
        m = rx.match(line)
        if m==None:
            print >> sys.stderr, "not a C function declaration: %s" % (line)
            continue
        #print "return type:%s, function: %s, parameters: %s" % (str(m.group(1))+' '+str(m.group(2)), m.group(3), m.group(4))
        rettype=(str(m.group(1))+' '+str(m.group(2))).lstrip().rstrip()
        funcname=m.group(3)
        allparams = m.group(4)

        paratypelist=[]
        pnts = string.split(allparams,',')
        for pnt in pnts:
            items=string.split(pnt)
            if len(items)<2:
                continue
            paratypelist.append( ''.join(items[:len(items)-1]) )

        if funcname not in sourcelist.keys():
            sourcelist[funcname] = list()

        v = sourcelist[funcname]
        v.append( rettype )
        v.append( paratypelist )

        n=n+1

    print >> sys.stdout, "%d known sources are loaded" % (n)
    #print sourcelist
    return sourcelist

def do_analysis(fbin):
    import angr
    import angr.analyses

    #ap = angr.Project(fbin, load_options={'auto_load_libs': False})
    #ap = angr.Project(fbin, load_options={'auto_load_libs': True}, main_opts={'backend':'cgc'})
    #ap = angr.Project(fbin, load_options={'auto_load_libs': True}, main_opts={'backend':'elf'})
    ap = angr.Project(fbin, load_options={'auto_load_libs': True})
    cfg = ap.analyses.CFGAccurate(keep_state=True)


    for node in cfg.graph.nodes():
        print `node`
        print repr(node.addr)
        print node.to_codenode()
        print node.input_state
        print node.final_states
        print node.simprocedure_name
        print node.instruction_addrs
        print node.block_id
        print node.irsb
        for stmt in ap.factory.block(node.addr).vex.statements:
            stmt.pp()
        print ap.loader.describe_addr(node.addr)
        print "===="

        so = ap.loader.find_object_containing(node.addr)
        if so is not None and node.addr in so.symbols_by_addr:
            name = so.symbols_by_addr[node.addr].name
            print name

    cdg = ap.analyses.CDG (cfg)
    ddg = ap.analyses.DDG (cfg)

    for fk in cfg.kb.functions.keys():
        func = cfg.kb.functions[fk]
        print "%s: %s" % (fk, func)
        print ap.loader.describe_addr(fk)
        print "call sites in %s " % (func.name)
        for cs in func.get_call_sites():
            print "cs addr: %s" % (cs)
            callee = func.get_call_target(cs)
            print "cs target: %s %s" % (callee, cfg.kb.functions[callee])

    print ap.entry

    print ap.loader.main_object
    print ap.loader.main_object.get_symbol("main")
    #for addr, symbol in ap.analyses.Identifier().run():
    #    print hex(addr), symbol

    s = ap.factory.entry_state()
    print "Entry state: %s" % (s)
    print "Entry state log actions: %s\n %s\n %s\n %s" % (s.log.actions, s.libc, s.cgc, s.fs)


    '''
    sm = ap.factory.simulation_manager(save_unconstrained=True)
    #symbolically execute the binary until an unconstrained path is reached
    while len(sm.unconstrained)==0:
        sm.step()
    unconstrained_state = sm.unconstrained[0]
    crashing_input = unconstrained_state.posix.dumps(0)
    print "buffer overflow found!"
    print repr(crashing_input)
    '''

    print ap.loader.all_objects


if __name__=="__main__":
    if len(sys.argv)<2:
        print >> sys.stderr, "missing the program to analyze..."
        sys.exit(1)
    sources = loadKnownSources('/home/hcai/Environments/known-sources.txt')

    print >> sys.stdout, "now analyzing %s with angr facilities..." % (sys.argv[1])
    do_analysis(sys.argv[1])

    sys.exit(0)

# hcai: set ts=4 tw=120 sts=4 sw=4
