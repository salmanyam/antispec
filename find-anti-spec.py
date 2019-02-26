# compute anti-spec of CGC sample programs with Angr
import numpy
import random
import os
import sys
import string

import inspect, re
import angr
import angr.analyses

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

        #v = sourcelist[funcname]
        #v.append( rettype )
        #v.append( paratypelist )
        sourcelist[funcname] = [rettype, paratypelist]

        n=n+1

    print >> sys.stdout, "%d known sources are loaded" % (n)
    #print sourcelist
    return sourcelist

def getFuncAddress(cfg, funcName, plt=None ):
    found = [
            addr for addr,func in cfg.kb.functions.iteritems()
            if funcName == func.name and (plt is None or func.is_plt == plt)
            ]
    if len( found ) > 0:
        print "Found "+funcName+"'s address at "+hex(found[0])+"!"
        return found[0]
    else:
        #raise Exception("No address found for function : "+funcName)
        return None

def locateCFGNode(graph, naddr):
    for node in graph.nodes():
        if repr(node.addr) == repr(naddr):
            return node
    return None

def locateDDGNode(ddg, cfgnode):
    ret =[]
    for node in ddg.data_graph.nodes():
        if repr(node.location.block_addr) == repr(cfgnode.addr):
            ret.append (node)
    return ret

def peekcfg(cfg):
    for fk in cfg.kb.functions.keys():
        print "%s: %s" % (fk, cfg.kb.functions[fk])
        print ap.loader.describe_addr(fk)

def antispec_per_source(ap,caller, csaddr,cfg,cdg,ddg):
    cfgnode = locateCFGNode (cfg.graph, csaddr)
    '''
    ddgnode = locateNode (ddg.graph, srcaddr)
    cdgnode = locateNode (cdg.graph, srcaddr)
    assert ddgnode!=None and cdgnode!=None

    cfgnodes = cfg.get_all_nodes( csaddr )
    print "cfg nodes associated with the callsite"
    for cn in cfgnodes:
        print cn

    print "DDG nodes associated with the callsite"
    ddgnodes = locateDDGNode(ddg, cfgnode)
    for dn in ddgnodes:
        print dn
    '''

    print "definitions at the call site"
    dview = angr.analyses.ddg.DDGView(cfg, ddg)
    defs = []
    '''
    defs = set()
    for i in range(0, cfgnode.size):
        item = dview[cfgnode.addr+i]
        defs.add(a for a in item.definitions)
    '''
    #print cfgnode.function_address
    sltargets = []
    #i = 0
    for ia in cfgnode.instruction_addrs:
        item = dview [ia]
        print ia
        print item
        print item.definitions
        defs.append( item.definitions )

        #sltargets.append ( (cfgnode, i) )
        #i=i+1
    print defs

    # take all statements in the callsite block as slicing criteria
    for i, stmt in enumerate( ap.factory.block(cfgnode.addr).vex.statements ):
        sltargets.append ( (cfgnode, i) )

    bs = ap.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=sltargets)
    #bs = ap.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=[(cfgnode, -1)])
    print "backward slice of call site"
    #print bs
    print bs.chosen_statements

    variables=[]
    for baddr,sids in bs.chosen_statements.iteritems():
        for sid in sids:
            defs.append( dview[baddr+sid].definitions )
            for node in ddg.data_graph.nodes():
                if (node.location.block_addr) == hex(baddr): #and node.location.stmt_idx == sid:
                    variables.append ( node )

    print defs
    print variables


    ''' forward analysis to check against boundary checking
    '''
    #print cfg.kb.functions.function(name="_terminate")

    #ddg.pp()
    #print ddg.get_all_nodes(cfgnode.addr, -1)
    #for node in ddg.graph.nodes():
    for node in ddg.data_graph.nodes():
        #print type(node)
        print node
        #print node.location
        #print node.location.block_addr, node.location.stmt_idx, node.location.sim_procedure

    for edge in ddg.data_graph.edges():
        print edge

    print "done OKAY: %s" % (cfgnode)
    print "done OKAY: %x" % (cfgnode.addr)
    print "done OKAY: %x" % (ap.factory.block(cfgnode.addr).addr)
    #print "callsite instructions: %s" % (cfgnode.irsb)
    #print "callsite instructions: %s" % (ap.factory.block(cfgnode.addr).capstone.insns)
    print "callsite instructions"
    for stmt in (ap.factory.block(cfgnode.addr).capstone.insns):
        print stmt

    sddg = ap.analyses.DDG (cfg, start=csaddr)
    sddg.pp()

    print caller
    print sddg.function_dependency_graph(caller)

def getCallers(cfg,faddr):
    ret = []
    for fk in cfg.kb.functions.keys():
        func = cfg.kb.functions[fk]
        for cs in func.get_call_sites():
            callee = func.get_call_target(cs)
            #print "cs target: %s %s" % (callee, cfg.kb.functions[callee])
            if callee == faddr:
                ret.append([func,cs])
    return ret

def do_analysis(fbin, sources):
    ap = angr.Project(fbin, load_options={'auto_load_libs': False})
    cfg = ap.analyses.CFGAccurate(keep_state=True, context_sensitivity_level=2)
    cfg.normalize()
    #peekcfg(cfg)
    cdg = ap.analyses.CDG (cfg)
    ddg = ap.analyses.DDG (cfg)
    '''
    ddg.pp()
    vfg = ap.analyses.VFG(cfg)
    for node in vfg.graph.nodes():
        print node
    '''
    #ddg = ap.analyses.VSA_DDG ( vfg )

    for fname in sources.keys():
        faddr = getFuncAddress(cfg, fname)
        if faddr == None:
            continue

        print "user input source: %s %s %s..." % (sources[fname][0], fname, sources[fname][1])
        print "callers of this user input sources:"
        allcallercs = getCallers(cfg,faddr)
        for callercs in allcallercs:
            caller = callercs[0]
            csaddr = callercs[1]
            print caller.name
            print "callsite in caller: %s" % (csaddr)
            print "strings in this caller: %s" % (caller.string_references())
            antispec_per_source(ap,caller,csaddr,cfg,cdg,ddg)

if __name__=="__main__":
    if len(sys.argv)<2:
        print >> sys.stderr, "missing the program to analyze..."
        sys.exit(1)
    sources = loadKnownSources('/home/hcai/Environments/known-sources.txt')

    print >> sys.stdout, "now analyzing %s with angr facilities..." % (sys.argv[1])
    do_analysis(sys.argv[1], sources)

    sys.exit(0)

# hcai: set ts=4 tw=120 sts=4 sw=4
