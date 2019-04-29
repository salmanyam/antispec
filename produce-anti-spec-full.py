# compute anti-spec of CGC sample programs with Angr
import numpy
import random
import os
import sys
import string

import inspect, re
import angr
import angr.analyses
import angr.sim_variable
import logging
import networkx

l = logging.getLogger("produce-anti-spec")
l.setLevel(logging.DEBUG)

def varname(p):
    for line in inspect.getframeinfo(inspect.currentframe().f_back)[3]:
        m = re.search(r'\bvarname\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', line)
        if m:
            return m.group(1)

# load the known sources into a dictionary in the format of
# {function-name:[return-type, [parameter1-type, parameter2-type,...]], ...}
def loadKnownSources(fn):
    fh = open(fn,'r')
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
        #print(allparams)
        paratypelist=[]
        pnts = allparams.split(',')
        for pnt in pnts:
            items=pnt.split()
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

    #print >> sys.stdout, "%d known sources are loaded" % (n)
    #salman print("%d known sources are loaded" % (n))
    #print sourcelist
    return sourcelist

def getFuncAddress(cfg, funcName, plt=None ):
    found = [
            addr for addr,func in cfg.kb.functions.items()
            if funcName == func.name and (plt is None or func.is_plt == plt)
            ]
    if len( found ) > 0:
        #salman print("Found "+funcName+"'s address at "+hex(found[0])+"!")
        return found[0]
    else:
        #raise Exception("No address found for function : "+funcName)
        return None

def locateCFGNode(cfg, naddr):
    for node in cfg.graph.nodes():
        if repr(node.addr) == repr(naddr):
            return node
    return None

def locateDDGDataNode(ddg, cfgnode):
    ret =[]
    for node in ddg.data_graph.nodes():
        if node.location.block_addr == cfgnode.addr:
            ret.append (node)
    return ret

def locateDDGStmtNode(ddg, cfgnode):
    ret =[]
    for node in ddg.graph.nodes():
        if node.block_addr == cfgnode.addr:
            ret.append (node)
    return ret

def peekcfg(cfg):
    for fk in cfg.kb.functions.keys():
        print ("%s: %s" % (fk, cfg.kb.functions[fk]))
        print (ap.loader.describe_addr(fk))

def boundary_checking(caller, callsitedefs, cfg, cdg):
    allguards = []
    cdnodes = []
    for cd in callsitedefs:
        cdnodes.append (locateCFGNode(cfg, cd.location.block_addr))
    '''
    find all cfgnodes that are associated with defs at the user input source callsite;
    if such a cfgnode guards other nodes on CDG, then the cfgnode itself is checking
    a def against some condition; we collect such cfgnodes
    '''
    #salman print ("%d cfgnodes associated with defs at callsite" % (len(cdnodes)))
    for node in cdnodes:
        if len(cdg.get_dependants(node))>=1:
            allguards.append (node)
        '''
        guardians = cdg.get_guardians(node)
        for guard in guardians:
            #print guard
            for block in caller.blocks:
                if block.addr == guard.addr:
                    allguards.append(guard)
        '''
    return allguards

def antispec_per_source(ap,caller, callee, csaddr,cfg,cdg,ddg):
    cfgnode = locateCFGNode (cfg, csaddr)
    #salman l.debug("cfgnode associated with callsite")
    #salma print ("node: %s" % (cfgnode))
    #salman print ("node addr: %x" % (cfgnode.addr))
    #salman print ("node block addr: %x" % (ap.factory.block(cfgnode.addr).addr))
    #print "callsite instructions: %s" % (cfgnode.irsb)
    #print "callsite instructions: %s" % (ap.factory.block(cfgnode.addr).capstone.insns)
    #salma l.debug("callsite instructions")
    #salman for stmt in (ap.factory.block(cfgnode.addr).capstone.insns):
        #salman print (stmt)


    '''salman
    l.info("guardian of the callsite (intraprocedural)")
    guardians = cdg.get_guardians(cfgnode) #return a list of nodes on whom the specific 
    #node is control dependent in the control dependence graph
    for guard in guardians:
        #print guard
        for block in caller.blocks:
            if block.addr == guard.addr:
                print (guard)'''

    #salman l.debug("data dependencies starting from callsite")
    #sddg = ap.analyses.DDG (cfg, start=csaddr, block_addrs=[csaddr])
    sddg = ap.analyses.DDG (cfg, start=csaddr)
    #sddg.pp()
    #salman print ("%d nodes, %d edges" % (len(sddg.graph.nodes()), len(sddg.graph.edges())))

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

    '''
    ddgnodes = set()
    for node in ddg.data_graph.nodes():
    #for node in ddg.graph.nodes():
        if callee.name in repr(node.location.sim_procedure):
            if not isinstance (node.variable, angr.sim_variable.SimConstantVariable):
                ddgnodes.add( node )
    '''

    ddgnodes = locateDDGDataNode(ddg, cfgnode)

    #salman l.debug("DDG nodes associated with the callsite")
    alldefs = set()
    allcons = set()
    total_ddnodes = 0
    total_definitions = 0
    total_data_consumers = 0
    total_control_consumers = 0
    total_boundary_checks = 0
    for node in ddgnodes:
        '''
        print node.location.block_addr, node.location.stmt_idx, node.location.ins_addr
        print "definitions for this node:"
        ## only register, stack, and memory variables are interesting to us
        if isinstance (node.variable, angr.sim_variable.SimConstantVariable):
            continue
        if isinstance (node.variable, angr.sim_variable.SimTemporaryVariable):
            continue
        '''
        # only stack, and memory variables are interesting to us
        if not (isinstance (node.variable, angr.sim_variable.SimStackVariable) or isinstance (node.variable, angr.sim_variable.SimMemoryVariable)):
            continue
        #salman print (node)
        total_ddnodes += 1
        defs = ddg.find_definitions(node.variable, simplified_graph=False)
        #print defs
        for df in defs:
            alldefs.add(df)
            #print df.location.block_addr, df.location.stmt_idx, df.location.ins_addr
            #print "sources of %s" % (df)
            srcs = ddg.find_sources(df, simplified_graph=False)
            #print srcs
            #print "consumers of %s" % (df)
            #cons = ddg.find_consumers(df, simplified_graph=False)
            cons = ddg.find_consumers(sddg, simplified_graph=False)
            #print cons
            for con in cons:
                allcons.add (con)

        '''
        cons = ddg.find_consumers(node, simplified_graph=False)
        for con in cons:
            allcons.add (con)
        print
        '''

    '''
    for edge in ddg.data_graph.edges():
        print edge
    '''
    
    #print('Number of DDG nodes associated with the callsite: %d' % total_ddnodes)
    print(total_ddnodes, end="endmark#$%@endmark")

    #salman l.debug("definitions at the call site")
    '''
    dview = ddg.view #angr.analyses.ddg.DDGView(cfg, ddg)
    print dview
    defs = []
    defs = set()
    for i in range(0, cfgnode.size):
        item = dview[cfgnode.addr+i]
        defs.add(a for a in item.definitions)
    print defs

    #print cfgnode.function_address
    #i = 0
    dvinses=[]
    for node in ddgnodes:
        #dviemitem = angr.analyses.ddg.DDGViewItem(ddg, node.variable)
        dvinses.append(dview [ node.location.ins_addr ])
        #sltargets.append ( (cfgnode, i) )
        #i=i+1
    print dvinses
    '''
    total_definitions = len(alldefs)
    #print('Number of definitions at the call site: %d' % total_definitions)
    print(total_definitions, end="endmark#$%@endmark")
    #salman for df in alldefs:
        #salman print (df)

    #l.debug("boundary checking of defs at call site")
    allguards = boundary_checking(caller, alldefs, cfg, cdg)
    total_boundary_checks = len(allguards)
    #print('boundary checking of defs at call site: %d' % total_boundary_checks)
    print(total_boundary_checks, end="endmark#$%@endmark")
    #salman for guard in allguards:
        #salman print (guard)

    #l.debug("Downstream data-flow impact of defs on callsite")
    # impact via control dependencies
    total_data_consumers = len(allcons)
    #print('Downstream data-flow impact of defs on callsite: %d' % total_data_consumers)
    print(total_data_consumers, end="endmark#$%@endmark")
    #salman for con in allcons:
        #salman print (con)

    #l.debug("Downstream control-flow impact of defs on callsite")
    # impact via control dependencies
    for cc in cdg.get_dependants(cfgnode):
        #print (cc)
        total_control_consumers += 1
    for guard in allguards:
        for cc in cdg.get_dependants(guard):
            #print (cc)
            total_control_consumers += 1

    #print('Downstream control-flow impact of defs on callsite: %d' %total_control_consumers)
    print(total_control_consumers, end="endmark#$%@endmark")
    return

    sltargets = []
    # take all statements in the callsite block as slicing criteria
    for i, stmt in enumerate( ap.factory.block(cfgnode.addr).vex.statements ):
        sltargets.append ( (cfgnode, i) )

    #logging.getLogger("angr.analyses.backward_slice").setLevel(logging.DEBUG)
    bs = ap.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=sltargets)
    #bs = ap.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=[(cfgnode, -1)])
    print ("backward slice of call site")
    #print bs
    #print bs.chosen_statements

    vardefs=[]
    for baddr,sids in bs.chosen_statements.items():
        print (hex(baddr), sids)
        for sid in sids:
            '''
            #defs.append( dview[baddr+sid].definitions )
            for node in ddg.data_graph.nodes():
            #for node in ddg.graph.nodes():
                if (node.location.block_addr) == hex(baddr) and node.location.stmt_idx == sid:
                    variables.append ( node )
            '''
            vardefs.append ( ddg.view[baddr+sid].definitions )

    #print defs
    print ("variable defs in the backward slice")
    print (vardefs)


    ''' forward analysis to check against boundary checking
    '''
    #print cfg.kb.functions.function(name="_terminate")

    #ddg.pp()
    #print ddg.get_all_nodes(cfgnode.addr, -1)
    #for node in ddg.graph.nodes():

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
    ap = angr.Project(fbin, load_options={'auto_load_libs': True} )
    cfg = ap.analyses.CFGEmulated(keep_state=True, context_sensitivity_level=2,state_add_options=angr.sim_options.refs)
    cfg.normalize()
    #peekcfg(cfg)
    cdg = ap.analyses.CDG (cfg)
    #logging.getLogger("angr.analyses.ddg").setLevel(logging.DEBUG)
    ddg = ap.analyses.DDG (cfg)
    #salman l.debug("=== data dependencies (from program entry) ===")
    #ddg.pp()
    #salman print ("%d nodes, %d edges" % (len(ddg.graph.nodes()), len(ddg.graph.edges())))

    '''
    vfg = ap.analyses.VFG(cfg)
    for node in vfg.graph.nodes():
        print node
    ddg = ap.analyses.VSA_DDG ( vfg, keep_data=True )

    print (ddg)
    print "nodes in VSA_DDG"
    for node in ddg.graph.nodes():
        print node
    print "edges in VSA_DDG"
    for edge in ddg.graph.edges():
        print edge
    '''

    func2ddg={}
    '''
    print "ddg blocks"
    for src, dst, data in ddg.graph.edges(data=True):
        print src.block_addr, dst.block_addr
    print "func blocks"
    '''
    # create a mapping from func to ddg edges
    for _, func in cfg.kb.functions.items():
        #print func.name
        if func not in func2ddg:
            func2ddg[func] = []
        for block in func.blocks:
            #print block.addr
            for src, dst, data in ddg.graph.edges(data=True):
                #print src.block_addr, dst.block_addr
                if src.block_addr == block.addr or dst.block_addr == block.addr:
                    func2ddg[func].append((src, dst, data))

    for fname in sources.keys():
        faddr = getFuncAddress(cfg, fname)
        if faddr == None:
            continue

        #salman l.info ("user input source:")
        print(fname, end="endmark#$%@endmark")
        print ("%s %s %s" % (sources[fname][0], fname, sources[fname][1]), end="endmark#$%@endmark")
        #salman l.debug("callers of this user input source:")
        allcallercs = getCallers(cfg,faddr)
        for callercs in allcallercs:
            caller = callercs[0]
            csaddr = callercs[1]
            print (caller.name, end="endmark#$%@endmark")
            #salman print (caller)
            #salman print ("callsite in caller: %s" % (hex(csaddr)))
            print (hex(csaddr), end="endmark#$%@endmark")
            #salman print ("strings in this caller: %s" % (caller.string_references()))
            #salman l.debug("=== data dependencies within this caller ===")
            #clddg = ddg.function_dependency_graph(caller)
            clddg = func2ddg[caller]
            #salman for src,dst,data in clddg:
                #salman print (src, dst, data)

            '''
            print clddg.graph
            for k in cfg.kb.functions.keys():
                func = cfg.kb.functions[k]
                print func.name
                fg = ddg.function_dependency_graph( func )
                if fg:
                    print fg.graph
            if clddg:
                for edge in clddg.graph.edges():
                    print edge
            '''
            antispec_per_source(ap,caller,cfg.kb.functions[faddr], csaddr,cfg,cdg,ddg)

if __name__=="__main__":
    if len(sys.argv)<2:
        print >> sys.stderr, "missing the program to analyze..."
        sys.exit(1)
    sources = loadKnownSources('/home/salman/angr-dev/antispec/known-sources.txt')

    #print >> sys.stdout, "now analyzing %s with angr facilities..." % (sys.argv[1])
    #salman print("now analyzing %s with angr facilities..." % (sys.argv[1]))
    print(sys.argv[1], end="endmark#$%@endmark")
    do_analysis(sys.argv[1], sources)

    sys.exit(0)

# hcai: set ts=4 tw=120 sts=4 sw=4
