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

def varname(p):
    for line in inspect.getframeinfo(inspect.currentframe().f_back)[3]:
        m = re.search(r'\bvarname\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', line)
        if m:
            return m.group(1)

def peekcfg(ap,cfg):
    for fk in cfg.kb.functions.keys():
        print "%s: %s" % (fk, cfg.kb.functions[fk])
        print ap.loader.describe_addr(fk)

def do_analysis(fbin):
    ap = angr.Project(fbin, load_options={'auto_load_libs': True})
    cfg = ap.analyses.CFGAccurate(keep_state=True, context_sensitivity_level=10)
    cfg.normalize()
    peekcfg(ap,cfg)
    cdg = ap.analyses.CDG (cfg)
    vfg = ap.analyses.VFG(cfg)

    print "nodes in VFG"
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

if __name__=="__main__":
    if len(sys.argv)<2:
        print >> sys.stderr, "missing the program to analyze..."
        sys.exit(1)
    print >> sys.stdout, "now analyzing %s with angr facilities..." % (sys.argv[1])
    do_analysis(sys.argv[1])

    sys.exit(0)

# hcai: set ts=4 tw=120 sts=4 sw=4
