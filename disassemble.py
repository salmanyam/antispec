# compute anti-spec of CGC sample programs with Angr
import numpy
import random
import os
import sys
import string

import inspect, re
import angr
import angr.analyses

def do_analysis(fbin):
    ap = angr.Project(fbin, load_options={'auto_load_libs': True})
    cfg = ap.analyses.CFGAccurate(keep_state=True, context_sensitivity_level=2)
    cfg.normalize()
    #peekcfg(cfg)
    cdg = ap.analyses.CDG (cfg)
    ddg = ap.analyses.DDG (cfg)
    ddg.pp()
    vfg = ap.analyses.VFG(cfg)
    for node in vfg.graph.nodes():
        print node
    #ddg = ap.analyses.VSA_DDG ( vfg )

    for node in cfg.graph.nodes():
        print node
        for stmt in (ap.factory.block(node.addr).capstone.insns):
            print stmt
        for i, stmt in enumerate(ap.factory.block(node.addr).vex.statements):
            print i, stmt

if __name__=="__main__":
    if len(sys.argv)<2:
        print >> sys.stderr, "missing the program to analyze..."
        sys.exit(1)

    print >> sys.stdout, "now analyzing %s with angr facilities..." % (sys.argv[1])
    do_analysis(sys.argv[1])

    sys.exit(0)

# hcai: set ts=4 tw=120 sts=4 sw=4
