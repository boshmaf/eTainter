
class TainitAnalysisResult(object):
    def __init__(self, state, defect_type, target_sink, tainted, sources, sload_sha3_bases, sstore_sha3_bases, sstore_slots, slot_live_access, slot_access_trace, storage_slot_type):
        self.state = state    
        self.defect_type=defect_type       
        self.target_sink = target_sink            
        self._tainted = tainted
        self.sources = sources
        self.sload_sha3_bases = sload_sha3_bases
        self.sstore_sha3_bases = sstore_sha3_bases
        self.sstore_slots = sstore_slots
        self.slot_live_access = slot_live_access
        self.slot_access_trace =slot_access_trace
        self.storage_slot_type = storage_slot_type
 
class TainitAnalysisBugDetails(object):
    def __init__(self,stdout, bug_addr, unbounded_loops, fun_call_restr,loops_with_calls, gas_griefing, hardcoded_gas, asserts, slot_live_access, temp_slots):     
        self.stdout = stdout
        self.bug_addr = bug_addr   
        self.unbounded_loops = unbounded_loops 
        self.fun_call_restr =fun_call_restr
        self.loops_with_calls = loops_with_calls
        self.gas_griefing = gas_griefing
        self.hardcoded_gas = hardcoded_gas
        self.asserts = asserts
        self.slot_live_access = slot_live_access
        self.temp_slots = temp_slots

    def print_bug_addresses(self, defect_name):
        result = ''
        for addresses in self.bug_addr[defect_name]:
            result += '->'.join(addresses) + ' '
        return result.strip()

def analyzed_sinks():
    global checked_sinks
    checked_sinks = []