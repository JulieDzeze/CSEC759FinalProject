#!/usr/bin/env python3

import argparse
import csv
import functools
import json
import subprocess
import tempfile
import os

def write_csv_row(outfile, header, row_data, dumpname):
    writer = csv.DictWriter(outfile, fieldnames=header)
    if outfile.tell() == 0:
        row_data.update({'dump_name': os.path.basename(dumpname)})
        writer.writeheader()
    writer.writerow(row_data)

def get_pslist(jsondump):
    procs = rc2kv(json.load(jsondump))
    len_procs = len(procs)
    sum_thds, sum_wow64, sum_hnds = 0, 0, 0
    set_ppids = set()

    for p in procs:
        set_ppids.add(p['PPID'])
        sum_thds += p['Thds']
        if p.get('Wow64') == 'True':
            sum_wow64 += 1
        sum_hnds += p['Hnds']

    return {
        'pslist.nproc': len_procs,
        'pslist.nppid': len(set_ppids),
        'pslist.avg_threads': sum_thds / len_procs,
        'pslist.nprocs64bit': sum_wow64,
        'pslist.avg_handlers': sum_hnds / len_procs,
    }

def get_dlllist(jsondump):
   dlllist = rc2kv(json.load(jsondump))
   pid_set = set()
   dll_count = 0

   for l in dlllist:
       pid_set.add(l['Pid'])
       dll_count += 1

   num_procs = len(pid_set)
   avg_dlls_per_proc = dll_count / num_procs if num_procs > 0 else 0

   return {
       'dlllist.ndlls': dll_count,
       'dlllist.avg_dlls_per_proc': avg_dlls_per_proc,
   }


def get_handles(jsondump):
    handles = rc2kv(json.load(jsondump))
    num_handles = len(handles)
    num_procs = len(set(h['Pid'] for h in handles))
    avg_handles_per_proc = num_handles / num_procs if num_procs > 0 else 0
    return {
        'handles.nhandles': num_handles,
        'handles.avg_handles_per_proc': avg_handles_per_proc,
    }

def get_ldrmodules(jsondump):
    ldrmodules = rc2kv(json.load(jsondump))
    num_ldrmodules = len(ldrmodules)
    num_not_in_load, num_not_in_init, num_not_in_mem = 0, 0, 0
    for m in ldrmodules:
        if not m['InLoad']:
            num_not_in_load += 1
        if not m['InInit']:
            num_not_in_init += 1
        if not m['InMem']:
            num_not_in_mem += 1
    return {
        'ldrmodules.not_in_load': num_not_in_load,
        'ldrmodules.not_in_init': num_not_in_init,
        'ldrmodules.not_in_mem': num_not_in_mem,
    }

def get_malfind(jsondump):
    malfind = rc2kv(json.load(jsondump))
    num_injections = len(malfind)
    return {
        'malfind.ninjections': num_injections,
    }

def get_psxview(jsondump):
    psxview = rc2kv(json.load(jsondump))
    counts = {
        'pslist': 0,
        'psscan': 0,
        'thrdproc': 0,
        'pspcid': 0,
        'csrss': 0,
        'session': 0,
        'deskthrd': 0
    }
    for p in psxview:
        for key, value in counts.items():
            if p[key] == 'False':
                counts[key] += 1
    return {
        'psxview.not_in_pslist': counts['pslist'],
        'psxview.not_in_eprocess_pool': counts['psscan'],
        'psxview.not_in_ethread_pool': counts['thrdproc'],
        'psxview.not_in_pspcid_list': counts['pspcid'],
        'psxview.not_in_csrss_handles': counts['csrss'],
        'psxview.not_in_session': counts['session'],
        'psxview.not_in_deskthrd': counts['deskthrd']
    }

def get_modules(jsondump):
    modules = rc2kv(json.load(jsondump))
    len_modules = len(modules)
    return {
        'modules.nmodules': len_modules
    }

def get_svcscan(jsondump):
    svcscan = rc2kv(json.load(jsondump))
    len_svcscan = len(svcscan)
    counts = {'kernel_drivers': 0, 'fs_drivers': 0, 'process_services': 0, 'shared_process_services': 0, 
              'interactive_process_services': 0, 'active_services': 0}
    for s in svcscan:
        service_type = s['ServiceType']
        if service_type == 'SERVICE_KERNEL_DRIVER':
            counts['kernel_drivers'] += 1 
        elif service_type == 'SERVICE_FILE_SYSTEM_DRIVER':
            counts['fs_drivers'] += 1 
        elif service_type == 'SERVICE_WIN32_OWN_PROCESS':
            counts['process_services'] += 1
        elif service_type == 'SERVICE_WIN32_SHARE_PROCESS':
            counts['shared_process_services'] += 1
        elif service_type == 'SERVICE_INTERACTIVE_PROCESS':
            counts['interactive_process_services'] += 1
        if s['State'] == 'SERVICE_RUNNING':
            counts['active_services'] += 1
    return {
        'svcscan.nservices': len_svcscan,
        'svcscan.kernel_drivers': counts['kernel_drivers'],
        'svcscan.fs_drivers': counts['fs_drivers'],
        'svcscan.process_services': counts['process_services'],
        'svcscan.shared_process_services': counts['shared_process_services'],
        'svcscan.interactive_process_services': counts['interactive_process_services'],
        'svcscan.nactive': counts['active_services']
    }

def get_callbacks(jsondump):
    callbacks = rc2kv(json.load(jsondump))
    num_callbacks = len(callbacks)
    num_anonymous = 0
    num_generic = 0
    for c in callbacks:
        if c['Module'] == 'UNKNOWN':
            num_anonymous += 1
        elif c['Type'] == 'GenericKernelCallback':
            num_generic += 1
    return {
        'callbacks.n_callbacks': num_callbacks,
        'callbacks.n_anonymous': num_anonymous,
        'callbacks.n_generic': num_generic,
    }

VOL_MODULES = {
    'pslist': get_pslist,
    'dlllist': get_dlllist,
    'handles': get_handles,
    'ldrmodules': get_ldrmodules,
    'malfind': get_malfind,
    'psxview': get_psxview,
    'modules': get_modules,
    'svcscan': get_svcscan,
    'callbacks': get_callbacks,
}

def parse_args() -> argparse.Namespace:
    """Parse command line arguments.
    
    Returns:
        An `argparse.Namespace` object containing the parsed arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('memdump', help='Path to memory dump file.')
    parser.add_argument('-o', '--output', default=None, help='Path to output CSV file.')
    parser.add_argument('-V', '--volatility-exe', default='volatility', help='Name of the volatility executable.')
    #args = parser.parse_args()
    return parser,parser.parse_args()

def rc2kv(rc):
    keys = rc['columns']
    return [{k: v for k, v in zip(keys, r)} for r in rc['rows']]

def run_volatility(volatility_exe, memory_dump_path, volatility_module, output_path):
    # Make sure to update the profile name to one that Volatility will support for the memory dumps
    cmd = [
        volatility_exe,
        '-f', memory_dump_path,
        '--output=json',
        '--profile=Win7SP1x86',
        '--output-file', output_path,
        '--', volatility_module
    ]
    subprocess.run(cmd, check=True)

def get_memory_dump_features(memory_dump_path, output_path, volatility_exe):
    features = {}
    if output_path is None:
        output_path = '{}.csv'.format(memory_dump_path)
    print('=> Outputting to', output_path)

    with tempfile.TemporaryDirectory() as workdir:
        vol = functools.partial(run_volatility, volatility_exe, memory_dump_path)
        for module, extractor in VOL_MODULES.items():
            print('=> Executing Volatility module', repr(module))
            output_file_path = os.path.join(workdir, module)
            vol(module, output_file_path)
            with open(output_file_path, 'r') as output:
                features.update(extractor(output))

    with open(output_path, 'a') as f:
        output_csv(f, features.keys(), features, memory_dump_path)

    print('=> Feature extraction complete')

def process_memory_dumps(args):
    p, args = parse_args()
    if not os.path.isfile(args.memdump):
        p.error('Specified memory dump does not exist or is not a file.')

    # Directory must be updated to your location of the script and memory dump file
    for filename in os.listdir('/data/'):
        if filename.endswith('.dmp'):
            path_in_str = os.path.join('/data/', filename)
            print('=> Executing: ' + filename)
            get_memory_dump_features(path_in_str, args.output, args.volatility_exe)

if __name__ == '__main__':
    p, args = parse_args()
    process_memory_dumps(args)
