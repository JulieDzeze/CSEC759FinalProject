# CSEC759FinalProject: VolMemLyzer Replication

This is my final project for the CSEC759 coursse with replicates the research done in this paper: VolMemLyzer: Volatile Memory Analyzer for Malware Classification using Feature Engineering

This relies on the implementation of VolMemLyzer, a Python-based Volatility feature extraction tool which extracts 30 features from sample memory dumps.

The feature it extracts include:
- F0: pslist - nproc - The total numer of processes
- F1: pslist - nppid - The total numer of parent processes
- F2: pslist - avg_threads - The average number of threads for the processes
- F3: pslist - nprocs64bit - The total numer of 64 bit processes
- F4: pslist - avg_handlers - The average number of handlers
- F5: dllist - ndlls - The total numer of loaded libraries of each process 
- F6: dllist - avg_dlls_per_proc - The average numer of loaded libraries of each process
- F7: handles - nhandles - The average number of handlers
- F8: handles - avg_handles - The average number of handlers
- F9: ldrmodules - not_in_load - The total numer of modules missing from the load list
- F10: ldrmodules - not_in_init - The total numer of modules missing from the init list
- F11: ldrmodules - not_in_mem - The total numer of modules missing from the memory list
- F12: malfind - ninjections - The total numer of hidden code injections 
- F13: psxview - not_in_pslist - The total numer of processes not found in pslist
- F14: psxview - not_in_eprocess_pool - The total numer of processes not found in psscan
- F15: psxview - not_in_ethread_pool - The total numer of processes not found in thrdproc
- F16: psxview - not_in_pspcid_list - The total numer of processes not found in pscpcid
- F17: psxview - not_in_csrss_handles - The total numer of processes not found in csrss
- F18: psxview - not_in_session - The total numer of processes not found in session
- F19: psxview - not_in_deskthrd - The total numer of processes not found in deskthrd
- F20: modules - nmodules - The total numer of modules
- F21: svcscan - nservices - The total numer of services
- F22: svcscan - kernel_drivers - The total numer of kernel drivers
- F23: svcscan - fs_drivers - The total numer of filesystem drivers
- F24: svcscan - process_services - The total numer of Windows 32 owned processes
- F25: svcscan - shared_process_services - The total numer of Windows 32 shared processes
- F26: svcscan - interactive_process_services - The total numer of interactive processes
- F27: svcscan - nactive - The total numer of modules
- F28: callbacks - ncallbacks - The total numer of callbacks
- F29: callbacks - nanonymous - The total numer of unknown processes
- F30: callbacks - ngeneric - The total numer of generic processes
 

## What is required:

Volalitity executable 

## How to intall Volatility on Ubuntu:
##### Note: Since memory dumps have been provided, Cuckoo Sandbox is not needed. 
`sudo apt install volatility` 

## How to run VolMemLyzer:
##### Note: ensure that the Python script and memory dump are in the same directory.

`python3 VolMemLyzer.py -o output.csv -V volatility memorydump(be2).dmp`


