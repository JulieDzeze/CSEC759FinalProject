# CSEC759FinalProject: VolMemLyzer Replication

This is my final project for the CSEC759 coursse with replicates the research done in this paper: VolMemLyzer: Volatile Memory Analyzer for Malware Classification using Feature Engineering

This relies on the implementation of VolMemLyzer, a Python-based Volatility feature extraction tool which extracts 32 features from sample memory dumps.

The feature it extracts include:
F0: Pslist - nproc - The total numer of processes
F1: Pslist - nppid - The total numer of parent processes

## What is required:

Volalitity executable 

## How to intall Volatility on Ubuntu:
##### Note: Since memory dumps have been provided, Cuckoo Sandbox is not needed. 
`sudo apt install volatility` 

## How to run VolMemLyzer:
##### Note: ensure that the Python script and memory dump are in the same directory.

`python3 VolMemLyzer.py -o output.csv -V volatility memorydump(be2).dmp`

## Features Extracted: 

