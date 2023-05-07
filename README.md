# CSEC759FinalProject: VolMemLyzer Replication

This is my final project for the CSEC759 coursse with replicates the research done in this paper: VolMemLyzer: Volatile Memory Analyzer for Malware Classification using Feature Engineering

This relies on the implementation of VolMemLyzer, a Volatility-dependent Python-based feature extraction tool which extractts 32 features from sample memory dumps.

# What is required:

Volalitity executable 

# How to intall Volatility on Ubuntu
sudo apt install volatility 

# How to run VolMemLyzer (ensure that the Python script and memory dump are in the same directory):

python3 VolMemLyzer.py -o output.csv -V volatility memorydump(be2).dmp

Features Extracted: 

