# PowerShell Collector

Collector.ps1 collects the following artifacts when run on Windows OS
- Collects event logs
- LNK/Jump list files
- Prefetch Files
- Registry hives

After collection it will create a Collector_<timestamp>.zip file in C:\. 

This is an alpha version that will be improved upon. Just upload to target computer run the collector.ps1 file and download created ZIP archive. Then cleanup by removing collector.ps1 and created ZIP archive from target computer.
