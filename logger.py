# logger.py

from pathlib import Path 
import subprocess

#for the logger 
from datetime import datetime

#for system interactiom
import os 
import sys 

def log_output(logfile: Path, title: str, content: str): 
    timestamp = datetime.now().strftime("%F %T")
    with open(logfile, "a") as f: 
        f.write(f"\n[{timestamp}] {title}\n")
        f.write(content + "\n")


