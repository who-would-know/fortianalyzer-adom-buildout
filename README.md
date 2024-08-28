FortiAnalyzer ADOM Buildout

This script automates the process of building out FortiAnalyzer ADOM to match FortiManager ADOM/VDOM structure.

Description  
The script automates the process of building out FortiAnalyzer ADOM by:

    Logging into FortiManager (Read-Only API User required)
    Identifying ADOMs associated with specific FortiGate devices
    Logging into FortiAnalyzer (Read-Write API User required)
    Create ADOMs and moving VDOM into them based on same structure found in your FortiManager

Usage

    Option 1) Python Windows EXE file.
            Download EXE Program under /dist folder (Click on *.exe then click on View Raw Link to DL)
            Double click EXE file follow instructions

    Option 2) Run locally via python or create EXE via pyinstaller
            Clone the repository to your local machine (Windows if creating Windows EXE)
            pip install pyinstaller
            See 'Build python to exe HOWTO.txt' file for pyinstaller command
            run EXE file under created /dist

Requirements

    Python 3.10
    FortiManager API access with Read-only API user account
    FortiGate Device Name displayed in FortiManager
    FortiAnalyzer API access with Read-Write API User account
