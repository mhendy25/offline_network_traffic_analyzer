## How to use SniffSift

## Downloading

Run `git clone https://github.com/mhendy25/offline_network_traffic_analyzer.git` to download the project to your desired destination

In the downloaded files, there will be a few important files. One is the `readme.md` file that will give a detailed description of our project.

Our project has commands like `ls`, `pwd`, and `cd` to allow users to navigate through their file system.


## Running the program in the command line
1. Go to the downloaded project location in the terminal.
2. To run the program use the following command `./cli_tool [.txt file]`. This will read the hex dump and print out the contents.
3. Alternatively, you can just run `./cli_tool` which will open the program where you can then navigate through your directories to find the desired file.

## Running the executable (MacOS ONLY)
1. You can run the executable file called `cli_tool` by double-clicking the executable. This will open in your root directory where you can use commands like `cd` or `pwd` to help navigate to your desired location.

## Running the program with python
1. Open a terminal window and navigate to the location of the downloaded files.
2. Ensure you have python installed and then install the following
Set up brew

Get rid of old wireshark. Delete app and run brew uninstall --force wireshark to be safe
Install wireshark by running brew install wireshark and brew install --cask wireshark
Check that it worked brew info --cask wireshark
Add an alias to your path directory alias wireshark='/Applications/Wireshark.app/Contents/MacOS/Wireshark'
Install Plotext by running pip install plotext or pip3 install plotext
Install Pyshark by running pip install pyshark==0.4.3 or pip3 install pyshark==0.4.3
Install Shutil by running pip install pytest-shutil


3. Type `python3 cli_tool.py` to open the application or `python3 cli_tool.py [.txt file]` to automatically load the file into the application. Note that if you want to automatically load the file into the application the file must be in the same folder as the application.
