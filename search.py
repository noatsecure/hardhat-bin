#!/usr/bin/env python
from pathlib import Path
from re import compile,search
from sys import argv

#################
### FUNCTIONS ###
#################
def args():
    try:
        directory = Path(argv[1]).resolve()
    except IndexError:
        print('ERROR: Argument 1: Directory that contains all of the sub-directories of SELinux polices to search.')
        exit(1)
    try:
        # Argument 2: Interface name or domain name to query
        query = argv[2]
    except IndexError:
        print('ERROR: Argument 2: Pass the interface or domain name query.')
        exit(2)
    return(directory, query)

def is_dir(directory):
    if Path(directory).is_dir(): return(True)
    print(f"ERROR: Directory does not exist: '{directory}'")
    exit(1)

class files:
    def __init__(self, directory):
        interfaces = self.path_glob(directory, '.if')
        support_files = self.path_glob(directory, '.spt')
        self.filenames = interfaces + support_files

    def __call__(self):
        return(self.filenames)

    def path_glob(self, directory, extension):
        filenames = Path(directory).glob(f"**/*{extension}")
        try:
            filenames = list(filenames)
        except TypeError:
            print(f"ERROR: No <filename>{extension} files found in any sub-directories within '{directory}'")
            exit(1)
        return(filenames)

def grep(query, interfaces):
    # Define the regular expression that will find the definition or interface for the $query
    query = compile(f"(define|interface)\(`{query}'")
    # Iterate through each file within the $interfaces list
    for filename in interfaces:
        # Obtain the current $filename and obtain its contents
        with open(filename, 'r') as f: contents = f.readlines()
        # Iterate through each line witin $contents. This is done via `range` so the line number that contains the $query can be obtained
        for i in range(len(contents)):
            # Define the current line, and remove extraneous whitespaces
            line = contents[i].strip()
            # Perform the search of $query in the current $line
            m = search(query, line.strip())
            try:
                # Attempt to obtain the match if it was found
                m = m.group()
            except AttributeError:
                # If the $query was not found in the current $line, then continue to the next line
                continue
            # If the $query was found, then return the file it was found in and the line number ($i)
            return(filename, i)
    return(False, False)

def show(filename, line):
    # Open $filename and obtain its full contents
    with open(filename, 'r') as f: contents = f.readlines()
    # Define the $contents as starting with the $line
    contents = contents[line:]
    # If the user's query is a definition AND the definition does _not_ end with a tick, then only show the definition line
    if (not contents[0].strip().endswith('`')):
        # Display the definition
        print(contents[0])
        # Return here since there's nothing left to do
        return
    # Iterate through each line within $contents
    for i in range(len(contents)):
        # Once the ending parenthesis is found, then break the loop
        if contents[i] == "')\n": break
    # Define the entire interface, including the ending parenthesis
    interface = contents[:(i + 1)]
    # Display the full interface to stdout
    print(''.join(interface))


############
### MAIN ###
############
def main(directory, query):
    # Ensure $directory is a valid directory
    is_dir(directory)
    # Obtain a list of all interface and support files within $directory (ends with '.if' and '.spt')
    filenames = files(directory)()
    # Obtain the filename of the file that contains the $query and the line number it was found on
    [filename, line] = grep(query, filenames)
    # Check if no matches were found
    if (filename is False) and (line is False):
        # Display an error message
        print(f"ERROR: Unable to find query: '{query}'")
        # Exit with an error
        exit(1)
    # Otherwise, display the full definition or interface to stdout
    show(filename, line)
    
#############
### START ###
#############
if __name__ == '__main__':
    [directory, query] = args()
    main(directory, query)
