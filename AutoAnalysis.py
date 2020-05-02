import pefile

def Analysis(dir):
    pe = pefile.PE(dir)
    networkFlag = False

    with open('results.txt', 'w') as f:
        f.truncate(0)
        try:
            print("SECTIONS:")
            for section in pe.sections:
                print(section.Name, hex(section.VirtualAddress),
                      hex(section.Misc_VirtualSize), section.SizeOfRawData)
                pe.parse_data_directories()

            try:
                print("IMPORTS:")
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    print(entry.dll)

                    for imp in entry.imports:
                        print('\t', hex(imp.address), imp.name)
                        if (check_str(imp.name, "Http") or check_str(imp.name, "Url")
                                or check_str(imp.name, "Internet") or check_str(imp.name, "Query")
                                or check_str(imp.name, "Peer") or check_str(imp.name, "Connect")
                                or check_str(imp.name, "IP") or check_str(imp.name, "Socket")):
                            networkFlag = True

            except AttributeError:
                print("Unable to read dll or import symbols")
                f.write("%s\n" % str("Unable to read dll or import symbols"))

            try:
                print("EXPORTS:")
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    print(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal)

            except AttributeError:
                print("Unable to read export symbols")
                f.write("%s\n" % str("Unable to read export symbols"))

            try:
                print("ENTRY IDs:")
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    print(entry.id)
            except AttributeError:
                print("Unable to read resource entries")
                f.write("%s\n" % str("Unable to read resource entries"))

        except AttributeError:
            print("Unable to read sections")
            f.write("%s\n" % str("Unable to read sections"))
        if(networkFlag):
            print("networkFlag =", networkFlag)
            f.write("%s\n" % str("Likely network/host relationship found"))
            print("Finished writing results to file")
        else:
            print("networkFlag = ", networkFlag)
            f.write("%s\n" % str("No likely network/host relationship found"))
            print("Finished writing results to file")

def check_str(s, sub):
    if(str(s.lower()).find(sub.lower())) == -1:
        return False
    else:
        return True

directory=r"E:\PycharmProjects\untitled1\3.exe"
Analysis(directory)