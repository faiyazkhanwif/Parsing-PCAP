//The code is written in C# inside a .NET 6.0 Console Application.
//Library used to process PCAP file - SharpPcap: https://github.com/dotpcap/sharppcap
//Library used to manage packets - Packet.NET: https://github.com/dotpcap/packetnet 

using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;


string pcapFile = "E:\\CodingFiles\\SaskExercise\\ParsingPCAP\\ParsingPCAP\\exercise.pcap";

try
{
    if (File.Exists(pcapFile))
    {
        // Parse the PCAP file and get the distribution of the destination port numbers with port counts (Task 1 &  Task2)
        Dictionary<int, int> portCounts = ParsePcapFile(pcapFile);

        // Output the frequency of ports sorted by the port numbers (Task 3)
        OutputPortFrequency(portCounts);
    }
    else
    {
        Console.WriteLine("The file does not exist.");
    } 
}
catch (Exception ex)
{

    Console.WriteLine(ex.Message);
}

// Function to parse the PCAP file and return the port counts
static Dictionary<int, int> ParsePcapFile(string pcapFile)
{
    Dictionary<int, int> portCounts = new Dictionary<int, int>();

    // Open the pcap file
    using (CaptureFileReaderDevice captureFileReader = new CaptureFileReaderDevice(pcapFile))
    {
        captureFileReader.OnPacketArrival += (sender, e) =>
        {
            // Parse the packet
            var packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);

            if (packet is EthernetPacket ethernetPacket)
            {
                if (ethernetPacket.PayloadPacket is IPPacket ipPacket)
                {
                    if (ipPacket.PayloadPacket is TransportPacket transportPacket)
                    {
                        int destinationPort = transportPacket.DestinationPort;
                        if (portCounts.ContainsKey(destinationPort))
                        {
                            portCounts[destinationPort]++;
                        }
                        else
                        {
                            portCounts[destinationPort] = 1;
                        }
                    }
                }
            }
        };

        // Start capturing packets
        captureFileReader.Open();
        captureFileReader.Capture();
        captureFileReader.Close();
    }

    return portCounts;
}


// Function to output the frequency of ports in sorted order
static void OutputPortFrequency(Dictionary<int, int> portCounts)
{
    var sortedPortCounts = portCounts.OrderBy(pair => pair.Key);

    foreach (var kvp in sortedPortCounts)
    {
        Console.WriteLine($"Port {kvp.Key}: {kvp.Value} packets");
    }
}