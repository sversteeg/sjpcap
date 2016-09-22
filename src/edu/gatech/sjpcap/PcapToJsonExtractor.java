package edu.gatech.sjpcap;

/**
 * Extracts JSON pairs from Wireshark PCAP files.
 @author miao, scv
 */

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

import com.cedarsoftware.util.io.JsonWriter;

import edu.gatech.sjpcap.Packet;
import edu.gatech.sjpcap.PcapParser;
import edu.gatech.sjpcap.TCPPacket;

public class PcapToJsonExtractor {

	private static void addRqResPair(List<String[]> trace_seq, String request, List<String> responses)
	{
		if (request != null)
		{
	        StringBuffer mergedRsps = new StringBuffer();
	        if (responses != null)
	        {
		        for (String rp: responses)
		            mergedRsps.append(rp);
	        }
	        String[] rq_rsp = new String[2];
	        rq_rsp[0] = request;
	        rq_rsp[1] = mergedRsps.toString();
			trace_seq.add(rq_rsp);
		}
	}
	
	private static void addRqRes(List<String[]> trace_seq, String request, List<String> responses, boolean domerge)
	{
		if (domerge)
			addRqResPair(trace_seq, request, responses);
		else
		{
	        String[] rq_rsp = new String[1 + responses.size()];
	        rq_rsp[0] = request;
	        for (int i = 0; i < responses.size(); i++)
	        	rq_rsp[1+i] = responses.get(i);
			trace_seq.add(rq_rsp);
		}
	}

	private static String copyByteArray(byte[] data) {
		char[] dest;
		dest = new char[data.length];
		for (int i = 0; i < data.length; i++)
			dest[i] = (char)data[i];
		return new String(dest);
	}

	// (Request|Response) = byte[]
	// List<byte[]> = [Request, Response 1, Response 2, ..., Response N]
	// List<List<byte[]>> = [[Request 1, Response 1 1, Response, 1 2, ...], [Request 2, Response 2 1, Response 2 2, ...]]
	private static List<String[]> doDataExtraction(InetAddress svc, PcapParser pcap_parser, boolean merge) {
		List<String[]> trace_seq = new ArrayList<String[]>();

		String request = null;
		List<String> responses = null;

		// for every packet
		for (Packet packet = pcap_parser.getPacket(); packet != Packet.EOF; packet = pcap_parser
				.getPacket()) {
			if (packet instanceof TCPPacket) {
				// cast as TCPPacket
				TCPPacket tcp_packet = (TCPPacket) packet;

				if (tcp_packet.data.length > 0) {// packets with data 
					
					byte[] data = tcp_packet.data;
					
					if (tcp_packet.dst_ip.equals(svc)) { // request

						// handle end of previous request, response pair
						if (request != null)
							addRqRes(trace_seq, request, responses, merge);

						// new respose sequence for this request.
						responses = new ArrayList<String>();

						// copy request data
						request = copyByteArray(data);

					} 
					else 
					{ // a response

						// copy response data
						String response = copyByteArray(data);
						// add response data to the response sequence of the
						// current request
                        if (responses != null)
    						responses.add(response);
					}
				}
			}
		}
		// add final pair
		if (request != null)
			addRqRes(trace_seq, request, responses, merge);
		return trace_seq;
	}

	public static List<String[]> extractBinaryData(InetAddress sut, String pcap_file_path, boolean merge) 
	{

		PcapParser pcap_parser = new PcapParser();
		pcap_parser.openFile(pcap_file_path);

		List<String[]> trace_seq = doDataExtraction(sut, pcap_parser, merge);

		pcap_parser.closeFile();

		return trace_seq;
	}

	/**
	 * Usage: PcapToJsonExtractor pcapfile outfile svc_ip svc_port
	 * @param args
	 * @throws IOException
	 */
	public static void main(String[] args) throws IOException {

//		Object trace_seq = extractBinaryData(new InetSocketAddress(
//				"74.53.140.153", 64583).getAddress(),
//				"data/smtp.pcap");
        String pcapfile = "data/cars-app.pcap";//"data/traces/car-app/cars-app.pcap" ;//
        String outfname = "data/cars-app.gson";//"data/traces/car-app/cars-app.json";//
        String svc_ip = "::1";//"136.186.6.220";////
        boolean merge = true;
        int svc_port = 3434;//19389;//
        /////////
        if (args.length == 5)
        {
        	pcapfile = args[0]; 
        	outfname = args[1];
            svc_ip = args[2];
            svc_port = Integer.parseInt(args[3]);
            merge = Boolean.valueOf(args[4]);
        }
/*<<<<<<< HEAD   
        InetAddress sut_addr = new InetSocketAddress(sut_ip, sut_port).getAddress();
		List<String[]> trace_seq = extractBinaryData(sut_addr, pcapfile, merge);
        ILibIO2.outputJsonPairs(outfname, trace_seq);
=======*/
        InetAddress svc_addr = new InetSocketAddress(svc_ip, svc_port).getAddress();
		List<String[]> trace_seq = extractBinaryData(svc_addr, pcapfile, merge);
		System.out.println(trace_seq.toString());
        //ILibIO.outputJsonPairs(outfname, trace_seq);
        FileOutputStream fos = new FileOutputStream(outfname);
        JsonWriter jw = new JsonWriter(fos);
        jw.write(trace_seq);
        jw.close();
        fos.close();
//>>>>>>> 6bcc88bf65d3b2faec0c797bb629d67f5a06c3de
	}
}
