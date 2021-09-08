/* 
 * Copyright 2010 Aalto University, ComNet
 * Released under GPLv3. See LICENSE.txt for details. 
 */
package report;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import core.DTNHost;
import core.Message;
import core.MessageListener;
import java.util.LinkedList;
import javax.xml.bind.DatatypeConverter;

/**
 * Report for generating different kind of total statistics about message
 * relaying performance. Messages that were created during the warm up period
 * are ignored.
 * <P><strong>Note:</strong> if some statistics could not be created (e.g.
 * overhead ratio if no messages were delivered) "NaN" is reported for
 * double values and zero for integer median(s).
 */
public class ReportSignature extends Report implements MessageListener {
	private List<Message> pesen;

	
	/**
	 * Constructor.
	 */
	public ReportSignature() {
		init();
	}

	@Override
	protected void init() {
		super.init();
                this.pesen = new ArrayList<Message>();
		
	}

	
	public void messageDeleted(Message m, DTNHost where, boolean dropped) {
		
	}

	
	public void messageTransferAborted(Message m, DTNHost from, DTNHost to) {
		
	}

	
	public void messageTransferred(Message m, DTNHost from, DTNHost to,
		          boolean finalTarget) {

        if (finalTarget) {
            pesen.add(m);
        }
	}


	public void newMessage(Message m) {
		
	}
	
	
	public void messageTransferStarted(Message m, DTNHost from, DTNHost to) {
		
	}
	

	@Override
	public void done() {
            List<byte[]> signatures = new LinkedList<byte[]>();
            String cetak = "";
		for(Message m : pesen){
                    cetak += m + " : " + m.getHops() + "\n";
                    signatures = (LinkedList<byte[]>) m.getProperty("signatures");
                    for(byte[] signature : signatures){
                        cetak += DatatypeConverter.printHexBinary(signature);
                        cetak += "\n";
                    }
                    cetak += "\n";
                }
		write(cetak);
		super.done();
	}
	
}
