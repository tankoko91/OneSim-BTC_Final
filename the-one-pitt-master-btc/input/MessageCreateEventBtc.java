/* 
 * Copyright 2010 Aalto University, ComNet
 * Released under GPLv3. See LICENSE.txt for details. 
 */
package input;

import btc.Wallet;
import core.DTNHost;
import core.Message;
import core.World;
import java.util.LinkedList;
import java.util.List;

/**
 * External event for creating a message.
 */
public class MessageCreateEventBtc extends MessageEvent {
	private int size;
	private int responseSize;
        private float price;
	
	/**
	 * Creates a message creation event with a optional response request
	 * @param from The creator of the message
	 * @param to Where the message is destined to
	 * @param id ID of the message
	 * @param size Size of the message
	 * @param responseSize Size of the requested response message or 0 if
	 * no response is requested
	 * @param time Time, when the message is created
	 */
	public MessageCreateEventBtc(int from, int to, String id, int size,
			int responseSize, double time, float price) {
		super(from,to, id, time);
		this.size = size;
		this.responseSize = responseSize;
                this.price = price;
	}

	
	/**
	 * Creates the message this event represents. 
	 */
	@Override
	public void processEvent(World world) {
		DTNHost to = world.getNodeByAddress(this.toAddr);
		DTNHost from = world.getNodeByAddress(this.fromAddr);			
		
		Message m = new Message(from, to, this.id, this.size);
		List<Wallet> wallets = new LinkedList<Wallet>();
                List<byte[]> signatures = new LinkedList<byte[]>();
                m.setResponseSize(this.responseSize);
                m.addProperty("rewards", this.price);
                m.addProperty("wallets", wallets);
                m.addProperty("signatures", signatures);
		from.createNewMessage(m);
	}
	
	@Override
	public String toString() {
		return super.toString() + " [" + fromAddr + "->" + toAddr + "] " +
		"size:" + size + " CREATE";
	}
}
