/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package report;

import btc.Incentive;
import btc.Wallet;
import core.DTNHost;
import core.Message;
import core.Settings;
import core.SimScenario;
import core.Tuple;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import routing.MessageRouter;
import routing.RoutingDecisionEngine;

/**
 *
 * @author Rosemary
 */
public class ReportTarikIncentive extends Report {
    
    public ReportTarikIncentive() {
        Settings settings = getSettings();
        init();
    }
    
    @Override
    protected void init() {
        super.init();
    }
    
    @Override
    public void done() {
        String cetak = "";
                Map<Message, List<DTNHost>> ack = Incentive.getAck();
                for (Map.Entry<Message, List<DTNHost>> entry : ack.entrySet()) {
                    cetak += entry.getKey() + "(" + entry.getKey().getProperty("rewards") + ")" + ":\n";
                    
                    Iterator<DTNHost> iter = entry.getValue().iterator();
                    while(iter.hasNext()){
                        DTNHost tup = iter.next();
                        cetak += tup;
                    }
                    cetak += "\n";
                }

//                Map<DTNHost, List<Message>> trustToken = Incentive.getTrustToken();
//                for (Map.Entry<DTNHost, List<Message>> entry : trustToken.entrySet()) {
//                    cetak += entry.getKey() + ":\n";
//                    
//                    Iterator<Message> iter = entry.getValue().iterator();
//                    while(iter.hasNext()){
//                        Message m = iter.next();
//                        cetak += m + ", ";
//                    }
//                    cetak += "\n";
//                }
                
        write(cetak);
        super.done();
    }
    
}
