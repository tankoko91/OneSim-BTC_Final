package routing;

import btc.*;
import btc.Incentive;
import btc.Wallet;
import java.util.*;

import core.*;
import org.bouncycastle.asn1.esf.OtherHash;
import static routing.MessageRouter.DENIED_DELIVERED;
import static routing.MessageRouter.DENIED_OLD;
import static routing.MessageRouter.RCV_OK;
import static routing.MessageRouter.TRY_LATER_BUSY;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import org.antlr.tool.Grammar;

/**
 * This class overrides ActiveRouter in order to inject calls to a
 * DecisionEngine object where needed add extract as much code from the update()
 * method as possible.
 *
 * <strong>Forwarding Logic:</strong>
 *
 * A DecisionEngineRouter maintains a List of Tuple<Message, Connection> in
 * support of a call to ActiveRouter.tryMessagesForConnected() in
 * DecisionEngineRouter.update(). Since update() is called so frequently, we'd
 * like as little computation done in it as possible; hence the List that gets
 * updated when events happen. Four events cause the List to be updated: a new
 * message from this host, a new received message, a connection goes up, or a
 * connection goes down. On a new message (either from this host or received
 * from a peer), the collection of open connections is examined to see if the
 * message should be forwarded along them. If so, a new Tuple is added to the
 * List. When a connection goes up, the collection of messages is examined to
 * determine to determine if any should be sent to this new peer, adding a Tuple
 * to the list if so. When a connection goes down, any Tuple in the list
 * associated with that connection is removed from the List.
 *
 * <strong>Decision Engines</strong>
 *
 * Most (if not all) routing decision making is provided by a
 * RoutingDecisionEngine object. The DecisionEngine Interface defines methods
 * that enact computation and return decisions as follows:
 *
 * <ul>
 * <li>In createNewMessage(), a call to RoutingDecisionEngine.newMessage() is
 * made. A return value of true indicates that the message should be added to
 * the message store for routing. A false value indicates the message should be
 * discarded.
 * </li>
 * <li>changedConnection() indicates either a connection went up or down. The
 * appropriate connectionUp() or connectionDown() method is called on the
 * RoutingDecisionEngine object. Also, on connection up events, this first peer
 * to call changedConnection() will also call
 * RoutingDecisionEngine.doExchangeForNewConnection() so that the two decision
 * engine objects can simultaneously exchange information and update their
 * routing tables (without fear of this method being called a second time).
 * </li>
 * <li>Starting a Message transfer, a protocol first asks the neighboring peer
 * if it's okay to send the Message. If the peer indicates that the Message is
 * OLD or DELIVERED, call to RoutingDecisionEngine.shouldDeleteOldMessage() is
 * made to determine if the Message should be removed from the message store.
 * <em>Note: if tombstones are enabled or deleteDelivered is disabled, the
 * Message will be deleted and no call to this method will be made.</em>
 * </li>
 * <li>When a message is received (in messageTransferred), a call to
 * RoutingDecisionEngine.isFinalDest() to determine if the receiving (this) host
 * is an intended recipient of the Message. Next, a call to
 * RoutingDecisionEngine.shouldSaveReceivedMessage() is made to determine if the
 * new message should be stored and attempts to forward it on should be made. If
 * so, the set of Connections is examined for transfer opportunities as
 * described above.
 * </li>
 * <li> When a message is sent (in transferDone()), a call to
 * RoutingDecisionEngine.shouldDeleteSentMessage() is made to ask if the
 * departed Message now residing on a peer should be removed from the message
 * store.
 * </li>
 * </ul>
 *
 * <strong>Tombstones</strong>
 *
 * The ONE has the the deleteDelivered option that lets a host delete a message
 * if it comes in contact with the message's destination. More aggressive
 * approach lets a host remember that a given message was already delivered by
 * storing the message ID in a list of delivered messages (which is called the
 * tombstone list here). Whenever any node tries to send a message to a host
 * that has a tombstone for the message, the sending node receives the
 * tombstone.
 *
 * @author PJ Dillon, University of Pittsburgh
 */
public class DecisionEngineRouter extends ActiveRouter {

    public static final String PUBSUB_NS = "DecisionEngineRouter";
    public static final String ENGINE_SETTING = "decisionEngine";
    public static final String TOMBSTONE_SETTING = "tombstones";
    public static final String CONNECTION_STATE_SETTING = "";

    protected boolean tombstoning;
    protected RoutingDecisionEngine decider;
    protected List<Tuple<Message, Connection>> outgoingMessages;

    protected Set<String> tombstones;

    //trusttoken yang dibawa oleh tiap2 node
//    protected List<Message> trustToken;
    //Koko was here
    /*
     * Trusttoken dibuat map, karena menyimpan nama host
     * yang membuat trusttoken, Misbehave node bisa menyimpan
     * beberapa nama host pembuat sekaligus
     */
    protected Map<DTNHost, Set<byte[]>> trustToken;
    private final String RSA = "RSA";

    protected KeyPair keyPair;

    protected Map<DTNHost, PublicKey> publicKeys;
    protected Map<String, Transaction> deposits;

    protected Set<DTNHost> blacklist;

    /**
     * Used to save state machine when new connections are made. See comment in
     * changedConnection()
     */
    protected Map<Connection, Integer> conStates;

    public DecisionEngineRouter(Settings s) {
        super(s);

        Settings routeSettings = new Settings(PUBSUB_NS);

        outgoingMessages = new LinkedList<Tuple<Message, Connection>>();

        decider = (RoutingDecisionEngine) routeSettings.createIntializedObject(
                "routing." + routeSettings.getSetting(ENGINE_SETTING));

        if (routeSettings.contains(TOMBSTONE_SETTING)) {
            tombstoning = routeSettings.getBoolean(TOMBSTONE_SETTING);
        } else {
            tombstoning = false;
        }

        if (tombstoning) {
            tombstones = new HashSet<String>(10);
        }
        conStates = new HashMap<Connection, Integer>(4);
        trustToken = new HashMap<DTNHost, Set<byte[]>>();
        publicKeys = new HashMap<DTNHost, PublicKey>();
        deposits = new HashMap<String, Transaction>();
        blacklist = new HashSet<DTNHost>();
    }

    public DecisionEngineRouter(DecisionEngineRouter r) {
        super(r);
        outgoingMessages = new LinkedList<Tuple<Message, Connection>>();
        decider = r.decider.replicate();
        tombstoning = r.tombstoning;

        if (this.tombstoning) {
            tombstones = new HashSet<String>(10);
        }
        conStates = new HashMap<Connection, Integer>(4);

        //inisialisasi trusttoken
        trustToken = new HashMap<DTNHost, Set<byte[]>>();
        publicKeys = new HashMap<DTNHost, PublicKey>();
        deposits = new HashMap<String, Transaction>();
        blacklist = new HashSet<DTNHost>();
    }

//@Override
    public MessageRouter replicate() {
        return new DecisionEngineRouter(this);
    }

    @Override
    public boolean createNewMessage(Message m) {
        if (decider.newMessage(m)) {
// if(m.getId().equals("M14"))
// System.out.println("Host: " + getHost() + "Creating M14");
            float price = (float) m.getProperty("rewards");

            if (getHost().getWallet().getBalance() > price) {
                makeRoomForNewMessage(m.getSize());
                m.setTtl(this.msgTtl);
                addToMessages(m, true);

                //proses deposit
                Wallet fromWallet = getHost().getWallet();
                Wallet toWallet = m.getTo().getWallet();
                deposits.put(m.toString(), fromWallet.sendFunds(toWallet.publicKey, price));
                addSignatureToMessage(m, this.getHost());
                findConnectionsForNewMessage(m, getHost());
                return true;
            }
        }
        return false;
    }

// @Override
// public void connectionUp(Connection con)
// {
// DTNHost myHost = getHost();
// DTNHost otherNode = con.getOtherNode(myHost);
// DecisionEngineRouter otherRouter = (DecisionEngineRouter)otherNode.getRouter();
//
// decider.connectionUp(myHost, otherNode);
//
/*
* This part is a little confusing because there's a problem we have to
* avoid. When a connection comes up, we're assuming here that the two
* hosts who are now connected will exchange some routing information and
* update their own based on what the get from the peer. So host A updates
* its routing table with info from host B, and vice versa. In the real
* world, A would send its *old* routing information to B and compute new
* routing information later after receiving B's *old* routing information.
* In ONE, changedConnection() is called twice, once for each host A and
* B, in a serial fashion. If it's called for A first, A uses B's old info
* to compute its new info, but B later uses A's *new* info to compute its
* new info.... and this can lead to some nasty problems.
*
* To combat this, whichever host calls changedConnection() first calls
* doExchange() once. doExchange() interacts with the DecisionEngine to
* initiate the exchange of information, and it's assumed that this code
* will update the information on both peers simultaneously using the old
* information from both peers.
     */
// if(shouldNotifyPeer(con))
// {
// this.doExchange(con, otherNode);
// otherRouter.didExchange(con);
// }

    /*
* Once we have new information computed for the peer, we figure out if
* there are any messages that should get sent to this peer.
     */
// Collection<Message> msgs = getMessageCollection();
// for(Message m : msgs)
// {
// if(decider.shouldSendMessageToHost(m, otherNode))
// outgoingMessages.add(new Tuple<Message,Connection>(m, con));
// }
// }
// @Override
// public void connectionDown(Connection con)
// {
// DTNHost myHost = getHost();
// DTNHost otherNode = con.getOtherNode(myHost);
// //DecisionEngineRouter otherRouter = (DecisionEngineRouter)otherNode.getRouter();
//
// decider.connectionDown(myHost, otherNode);
//
// conStates.remove(con);
//
// /*
// * If we  were trying to send message to this peer, we need to remove them
// * from the outgoing List.
// */
// for(Iterator<Tuple<Message,Connection>> i = outgoingMessages.iterator();
// i.hasNext();)
// {
// Tuple<Message, Connection> t = i.next();
// if(t.getValue() == con)
// i.remove();
// }
// }
    @Override
    public void changedConnection(Connection con) {
        DTNHost myHost = getHost();
        DTNHost otherNode = con.getOtherNode(myHost);
        DecisionEngineRouter otherRouter = (DecisionEngineRouter) otherNode.getRouter();
        if (con.isUp()) {
            decider.connectionUp(myHost, otherNode);

            //jika observer bertemu dengan volunteer
            if (isObserver(getHost()) && (isVolunteer(otherNode) || isMisbehave(otherNode))) {
                Map<String, Transaction> otherDeposits = ((DecisionEngineRouter) otherNode.getRouter()).getDeposits();
                if (!otherDeposits.isEmpty()) {
                    for (Map.Entry<String, Transaction> entry : otherDeposits.entrySet()) {
                        Incentive.setDeposit(entry.getKey(), entry.getValue());
                    }
                    otherDeposits.clear();
                }

                //Koko was here
                /*
                 * Bertukar Trusttoken, jika Observer bertemu volunteer/misbehave
                 */
                Map<DTNHost, Set<byte[]>> otherTrustToken = otherRouter.getTrustToken();

                if (!otherTrustToken.isEmpty()) {
                    
                    if(isVolunteer(otherNode)){
                        for (Map.Entry<DTNHost, Set<byte[]>> entry : otherTrustToken.entrySet()) {
                            DTNHost key = entry.getKey();
                            Set<byte[]> value = entry.getValue();
                            
                            Incentive.setTrustToken(key, value, true, getHost(), publicKeys);
                        }
                    }
                    
                    Random rand = new Random();
                    int rand_int = 0;
                    
                    if(Incentive.isBlacklistActive()){
                        rand_int = rand.nextInt(4);
                    }
                    
                    boolean chance = true;
                    switch(rand_int){
                        case 0:
                            chance = true;
                            break;
                        case 1:
                            chance = false;
                            break;
                        case 2:
                            chance = false;
                            break;
                        case 3:
                            chance = false;
                            break;
                    }
                    
                    if(isMisbehave(otherNode)){
                    //meminta trusttoken volunteer yang ditemui, dan dicatat ke cloud
                        for (Map.Entry<DTNHost, Set<byte[]>> entry : otherTrustToken.entrySet()) {
                            DTNHost key = entry.getKey();
                            Set<byte[]> value = entry.getValue();
                            
                            Incentive.setTrustToken(key, value, chance, getHost(), publicKeys);
                        }
                    }
                    //hapus trust token yang dibawa volunteer
//                    otherRouter.getTrustToken().clear();
                }

                //jika ack di cloud tidak kosong
//                if (!Incentive.getAck().isEmpty()) {
//                    //membuat incentive
//                    Incentive.createIncentive();
//                }

                if (!Incentive.getVerificating().isEmpty()) {
                    Incentive.createIncentive();
                }
                
                if (!Incentive.getPending().isEmpty()) {
                    Incentive.prosesPayment();
                }

                
                //jika ada blacklist di cloud
                if (!Incentive.getBlacklist().isEmpty()) {
                    //memproses payment
                    this.blacklist = Incentive.getBlacklist();
                }

            }

            //jika volunteer bertemu shelter akan meminta deposit
            if ((isVolunteer(getHost()) || isMisbehave(getHost())) && isShelter(otherNode)) {
                Map<String, Transaction> otherDeposits = ((DecisionEngineRouter) otherNode.getRouter()).getDeposits();
                if (!otherDeposits.isEmpty()) {
//                    MessageRouter mroute = otherNode.getRouter();
//                    DecisionEngineRouter deRoute = (DecisionEngineRouter) mroute;
                    //volunteere meminta map shelter
                    for (Map.Entry<String, Transaction> entry : otherDeposits.entrySet()) {
                        this.deposits.put(entry.getKey(), entry.getValue());
                    }
                    //hapus map shelter
                    otherDeposits.clear();
                }
            }

            /*
             * This part is a little confusing because there's a problem we have to
             * avoid. When a connection comes up, we're assuming here that the two
             * hosts who are now connected will exchange some routing information and
             * update their own based on what the get from the peer. So host A updates
             * its routing table with info from host B, and vice versa. In the real
             * world, A would send its *old* routing information to B and compute new
             * routing information later after receiving B's *old* routing information.
             * In ONE, changedConnection() is called twice, once for each host A and
             * B, in a serial fashion. If it's called for A first, A uses B's old info
             * to compute its new info, but B later uses A's *new* info to compute its
             * new info.... and this can lead to some nasty problems.
             *
             * To combat this, whichever host calls changedConnection() first calls
             * doExchange() once. doExchange() interacts with the DecisionEngine to
             * initiate the exchange of information, and it's assumed that this code
             * will update the information on both peers simultaneously using the old
             * information from both peers.
             */
            if (shouldNotifyPeer(con)) {
                this.doExchange(con, otherNode);
                otherRouter.didExchange(con);
            }

            /*
             * Once we have new information computed for the peer, we figure out if
             * there are any messages that should get sent to this peer.
             */
            Collection<Message> msgs = getMessageCollection();
            for (Message m : msgs) {
                if (decider.shouldSendMessageToHost(m, otherNode, this.getHost())) {

                    outgoingMessages.add(new Tuple<Message, Connection>(m, con));

                    //mencatat trusttoken dirinya
                    addTrustToken(this.getHost(), m);

                    //menandatangani pesan dengan privateKey diri sendiri
                    if (isVolunteer(getHost()) || isMisbehave(getHost())) {
                        addSignatureToMessage(m, this.getHost());
//                        System.out.println("signature : " + this.getHost());
                    }

                    //Koko was here
                    Random rand = new Random();
                    DTNHost accomplice;

                    //jika misbehave maka akan mengambil data accomplice
                    if (isMisbehave(getHost())) {
                        /*
                         * Mengambil host secara acak dari list Misbehave
                         * Ulangi jika mendapat dirinya sendiri
                         */
                        List<DTNHost> accomplices = new ArrayList<DTNHost>(SimScenario.getInstance().getMisbehaves());
                        
                        accomplices.remove(getHost());
                        
                        for(DTNHost d : blacklist){
                            if(accomplices.contains(d)){
                                accomplices.remove(d);
                            }
                        }
                        
                        for(DTNHost h : m.getHops()){
                            if(accomplices.contains(h)){
                                accomplices.remove(h);
                            }
                        }
                        
                        
                        
                        if(!accomplices.isEmpty()){
                            
                            accomplice = accomplices.get(rand.nextInt(accomplices.size()));
                            
                            //mencatat trusttoken accomplice
                            addTrustToken(accomplice, m);

                            //menandatangani pesan dengan privateKey accomplice
                            m.addNodeOnPath(accomplice);
                            addSignatureMisToMessage(m, accomplice);
                        }
                        
//                        System.out.println("signature : " + accomplice);
                    }
                }
            }
        } else {
            decider.connectionDown(myHost, otherNode);

            conStates.remove(con);

            /*
             * If we  were trying to send message to this peer, we need to remove them
             * from the outgoing List.
             */
            for (Iterator<Tuple<Message, Connection>> i = outgoingMessages.iterator();
                    i.hasNext();) {
                Tuple<Message, Connection> t = i.next();
                if (t.getValue() == con) {
                    i.remove();
                }
            }
        }
    }

    public Map<String, Transaction> getDeposits() {
        return deposits;
    }

    protected void doExchange(Connection con, DTNHost otherHost) {
        conStates.put(con, 1);
        decider.doExchangeForNewConnection(con, otherHost);

        //jika belum memiliki keypair, maka generate keypair
        if (keyPair == null) {
            try {
                keyPair = generateRSAKkeyPair();
            } catch (Exception ex) {

            }
            publicKeys.put(getHost(), keyPair.getPublic());
        }

        MessageRouter otherRouter = otherHost.getRouter();
        DecisionEngineRouter otherDe = (DecisionEngineRouter) otherRouter;

        //membaca map public keys milik otherhost, kemudian simpan ke map public keys sendiri
        for (Map.Entry<DTNHost, PublicKey> entry : otherDe.getPublicKeys().entrySet()) {
            publicKeys.put(entry.getKey(), entry.getValue());
        }

        //jika blacklist orang yang ditemui ada isinya, maka dicopy ke blacklist diri sendiri
        for (DTNHost black : otherDe.getBlacklist()) {
            this.blacklist.add(black);
        }

//        System.out.println(getHost() + " : ");
//        for(Map.Entry<DTNHost, PublicKey> entry : otherDe.getPublicKeys().entrySet()){
//            System.out.println(entry.getKey() + ", " + entry.getValue());
//        }
    }

    /**
     * Called by a peer DecisionEngineRouter to indicated that it already
     * performed an information exchange for the given connection.
     *
     * @param con Connection on which the exchange was performed
     */
    protected void didExchange(Connection con) {
        conStates.put(con, 1);
    }

    @Override
    protected int startTransfer(Message m, Connection con) {
        int retVal;

        if (!con.isReadyForTransfer()) {
            return TRY_LATER_BUSY;
        }

        retVal = con.startTransfer(getHost(), m);

        if (retVal == RCV_OK) { // started transfer
            addToSendingConnections(con);
        } else if (tombstoning && retVal == DENIED_DELIVERED) {
            this.deleteMessage(m.getId(), false);
            tombstones.add(m.getId());
        } else if (deleteDelivered && (retVal == DENIED_OLD || retVal == DENIED_DELIVERED)
                && decider.shouldDeleteOldMessage(m, con.getOtherNode(getHost()))) {
            /* final recipient has already received the msg -> delete it */
// if(m.getId().equals("M14"))
// System.out.println("Host: " + getHost() + " told to delete M14");
            this.deleteMessage(m.getId(), false);
        }

        return retVal;
    }

    @Override
    public int receiveMessage(Message m, DTNHost from) {
        if (isDeliveredMessage(m) || (tombstoning && tombstones.contains(m.getId()))) {
            return DENIED_DELIVERED;
        }

        return super.receiveMessage(m, from);
    }

    @Override
    public Message messageTransferred(String id, DTNHost from) {
        Message incoming = removeFromIncomingBuffer(id, from);

        if (incoming == null) {
            throw new SimError("No message with ID " + id + " in the incoming "
                    + "buffer of " + getHost());
        }

        incoming.setReceiveTime(SimClock.getTime());

        Message outgoing = incoming;
        for (Application app : getApplications(incoming.getAppID())) {
// Note that the order of applications is significant
// since the next one gets the output of the previous.
            outgoing = app.handle(outgoing, getHost());
            if (outgoing == null) {
                break; // Some app wanted to drop the message
            }
        }

        Message aMessage = (outgoing == null) ? (incoming) : (outgoing);

        boolean isFinalRecipient = decider.isFinalDest(aMessage, getHost());
        boolean isFirstDelivery = isFinalRecipient
                && !isDeliveredMessage(aMessage);

        if (outgoing != null && decider.shouldSaveReceivedMessage(aMessage, getHost())) {
// not the final recipient and app doesn't want to drop the message
// -> put to buffer

            //jika node Misbehave maka akan menambah di message path dan signature kedua
            addToMessages(aMessage, false);

// Determine any other connections to which to forward a message
            findConnectionsForNewMessage(aMessage, from);
        }

        if (isFirstDelivery) {
//            Incentive.setAck(aMessage);
            Incentive.setAck(aMessage, this.publicKeys);
            this.deliveredMessages.put(id, aMessage);
        }
        this.deliveredMessages.put(id, aMessage);

        for (MessageListener ml : this.mListeners) {
            ml.messageTransferred(aMessage, from, getHost(),
                    isFirstDelivery);
        }

        return aMessage;
    }

    @Override
    protected void transferDone(Connection con) {
        Message transferred = this.getMessage(con.getMessage().getId());

        for (Iterator<Tuple<Message, Connection>> i = outgoingMessages.iterator();
                i.hasNext();) {
            Tuple<Message, Connection> t = i.next();
            if (t.getKey().getId().equals(transferred.getId())
                    && t.getValue().equals(con)) {
                i.remove();
                break;
            }
        }

        if (decider.shouldDeleteSentMessage(transferred, con.getOtherNode(getHost()))) {
// if(transferred.getId().equals("M14"))
// System.out.println("Host: " + getHost() + " deleting M14 after transfer");
            this.deleteMessage(transferred.getId(), false);

// for(Iterator<Tuple<Message, Connection>> i = outgoingMessages.iterator();
// i.hasNext();)
// {
// Tuple<Message, Connection> t = i.next();
// if(t.getKey().getId().equals(transferred.getId()))
// {
// i.remove();
// }
// }
        }
    }

    @Override
    public void deleteMessage(String id, boolean drop) {
        super.deleteMessage(id, drop);

        for (Iterator<Tuple<Message, Connection>> i = outgoingMessages.iterator();
                i.hasNext();) {
            Tuple<Message, Connection> t = i.next();
            if (t.getKey().getId().equals(id)) {
                i.remove();
            }
        }
    }

    @Override
    public void update() {
        super.update();

        decider.update(getHost());

        if (!canStartTransfer() || isTransferring()) {
            return; // nothing to transfer or is currently transferring
        }

        tryMessagesForConnected(outgoingMessages);

        for (Iterator<Tuple<Message, Connection>> i = outgoingMessages.iterator();
                i.hasNext();) {
            Tuple<Message, Connection> t = i.next();
            if (!this.hasMessage(t.getKey().getId())) {
                i.remove();
            }
        }
    }

    public RoutingDecisionEngine getDecisionEngine() {
        return this.decider;
    }

    protected boolean shouldNotifyPeer(Connection con) {
        Integer i = conStates.get(con);
        return i == null || i < 1;
    }

    protected void findConnectionsForNewMessage(Message m, DTNHost from) {
// for(Connection c : getHost())
        for (Connection c : getConnections()) {
            DTNHost other = c.getOtherNode(getHost());
            if (other != from && decider.shouldSendMessageToHost(m, other, this.getHost())) {
// if(m.getId().equals("M14"))
// System.out.println("Adding attempt for M14 from: " + getHost() + " to: " + other);
//                if(isVolunteer(other) || isMisbehave(other) || m.getTo()==other){
//                        if(!blacklist.contains(other) && !m.getHops().contains(other)){

                outgoingMessages.add(new Tuple<Message, Connection>(m, c));

                //mencatat trusttoken dirinya
                addTrustToken(this.getHost(), m);

                //menandatangani pesan dengan privateKey diri sendiri
                if (isVolunteer(getHost()) || isMisbehave(getHost())) {
                    addSignatureToMessage(m, this.getHost());

//                    System.out.println("signature : " + this.getHost());
                }

                //Koko was here
                Random rand = new Random();
                DTNHost accomplice;

                //jika misbehave maka akan mengambil data accomplice
                if (isMisbehave(getHost())) {
                    /*
                     * Mengambil host secara acak dari list Misbehave
                     * Ulangi jika mendapat dirinya sendiri
                     */
                    List<DTNHost> accomplices = new ArrayList<DTNHost>(SimScenario.getInstance().getMisbehaves());
                    
                    accomplices.remove(getHost());

                    for(DTNHost d : blacklist){
                        if(accomplices.contains(d)){
                            accomplices.remove(d);
                        }
                    }

                    for(DTNHost h : m.getHops()){
                        if(accomplices.contains(h)){
                            accomplices.remove(h);
                        }
                    }
                    
                    if(!accomplices.isEmpty()){
                        
                        accomplice = accomplices.get(rand.nextInt(accomplices.size()));
                        
                        //mencatat trusttoken accomplice
                        addTrustToken(accomplice, m);

                        //menandatangani pesan dengan privateKey accomplice
                        m.addNodeOnPath(accomplice);
                        addSignatureMisToMessage(m, accomplice);
                    }

//                        System.out.println("signature : " + accomplice);
                }
            }
        }
    }

    public void addTrustToken(DTNHost thisHost, Message m) {
        String me = thisHost.toString();
        //Koko was here
        if (isVolunteer(thisHost) || isMisbehave(thisHost)) {
//            trustToken.add(m);
            Set<byte[]> messages;
            /*
             * Jika menambah isi trusttoken, jika belum ada maka buat baru
             */
            if (trustToken.containsKey(thisHost)) {
                messages = trustToken.get(thisHost);
            } else {
                messages = new HashSet<byte[]>();
            }

            String trustoken = m.toString();
            DecisionEngineRouter thisDe = (DecisionEngineRouter) thisHost.getRouter();

            try {
                messages.add(do_RSAEncryption(trustoken, thisDe.getKeyPair().getPrivate()));
            } catch (Exception ex) {

            }
        
//            System.out.println(thisHost + ", " + messages);
            trustToken.put(thisHost, messages);

//            for (Map.Entry<DTNHost, List<Message>> entry : trustToken.entrySet()) {
//                DTNHost key = entry.getKey();
//                List<Message> value = entry.getValue();
//
//                System.out.println(key + " : " + value);
//            }
        }
    }

    private boolean isShelter(DTNHost otherHost) {
        if (otherHost.toString().startsWith("She")) {
            return true;
        }
        return false;
    }

    private boolean isVolunteer(DTNHost otherHost) {
        if (otherHost.toString().startsWith("Vol")) {
            return true;
        }
        return false;
    }

    private boolean isOpCen(DTNHost otherHost) {
        if (otherHost.toString().startsWith("OpC")) {
            return true;
        }
        return false;
    }

    private boolean isObserver(DTNHost otherHost) {
        if (otherHost.toString().startsWith("OBS")) {
            return true;
        }
        return false;
    }

    private boolean isMisbehave(DTNHost otherHost) {
        if (otherHost.toString().startsWith("Mis")) {
            return true;
        }
        return false;
    }

    private void addSignatureToMessage(Message m, DTNHost thisHost) {
        List<byte[]> signatures = (List<byte[]>) m.getProperty("signatures");

        String signature = m.toString() + getHost().toString();
        byte[] result = null;
        try {
            result = do_RSAEncryption(signature, keyPair.getPrivate());
            if (signatures.isEmpty()) {
                signatures.add(result);
            } else if (!result.equals(signatures.get(signatures.size() - 1))) {
                signatures.add(result);
            }

//            if(m.toString().equals("M6") || m.toString().equals("M1")){
//            System.out.println("Enkripsi " + m + " Mulai " + getHost());
//            System.out.println(do_RSADecryption(result, keyPair.getPublic()));
//                System.out.println("size : " + signatures.size());
//        }
        } catch (Exception ex) {

        }

//        m.updateProperty("signatures", signatures);
    }

    private void addSignatureMisToMessage(Message m, DTNHost host) {
        List<byte[]> signatures = new LinkedList<byte[]>();
        signatures = (List<byte[]>) m.getProperty("signatures");

        String signature = m.toString() + host.toString();
        DecisionEngineRouter otherDe = (DecisionEngineRouter) host.getRouter();

        try {
            signatures.add(do_RSAEncryption(signature, otherDe.getKeyPair().getPrivate()));
        } catch (Exception ex) {

        }

        m.updateProperty("signatures", signatures);
    }

//    public List<Message> getTrustToken() {
//        return trustToken;
//    }
    public Map<DTNHost, Set<byte[]>> getTrustToken() {
        return trustToken;
    }

    public Map<DTNHost, PublicKey> getPublicKeys() {
        return publicKeys;
    }

    public KeyPair getKeyPair() {
        return this.keyPair;
    }

    public KeyPair generateRSAKkeyPair()
            throws Exception {
        SecureRandom secureRandom
                = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);

        keyPairGenerator.initialize(
                2048, secureRandom);
        return keyPairGenerator
                .generateKeyPair();
    }

    public byte[] do_RSAEncryption(
            String plainText,
            PrivateKey privateKey)
            throws Exception {
        Cipher cipher
                = Cipher.getInstance(RSA);

        cipher.init(
                Cipher.ENCRYPT_MODE, privateKey);

        return cipher.doFinal(
                plainText.getBytes());
    }

    public String do_RSADecryption(byte[] cipherText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");

        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] result = cipher.doFinal(cipherText);

        return new String(result);
    }

    public Set<DTNHost> getBlacklist() {
        return blacklist;
    }

}
