package server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.security.KeyStore;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.concurrent.Semaphore;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.security.cert.X509Certificate;

import data.Hasher;
import data.Journal;

public class Server implements Runnable {
	private static final File journalFile = new File("journals");
	private static HashMap<String, LinkedList<Journal>> journals = new HashMap<String, LinkedList<Journal>>();
	private static Semaphore connectSem;
	private static ServerSocket serverSocket = null;
	private static FileHandler fh;
	private static Logger logger;
    private static int numConnectedClients = 0;
    private static final int MAX_NBR_CONNECTIONS = 10;
    private static final String TRUSTSTORE_SHA256 = "9e86e1d7651a0215cd6417cca16f73298ffae70509bb819ed8f8163a6bf57532";
    private static String certFolderPath = "Certificates" + File.separator + "Server" + File.separator;

    public Server(ServerSocket ss) throws IOException {
        serverSocket = ss;
        connectSem = new Semaphore(MAX_NBR_CONNECTIONS);
        newListener();
    }
    
    public void run() {
        try {
        	connectSem.acquire();
            SSLSocket socket=(SSLSocket)serverSocket.accept();
            newListener();
            SSLSession session = socket.getSession();
            X509Certificate cert = (X509Certificate)session.getPeerCertificateChain()[0];
            String subject = cert.getSubjectDN().getName();
    	    numConnectedClients++;
            System.out.println(subject + " connected");
            System.out.println(numConnectedClients + " concurrent connection(s)\n");
            
            Subject suuu = new Subject(subject);
            
            ObjectOutputStream out = null;
            ObjectInputStream in = null;
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());
            
            communication(out, in, suuu);

			in.close();
			out.close();
			socket.close();
    	    numConnectedClients--;
    	    connectSem.release();
            System.out.println("client disconnected");
            System.out.println(numConnectedClients + " concurrent connection(s)\n");
		} catch (IOException e) {
            System.out.println("Client died: " + e.getMessage());
            e.printStackTrace();
            return;
        } catch (InterruptedException e) {
			e.printStackTrace();
		}
    }

    private void newListener() { (new Thread(this)).start(); } // calls run()

    public static void main(String args[]) throws ClassNotFoundException, IOException {
        log("startup");
        load();
        int port = 14922;
        if (args.length >= 1) {
            port = Integer.parseInt(args[0]);
        }
        
        if (!Hasher.hashFile(certFolderPath + "servertruststore").equals(TRUSTSTORE_SHA256)) {
        	System.out.println("[WARNING] Truststore is corrupt or has been tampered with!");
        	System.exit(-1);
        }
        
        String type = "TLS";
        try {
            ServerSocketFactory ssf = getServerSocketFactory(type);
            ServerSocket ss = ssf.createServerSocket(port);
            ((SSLServerSocket)ss).setNeedClientAuth(true); // enables client authentication
            new Server(ss);
        } catch (IOException e) {
            System.out.println("Unable to start Server: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static ServerSocketFactory getServerSocketFactory(String type) {
        if (type.equals("TLS")) {
            SSLServerSocketFactory ssf = null;
            try { // set up key manager to perform server authentication
                SSLContext ctx = SSLContext.getInstance("TLS");
                KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
                KeyStore ks = KeyStore.getInstance("JKS");
				KeyStore ts = KeyStore.getInstance("JKS");
                char[] password = "password".toCharArray();

                ks.load(new FileInputStream(certFolderPath + "serverkeystore"), password);  // keystore password (storepass)
                ts.load(new FileInputStream(certFolderPath + "servertruststore"), password); // truststore password (storepass)
                kmf.init(ks, password); // certificate password (keypass)
                tmf.init(ts);  // possible to use keystore as truststore here
                ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
                ssf = ctx.getServerSocketFactory();
                return ssf;
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            return ServerSocketFactory.getDefault();
        }
        return null;
    }
    
    private void communication(ObjectOutputStream out, ObjectInputStream in, Subject subject) throws IOException {
    	Object msg;
	    	msg = receive(in);
	    	if (!(msg instanceof String)) {
	    		send(out, "Command is not String");
	    	}else{
	    	switch ((String)msg) {
	    	case "read":
	    		read(out, in, msg, subject);
	    		break;
	    	case "write":
	    		write(out, in, msg, subject);
	    		break;
	    	case "add":
	    		add(out, in, msg, subject);
	    		break;
	    	case "delete":
	    		delete(out, in, msg, subject);
	    		break;
	    	default:
	    		send(out, "Did not recognise command");
	    		break;
	    	}
	    }
    }
    

   
    private void read(ObjectOutputStream out, ObjectInputStream in, Object msg, Subject subject){
    	msg = receive(in);
		if (!(msg instanceof String)) {
			log("[FAILED] Unknown input for Read");
			send(out, "Unknown input for Read");
			return;
    	}
		String patient = (String)msg;
		LinkedList<Journal> journals = Server.journals.get(patient);
		if (journals == null || journals.isEmpty()) {
			log("[FAILED] " + subject.getProperty("CN") + " tried to read from non-existing journal.");
			send(out, "Failed");
			return;
		}
		LinkedList<Journal> granted = new LinkedList<>();
		for (Journal journal : journals) {
			if (subject.getProperty("O").equals("patient") && subject.getProperty("CN").equals(journal.getPatient())
					|| subject.getProperty("O").equals("nurse") && subject.getProperty("OU").equals(journal.getDivision())
					|| subject.getProperty("O").equals("doctor") && subject.getProperty("OU").equals(journal.getDivision())
					|| subject.getProperty("O").equals("government")) {
				granted.add(journal);
			}
		}
		if (granted.isEmpty()) {
			log("[DENIED] " + subject.getProperty("CN") + " tried to read " + journals.toString());
			send(out, "Access denied");
			return;
		}
		
		send(out, granted);
		log("[GRANTED] " + subject.getProperty("CN") + " read " + granted.toString());
    }
    
	@SuppressWarnings("unchecked")
	private void write(ObjectOutputStream out, ObjectInputStream in, Object msg, Subject subject) throws IOException{
		msg = receive(in);
		if (!(msg instanceof String)) {
			log("[FAILED] Unknown input for Write");
			send(out, "Unknown input for Write");
			return;
    	}
		String patient = (String) msg;
		LinkedList<Journal> journals = Server.journals.get(patient);
		if (journals == null ||journals.isEmpty()) {
			log("[FAILED] " + subject.getProperty("CN") + " tried to write to non-existing journal.");
			send(out, "Failed");
			return;
		}
		LinkedList<Journal> granted = new LinkedList<>();
		LinkedList<Integer> indexList = new LinkedList<>();
		int counter = 0;
		for (Journal journal : journals) {
			if (subject.getProperty("O").equals("nurse") && subject.getProperty("CN").equals(journal.getNurse())
					|| subject.getProperty("O").equals("doctor") && subject.getProperty("CN").equals(journal.getDoctor())) {
				granted.add(journal);
				indexList.add(counter);
			}
			counter++;
		}
		if (granted.isEmpty()) {
			log("[DENIED] " + subject.getProperty("CN") + " tried to write to " + journals.toString());
			send(out, "Access denied");
			return;
		}
		send(out, granted);
		msg = receive(in);
		if (!(msg instanceof LinkedList<?>)) {
			log("[FAILED] Unknown input for Write");
			send(out, "Unknown input for Write");
			return;
		}
		
		counter = 0;
		for (Journal journal : (LinkedList<Journal>) msg) {
			journals.set(indexList.get(counter), journal);
			counter++;
		}
		save();
		log("[GRANTED] " + subject.getProperty("CN") + " wrote to " + journals.toString());
		send(out, "Access granted");
	}
	
	private void add(ObjectOutputStream out, ObjectInputStream in, Object msg, Subject subject) throws IOException{
		msg = receive(in);
		if (!(msg instanceof Journal)) {
			log("[FAILED] Unknown input for Add");
			send(out, "Unknown input for Add");
			return;
    	}
		Journal journal = (Journal)msg;
		if (!(subject.getProperty("O").equals("doctor") && subject.getProperty("CN").equals(journal.getDoctor()))) {
			log("[DENIED] " + subject.getProperty("CN") + " tried to add " + journal.toString());
			send(out, "Access denied");
			return;
		}
		LinkedList<Journal> jrnel = journals.get(journal.getPatient());
		if (jrnel == null) {
			jrnel = new LinkedList<Journal>();
			journals.put(journal.getPatient(), jrnel);
		}
		jrnel.add(journal);
		save();
		log("[GRANTED] " + subject.getProperty("CN") + " added " + journal.toString());
		send(out, "Access granted");
	}
	
	private void delete(ObjectOutputStream out, ObjectInputStream in, Object msg, Subject subject) throws IOException{
		msg = receive(in);
		if (!(msg instanceof String)) {
			log("[FAILED] Unknown input for Delete");
			send(out, "Unknown input for Delete");
			return;
    	}
		String patient = (String)msg;
		LinkedList<Journal> journals = Server.journals.get(patient);
		for (Journal journal : journals) {
			if (!(subject.getProperty("O").equals("government"))) {
				log("[DENIED] " + subject.getProperty("CN") + " tried to remove " + journal.toString());
				send(out, "Access denied");
				return;
			}
			if (journal == null) {	//cannot delete what isn't there
				log("[FAILED] " + subject.getProperty("CN") + " tried to remove non-existing journal.");
				send(out, "Failed");
				return;
			}
		}
		Server.journals.remove(patient);
		save();
		log("[GRANTED] " + subject.getProperty("CN") + " removed " + journals.toString());
		send(out, "Access granted");
	}
    
	private Object receive(ObjectInputStream in){
		Object msg = null;
		try {
			msg = in.readObject();
        } catch (ClassNotFoundException | IOException e) {
        	e.printStackTrace();
        }
        return msg;
    }
    
    private void send(ObjectOutputStream out, Object obj) {
    	try {
			out.writeObject(obj);
			out.reset();
			out.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
    }
    
    @SuppressWarnings("unchecked")
	private static void load() throws ClassNotFoundException, IOException {
    	if (journalFile.exists()) {
	    	ObjectInputStream in = new ObjectInputStream(new FileInputStream(journalFile));
	    	journals = (HashMap<String, LinkedList<Journal>>) in.readObject();
	    	in.close();
    	}
	}
	
	private static void save() throws IOException {
		ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(journalFile));
		out.writeObject(journals);
		out.close();
	}
    
    private static void log(String message) {
    	logger = Logger.getLogger( Server.class.getName() );
	    File file = new File("Logs");
	    if (!file.exists()) {
	    	System.out.println("nodir");
	    	file.mkdir();
	    }
	    String filepath = file + File.separator + "Server_";
        SimpleDateFormat format = new SimpleDateFormat("MM-dd");
        try {new FileHandler();   
            fh = new FileHandler(filepath + format.format(Calendar.getInstance().getTime()) + ".log", true);
        } catch (Exception e) {
            e.printStackTrace();
        }
        fh.setFormatter(new SimpleFormatter());
        logger.addHandler(fh);
        logger.info(message);
        fh.close();
    }
}
