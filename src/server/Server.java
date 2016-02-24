package server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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

import java.util.concurrent.Semaphore;

import data.Hasher;
import data.Journal;

public class Server implements Runnable {
	private static final File journalFile = new File("journals");
	private static HashMap<String, LinkedList<Journal>> journals = new HashMap<>();
	private static Semaphore connectSem;
	private static ServerSocket serverSocket = null;
	private static FileHandler fh;
	private static Logger logger;
    private static int numConnectedClients = 0;
    private static final int MAX_NBR_CONNECTIONS = 10;
    private static final String TRUSTSTORE_SHA256 = "e6438b093f45db2de16398a8653cd947e96cce0db8e983573a9d85592e8101c3";
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
            String issuer = cert.getIssuerDN().getName();
            BigInteger serialNo = cert.getSerialNumber();
    	    numConnectedClients++;
            System.out.println("client connected");
            System.out.println("client name (cert subject DN field): " + subject);
            System.out.println("issuer name:\n" + issuer+ "\n");
            System.out.println("serial number:\n" + serialNo.toString());
            System.out.println(numConnectedClients + " concurrent connection(s)\n");
            
            Subject suuu = new Subject(subject);
            
            System.out.println(suuu.getProperty("CN"));

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
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }

    private void newListener() { (new Thread(this)).start(); } // calls run()

    public static void main(String args[]) throws ClassNotFoundException, IOException {
        setupLogger();
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
	    		send(out, "failed");
	    	}else{
	    	switch ((String)msg) {
	    	case "read":	//Patient: Own, Nurse: Own and division, Doctor: Own and division, Government agency: all
	    		read(out, in, msg, subject);
	    		break;
	    	case "write":	//Nurse: Own, Doctor: Own
	    		write(out, in, msg, subject);
	    		break;
	    	case "add":		//Doctor only
	    		add(out, in, msg, subject);
	    		break;
	    	case "delete":	//Government agency: all
	    		delete(out, in, msg, subject);
	    		break;
	    	default:
	    		send(out, "failed");
	    		break;
	    	}
	    }
    }
    

   
    private void read(ObjectOutputStream out, ObjectInputStream in, Object msg, Subject subject){
    	msg = receive(in);
		if (!(msg instanceof String)) {
			logger.info("[FAILED] Unknown input for Read");
			send(out, "failed");
			return;
    	}
		LinkedList<Journal> journals = Server.journals.get(msg);
		if (journals.isEmpty()) {
			logger.info("[FAILED] " + subject.getProperty("CN") + " tried to read from non-existing journal.");
			send(out, "failed");
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
			logger.info("[DENIED] " + subject.getProperty("CN") + " tried to read " + journals.toString());
			send(out, "access denied");
			return;
		}
		logger.info("[GRANTED] " + subject.getProperty("CN") + " read " + granted.toString());
		send(out, granted);
    }
    
	@SuppressWarnings("unchecked")
	private void write(ObjectOutputStream out, ObjectInputStream in, Object msg, Subject subject) throws IOException{
		msg = receive(in);
		if (!(msg instanceof String)) {
			logger.info("[FAILED] Unknown input for Write");
			send(out, "failed");
			return;
    	}
		LinkedList<Journal> journals = Server.journals.get(msg);
		if (journals.isEmpty()) {
			logger.info("[FAILED] " + subject.getProperty("CN") + " tried to write to non-existing journal.");
			send(out, "failed");
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
			logger.info("[DENIED] " + subject.getProperty("CN") + " tried to write to " + journals.toString());
			send(out, "access denied");
			return;
		}
		send(out, granted);
		msg = receive(in);
		if (!(msg instanceof LinkedList<?>)) {
			logger.info("[FAILED] Unknown input for write");
			send(out, "failed");
			return;
		}
		
		counter = 0;
		for (Journal journal : (LinkedList<Journal>) msg) {
			journals.set(indexList.get(counter), journal);
			counter++;
		}
		save();
		logger.info("[GRANTED] " + subject.getProperty("CN") + " wrote to " + journals.toString());
		send(out, "confirmed");
	}
	
	private void add(ObjectOutputStream out, ObjectInputStream in, Object msg, Subject subject) throws IOException{
		msg = receive(in);
		if (!(msg instanceof Journal)) {
			logger.info("[FAILED] Unknown input for Add");
			send(out, "failed");
			return;
    	}
		Journal journal = (Journal)msg;
		if (!(subject.getProperty("O").equals("doctor") && subject.getProperty("CN").equals(journal.getDoctor()))) {
			logger.info("[DENIED] " + subject.getProperty("CN") + " tried to add " + journal.toString());
			send(out, "access denied");
			return;
		}
		if (journals.get(journal.getPatient()) != null) {	//cannot overwrite with add
			logger.info("[FAILED] " + subject.getProperty("CN") + " tried to add " + journal.toString());
			send(out, "failed");
			return;
		}
		LinkedList<Journal> jrnel = journals.get(journal.getPatient());
		if (jrnel == null) {
			jrnel = new LinkedList<Journal>();
			journals.put(journal.getPatient(), jrnel);
		}
		jrnel.add(journal);
		save();
		logger.info("[GRANTED] " + subject.getProperty("CN") + " added " + journal.toString());
		send(out, "access granted");
	}
	
	private void delete(ObjectOutputStream out, ObjectInputStream in, Object msg, Subject subject) throws IOException{
		msg = receive(in);
		if (!(msg instanceof String)) {
			logger.info("[FAILED] Unknown input for Delete");
			send(out, "failed");
			return;
    	}
		LinkedList<Journal> journals = Server.journals.get(msg);
		for (Journal journal : journals) {
			if (!(subject.getProperty("O").equals("government"))) {
				logger.info("[DENIED] " + subject.getProperty("CN") + " tried to remove " + journal.toString());
				send(out, "access denied");
				return;
			}
			if (journal == null) {	//cannot delete what isn't there
				logger.info("[FAILED] " + subject.getProperty("CN") + " tried to remove non-existing journal.");
				send(out, "failed");
				return;
			}
		}
		Server.journals.remove(journals);
		save();
		logger.info("[GRANTED] " + subject.getProperty("CN") + " removed " + journals.toString());
		send(out, "access granted");
	}
    
	private Object receive(ObjectInputStream in){
		Object msg = null;
		try {
			msg = in.readUnshared();
        } catch (ClassNotFoundException | IOException e) {
        	e.printStackTrace();
        }
        return msg;
    }
    
    private void send(ObjectOutputStream out, Object obj) {
    	try {
    		out.reset();
			out.writeUnshared(obj);
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
    
    // Sets up logger to write to file. A new file will be made for each day.
    private static void setupLogger() {
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
	        logger.info("startup");
    }
}
