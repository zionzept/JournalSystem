package server;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.security.KeyStore;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.HashMap;
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

import data.Journal;

public class Server implements Runnable {
	static FileHandler fh;
	private static Logger logger;
    private ServerSocket serverSocket = null;
    private static int numConnectedClients = 0;
    HashMap<String, Journal> journals = new HashMap<String, Journal>();

    public Server(ServerSocket ss) throws IOException {
        serverSocket = ss;
        newListener();
    }
    
    public void run() {
        try {
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

            ObjectOutputStream out = null;
            ObjectInputStream in = null;
            out = (ObjectOutputStream)(socket.getOutputStream());
            in = (ObjectInputStream)(socket.getInputStream());
            
            communication(out, in);

			in.close();
			out.close();
			socket.close();
    	    numConnectedClients--;
            System.out.println("client disconnected");
            System.out.println(numConnectedClients + " concurrent connection(s)\n");
		} catch (IOException e) {
            System.out.println("Client died: " + e.getMessage());
            e.printStackTrace();
            return;
        }
    }

    private void newListener() { (new Thread(this)).start(); } // calls run()

    public static void main(String args[]) {
        setupLogger();
        int port = -1;
        if (args.length >= 1) {
            port = Integer.parseInt(args[0]);
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

                ks.load(new FileInputStream("serverkeystore"), password);  // keystore password (storepass)
                ts.load(new FileInputStream("servertruststore"), password); // truststore password (storepass)
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
    
    private void communication(ObjectOutputStream out, ObjectInputStream in) {
    	Object msg;
    	while (true) {
	    	msg = receive(in);
	    	if (!(msg instanceof String)) {
	    		send(out, "failed");
	    		continue;
	    	}
	    	switch ((String)msg) {
	    	case "read":	//Patient: Own, Nurse: Own and division, Doctor: Own and division, Government agency: all
	    		read(out, in, msg);
	    		break;
	    	case "write":	//Nurse: Own, Doctor: Own
	    		write(out, in, msg);
	    		break;
	    	case "add":		//Doctor only
	    		add(out, in, msg);
	    		break;
	    	case "delete":	//Government agency: all
	    		delete(out, in, msg);
	    		break;
	    	default:
	    		send(out, "failed");
	    		continue;
	    	}
    	}
    }
    

   
    private void read(ObjectOutputStream out, ObjectInputStream in, Object msg){
    	msg = receive(in);
		if (!(msg instanceof String)) {
			send(out, "failed");
			return;
    	}
		//TODO: check access rights
		Journal journal = journals.get(msg);
		if (journal == null) {
			send(out, "failed");
			return;
		}
		logger.info("Read " + journal.toString());
		send(out, journal);
    }
    
	private void write(ObjectOutputStream out, ObjectInputStream in, Object msg){
		msg = receive(in);
		if (!(msg instanceof String)) {
			send(out, "failed");
			return;
    	}
		//TODO: check access rights
		Journal journal = journals.get(msg);
		if (journal == null) {
			send(out, "failed");
			return;
		}
		send(out, journal);
		msg = receive(in);
		if (!(msg instanceof Journal)) {
			send(out, "failed");
			return;
		}
		journals.put(journal.getPatient(), journal);
		logger.info("Write " + journal.toString());
		send(out, "confirmed");
	}
	
	private void add(ObjectOutputStream out, ObjectInputStream in, Object msg){
		msg = receive(in);
		if (!(msg instanceof Journal)) {
			send(out, "failed");
			return;
    	}
		//TODO: check access rights 
		Journal journal = (Journal)msg;
		if (journals.get(journal.getPatient()) != null) {	//cannot overwrite with add
			send(out, "failed");
			return;
		}
		journals.put(journal.getPatient(), journal);
		logger.info("Added " + journal.toString());
		send(out, "access granted");
	}
	
	private void delete(ObjectOutputStream out, ObjectInputStream in, Object msg){
		msg = receive(in);
		if (!(msg instanceof String)) {
			send(out, "failed");
			return;
    	}
		//TODO: check access rights 
		Journal journal = journals.get(msg);
		if (journal == null) {	//cannot delete what isn't there
			send(out, "failed");
			return;
		}
		journals.remove(journal);
		logger.info("Removed " + journal.toString());
		send(out, "access granted");
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
			out.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
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
