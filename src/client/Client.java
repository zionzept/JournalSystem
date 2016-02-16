package client;
import java.net.*;
import java.io.*;
import javax.net.ssl.*;
import javax.security.cert.X509Certificate;

import data.Journal;

import java.security.KeyStore;
import java.security.cert.*;
import java.math.BigInteger;

/*
 * This example shows how to set up a key manager to perform client
 * authentication.
 *
 * This program assumes that the client is not inside a firewall.
 * The application can be modified to connect to a server outside
 * the firewall by following SSLSocketClientWithTunneling.java.
 */



public class Client {
	
	private static ObjectInputStream in;
	
    public static void main(String[] args) throws Exception {
        String host = null;
        int port = -1;
        String command = "";
        String commandArg = "";
        String keystore = "";
        for (int i = 0; i < args.length; i++) {
            System.out.println("args[" + i + "] = " + args[i]);
        }
        if (args.length < 5) {
            System.out.println("USAGE: java client host port");
            System.exit(-1);
        }
        try { /* get input parameters */
            host = args[0];
            port = Integer.parseInt(args[1]);
            command = args[2];
            commandArg = args[3];
            keystore = args[4];
        } catch (IllegalArgumentException e) {
            System.out.println("USAGE: java client host port command commandarg username");
            System.exit(-1);
        }

        try { /* set up a key manager for client authentication */
            SSLSocketFactory factory = null;
            try {
                char[] password = "password".toCharArray();
                KeyStore ks = KeyStore.getInstance("JKS");
                KeyStore ts = KeyStore.getInstance("JKS");
                KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
                SSLContext ctx = SSLContext.getInstance("TLS");
                ks.load(new FileInputStream(keystore), password);  // keystore password (storepass)
				ts.load(new FileInputStream("clienttruststore"), password); // truststore password (storepass);
				kmf.init(ks, password); // user password (keypass)
				tmf.init(ts); // keystore can be used as truststore here
				ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
                factory = ctx.getSocketFactory();
            } catch (Exception e) {
                throw new IOException(e.getMessage());
            }
            SSLSocket socket = (SSLSocket)factory.createSocket(host, port);
            System.out.println("\nsocket before handshake:\n" + socket + "\n");

            /*
             * send http request
             *
             * See SSLSocketClient.java for more information about why
             * there is a forced handshake here when using PrintWriters.
             */
            socket.startHandshake();

            SSLSession session = socket.getSession();
            X509Certificate cert = (X509Certificate)session.getPeerCertificateChain()[0];
            String subject = cert.getSubjectDN().getName();
	    String issuer = cert.getIssuerDN().getName();
	    BigInteger serialNo = cert.getSerialNumber();
            System.out.println("certificate name (subject DN field) on certificate received from server:\n" + subject + "\n");
	    System.out.println("issuer name:\n" + issuer+ "\n");
	    System.out.println("serial number:\n" + serialNo.toString());
            System.out.println("socket after handshake:\n" + socket + "\n");
            System.out.println("secure connection established\n\n");

            BufferedReader read = new BufferedReader(new InputStreamReader(System.in));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            in = new ObjectInputStream(socket.getInputStream());
            
            
            switch (command) {
            case "add":
            	add(commandArg, out);
            	break;
            case "delete":
            	delete(commandArg, out);
            	break;
            	
            case "read":
            	read(commandArg, out);
            	break;
            	
            case "write":
            	write(commandArg, out);
            	break;
            }
            	
            
//          String msg;
//			for (;;) {
//                System.out.print(">");
//                msg = read.readLine();
//                if (msg.equalsIgnoreCase("quit")) {
//				    break;
//				}
//                System.out.print("sending '" + msg + "' to server...");
//                out.println(msg);
//                out.flush();
//                System.out.println("done");
//
//                System.out.println("received '" + in.readLine() + "' from server\n");
//            }
            in.close();
			out.close();
			read.close();
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }             
    }
    private static void read(String patient, PrintWriter out){
		out.println("read " + patient);
		Journal journal = null;
		try {
			journal = (Journal)in.readObject();
		} catch (Exception e) {
			e.printStackTrace();
		}
		if(journal != null) {
			displayJournal(journal, false);
		} else {
			System.out.println("Did not recieve a journal from server");
		}
		
    }
    
    private static void write(String patient, PrintWriter out){
    	out.println("write " + patient);
    	Journal journal = null;
		try {
			journal = (Journal)in.readObject();
		} catch (Exception e) {
			e.printStackTrace();
		}
		if(journal != null) {
			displayJournal(journal, true);
	    	out.println(journal);
		} else {
			System.out.println("Did not recieve a journal from server");
		}
    }
    
    private static void add(String patient, PrintWriter out){
    	Journal journal = new Journal(patient, patient, patient, patient);
    	displayJournal(journal, true);
    	out.println("add " + patient);
    	out.println(journal);
    }
    
    private static void delete(String patient, PrintWriter out){
    	out.println("delete " + patient);
    }
    
    private static void displayJournal(Journal journal, boolean editable) {
    	GUICreatorThread guict = new GUICreatorThread(journal, editable);
    	guict.start();
    	try {
			guict.join();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
    }
    
}
