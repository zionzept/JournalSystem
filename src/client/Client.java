package client;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.security.cert.X509Certificate;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

import data.Hasher;
import data.Journal;

import java.security.KeyStore;
import java.security.cert.*;
import java.util.LinkedList;
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
	private static final String certFolderPath = "Certificates" + File.separator + "Client" + File.separator;
	private static final String TRUSTSTORE_SHA256 = "e6438b093f45db2de16398a8653cd947e96cce0db8e983573a9d85592e8101c3";

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
		
		if (!Hasher.hashFile(certFolderPath + "clienttruststore").equals(TRUSTSTORE_SHA256)) {
			System.out.println("[WARNING] Truststore is corrupt or has been tampered with!");
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
				char[] trustStorePassword = "password".toCharArray();
				char[] keyStorePassword = passPrompt();
				KeyStore ks = KeyStore.getInstance("JKS");
				KeyStore ts = KeyStore.getInstance("JKS");
				KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
				TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
				SSLContext ctx = SSLContext.getInstance("TLS");
				ks.load(new FileInputStream(certFolderPath + keystore), keyStorePassword); // keystore
																	// password
																	// (storepass)
				ts.load(new FileInputStream(certFolderPath + "clienttruststore"), trustStorePassword); // truststore
																			// password
																			// (storepass);
				kmf.init(ks, keyStorePassword); // user password (keypass)
				tmf.init(ts); // keystore can be used as truststore here
				ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
				factory = ctx.getSocketFactory();
			} catch (Exception e) {
				throw new IOException(e.getMessage());
			}
			System.out.println(host + " " + port);
			SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
			System.out.println("\nsocket before handshake:\n" + socket + "\n");

			/*
			 * send http request
			 *
			 * See SSLSocketClient.java for more information about why there is
			 * a forced handshake here when using PrintWriters.
			 */
			socket.startHandshake();

			SSLSession session = socket.getSession();
			X509Certificate cert = (X509Certificate) session.getPeerCertificateChain()[0];
			String subject = cert.getSubjectDN().getName();
			String issuer = cert.getIssuerDN().getName();
			BigInteger serialNo = cert.getSerialNumber();
			System.out.println(
					"certificate name (subject DN field) on certificate received from server:\n" + subject + "\n");
			System.out.println("issuer name:\n" + issuer + "\n");
			System.out.println("serial number:\n" + serialNo.toString());
			System.out.println("socket after handshake:\n" + socket + "\n");
			System.out.println("secure connection established\n\n");

			ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
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
			in.close();
			out.flush();
			out.close();
			socket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static void read(String patient, ObjectOutputStream out) {
		LinkedList<Journal> journals = null;
		Object o = null;
		try {
			out.writeObject("read");
			out.writeObject(patient);
			o = in.readObject();
		} catch (IOException | ClassNotFoundException e1) {
			e1.printStackTrace();
		}

		if (o != null && o.getClass().equals(LinkedList.class)) {
			journals = (LinkedList<Journal>) o;
			displayJournal(journals, false);
		} else {
			System.out.println("Access denied");
		}
	}

	private static void write(String patient, ObjectOutputStream out) {
		LinkedList<Journal> journals = null;
		Object o = null;
		try {
			out.writeObject("write");
			out.writeObject(patient);
			out.reset();
			o = in.readObject();
		} catch (IOException | ClassNotFoundException e1) {
			e1.printStackTrace();
		}

		if (o != null && o.getClass().equals(LinkedList.class)) {
			journals = (LinkedList<Journal>) o;
			LinkedList<Journal> sendJournals = new LinkedList<Journal>();
			for(Journal j : journals){
				sendJournals.add(j);
			}
			displayJournal(sendJournals, true);

			
			try {
				out.writeObject(sendJournals);
				out.reset();
				String answer = (String)in.readObject();
				System.out.println(answer);
			} catch (IOException | ClassNotFoundException e) {
				e.printStackTrace();
			}
		} else {
			System.out.println("Did not recieve a journal from server");
		}
	}

	private static void add(String patient, ObjectOutputStream out) {
		Journal journal = new Journal("<patient>", "<doctor>", "<nurse>", "<division>", "<data>");
		LinkedList<Journal> dispJournal = new LinkedList<Journal>();
		dispJournal.add(journal);
		displayJournal(dispJournal, true);
		try {
			out.writeObject("add");
			out.writeObject(journal);
			out.reset();
			String answer = (String) in.readObject();
			System.out.println(answer);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
	}

	private static void delete(String patient, ObjectOutputStream out) {
		try {
			out.writeObject("delete");
			out.writeObject(patient);
			String answer = (String)in.readObject();
			System.out.println(answer);
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}
	}

	private static void displayJournal(LinkedList<Journal> journals, boolean editable) {
		for(Journal journal : journals) {
			GUICreatorThread guict = new GUICreatorThread(journal, editable);
			guict.start();
			try {
				guict.join();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}
	
	private static char[] passPrompt(){
		JPanel panel = new JPanel();
		JLabel label = new JLabel("Enter a password:");
		JPasswordField pass = new JPasswordField(10);
		panel.add(label);
		panel.add(pass);
		String[] options = new String[]{"OK"};
		int option = JOptionPane.showOptionDialog(null, panel, "The title",
		                         JOptionPane.NO_OPTION, JOptionPane.PLAIN_MESSAGE,
		                         null, options, pass);
		if(option != JOptionPane.CLOSED_OPTION) // pressing OK button
		{
		    char[] password = pass.getPassword();
		    return password;
		}else{
			return new char[0];
		}
	}
}