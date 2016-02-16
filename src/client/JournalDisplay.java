package client;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextArea;

import data.Journal;

public class JournalDisplay extends JFrame{
	private JTextArea dataTextArea;
	private JTextArea divisionTextArea;
	private JTextArea doctorTextArea;
	private JTextArea patientTextArea;
	private JTextArea nurseTextArea;
	private JButton confirmButton;
	private JButton cancelButton;
	private Journal journal;
	private boolean done;
	
	
	/**
	 * Creates and displays a window with editable or non editable fields containing journal information.
	 * 
	 * @param journal The journal to be displayed.
	 * @param editable True if text fields should be editable, false if not.
	 */
	public JournalDisplay(Journal journal, boolean editable) {
		this.journal = journal;
		done = false;
		
		dataTextArea = new JTextArea();
		divisionTextArea = new JTextArea();
		doctorTextArea = new JTextArea();
		patientTextArea = new JTextArea();
		nurseTextArea = new JTextArea();
		confirmButton = new JButton("Confirm");
		cancelButton = new JButton("Cancel");
		
		
		this.setLayout(new BorderLayout());
		JPanel nameGrid = new JPanel(new GridLayout(1, 4));
		JPanel buttonGrid = new JPanel(new GridLayout(1, 2));
		
		dataTextArea.setEditable(editable);
		divisionTextArea.setEditable(editable);
		doctorTextArea.setEditable(editable);
		patientTextArea.setEditable(editable);
		nurseTextArea.setEditable(editable);
		
		dataTextArea.setBorder(BorderFactory.createLineBorder(Color.black));
		divisionTextArea.setBorder(BorderFactory.createLineBorder(Color.black));
		doctorTextArea.setBorder(BorderFactory.createLineBorder(Color.black));
		patientTextArea.setBorder(BorderFactory.createLineBorder(Color.black));
		nurseTextArea.setBorder(BorderFactory.createLineBorder(Color.black));
		
		confirmButton.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				saveJournal();
			}
		});
		
		nameGrid.add(patientTextArea);
		nameGrid.add(doctorTextArea);
		nameGrid.add(nurseTextArea);
		nameGrid.add(divisionTextArea);
		
		buttonGrid.add(confirmButton);
		buttonGrid.add(cancelButton);
	
		this.add(nameGrid, BorderLayout.NORTH);
		this.add(dataTextArea, BorderLayout.CENTER);
		this.add(buttonGrid, BorderLayout.SOUTH);
		
		divisionTextArea.setText(this.journal.getDivision());
		doctorTextArea.setText(this.journal.getDoctor());
		dataTextArea.setText(this.journal.getData());
		patientTextArea.setText(this.journal.getPatient());
		nurseTextArea.setText(this.journal.getNurse());

		this.setSize(600, 600);
		this.setVisible(true);
	}
	
	public synchronized void waitForDone() {
		while(!done) {
			try {
				wait();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}
	
	private void saveJournal() {
		journal.setData(dataTextArea.getText());
		journal.setDoctor(doctorTextArea.getText());
		journal.setPatient(patientTextArea.getText());
		journal.setNurse(nurseTextArea.getText());
		journal.setDivision(divisionTextArea.getText());
		done = true;
		notifyAll();
		
	}
}
