package client;

import javax.swing.JFrame;
import javax.swing.JTextArea;
import data.Journal;

public class JournalDisplay extends JFrame{
	private JTextArea journalTextArea;
	private JTextArea divisionTextArea;
	private JTextArea doctorTextArea;
	private JTextArea patientTextArea;
	private JTextArea nurseTextArea;
	private Journal journal;
	
	public JournalDisplay(Journal journal, boolean editable) {
		journalTextArea = new JTextArea();
		divisionTextArea = new JTextArea();
		doctorTextArea = new JTextArea();
		patientTextArea = new JTextArea();
		nurseTextArea = new JTextArea();
		
		journalTextArea.setEditable(editable);
		divisionTextArea.setEditable(editable);
		doctorTextArea.setEditable(editable);
		patientTextArea.setEditable(editable);
		nurseTextArea.setEditable(editable);
		this.journal = journal;
		
	}
}
